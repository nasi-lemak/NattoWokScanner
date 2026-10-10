//! A deliberately tiny plain-HTTP client for talking to LAN devices (UPnP
//! descriptions, admin page titles, captive-portal checks).

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_BODY: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Contents of the HTML `<title>`, whitespace collapsed.
    pub fn title(&self) -> Option<String> {
        let text = xml_text(&self.body, "title")?;
        (!text.is_empty()).then(|| text.chars().take(100).collect())
    }
}

pub async fn get(addr: SocketAddr, host: &str, path: &str, timeout: Duration) -> Result<Response> {
    tokio::time::timeout(timeout, request(addr, "GET", host, path, &[], "")).await.context("timed out")?
}

pub async fn post(
    addr: SocketAddr,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
    timeout: Duration,
) -> Result<Response> {
    tokio::time::timeout(timeout, request(addr, "POST", host, path, headers, body)).await.context("timed out")?
}

async fn request(
    addr: SocketAddr,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<Response> {
    let mut stream = TcpStream::connect(addr).await?;
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NattoWokScanner/{}\r\nAccept: */*\r\nConnection: close\r\n",
        env!("CARGO_PKG_VERSION")
    );
    for (k, v) in headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    if method != "GET" {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).await?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 || buf.len() >= MAX_BODY {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    parse(&buf)
}

pub fn parse(raw: &[u8]) -> Result<Response> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").or_else(|| text.split_once("\n\n")).unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    if !parts.next().unwrap_or_default().starts_with("HTTP/") {
        bail!("not an HTTP response");
    }
    let status = parts.next().and_then(|s| s.parse().ok()).context("bad status")?;
    let headers: Vec<(String, String)> =
        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked { dechunk(body) } else { body.to_string() };
    Ok(Response { status, headers, body })
}

/// Decodes a chunked body, tolerating truncation (we stop reading at 64 KiB).
fn dechunk(mut rest: &str) -> String {
    let mut out = String::new();
    while let Some((size_line, after)) = rest.split_once("\r\n") {
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(size_hex, 16) else { break };
        if size == 0 {
            break;
        }
        let take = size.min(after.len());
        let Some(chunk) = after.get(..take) else { break };
        out.push_str(chunk);
        rest = after.get(take..).unwrap_or_default().trim_start_matches("\r\n");
    }
    out
}

/// Text inside the first `<tag>...</tag>` (case-insensitive, attributes allowed),
/// with entities for the common characters decoded and whitespace collapsed.
pub fn xml_text(doc: &str, tag: &str) -> Option<String> {
    let lower = doc.to_ascii_lowercase();
    let open = format!("<{}", tag.to_ascii_lowercase());
    let mut search = 0;
    let start = loop {
        let i = lower[search..].find(&open)? + search;
        let after = lower.as_bytes().get(i + open.len()).copied();
        if matches!(after, Some(b'>') | Some(b' ') | Some(b'\t') | Some(b'\n')) {
            break lower[i..].find('>')? + i + 1;
        }
        search = i + open.len();
    };
    let end = lower[start..].find(&format!("</{}", tag.to_ascii_lowercase()))? + start;
    let text = doc[start..end]
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'");
    Some(text.split_whitespace().collect::<Vec<_>>().join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_response_and_title() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: lighttpd\r\nContent-Type: text/html\r\n\r\n<html><head><TITLE>\n  RT-AX88U &amp; friends </TITLE></head></html>";
        let r = parse(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("server"), Some("lighttpd"));
        assert_eq!(r.title().as_deref(), Some("RT-AX88U & friends"));
    }

    #[test]
    fn extracts_xml_fields() {
        let doc = "<root><device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>\
                   <friendlyName>Living Room</friendlyName><modelNameX>no</modelNameX><modelName>Sonos One</modelName></device></root>";
        assert_eq!(xml_text(doc, "friendlyName").as_deref(), Some("Living Room"));
        assert_eq!(xml_text(doc, "modelName").as_deref(), Some("Sonos One"));
        assert_eq!(xml_text(doc, "missing"), None);
    }

    #[test]
    fn decodes_chunked_bodies() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n<title>\r\n9;ext=1\r\nMy Router\r\n8\r\n</title>\r\n0\r\n\r\n";
        let r = parse(raw).unwrap();
        assert_eq!(r.body, "<title>My Router</title>");
        assert_eq!(r.title().as_deref(), Some("My Router"));
    }

    #[test]
    fn rejects_non_http() {
        assert!(parse(b"SSH-2.0-OpenSSH_9.6\r\n").is_err());
    }
}
