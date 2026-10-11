//! A small HTTPS client: the OS trust store, redirects, and a size cap.
//! Used for the speed test and for downloading vendor-list updates.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// A TLS connector trusting the operating system's certificates, so
/// corporate proxies with their own CA keep working.
pub fn connector() -> Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if roots.is_empty() {
        bail!("couldn't load this computer's trusted certificates");
    }
    let config = ClientConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// `https://host[:port]/path` -> (host, port, path).
pub fn split_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url.strip_prefix("https://").context("only https:// links are supported")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().context("bad port")?),
        None => (authority.to_string(), 443),
    };
    anyhow::ensure!(!host.is_empty(), "no host in {url}");
    Ok((host, port, path))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = find(rest, b"\r\n").context("bad chunked body")?;
        let size_text = String::from_utf8_lossy(&rest[..line_end]);
        let size =
            usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16).context("bad chunk size")?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(rest.get(..size).context("truncated chunk")?);
        rest = rest.get(size + 2..).unwrap_or_default();
    }
}

pub struct Response {
    pub status: u16,
    /// Header names are lower-cased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Splits a raw response into status, headers and decoded body.
pub fn parse_response(raw: &[u8]) -> Result<Response> {
    let split = find(raw, b"\r\n\r\n").context("incomplete response")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.lines();
    let status =
        lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse().ok()).context("bad status")?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let body = &raw[split + 4..];
    let chunked = headers.iter().any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked { dechunk(body)? } else { body.to_vec() };
    Ok(Response { status, headers, body })
}

/// Downloads `url` (following up to 3 redirects), refusing bodies over `max_bytes`.
pub async fn get(url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    let tls = connector()?;
    let mut url = url.to_string();
    for _ in 0..4 {
        let (host, port, path) = split_url(&url)?;
        let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host.as_str(), port)))
            .await
            .context("timed out connecting")??;
        let mut stream = tls.connect(ServerName::try_from(host.clone())?, tcp).await?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NattoWokScanner/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );
        stream.write_all(req.as_bytes()).await?;
        let mut raw = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        let read = async {
            loop {
                let n = match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    // Many servers close TLS without a close_notify; we have the data.
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(anyhow::Error::from(e)),
                };
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > max_bytes + 64 * 1024 {
                    bail!("the download is larger than expected");
                }
            }
            Ok(())
        };
        tokio::time::timeout(Duration::from_secs(120), read).await.context("download timed out")??;
        let Response { status, headers, body } = parse_response(&raw)?;
        match status {
            200 => return Ok(body),
            301 | 302 | 303 | 307 | 308 => {
                let location = headers.iter().find(|(k, _)| k == "location").map(|(_, v)| v.clone());
                url = location.context("redirect without a location")?;
                if url.starts_with('/') {
                    url = format!("https://{host}{url}");
                }
            }
            other => bail!("{host} answered {other}"),
        }
    }
    bail!("too many redirects")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_urls() {
        assert_eq!(
            split_url("https://standards-oui.ieee.org/oui/oui.csv").unwrap(),
            ("standards-oui.ieee.org".into(), 443, "/oui/oui.csv".into())
        );
        assert_eq!(split_url("https://h:8443").unwrap(), ("h".into(), 8443, "/".into()));
        assert!(split_url("http://plain.example/").is_err());
    }

    #[test]
    fn parses_chunked_and_plain_responses() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"Wikipedia");
        let raw = b"HTTP/1.1 302 Found\r\nLocation: /new\r\nContent-Length: 0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 302);
        assert_eq!(r.headers[0], ("location".to_string(), "/new".to_string()));
        assert!(r.body.is_empty());
    }
}
