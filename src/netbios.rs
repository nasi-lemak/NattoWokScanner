//! NetBIOS node-status queries: Windows PCs and Samba servers answer with
//! their computer name and workgroup.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

#[derive(Debug, Clone, PartialEq)]
pub struct NetbiosInfo {
    pub name: String,
    pub workgroup: Option<String>,
}

pub fn status_request(id: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(50);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    p.push(0x20);
    let mut raw = [0u8; 16];
    raw[0] = b'*';
    for b in raw {
        p.push(b'A' + (b >> 4));
        p.push(b'A' + (b & 0x0F));
    }
    p.push(0);
    p.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]);
    p
}

pub fn parse_status(buf: &[u8]) -> Option<NetbiosInfo> {
    // Header (12) + encoded name (34) + type/class/ttl/rdlength (10).
    let mut pos = 12;
    if buf.get(pos)? & 0xC0 == 0xC0 {
        pos += 2;
    } else {
        while *buf.get(pos)? != 0 {
            pos += 1 + usize::from(buf[pos]);
        }
        pos += 1;
    }
    pos += 10;
    let count = usize::from(*buf.get(pos)?);
    pos += 1;
    let mut name = None;
    let mut workgroup = None;
    for i in 0..count {
        let entry = buf.get(pos + i * 18..pos + i * 18 + 18)?;
        let label = String::from_utf8_lossy(&entry[..15]).trim_end().to_string();
        let suffix = entry[15];
        let group = entry[16] & 0x80 != 0;
        if suffix == 0x00 && !group && name.is_none() && !label.is_empty() {
            name = Some(label);
        } else if suffix == 0x00 && group && workgroup.is_none() && !label.is_empty() {
            workgroup = Some(label);
        }
    }
    Some(NetbiosInfo { name: name?, workgroup })
}

pub async fn query_all(ips: &[Ipv4Addr], listen: Duration) -> HashMap<Ipv4Addr, NetbiosInfo> {
    let mut found = HashMap::new();
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        return found;
    };
    for (i, ip) in ips.iter().enumerate() {
        let _ = socket.send_to(&status_request(i as u16), SocketAddr::from((*ip, 137))).await;
    }
    let deadline = Instant::now() + listen;
    let mut buf = [0u8; 1024];
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let Ok(Ok((n, SocketAddr::V4(from)))) = tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await
        else {
            break;
        };
        if let Some(info) = parse_status(&buf[..n]) {
            found.insert(*from.ip(), info);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_wildcard_name() {
        let p = status_request(7);
        assert_eq!(p.len(), 50);
        assert_eq!(&p[13..15], b"CK");
        assert_eq!(&p[15..17], b"AA");
    }

    #[test]
    fn parses_node_status() {
        let mut r = status_request(7);
        r[2] = 0x84;
        r.truncate(12 + 34);
        r.extend_from_slice(&[0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        r.push(2);
        let entry = |name: &str, suffix: u8, group: bool| {
            let mut n = format!("{name:<15}").into_bytes();
            n.push(suffix);
            n.extend_from_slice(&[if group { 0x84 } else { 0x04 }, 0]);
            n
        };
        r.extend(entry("DESKTOP-ABC123", 0, false));
        r.extend(entry("WORKGROUP", 0, true));
        let info = parse_status(&r).unwrap();
        assert_eq!(info.name, "DESKTOP-ABC123");
        assert_eq!(info.workgroup.as_deref(), Some("WORKGROUP"));
    }
}
