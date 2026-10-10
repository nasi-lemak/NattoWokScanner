//! UPnP / SSDP discovery: smart TVs, media players, routers and NAS boxes
//! announce a description document with their friendly name and model.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::http;
use crate::model::UpnpInfo;

const SSDP_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);

#[derive(Debug, Default, Clone)]
pub struct SsdpHost {
    pub server: Option<String>,
    pub location: Option<String>,
    pub search_targets: Vec<String>,
}

fn search_packet(st: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\nUSER-AGENT: NattoWokScanner/{} UPnP/1.1\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    )
}

pub async fn discover(local_ip: Ipv4Addr, listen: Duration) -> HashMap<Ipv4Addr, SsdpHost> {
    let mut hosts: HashMap<Ipv4Addr, SsdpHost> = HashMap::new();
    let Ok(socket) = (|| -> std::io::Result<UdpSocket> {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        s.set_multicast_if_v4(&local_ip)?;
        s.set_multicast_ttl_v4(4)?;
        s.set_nonblocking(true)?;
        s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
        UdpSocket::from_std(s.into())
    })() else {
        return hosts;
    };
    let targets = ["ssdp:all", "upnp:rootdevice", "urn:schemas-upnp-org:device:InternetGatewayDevice:1"];
    for st in targets {
        let _ = socket.send_to(search_packet(st).as_bytes(), SSDP_ADDR).await;
    }
    let deadline = Instant::now() + listen;
    let mut resent = false;
    let mut buf = vec![0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if !resent && remaining < listen / 2 {
            resent = true;
            let _ = socket.send_to(search_packet("ssdp:all").as_bytes(), SSDP_ADDR).await;
        }
        let Ok(Ok((n, SocketAddr::V4(from)))) =
            tokio::time::timeout(remaining.min(listen / 2), socket.recv_from(&mut buf)).await
        else {
            continue;
        };
        let Ok(resp) = http::parse(&buf[..n]) else { continue };
        let host = hosts.entry(*from.ip()).or_default();
        if host.server.is_none() {
            host.server = resp.header("server").map(str::to_string);
        }
        if let Some(st) = resp.header("st")
            && !host.search_targets.iter().any(|s| s == st)
        {
            host.search_targets.push(st.to_string());
        }
        // Prefer the root device description.
        if let Some(loc) = resp.header("location")
            && (host.location.is_none() || resp.header("st") == Some("upnp:rootdevice"))
        {
            host.location = Some(loc.to_string());
        }
    }
    hosts
}

/// Splits `http://192.168.1.5:49152/desc.xml` into socket address and path.
/// Only plain HTTP URLs pointing back at the announcing device are accepted,
/// so a misbehaving device can't make us fetch arbitrary URLs.
pub fn parse_location(location: &str, expected_ip: Ipv4Addr) -> Option<(SocketAddr, String)> {
    let rest = location.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (authority, 80),
    };
    let ip: Ipv4Addr = host.parse().ok()?;
    (ip == expected_ip).then(|| (SocketAddr::from((ip, port)), path))
}

pub async fn describe(ip: Ipv4Addr, host: &SsdpHost) -> UpnpInfo {
    let mut info = UpnpInfo { server: host.server.clone(), ..Default::default() };
    let Some((addr, path)) = host.location.as_deref().and_then(|l| parse_location(l, ip)) else {
        return info;
    };
    if let Ok(resp) = http::get(addr, &addr.to_string(), &path, Duration::from_secs(2)).await {
        let doc = &resp.body;
        info.friendly_name = http::xml_text(doc, "friendlyName").filter(|s| !s.is_empty());
        info.manufacturer = http::xml_text(doc, "manufacturer").filter(|s| !s.is_empty());
        let model = http::xml_text(doc, "modelName").filter(|s| !s.is_empty());
        let number = http::xml_text(doc, "modelNumber").filter(|s| !s.is_empty());
        info.model = match (model, number) {
            (Some(m), Some(n)) if !m.contains(&n) => Some(format!("{m} {n}")),
            (m, n) => m.or(n),
        };
        info.device_type = http::xml_text(doc, "deviceType").filter(|s| !s.is_empty());
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_follows_locations_on_the_same_device() {
        let ip = Ipv4Addr::new(192, 168, 1, 5);
        assert_eq!(
            parse_location("http://192.168.1.5:49152/desc.xml", ip),
            Some((SocketAddr::from((ip, 49152)), "/desc.xml".into()))
        );
        assert_eq!(parse_location("http://192.168.1.5", ip), Some((SocketAddr::from((ip, 80)), "/".into())));
        assert_eq!(parse_location("http://10.0.0.1/desc.xml", ip), None);
        assert_eq!(parse_location("https://192.168.1.5/desc.xml", ip), None);
        assert_eq!(parse_location("http://evil.example/desc.xml", ip), None);
    }
}
