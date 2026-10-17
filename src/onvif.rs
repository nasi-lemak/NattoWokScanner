//! ONVIF (WS-Discovery) camera discovery. Most IP cameras and video
//! recorders answer a multicast "probe" on UDP 3702 with their type, name
//! and hardware model, even when they open no other obvious ports.
//!
//! Windows PCs and printers answer WS-Discovery too; only replies that
//! mention ONVIF are kept.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

const WSD_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 3702);

#[derive(Debug, Default, Clone, PartialEq)]
pub struct OnvifHost {
    /// Says it sends video (a camera, doorbell or video encoder).
    pub video: bool,
    pub name: Option<String>,
    pub hardware: Option<String>,
}

fn message_id() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::fill(&mut b);
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("uuid:{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

fn probe(types: Option<&str>) -> String {
    let types = types.map(|t| format!("<d:Types>{t}</d:Types>")).unwrap_or_default();
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" "#,
            r#"xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl">"#,
            r#"<e:Header><w:MessageID>{id}</w:MessageID><w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"#,
            r#"<w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>"#,
            r#"<e:Body><d:Probe>{types}</d:Probe></e:Body></e:Envelope>"#
        ),
        id = message_id(),
        types = types
    )
}

/// Text of the first element with this local name, whatever its namespace
/// prefix (`<d:Scopes>`, `<wsdd:Scopes>`, `<Scopes>`).
fn element(doc: &str, local: &str) -> Option<String> {
    let mut rest = doc;
    while let Some(i) = rest.find('<') {
        rest = &rest[i + 1..];
        let end = rest.find(['>', ' ', '\t', '\r', '\n', '/'])?;
        let tag = &rest[..end];
        if tag.rsplit(':').next() == Some(local) && !tag.starts_with('/') {
            let start = rest.find('>')? + 1;
            if rest[..start].ends_with("/>") {
                return Some(String::new());
            }
            let body = &rest[start..];
            let close = body.find("</")?;
            return Some(body[..close].split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
    None
}

/// `onvif://www.onvif.org/name/Front%20Door` -> `Front Door`.
fn scope_value(scopes: &str, key: &str) -> Option<String> {
    let prefix = format!("onvif://www.onvif.org/{key}/");
    let raw = scopes.split_whitespace().find_map(|s| s.strip_prefix(&prefix))?;
    let mut out = Vec::new();
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(b) = raw.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(if bytes[i] == b'_' { b' ' } else { bytes[i] });
        i += 1;
    }
    let text = String::from_utf8_lossy(&out).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Reads one ProbeMatch reply; `None` when it isn't from an ONVIF device.
pub fn parse_reply(xml: &str) -> Option<OnvifHost> {
    let types = element(xml, "Types").unwrap_or_default();
    let scopes = element(xml, "Scopes").unwrap_or_default();
    let lower_scopes = scopes.to_ascii_lowercase();
    if !types.contains("NetworkVideoTransmitter") && !lower_scopes.contains("onvif://") {
        return None;
    }
    let video = types.contains("NetworkVideoTransmitter")
        || ["type/video_encoder", "type/network_video_transmitter", "type/networkvideotransmitter", "type/ptz"]
            .iter()
            .any(|t| lower_scopes.contains(t));
    Some(OnvifHost { video, name: scope_value(&scopes, "name"), hardware: scope_value(&scopes, "hardware") })
}

pub async fn discover(local_ip: Ipv4Addr, listen: Duration) -> HashMap<Ipv4Addr, OnvifHost> {
    let mut hosts = HashMap::new();
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
    // Some cameras only answer a typed probe, others only an untyped one.
    let probes = [probe(Some("dn:NetworkVideoTransmitter")), probe(None)];
    for p in &probes {
        let _ = socket.send_to(p.as_bytes(), WSD_ADDR).await;
    }
    let deadline = Instant::now() + listen;
    let mut resent = false;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if !resent && remaining < listen / 2 {
            resent = true;
            let _ = socket.send_to(probes[0].as_bytes(), WSD_ADDR).await;
        }
        let Ok(Ok((n, SocketAddr::V4(from)))) =
            tokio::time::timeout(remaining.min(listen / 2), socket.recv_from(&mut buf)).await
        else {
            continue;
        };
        if let Some(host) = parse_reply(&String::from_utf8_lossy(&buf[..n])) {
            let entry: &mut OnvifHost = hosts.entry(*from.ip()).or_default();
            entry.video |= host.video;
            entry.name = entry.name.take().or(host.name);
            entry.hardware = entry.hardware.take().or(host.hardware);
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPLY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
<SOAP-ENV:Body><wsdd:ProbeMatches><wsdd:ProbeMatch>
<wsa:EndpointReference><wsa:Address>urn:uuid:2419d68a-2dd2-21b2-a205-ec</wsa:Address></wsa:EndpointReference>
<wsdd:Types>dn:NetworkVideoTransmitter</wsdd:Types>
<wsdd:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/Profile/Streaming onvif://www.onvif.org/hardware/IPC-HFW1230S onvif://www.onvif.org/name/Front%20Door onvif://www.onvif.org/location/country/china</wsdd:Scopes>
<wsdd:XAddrs>http://192.168.1.64/onvif/device_service</wsdd:XAddrs>
</wsdd:ProbeMatch></wsdd:ProbeMatches></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;

    #[test]
    fn reads_camera_replies() {
        let host = parse_reply(REPLY).unwrap();
        assert!(host.video);
        assert_eq!(host.name.as_deref(), Some("Front Door"));
        assert_eq!(host.hardware.as_deref(), Some("IPC-HFW1230S"));
    }

    #[test]
    fn ignores_windows_and_printers() {
        let pc = "<s:Envelope><s:Body><wsd:ProbeMatches><wsd:ProbeMatch><wsd:Types>wsdp:Device pub:Computer</wsd:Types>\
                  <wsd:XAddrs>http://192.168.1.20:5357/</wsd:XAddrs></wsd:ProbeMatch></wsd:ProbeMatches></s:Body></s:Envelope>";
        assert_eq!(parse_reply(pc), None);
    }

    #[test]
    fn probe_is_well_formed() {
        let p = probe(Some("dn:NetworkVideoTransmitter"));
        assert!(p.contains("<d:Types>dn:NetworkVideoTransmitter</d:Types>"));
        assert!(p.contains("uuid:"));
        assert!(!probe(None).contains("Types"));
    }
}
