//! Bonjour / mDNS discovery. Devices happily tell us their name, model and
//! what they do, if we ask nicely.
//!
//! We query from an ephemeral port, which makes responders answer us directly
//! (RFC 6762 §6.7 "legacy unicast"), so we never need to bind port 5353 and
//! don't fight with the system's own mDNS daemon.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::dns::{self, RData};
use crate::model::Advertised;

const MDNS_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);

/// Service types worth asking for even when a device does not answer the
/// generic service enumeration.
pub const SERVICE_TYPES: &[&str] = &[
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_googlecast._tcp.local",
    "_spotify-connect._tcp.local",
    "_sonos._tcp.local",
    "_ipp._tcp.local",
    "_ipps._tcp.local",
    "_printer._tcp.local",
    "_pdl-datastream._tcp.local",
    "_uscan._tcp.local",
    "_scanner._tcp.local",
    "_hap._tcp.local",
    "_matter._tcp.local",
    "_hue._tcp.local",
    "_companion-link._tcp.local",
    "_device-info._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_adisk._tcp.local",
    "_rfb._tcp.local",
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_workstation._tcp.local",
    "_http._tcp.local",
    "_amzn-wplay._tcp.local",
    "_androidtvremote2._tcp.local",
    "_home-assistant._tcp.local",
    "_esphomelib._tcp.local",
    "_mqtt._tcp.local",
    "_nvstream._tcp.local",
    "_plexmediasvr._tcp.local",
];

/// What a service type means, in plain words.
pub fn describe_service(service: &str) -> &'static str {
    let s = service.trim_end_matches(".local").trim_end_matches('.');
    match s {
        "_airplay._tcp" => "AirPlay video/screen mirroring",
        "_raop._tcp" => "AirPlay audio",
        "_googlecast._tcp" => "Google Cast (Chromecast)",
        "_spotify-connect._tcp" => "Spotify Connect speaker",
        "_sonos._tcp" => "Sonos speaker",
        "_ipp._tcp" | "_ipps._tcp" | "_printer._tcp" | "_pdl-datastream._tcp" => "Printing",
        "_uscan._tcp" | "_scanner._tcp" => "Document scanning",
        "_hap._tcp" => "Apple HomeKit accessory",
        "_matter._tcp" | "_matterc._udp" => "Matter smart-home device",
        "_hue._tcp" => "Philips Hue bridge",
        "_companion-link._tcp" => "Apple device pairing (iPhone/iPad/Mac)",
        "_device-info._tcp" => "Device model information",
        "_smb._tcp" => "Windows file sharing",
        "_afpovertcp._tcp" => "Apple file sharing",
        "_adisk._tcp" => "Time Machine backup disk",
        "_rfb._tcp" => "Screen sharing (VNC)",
        "_ssh._tcp" | "_sftp-ssh._tcp" => "Remote login (SSH)",
        "_workstation._tcp" => "Linux workstation",
        "_http._tcp" => "Web interface",
        "_amzn-wplay._tcp" => "Amazon Fire TV",
        "_androidtvremote2._tcp" => "Android TV remote control",
        "_home-assistant._tcp" => "Home Assistant",
        "_esphomelib._tcp" => "ESPHome smart-home device",
        "_mqtt._tcp" => "MQTT smart-home broker",
        "_nvstream._tcp" => "NVIDIA GameStream",
        "_plexmediasvr._tcp" => "Plex media server",
        _ => "Network service",
    }
}

#[derive(Debug, Default, Clone)]
pub struct MdnsHost {
    pub hostnames: BTreeSet<String>,
    pub services: BTreeSet<Advertised>,
    /// TXT key/values merged across services (`model`, `md`, `fn`, `ty`, ...).
    pub txt: BTreeMap<String, String>,
}

fn multicast_socket(local_ip: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_multicast_if_v4(&local_ip)?;
    s.set_multicast_ttl_v4(255)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
    UdpSocket::from_std(s.into())
}

/// Instance label from `Living Room._airplay._tcp.local`.
fn instance_name(full: &str, service: &str) -> String {
    full.strip_suffix(service).map(|s| s.trim_end_matches('.')).unwrap_or(full).replace("\\032", " ").to_string()
}

fn service_of(name: &str) -> Option<String> {
    let parts: Vec<&str> = name.split('.').collect();
    let i = parts.iter().position(|p| *p == "_tcp" || *p == "_udp")?;
    (i >= 1).then(|| format!("{}.{}.local", parts[i - 1], parts[i]))
}

pub async fn discover(local_ip: Ipv4Addr, listen: Duration) -> HashMap<Ipv4Addr, MdnsHost> {
    let mut hosts: HashMap<Ipv4Addr, MdnsHost> = HashMap::new();
    let Ok(socket) = multicast_socket(local_ip) else {
        return hosts;
    };
    let mut questions: Vec<(String, u16)> = vec![("_services._dns-sd._udp.local".into(), dns::TYPE_PTR)];
    questions.extend(SERVICE_TYPES.iter().map(|s| (s.to_string(), dns::TYPE_PTR)));

    let send_batch = |qs: &[(String, u16)]| {
        let refs: Vec<(&str, u16)> = qs.iter().map(|(n, t)| (n.as_str(), *t)).collect();
        dns::build_query(0, &refs, false)
    };
    for chunk in questions.chunks(12) {
        let _ = socket.send_to(&send_batch(chunk), MDNS_ADDR).await;
    }

    let mut asked: BTreeSet<String> = SERVICE_TYPES.iter().map(|s| s.to_string()).collect();
    let mut buf = vec![0u8; 9000];
    let deadline = Instant::now() + listen;
    let mut resent = false;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        // Resend once halfway through; mDNS over Wi-Fi drops packets.
        if !resent && remaining < listen / 2 {
            resent = true;
            for chunk in questions.chunks(12) {
                let _ = socket.send_to(&send_batch(chunk), MDNS_ADDR).await;
            }
        }
        let wait = remaining.min(listen / 2);
        let Ok(Ok((n, from))) = tokio::time::timeout(wait, socket.recv_from(&mut buf)).await else {
            continue;
        };
        let SocketAddr::V4(from) = from else { continue };
        let Ok(msg) = dns::parse(&buf[..n]) else { continue };
        if !msg.is_response {
            continue;
        }
        let mut new_types = Vec::new();
        let host = hosts.entry(*from.ip()).or_default();
        absorb(host, &msg.records, &mut new_types);
        // Follow up on service types we learned about from enumeration.
        let fresh: Vec<(String, u16)> =
            new_types.into_iter().filter(|t| asked.insert(t.clone())).map(|t| (t, dns::TYPE_PTR)).collect();
        for chunk in fresh.chunks(12) {
            let _ = socket.send_to(&send_batch(chunk), MDNS_ADDR).await;
        }
    }
    hosts.retain(|_, h| !h.hostnames.is_empty() || !h.services.is_empty());
    hosts
}

/// Asks each device directly (unicast to port 5353) for its own name. Apple
/// devices and Linux machines running Avahi answer this even when they
/// advertise no services.
pub async fn resolve_names(ips: &[Ipv4Addr], listen: Duration) -> HashMap<Ipv4Addr, String> {
    let mut names = HashMap::new();
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        return names;
    };
    for ip in ips {
        let packet = dns::build_query(0, &[(&dns::reverse_name(*ip), dns::TYPE_PTR)], false);
        let _ = socket.send_to(&packet, SocketAddr::from((*ip, 5353))).await;
    }
    let deadline = Instant::now() + listen;
    let mut buf = vec![0u8; 9000];
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let Ok(Ok((n, SocketAddr::V4(from)))) = tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await
        else {
            break;
        };
        let Ok(msg) = dns::parse(&buf[..n]) else { continue };
        let name = msg.records.into_iter().find_map(|r| match r.data {
            RData::Ptr(target) if r.name.ends_with(".in-addr.arpa") => Some(target),
            _ => None,
        });
        if let Some(name) = name {
            names.insert(*from.ip(), name.trim_end_matches('.').trim_end_matches(".local").to_string());
        }
    }
    names
}

fn absorb(host: &mut MdnsHost, records: &[dns::Record], new_types: &mut Vec<String>) {
    let mut ports: HashMap<&str, u16> = HashMap::new();
    for r in records {
        if let RData::Srv { port, target } = &r.data {
            ports.insert(r.name.as_str(), *port);
            if target.ends_with(".local") {
                host.hostnames.insert(target.trim_end_matches(".local").to_string());
            }
        }
    }
    for r in records {
        match &r.data {
            RData::Ptr(target) if r.name == "_services._dns-sd._udp.local" => {
                new_types.push(target.clone());
            }
            RData::Ptr(target) if r.name.ends_with(".in-addr.arpa") => {
                host.hostnames.insert(target.trim_end_matches(".local").to_string());
            }
            RData::Ptr(target) => {
                let Some(service) = service_of(&r.name) else { continue };
                host.services.insert(Advertised {
                    description: describe_service(&service).to_string(),
                    instance: Some(instance_name(target, &service)).filter(|s| !s.is_empty()),
                    port: ports.get(target.as_str()).copied(),
                    service: service.trim_end_matches(".local").to_string(),
                });
            }
            RData::A(_) if r.name.ends_with(".local") => {
                host.hostnames.insert(r.name.trim_end_matches(".local").to_string());
            }
            RData::Txt(entries) => {
                for entry in entries {
                    if let Some((k, v)) = entry.split_once('=') {
                        let k = k.to_ascii_lowercase();
                        if !v.is_empty()
                            && matches!(
                                k.as_str(),
                                "model"
                                    | "md"
                                    | "fn"
                                    | "ty"
                                    | "usb_mfg"
                                    | "usb_mdl"
                                    | "am"
                                    | "manufacturer"
                                    | "product"
                                    | "name"
                            )
                        {
                            host.txt.entry(k).or_insert_with(|| v.to_string());
                        }
                    }
                }
                // A TXT record also proves the service exists, even without a PTR.
                if let Some(service) = service_of(&r.name)
                    && service != "_services._dns-sd._udp.local"
                {
                    let instance = instance_name(&r.name, &service);
                    let adv = Advertised {
                        description: describe_service(&service).to_string(),
                        instance: Some(instance).filter(|s| !s.is_empty()),
                        port: ports.get(r.name.as_str()).copied(),
                        service: service.trim_end_matches(".local").to_string(),
                    };
                    if !host.services.iter().any(|s| s.service == adv.service && s.instance == adv.instance) {
                        host.services.insert(adv);
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Record;

    #[test]
    fn absorbs_service_records() {
        let records = vec![
            Record {
                name: "_googlecast._tcp.local".into(),
                rtype: 12,
                data: RData::Ptr("Chromecast-abc._googlecast._tcp.local".into()),
            },
            Record {
                name: "Chromecast-abc._googlecast._tcp.local".into(),
                rtype: 33,
                data: RData::Srv { port: 8009, target: "abc123.local".into() },
            },
            Record {
                name: "Chromecast-abc._googlecast._tcp.local".into(),
                rtype: 16,
                data: RData::Txt(vec!["md=Chromecast Ultra".into(), "fn=Living Room TV".into()]),
            },
            Record {
                name: "_services._dns-sd._udp.local".into(),
                rtype: 12,
                data: RData::Ptr("_foo._tcp.local".into()),
            },
        ];
        let mut host = MdnsHost::default();
        let mut new_types = Vec::new();
        absorb(&mut host, &records, &mut new_types);
        assert_eq!(new_types, vec!["_foo._tcp.local".to_string()]);
        assert!(host.hostnames.contains("abc123"));
        assert_eq!(host.txt.get("md").map(String::as_str), Some("Chromecast Ultra"));
        assert_eq!(host.txt.get("fn").map(String::as_str), Some("Living Room TV"));
        assert_eq!(host.services.len(), 1);
        let svc = host.services.iter().next().unwrap();
        assert_eq!(svc.service, "_googlecast._tcp");
        assert_eq!(svc.instance.as_deref(), Some("Chromecast-abc"));
        assert_eq!(svc.port, Some(8009));
    }
}
