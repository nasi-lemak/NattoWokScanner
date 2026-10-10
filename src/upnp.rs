//! Asks the router (over UPnP IGD) what it forwards from the internet into
//! your network: the ports games, cameras and other apps opened on their own.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::http;
use crate::model::{PortMapping, RouterExposure};
use crate::ssdp::parse_location;

const TIMEOUT: Duration = Duration::from_secs(3);
/// Routers rarely hold more than a few dozen mappings; stop well before
/// a buggy one makes us loop forever.
const MAX_MAPPINGS: u32 = 256;

#[derive(Debug, Clone, PartialEq)]
pub struct Igd {
    pub control: SocketAddr,
    pub path: String,
    pub service_type: String,
}

/// Every `<service>` block's type and control URL in a description document.
fn services(doc: &str) -> Vec<(String, String)> {
    let lower = doc.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(start) = lower[from..].find("<service>").map(|i| i + from) {
        let Some(end) = lower[start..].find("</service>").map(|i| i + start) else { break };
        let block = &doc[start..end];
        if let (Some(st), Some(ctl)) = (http::xml_text(block, "serviceType"), http::xml_text(block, "controlURL")) {
            out.push((st, ctl));
        }
        from = end;
    }
    out
}

/// Finds the WAN connection service that answers port-mapping queries.
pub fn find_control(doc: &str, location: &str, gateway: Ipv4Addr) -> Option<Igd> {
    let (service_type, control_url) = services(doc)
        .into_iter()
        .filter(|(st, _)| st.contains(":WANIPConnection:") || st.contains(":WANPPPConnection:"))
        .max_by_key(|(st, _)| st.contains("WANIPConnection"))?;
    // Absolute control URLs must point back at the router itself.
    if control_url.starts_with("http://") {
        let (control, path) = parse_location(&control_url, gateway)?;
        return Some(Igd { control, path, service_type });
    }
    let base =
        http::xml_text(doc, "URLBase").filter(|b| b.starts_with("http://")).unwrap_or_else(|| location.to_string());
    let (control, _) = parse_location(&base, gateway)?;
    let path = if control_url.starts_with('/') { control_url } else { format!("/{control_url}") };
    Some(Igd { control, path, service_type })
}

async fn soap(igd: &Igd, action: &str, args: &[(&str, String)]) -> Result<http::Response> {
    let args: String = args.iter().map(|(k, v)| format!("<{k}>{v}</{k}>")).collect();
    let body = format!(
        "<?xml version=\"1.0\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{action} xmlns:u=\"{st}\">{args}</u:{action}></s:Body></s:Envelope>",
        st = igd.service_type
    );
    let soap_action = format!("\"{}#{action}\"", igd.service_type);
    http::post(
        igd.control,
        &igd.control.to_string(),
        &igd.path,
        &[("Content-Type", "text/xml; charset=\"utf-8\""), ("SOAPAction", &soap_action)],
        &body,
        TIMEOUT,
    )
    .await
}

fn field(doc: &str, name: &str) -> Option<String> {
    http::xml_text(doc, name).filter(|s| !s.is_empty())
}

pub fn parse_mapping(doc: &str) -> Option<PortMapping> {
    Some(PortMapping {
        external_port: field(doc, "NewExternalPort")?.parse().ok()?,
        protocol: field(doc, "NewProtocol").unwrap_or_else(|| "TCP".into()).to_uppercase(),
        internal_ip: field(doc, "NewInternalClient").and_then(|ip| ip.parse().ok()),
        internal_port: field(doc, "NewInternalPort").and_then(|p| p.parse().ok()).unwrap_or(0),
        description: field(doc, "NewPortMappingDescription"),
        enabled: field(doc, "NewEnabled").is_none_or(|e| e == "1" || e.eq_ignore_ascii_case("true")),
        lease_seconds: field(doc, "NewLeaseDuration").and_then(|l| l.parse().ok()).filter(|l| *l > 0),
        remote_host: field(doc, "NewRemoteHost"),
    })
}

/// Addresses that aren't really on the internet: private, carrier-grade NAT
/// (100.64.0.0/10), link-local.
pub fn is_shared_address(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private() || ip.is_link_local() || ip.is_unspecified() || (o[0] == 100 && (64..128).contains(&o[1]))
}

/// What the router at `gateway` (announced at `location`) exposes.
/// Returns `None` when it doesn't speak UPnP IGD.
pub async fn exposure(location: &str, gateway: Ipv4Addr) -> Option<RouterExposure> {
    let (addr, path) = parse_location(location, gateway)?;
    let desc = http::get(addr, &addr.to_string(), &path, TIMEOUT).await.ok()?;
    let igd = find_control(&desc.body, location, gateway)?;
    query(&igd).await.ok()
}

async fn query(igd: &Igd) -> Result<RouterExposure> {
    let ip_resp = soap(igd, "GetExternalIPAddress", &[]).await?;
    let external_ip = (ip_resp.status == 200).then(|| field(&ip_resp.body, "NewExternalIPAddress")).flatten();
    let shared_address = external_ip.as_deref().and_then(|ip| ip.parse().ok()).is_some_and(is_shared_address);
    let mut mappings = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    for index in 0..MAX_MAPPINGS {
        if Instant::now() > deadline {
            break;
        }
        // The list ends with a SOAP fault (713, "SpecifiedArrayIndexInvalid").
        let resp = soap(igd, "GetGenericPortMappingEntry", &[("NewPortMappingIndex", index.to_string())])
            .await
            .context("router stopped answering")?;
        if resp.status != 200 {
            break;
        }
        match parse_mapping(&resp.body) {
            Some(m) => mappings.push(m),
            None => break,
        }
    }
    Ok(RouterExposure { external_ip, shared_address, mappings })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const DESC: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
   <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
    <serviceList>
     <service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/ctl/CmnIfCfg</controlURL></service>
     <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service>
    </serviceList></device></deviceList></device></deviceList></device></root>"#;

    fn mapping_xml(port: u16, client: &str, desc: &str) -> String {
        format!(
            "<s:Envelope><s:Body><u:GetGenericPortMappingEntryResponse>\
             <NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort><NewProtocol>UDP</NewProtocol>\
             <NewInternalPort>{port}</NewInternalPort><NewInternalClient>{client}</NewInternalClient>\
             <NewEnabled>1</NewEnabled><NewPortMappingDescription>{desc}</NewPortMappingDescription>\
             <NewLeaseDuration>0</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"
        )
    }

    #[test]
    fn finds_the_wan_control_url() {
        let gw = Ipv4Addr::new(192, 168, 1, 1);
        let igd = find_control(DESC, "http://192.168.1.1:5000/rootDesc.xml", gw).unwrap();
        assert_eq!(igd.control, SocketAddr::from((gw, 5000)));
        assert_eq!(igd.path, "/ctl/IPConn");
        assert!(igd.service_type.ends_with("WANIPConnection:1"));
        // A control URL pointing somewhere else is refused.
        let evil = DESC.replace("/ctl/IPConn", "http://10.9.9.9/ctl");
        assert!(find_control(&evil, "http://192.168.1.1:5000/rootDesc.xml", gw).is_none());
    }

    #[test]
    fn parses_mappings_and_shared_addresses() {
        let m = parse_mapping(&mapping_xml(3074, "192.168.1.31", "Xbox &amp; Live")).unwrap();
        assert_eq!(m.external_port, 3074);
        assert_eq!(m.protocol, "UDP");
        assert_eq!(m.internal_ip, Some(Ipv4Addr::new(192, 168, 1, 31)));
        assert_eq!(m.description.as_deref(), Some("Xbox & Live"));
        assert!(m.enabled);
        assert_eq!(m.lease_seconds, None);
        assert_eq!(m.remote_host, None);
        assert!(is_shared_address("100.72.1.9".parse().unwrap()));
        assert!(is_shared_address("10.1.2.3".parse().unwrap()));
        assert!(!is_shared_address("81.2.69.160".parse().unwrap()));
    }

    /// A pretend router that answers the description and SOAP requests.
    #[tokio::test]
    async fn reads_mappings_from_a_router() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let mut buf = vec![0u8; 8192];
                let mut req = String::new();
                // Read until the whole body (or headers for GET) has arrived.
                loop {
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    req.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if req.starts_with("GET") && req.contains("\r\n\r\n") || req.contains("</s:Envelope>") {
                        break;
                    }
                }
                let (status, body) = if req.starts_with("GET /rootDesc.xml") {
                    ("200 OK", DESC.to_string())
                } else if req.contains("#GetExternalIPAddress") {
                    ("200 OK", "<NewExternalIPAddress>81.2.69.160</NewExternalIPAddress>".to_string())
                } else if req.contains("<NewPortMappingIndex>0<") {
                    ("200 OK", mapping_xml(3074, "192.168.1.31", "Xbox"))
                } else if req.contains("<NewPortMappingIndex>1<") {
                    ("200 OK", mapping_xml(554, "192.168.1.52", "IPCam"))
                } else {
                    ("500 Internal Server Error", "<errorCode>713</errorCode>".to_string())
                };
                let resp =
                    format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        let location = format!("http://127.0.0.1:{port}/rootDesc.xml");
        let exp = exposure(&location, Ipv4Addr::LOCALHOST).await.expect("router answered");
        assert_eq!(exp.external_ip.as_deref(), Some("81.2.69.160"));
        assert!(!exp.shared_address);
        assert_eq!(exp.mappings.len(), 2);
        assert_eq!(exp.mappings[1].external_port, 554);
        assert_eq!(exp.mappings[1].description.as_deref(), Some("IPCam"));
    }
}
