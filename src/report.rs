//! Exports: CSV for spreadsheets, Markdown for sending to whoever helps you
//! with tech, and JSON for scripts.

use std::fmt::Write;

use std::collections::HashSet;

use serde_json::json;

use crate::identify::is_device_word;
use crate::model::{Device, ScanReport, Severity};

fn csv_field(s: &str) -> String {
    // Leading =, +, - or @ would be run as a formula by spreadsheet apps.
    let s = if s.starts_with(['=', '+', '-', '@']) { format!("'{s}") } else { s.to_string() };
    if s.contains([',', '"', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s }
}

pub fn to_csv(report: &ScanReport) -> String {
    let mut out = String::from(
        "name,ip,mac,vendor,kind,confidence,model,hostname,online,trusted,tags,open_ports,first_seen,last_seen\n",
    );
    for d in &report.devices {
        let row = [
            d.display_name().to_string(),
            d.ip.to_string(),
            d.mac.clone().unwrap_or_default(),
            d.vendor.clone().unwrap_or_else(|| if d.private_mac { "(private address)".into() } else { String::new() }),
            d.kind.label().to_string(),
            d.confidence.to_string(),
            d.model.clone().unwrap_or_default(),
            d.hostname.clone().unwrap_or_default(),
            d.online.to_string(),
            d.trusted.to_string(),
            d.tags.join(" "),
            d.open_ports.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(" "),
            d.first_seen.map(|t| t.to_rfc3339()).unwrap_or_default(),
            d.last_seen.map(|t| t.to_rfc3339()).unwrap_or_default(),
        ];
        out.push_str(&row.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

fn md(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

pub fn to_markdown(report: &ScanReport) -> String {
    let n = &report.network;
    let mut out = String::new();
    let _ = writeln!(out, "# Network report\n");
    let _ = writeln!(
        out,
        "Scanned {} on {} by NattoWok Scanner.\n",
        n.scan_range,
        report.finished_at.format("%Y-%m-%d %H:%M UTC")
    );
    let _ = writeln!(out, "- **Health score:** {}/100", report.health_score);
    let _ = writeln!(out, "- **This computer:** {} on {}", n.ip, n.interface_label.as_deref().unwrap_or(&n.interface));
    if let Some(gw) = n.gateway {
        let _ = writeln!(out, "- **Router:** {gw}");
    }
    if !n.dns_servers.is_empty() {
        let dns: Vec<String> = n.dns_servers.iter().map(ToString::to_string).collect();
        let _ = writeln!(out, "- **DNS servers:** {}", dns.join(", "));
    }
    let online = report.devices.iter().filter(|d| d.online).count();
    let _ = writeln!(out, "- **Devices online:** {online}\n");

    let mut findings: Vec<_> = report.all_findings().filter(|f| !f.ignored && f.severity > Severity::Info).collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    if !findings.is_empty() {
        let _ = writeln!(out, "## Things to fix\n");
        for f in findings {
            let _ = writeln!(
                out,
                "- **[{}] {}**: {} *Fix:* {}",
                f.severity.label(),
                md(&f.title),
                md(&f.explanation),
                md(&f.fix)
            );
        }
        out.push('\n');
    }

    if let Some(exp) = &report.exposure {
        let mappings: Vec<_> = exp.mappings.iter().filter(|m| m.enabled).collect();
        let _ = writeln!(out, "## Open to the internet\n");
        if let Some(ip) = &exp.external_ip {
            let shared = if exp.shared_address { " (shared by the provider: carrier-grade NAT)" } else { "" };
            let _ = writeln!(out, "Public address: {ip}{shared}\n");
        }
        if mappings.is_empty() {
            let _ = writeln!(out, "The router forwards no ports.\n");
        } else {
            let _ = writeln!(out, "| External port | To | Opened by |");
            let _ = writeln!(out, "|---|---|---|");
            for m in mappings {
                let to = m.internal_ip.map_or("?".to_string(), |ip| {
                    let name = report.devices.iter().find(|d| d.ip == ip).map(|d| d.display_name().to_string());
                    format!("{} ({ip}:{})", name.unwrap_or_default(), m.internal_port)
                });
                let _ = writeln!(
                    out,
                    "| {} {} | {} | {} |",
                    m.external_port,
                    m.protocol,
                    md(&to),
                    md(m.description.as_deref().unwrap_or(""))
                );
            }
            out.push('\n');
        }
    }

    let _ = writeln!(out, "## Devices\n");
    let _ = writeln!(out, "| Name | Type | IP | Manufacturer | Open ports | Status |");
    let _ = writeln!(out, "|---|---|---|---|---|---|");
    for d in &report.devices {
        let vendor =
            d.vendor.clone().unwrap_or_else(|| if d.private_mac { "private address".into() } else { "?".into() });
        let ports = d.open_ports.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(", ");
        let status = match (d.online, d.trusted) {
            (false, _) => "offline",
            (true, true) => "trusted",
            (true, false) => "not reviewed",
        };
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} |",
            md(d.display_name()),
            d.kind.label(),
            d.ip,
            md(&vendor),
            ports,
            status
        );
    }
    if !report.notes.is_empty() {
        let _ = writeln!(out, "\n## Notes\n");
        for note in &report.notes {
            let _ = writeln!(out, "- {}", md(note));
        }
    }
    out
}

/// Splits text into alternating word / separator pieces.
fn pieces(text: &str) -> Vec<(bool, String)> {
    let mut out: Vec<(bool, String)> = Vec::new();
    for c in text.chars() {
        let word = c.is_alphanumeric();
        match out.last_mut() {
            Some((w, s)) if *w == word => s.push(c),
            _ => out.push((word, c.to_string())),
        }
    }
    out
}

/// A name a device chose for itself, with every word that isn't a device
/// word, a known product word, or a short number replaced by `*`.
fn scrub_name(text: &str, product_words: &HashSet<String>) -> String {
    pieces(text)
        .into_iter()
        .map(|(word, s)| {
            let keep = !word
                || is_device_word(&s)
                || product_words.contains(&s.to_lowercase())
                || (s.len() <= 4 && s.chars().all(|c| c.is_ascii_digit()));
            if keep { s } else { "*".to_string() }
        })
        .collect()
}

/// Free text (service banners, page titles): keep it, but remove the words
/// that appear in the device's own names and any addresses.
fn scrub_free_text(text: &str, personal: &HashSet<String>) -> String {
    let without_addresses = text
        .split_whitespace()
        .map(|w| {
            let bare = w.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            let looks_like_address =
                bare.parse::<std::net::Ipv4Addr>().is_ok() || crate::oui::normalize(bare).is_some();
            if looks_like_address { "*" } else { w }
        })
        .collect::<Vec<_>>()
        .join(" ");
    pieces(&without_addresses)
        .into_iter()
        .map(|(word, s)| if word && personal.contains(&s.to_lowercase()) { "*".to_string() } else { s })
        .collect()
}

fn anonymise_device(d: &Device, n: usize) -> serde_json::Value {
    // Words from the maker and model are product words, never personal.
    let mut product_words = HashSet::new();
    let add_words = |set: &mut HashSet<String>, s: &Option<String>| {
        for (w, piece) in pieces(s.as_deref().unwrap_or("")) {
            if w {
                set.insert(piece.to_lowercase());
            }
        }
    };
    add_words(&mut product_words, &d.vendor);
    add_words(&mut product_words, &d.model);
    if let Some(u) = &d.upnp {
        add_words(&mut product_words, &u.manufacturer);
        add_words(&mut product_words, &u.model);
    }
    // Words in names the device or its owner chose are treated as personal.
    let mut personal = HashSet::new();
    for name in [&d.hostname, &d.netbios_name, &d.custom_name, &Some(d.name.clone())]
        .into_iter()
        .chain(d.advertised.iter().map(|a| &a.instance))
        .chain(d.upnp.as_ref().map(|u| &u.friendly_name))
    {
        add_words(&mut personal, name);
    }
    personal.retain(|w| !is_device_word(w) && !product_words.contains(w) && !w.chars().all(|c| c.is_ascii_digit()));
    let scrub = |s: &Option<String>| s.as_deref().map(|t| scrub_name(t, &product_words));

    json!({
        "ref": format!("d{n}"),
        "mac_prefix": if d.private_mac { None } else { d.mac.as_deref().and_then(|m| m.get(..8)) },
        "private_mac": d.private_mac,
        "vendor": d.vendor,
        "detected_kind": d.detected_kind.unwrap_or(d.kind),
        "detected_confidence": d.detected_confidence.unwrap_or(d.confidence),
        "corrected_kind": d.detected_kind.map(|_| d.kind),
        "model": d.model,
        "hostname": scrub(&d.hostname),
        "netbios_name": scrub(&d.netbios_name),
        "is_gateway": d.is_gateway,
        "is_self": d.is_self,
        "advertised": d.advertised.iter().map(|a| json!({
            "service": a.service,
            "instance": scrub(&a.instance),
            "port": a.port,
        })).collect::<Vec<_>>(),
        "upnp": d.upnp.as_ref().map(|u| json!({
            "friendly_name": scrub(&u.friendly_name),
            "manufacturer": u.manufacturer,
            "model": u.model,
            "device_type": u.device_type,
            "server": u.server.as_deref().map(|s| scrub_free_text(s, &personal)),
        })),
        "open_ports": d.open_ports.iter().map(|p| json!({
            "port": p.port,
            "banner": p.banner.as_deref().map(|b| scrub_free_text(b, &personal)),
        })).collect::<Vec<_>>(),
        "evidence": d.evidence.iter().filter(|e| e.source != "You").map(|e| json!({ "source": e.source, "weight": e.weight })).collect::<Vec<_>>(),
    })
}

/// A copy of the scan that helps improve device detection without saying
/// whose network it is. People review it and decide whether to share it.
pub fn to_anonymised_json(report: &ScanReport) -> String {
    let devices: Vec<serde_json::Value> =
        report.devices.iter().filter(|d| d.online).enumerate().map(|(i, d)| anonymise_device(d, i + 1)).collect();
    let doc = json!({
        "about": "Anonymised NattoWok scan for improving device detection. Removed: names, notes and tags you added, \
                  IP addresses, the unique half of every hardware address (all of it for private addresses), your \
                  Wi-Fi network's name and your public address. Names that devices announce keep only device words \
                  (\"*-iPhone\"); other words are replaced by *. Please read it before sharing.",
        "nattowok_version": env!("CARGO_PKG_VERSION"),
        "router_brand": report.router_guide.as_ref().filter(|g| !g.generic).map(|g| g.brand.clone()),
        "devices": devices,
    });
    serde_json::to_string_pretty(&doc).expect("JSON values always serialise")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymises_names_and_addresses() {
        use crate::model::{Advertised, DeviceKind, NetworkInfo, OpenPort};
        let mut d = Device::new("192.168.1.23".parse().unwrap(), Some("F0:D1:A9:12:34:56".into()));
        d.vendor = Some("Apple".into());
        d.model = Some("iPhone".into());
        d.kind = DeviceKind::Tablet;
        d.detected_kind = Some(DeviceKind::Phone);
        d.detected_confidence = Some(88);
        d.hostname = Some("Kims-iPhone".into());
        d.custom_name = Some("Kim's phone".into());
        d.notes = Some("bought in Penang".into());
        d.advertised.push(Advertised {
            service: "_companion-link._tcp".into(),
            description: String::new(),
            instance: Some("Kim's iPhone 15".into()),
            port: None,
        });
        d.open_ports.push(OpenPort {
            port: 80,
            service: String::new(),
            banner: Some("Kims admin page on 192.168.1.23".into()),
        });
        let mut private = Device::new("192.168.1.88".parse().unwrap(), Some("DA:A1:19:5C:2E:01".into()));
        private.private_mac = true;
        let report = ScanReport {
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
            network: NetworkInfo {
                interface: "wlan0".into(),
                interface_label: None,
                ip: "192.168.1.10".parse().unwrap(),
                prefix: 24,
                scan_range: "192.168.1.0/24".into(),
                mac: None,
                gateway: None,
                gateway_mac: None,
                dns_servers: vec![],
                mtu: None,
                link_speed_mbps: None,
                wireless: true,
            },
            devices: vec![d, private],
            findings: vec![],
            health_score: 100,
            notes: vec![],
            exposure: None,
            wifi: None,
            router_guide: None,
        };
        let out = to_anonymised_json(&report);
        for secret in ["Kim", "Penang", "192.168", "12:34:56", "DA:A1", "wlan0"] {
            assert!(!out.contains(secret), "{secret} leaked:\n{out}");
        }
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let d0 = &v["devices"][0];
        assert_eq!(d0["hostname"], "*-iPhone");
        assert_eq!(d0["mac_prefix"], "F0:D1:A9");
        assert_eq!(d0["detected_kind"], "phone");
        assert_eq!(d0["corrected_kind"], "tablet");
        assert_eq!(d0["advertised"][0]["instance"], "*'* iPhone 15");
        assert_eq!(d0["open_ports"][0]["banner"], "* admin page on *");
        assert!(v["devices"][1]["mac_prefix"].is_null(), "private addresses are dropped entirely");
    }

    #[test]
    fn escapes_csv() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=HYPERLINK(1)"), "'=HYPERLINK(1)");
    }
}
