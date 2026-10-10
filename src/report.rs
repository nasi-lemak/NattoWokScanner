//! Exports: CSV for spreadsheets, Markdown for sending to whoever helps you
//! with tech, and JSON for scripts.

use std::fmt::Write;

use crate::model::{ScanReport, Severity};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_csv() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=HYPERLINK(1)"), "'=HYPERLINK(1)");
    }
}
