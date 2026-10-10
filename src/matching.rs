//! Recognises a device that came back under a new hardware address.
//!
//! Phones and laptops can rotate their private Wi-Fi address, and a device
//! moved to a new network adapter or dock gets a new one too. Without help,
//! it would come back as a stranger and lose the name it was given.

use crate::model::{Device, DeviceKind};

/// Suggest "is this the same as …?" at or above this score.
pub const SUGGEST: u32 = 35;
/// Carry the name over without asking at or above this score (only for
/// private addresses, and only when the device's own name matches too).
pub const AUTO: u32 = 75;

/// Default names shared by thousands of devices; matching on them proves nothing.
const GENERIC: &[&str] = &[
    "iphone",
    "ipad",
    "android",
    "localhost",
    "galaxy",
    "pixel",
    "macbook",
    "macbookpro",
    "macbookair",
    "imac",
    "macmini",
    "espressif",
    "esp32",
    "esp8266",
    "raspberrypi",
    "ubuntu",
    "debian",
    "linux",
    "windows",
    "desktop",
    "laptop",
    "unknown",
    "chromecast",
    "printer",
    "camera",
    "privatedevice",
    "yourrouter",
    "thiscomputer",
];

fn norm(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric()).flat_map(char::to_lowercase).collect()
}

fn distinctive(s: &str) -> bool {
    let n = norm(s);
    n.len() >= 4 && !GENERIC.contains(&n.as_str()) && !n.chars().all(|c| c.is_ascii_digit())
}

fn same_name(a: Option<&str>, b: Option<&str>) -> Option<String> {
    let (a, b) = (a?, b?);
    (distinctive(a) && norm(a) == norm(b)).then(|| a.to_string())
}

/// Names a device announces about itself (Bonjour instances, UPnP name).
fn announced_names(d: &Device) -> Vec<String> {
    d.advertised
        .iter()
        .filter_map(|a| a.instance.clone())
        .chain(d.upnp.as_ref().and_then(|u| u.friendly_name.clone()))
        .filter(|n| distinctive(n))
        .collect()
}

/// How alike two devices are, and why. `name_based` is true when part of
/// the score comes from the devices' own names, the most reliable signal.
pub fn similarity(new: &Device, old: &Device) -> (u32, bool, Vec<String>) {
    let mut reasons = Vec::new();
    let mut name_score = 0;
    if let Some(h) = same_name(new.hostname.as_deref(), old.hostname.as_deref()) {
        name_score = 50;
        reasons.push(format!("Same network name (\"{h}\")"));
    }
    if let Some(n) = same_name(new.netbios_name.as_deref(), old.netbios_name.as_deref()) {
        name_score += 50;
        reasons.push(format!("Same Windows name (\"{n}\")"));
    }
    let old_announced: Vec<String> = announced_names(old).iter().map(|n| norm(n)).collect();
    if let Some(n) = announced_names(new).into_iter().find(|n| old_announced.contains(&norm(n))) {
        name_score += 40;
        reasons.push(format!("Announces the same name (\"{n}\")"));
    }
    let name_score = name_score.min(60);
    let mut score = name_score;

    if let (Some(a), Some(b)) = (&new.model, &old.model)
        && norm(a) == norm(b)
    {
        score += 15;
        reasons.push(format!("Same model ({a})"));
    }
    if new.kind == old.kind && new.kind != DeviceKind::Unknown {
        score += 10;
        reasons.push(format!("Same type ({})", new.kind.label()));
    }
    if let (Some(a), Some(b)) = (&new.vendor, &old.vendor)
        && a == b
    {
        score += 10;
        reasons.push(format!("Same manufacturer ({a})"));
    }
    let ports = |d: &Device| d.open_ports.iter().map(|p| p.port).collect::<Vec<_>>();
    if !new.open_ports.is_empty() && ports(new) == ports(old) {
        score += 15;
        reasons.push("Same open ports".to_string());
    }
    if new.private_mac && old.private_mac {
        score += 5;
        reasons.push("Both use a private Wi-Fi address".to_string());
    }
    if new.ip == old.ip {
        score += 15;
        reasons.push(format!("Same IP address ({})", new.ip));
    }
    (score, name_score > 0, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::OpenPort;
    use std::net::Ipv4Addr;

    fn phone(ip: u8, mac: &str, host: &str) -> Device {
        let mut d = Device::new(Ipv4Addr::new(192, 168, 1, ip), Some(mac.into()));
        d.private_mac = true;
        d.kind = DeviceKind::Phone;
        d.model = Some("iPhone".into());
        d.hostname = Some(host.into());
        d.open_ports.push(OpenPort { port: 62078, service: String::new(), banner: None });
        d
    }

    #[test]
    fn rotated_private_address_is_a_strong_match() {
        let (score, by_name, reasons) =
            similarity(&phone(23, "DA:00:00:00:00:02", "Kims-iPhone"), &phone(23, "DA:00:00:00:00:01", "Kims-iPhone"));
        assert!(score >= AUTO, "score {score}");
        assert!(by_name);
        assert!(reasons.iter().any(|r| r.contains("Kims-iPhone")));
    }

    #[test]
    fn generic_names_prove_nothing() {
        let (score, by_name, _) =
            similarity(&phone(23, "DA:00:00:00:00:02", "iPhone"), &phone(40, "DA:00:00:00:00:01", "iPhone"));
        assert!(!by_name);
        assert!(score < AUTO);
    }

    #[test]
    fn different_devices_score_low() {
        let a = Device::new(Ipv4Addr::new(192, 168, 1, 5), Some("00:11:22:33:44:55".into()));
        let mut b = Device::new(Ipv4Addr::new(192, 168, 1, 9), Some("66:11:22:33:44:55".into()));
        b.hostname = Some("printer-upstairs".into());
        assert!(similarity(&a, &b).0 < SUGGEST);
    }
}
