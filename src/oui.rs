//! MAC address helpers and the embedded IEEE vendor registry.

use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

use flate2::read::GzDecoder;

static OUI_GZ: &[u8] = include_bytes!("../data/oui.tsv.gz");

fn table() -> &'static HashMap<u32, String> {
    static TABLE: OnceLock<HashMap<u32, String>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut text = String::new();
        if GzDecoder::new(OUI_GZ).read_to_string(&mut text).is_err() {
            return HashMap::new();
        }
        text.lines()
            .filter_map(|line| {
                let (prefix, name) = line.split_once('\t')?;
                Some((u32::from_str_radix(prefix, 16).ok()?, name.to_string()))
            })
            .collect()
    })
}

/// Parses the many spellings of a MAC address (`aa:bb:..`, `AA-BB-..`,
/// `aabb.ccdd.eeff`, and macOS's zero-stripped `a:b:c:..`) into canonical
/// upper-case colon form. Returns `None` for all-zero, broadcast or malformed
/// addresses.
pub fn normalize(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let octets: Vec<u8> = if raw.contains(':') || raw.contains('-') {
        let parts: Vec<&str> = raw.split([':', '-']).collect();
        if parts.len() != 6 {
            return None;
        }
        parts
            .iter()
            .map(|p| if p.is_empty() || p.len() > 2 { None } else { u8::from_str_radix(p, 16).ok() })
            .collect::<Option<_>>()?
    } else {
        let hex: String = raw.chars().filter(|c| *c != '.').collect();
        if hex.len() != 12 {
            return None;
        }
        (0..6).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()).collect::<Option<_>>()?
    };
    if octets.iter().all(|b| *b == 0) || octets.iter().all(|b| *b == 0xff) {
        return None;
    }
    Some(octets.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"))
}

pub fn octets(mac: &str) -> Option<[u8; 6]> {
    let canon = normalize(mac)?;
    let mut out = [0u8; 6];
    for (i, part) in canon.split(':').enumerate() {
        out[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(out)
}

/// Locally administered addresses are not tied to a manufacturer. On a home
/// network that almost always means a phone, tablet or laptop using a private
/// ("randomized") Wi-Fi address.
pub fn is_locally_administered(mac: &str) -> bool {
    octets(mac).is_some_and(|o| o[0] & 0x02 != 0)
}

pub fn is_multicast(mac: &str) -> bool {
    octets(mac).is_some_and(|o| o[0] & 0x01 != 0)
}

/// Vendor that registered this MAC's prefix, if it is a globally unique one.
pub fn vendor(mac: &str) -> Option<&'static str> {
    let o = octets(mac)?;
    if o[0] & 0x03 != 0 {
        return None;
    }
    let key = (u32::from(o[0]) << 16) | (u32::from(o[1]) << 8) | u32::from(o[2]);
    table().get(&key).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_common_formats() {
        assert_eq!(normalize("aa:bb:cc:dd:ee:ff").as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(normalize("AA-BB-CC-DD-EE-0F").as_deref(), Some("AA:BB:CC:DD:EE:0F"));
        assert_eq!(normalize("0:11:2:33:4:55").as_deref(), Some("00:11:02:33:04:55"));
        assert_eq!(normalize("0011.2233.4455").as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(normalize("00:00:00:00:00:00"), None);
        assert_eq!(normalize("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(normalize("(incomplete)"), None);
        assert_eq!(normalize("aa:bb:cc:dd:ee"), None);
    }

    #[test]
    fn looks_up_vendors() {
        assert_eq!(vendor("B8:27:EB:12:34:56"), Some("Raspberry Pi Foundation"));
        assert_eq!(vendor("00:0c:29:aa:bb:cc"), Some("VMware"));
        assert_eq!(vendor("DA:A1:19:00:00:01"), None, "randomized MACs have no vendor");
    }

    #[test]
    fn detects_private_addresses() {
        assert!(is_locally_administered("DA:A1:19:00:00:01"));
        assert!(is_locally_administered("02:00:00:00:00:01"));
        assert!(!is_locally_administered("B8:27:EB:12:34:56"));
        assert!(is_multicast("01:00:5E:00:00:FB"));
    }
}
