//! MAC address helpers and the IEEE vendor registry: a copy is built in, and
//! `nattowok update-vendors` can fetch a newer one into the data folder.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

static OUI_GZ: &[u8] = include_bytes!("../data/oui.tsv.gz");
static OVERRIDE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// File name of a downloaded vendor list inside the data folder.
pub const UPDATED_FILE: &str = "oui.tsv.gz";

/// Use a downloaded vendor list from `data_dir` if there is one. Call before
/// the first lookup.
pub fn init(data_dir: &Path) {
    let _ = OVERRIDE_DIR.set(data_dir.to_path_buf());
}

fn decode(gz: &[u8]) -> Option<HashMap<u32, String>> {
    let mut text = String::new();
    GzDecoder::new(gz).read_to_string(&mut text).ok()?;
    let table: HashMap<u32, String> = text
        .lines()
        .filter_map(|line| {
            let (prefix, name) = line.split_once('\t')?;
            Some((u32::from_str_radix(prefix, 16).ok()?, name.to_string()))
        })
        .collect();
    (!table.is_empty()).then_some(table)
}

/// The vendor table and where it came from.
fn loaded() -> &'static (HashMap<u32, String>, String) {
    static TABLE: OnceLock<(HashMap<u32, String>, String)> = OnceLock::new();
    TABLE.get_or_init(|| {
        if let Some(dir) = OVERRIDE_DIR.get() {
            let path = dir.join(UPDATED_FILE);
            if let Some(table) = std::fs::read(&path).ok().and_then(|gz| decode(&gz)) {
                let when = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .map(|t| chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%d").to_string())
                    .unwrap_or_default();
                return (table, format!("downloaded {when}"));
            }
        }
        (decode(OUI_GZ).unwrap_or_default(), "built in".to_string())
    })
}

fn table() -> &'static HashMap<u32, String> {
    &loaded().0
}

/// "built in, 40316 vendors" / "downloaded 2026-10-11, 40400 vendors".
pub fn source() -> String {
    let (t, origin) = loaded();
    format!("{origin}, {} vendors", t.len())
}

fn split_csv(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                fields.last_mut().expect("non-empty").push('"');
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(String::new()),
            _ => fields.last_mut().expect("non-empty").push(c),
        }
    }
    fields
}

/// Strips legal-entity noise so people see "Apple" rather than "Apple, Inc.".
pub fn tidy_vendor(name: &str) -> String {
    const SUFFIXES: &[&str] = &[
        "co., ltd.",
        "co.,ltd.",
        "co., ltd",
        "co.,ltd",
        "co. ltd.",
        "co ltd",
        "corporation",
        "corp.",
        "corp",
        "incorporated",
        "inc.",
        "inc",
        "limited",
        "ltd.",
        "ltd",
        "llc",
        "l.l.c.",
        "gmbh",
        "s.a.",
        "s.p.a.",
        "b.v.",
        "pty",
        "a/s",
        "ab",
        "oy",
        "sas",
        "s.r.l.",
        "srl",
        "technology",
        "technologies",
        "electronics",
        "co.",
        "co",
    ];
    let mut s = name.split_whitespace().collect::<Vec<_>>().join(" ");
    loop {
        let trimmed = s.trim_end_matches([',', ' ', '.']).to_string();
        let lower = trimmed.to_ascii_lowercase();
        let Some(suffix) = SUFFIXES.iter().find(|suf| {
            lower.ends_with(*suf) && lower.len() > suf.len() + 2 && {
                let boundary = lower.as_bytes()[lower.len() - suf.len() - 1];
                boundary == b' ' || boundary == b','
            }
        }) else {
            return trimmed;
        };
        s = trimmed[..trimmed.len() - suffix.len()].to_string();
    }
}

/// Turns the IEEE MA-L registry CSV into sorted `(prefix, vendor)` rows.
pub fn parse_ieee_csv(text: &str) -> Vec<(String, String)> {
    let mut rows: Vec<(String, String)> = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = split_csv(line);
            let prefix = fields.get(1)?.trim().to_ascii_uppercase();
            let name = tidy_vendor(fields.get(2)?);
            (prefix.len() == 6 && prefix.chars().all(|c| c.is_ascii_hexdigit()) && !name.is_empty())
                .then_some((prefix, name))
        })
        .collect();
    rows.sort();
    rows.dedup_by(|a, b| a.0 == b.0);
    rows
}

/// The compact gzipped form the table is stored in.
pub fn encode_table(rows: &[(String, String)]) -> std::io::Result<Vec<u8>> {
    let mut out = GzEncoder::new(Vec::new(), Compression::best());
    for (prefix, name) in rows {
        writeln!(out, "{prefix}\t{name}")?;
    }
    out.finish()
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
    fn converts_ieee_csv() {
        let csv = "Registry,Assignment,Organization Name,Organization Address\n\
                   MA-L,ACBC32,\"Apple, Inc.\",\"1 Infinite Loop Cupertino CA US 95014 \"\n\
                   MA-L,286fb9,\"Nokia Shanghai Bell Co., Ltd.\",somewhere\n\
                   MA-L,XYZ123,Broken,nowhere\n";
        let rows = parse_ieee_csv(csv);
        assert_eq!(rows, vec![("286FB9".into(), "Nokia Shanghai Bell".into()), ("ACBC32".into(), "Apple".into())]);
        let table = decode(&encode_table(&rows).unwrap()).unwrap();
        assert_eq!(table.get(&0xACBC32).map(String::as_str), Some("Apple"));
    }

    #[test]
    fn detects_private_addresses() {
        assert!(is_locally_administered("DA:A1:19:00:00:01"));
        assert!(is_locally_administered("02:00:00:00:00:01"));
        assert!(!is_locally_administered("B8:27:EB:12:34:56"));
        assert!(is_multicast("01:00:5E:00:00:FB"));
    }
}
