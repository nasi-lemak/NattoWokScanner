//! Known security flaws that attackers are actively using, from the US
//! cybersecurity agency's (CISA) Known Exploited Vulnerabilities catalog,
//! filtered to home router, camera and storage brands.
//!
//! A device matches only when both its brand and an exact model name agree
//! (e.g. a TP-Link device reporting "Archer AX21"), or, for a few brands
//! whose own system software is targeted (MikroTik RouterOS, Synology DSM,
//! Hikvision cameras...), when brand and device type agree. Devices rarely
//! say which firmware they run, so the advice is "make sure it's updated",
//! unless the maker no longer fixes that model.
//!
//! A copy is built in; `nattowok update-flaws` downloads the current list.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{Device, DeviceKind, Finding, FixTopic, Severity};

static BUILT_IN: &str = include_str!("../data/flaws.json");
static OVERRIDE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// File name of a downloaded list inside the data folder.
pub const UPDATED_FILE: &str = "flaws.json";
pub const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Flaw {
    pub cve: String,
    pub vendor: String,
    pub product: String,
    /// Model names, upper case without spaces or hyphens ("TLWR841N").
    #[serde(default)]
    pub models: Vec<String>,
    pub added: String,
    pub summary: String,
    /// The maker no longer fixes the affected products.
    #[serde(default)]
    pub unsupported: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Catalog {
    pub version: String,
    pub flaws: Vec<Flaw>,
}

/// Brands covered: CISA's vendor name, how it shows up in hardware
/// addresses or device descriptions, the kind of device it makes, and the
/// products that apply to every device of that kind ("*" for all).
const BRANDS: &[(&str, &[&str], DeviceKind, &[&str])] = &[
    ("TP-Link", &["TPLINK"], DeviceKind::Router, &[]),
    ("D-Link", &["DLINK"], DeviceKind::Router, &[]),
    ("NETGEAR", &["NETGEAR"], DeviceKind::Router, &[]),
    ("ASUS", &["ASUS"], DeviceKind::Router, &[]),
    ("Linksys", &["LINKSYS"], DeviceKind::Router, &[]),
    ("Zyxel", &["ZYXEL"], DeviceKind::Router, &[]),
    ("DrayTek", &["DRAYTEK"], DeviceKind::Router, &[]),
    ("Tenda", &["TENDA"], DeviceKind::Router, &[]),
    ("MikroTik", &["MIKROTIK", "ROUTERBOARD"], DeviceKind::Router, &["RouterOS"]),
    ("Ubiquiti", &["UBIQUITI"], DeviceKind::Router, &["UniFi OS"]),
    ("Hikvision", &["HIKVISION"], DeviceKind::Camera, &["*"]),
    ("Dahua", &["DAHUA"], DeviceKind::Camera, &["*"]),
    ("Edimax", &["EDIMAX"], DeviceKind::Camera, &[]),
    ("Synology", &["SYNOLOGY"], DeviceKind::Nas, &["DiskStation Manager", "DSM"]),
    ("QNAP", &["QNAP"], DeviceKind::Nas, &["QTS", "Network Attached Storage", "NAS", "Photo Station"]),
];

fn norm(text: &str) -> String {
    text.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_uppercase()).collect()
}

/// Model-like words in a product name or description: letters and digits,
/// at least three characters, not a hardware revision ("V10") or a speed
/// class ("AC1900", "AX3000").
fn model_tokens(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .split(|c: char| c.is_whitespace() || ",/();:.'\"".contains(c))
        // Model names are written with capitals; "ncc2" is a file name.
        .filter(|w| w.chars().any(|c| c.is_ascii_uppercase()))
        .map(norm)
        .filter(|t| {
            t.len() >= 3
                && t.chars().any(|c| c.is_ascii_digit())
                && !is_hardware_version(t)
                && t.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && !t.starts_with("CVE")
                && !is_speed_class(t)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// "V2", "V10": hardware revisions, not models.
fn is_hardware_version(t: &str) -> bool {
    t.strip_prefix('V').is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
}

fn is_speed_class(t: &str) -> bool {
    ["AC", "AX", "BE", "N"]
        .iter()
        .any(|p| t.strip_prefix(p).is_some_and(|rest| rest.len() >= 3 && rest.chars().all(|c| c.is_ascii_digit())))
}

/// Picks the home-device entries out of CISA's catalog JSON.
pub fn from_kev(json: &str) -> Result<Catalog> {
    let v: serde_json::Value = serde_json::from_str(json).context("the flaw list isn't valid JSON")?;
    let version = v.get("catalogVersion").and_then(|s| s.as_str()).unwrap_or_default().to_string();
    let list = v.get("vulnerabilities").and_then(|l| l.as_array()).context("the flaw list has no entries")?;
    let text = |e: &serde_json::Value, k: &str| e.get(k).and_then(|s| s.as_str()).unwrap_or_default().to_string();
    let mut flaws = Vec::new();
    for e in list {
        let vendor = text(e, "vendorProject");
        let Some((name, _, _, family)) = BRANDS.iter().find(|(n, ..)| n.eq_ignore_ascii_case(&vendor)) else {
            continue;
        };
        let product = text(e, "product");
        let description = text(e, "shortDescription");
        // Models are named in the first sentence; later ones hold file paths.
        let summary = description.split(". ").next().unwrap_or(&description).trim_end_matches('.').to_string();
        let mut models = model_tokens(&product);
        models.extend(model_tokens(&summary));
        models.sort();
        models.dedup();
        let family_wide = family.iter().any(|f| *f == "*" || product.to_lowercase().contains(&f.to_lowercase()));
        if models.is_empty() && !family_wide {
            continue; // Too vague to match to a device ("Routers", "Live Update").
        }
        let action = format!("{} {} {description}", text(e, "requiredAction"), text(e, "notes")).to_lowercase();
        let unsupported = ["end-of-life", "(eol)", "end-of-service", "legacy", "no longer supported"]
            .iter()
            .any(|w| action.contains(w));
        flaws.push(Flaw {
            cve: text(e, "cveID"),
            vendor: name.to_string(),
            product,
            models,
            added: text(e, "dateAdded"),
            summary,
            unsupported,
        });
    }
    flaws.sort_by(|a, b| b.added.cmp(&a.added).then(a.cve.cmp(&b.cve)));
    Ok(Catalog { version, flaws })
}

/// Use a downloaded list from `data_dir` if there is one. Call before the
/// first lookup.
pub fn init(data_dir: &Path) {
    let _ = OVERRIDE_DIR.set(data_dir.to_path_buf());
}

pub fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let built_in: Catalog = serde_json::from_str(BUILT_IN).unwrap_or_default();
        let downloaded = OVERRIDE_DIR
            .get()
            .and_then(|d| std::fs::read_to_string(d.join(UPDATED_FILE)).ok())
            .and_then(|t| serde_json::from_str::<Catalog>(&t).ok());
        match downloaded {
            Some(d) if d.version >= built_in.version => d,
            _ => built_in,
        }
    })
}

/// Whether `token` appears in `hay` and isn't the start of a longer model
/// number ("AC15" isn't in "AC1500").
fn has_model(hay: &str, token: &str) -> bool {
    hay.match_indices(token).any(|(i, _)| !hay[i + token.len()..].starts_with(|c: char| c.is_ascii_digit()))
}

/// The flaws that apply to a device: (matched by model, the model name
/// matched) and those matched by brand and type alone.
pub fn matching<'a>(d: &Device, catalog: &'a Catalog) -> (Vec<(&'a Flaw, String)>, Vec<&'a Flaw>) {
    let maker = norm(&format!(
        "{} {}",
        d.vendor.as_deref().unwrap_or_default(),
        d.upnp.as_ref().and_then(|u| u.manufacturer.as_deref()).unwrap_or_default()
    ));
    let brand = BRANDS.iter().find(|(_, aliases, ..)| aliases.iter().any(|a| maker.contains(a)));
    let Some((brand, _, kind, family)) = brand else { return (Vec::new(), Vec::new()) };
    let mut texts: Vec<&str> = Vec::new();
    texts.extend(d.model.as_deref());
    if let Some(u) = &d.upnp {
        texts.extend(u.model.as_deref());
        texts.extend(u.friendly_name.as_deref());
    }
    texts.extend(d.hostname.as_deref());
    texts.extend(d.open_ports.iter().filter_map(|p| p.banner.as_deref()));
    let hay = norm(&texts.join(" "));
    let mut by_model = Vec::new();
    let mut by_family = Vec::new();
    for f in catalog.flaws.iter().filter(|f| f.vendor == *brand) {
        if let Some(m) = f.models.iter().find(|m| has_model(&hay, m)) {
            by_model.push((f, m.clone()));
        } else if d.kind == *kind
            && family.iter().any(|p| *p == "*" || f.product.to_lowercase().contains(&p.to_lowercase()))
        {
            by_family.push(f);
        }
    }
    (by_model, by_family)
}

fn cves(list: &[&Flaw]) -> String {
    let ids: Vec<&str> = list.iter().map(|f| f.cve.as_str()).collect();
    match ids.len() {
        0 => String::new(),
        1..=3 => ids.join(", "),
        n => format!("{} and {} more", ids[..2].join(", "), n - 2),
    }
}

pub fn findings(d: &Device) -> Vec<Finding> {
    findings_with(d, catalog())
}

pub fn findings_with(d: &Device, catalog: &Catalog) -> Vec<Finding> {
    let (by_model, by_family) = matching(d, catalog);
    let name = d.display_name();
    if !by_model.is_empty() {
        let flaws: Vec<&Flaw> = by_model.iter().map(|(f, _)| *f).collect();
        let first = flaws[0];
        let unsupported = flaws.iter().any(|f| f.unsupported);
        let model = d
            .model
            .clone()
            .or_else(|| d.upnp.as_ref().and_then(|u| u.model.clone()))
            .unwrap_or_else(|| by_model[0].1.clone());
        let (count, versions) = if flaws.len() == 1 {
            ("a flaw".to_string(), "It may only affect certain hardware or firmware versions.")
        } else {
            (format!("{} flaws", flaws.len()), "Some only affect certain hardware or firmware versions.")
        };
        let verb = if flaws.len() == 1 { "is" } else { "are" };
        let fix = if unsupported {
            "The maker no longer fixes this model. Replace it when you can. Until then, make sure remote management is off and its admin page isn't reachable from the internet."
        } else {
            "Update its firmware to the latest version, from its app or admin page, and turn on automatic updates if it has them. NattoWok can't see which version it runs, so if it's already up to date you may be safe."
        };
        return vec![Finding {
            id: format!("flaw:{}", d.id),
            severity: if unsupported { Severity::High } else { Severity::Medium },
            title: format!("{name} is a model attackers are targeting"),
            explanation: format!(
                "The US cybersecurity agency (CISA) lists {count} in the {} {model} that {verb} being used in real attacks: {} ({}). {versions}",
                first.vendor,
                first.summary,
                cves(&flaws)
            ),
            fix: fix.to_string(),
            device_id: Some(d.id.clone()),
            ignored: false,
            topic: Some(FixTopic::Firmware),
        }];
    }
    if let Some(latest) = by_family.first() {
        return vec![Finding {
            id: format!("flaw-brand:{}", d.id),
            severity: Severity::Low,
            title: format!("Keep {name} updated: attackers target {} {}", latest.vendor, latest.product),
            explanation: format!(
                "The US cybersecurity agency (CISA) lists {} in {} {} that attackers have used, most recently added {}: {} ({}).",
                if by_family.len() == 1 { "a flaw".to_string() } else { format!("{} flaws", by_family.len()) },
                latest.vendor,
                latest.product,
                latest.added,
                latest.summary,
                cves(&by_family)
            ),
            fix: "Make sure it runs the latest firmware: check in its app or admin page, and turn on automatic updates if it has them.".into(),
            device_id: Some(d.id.clone()),
            ignored: false,
            topic: Some(FixTopic::Firmware),
        }];
    }
    Vec::new()
}

/// "built in, catalog 2026.11.20 (151 entries)".
pub fn source() -> String {
    let c = catalog();
    format!("catalog {} ({} entries)", c.version, c.flaws.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::UpnpInfo;
    use std::net::Ipv4Addr;

    const KEV: &str = r#"{"catalogVersion":"2026.11.20","vulnerabilities":[
      {"cveID":"CVE-2023-1389","vendorProject":"TP-Link","product":"Archer AX21","dateAdded":"2023-05-01",
       "shortDescription":"TP-Link Archer AX-21 contains a command injection vulnerability that allows for remote code execution.",
       "requiredAction":"Apply updates per vendor instructions.","notes":""},
      {"cveID":"CVE-2018-14558","vendorProject":"Tenda","product":"AC7, AC9, and AC10 Routers","dateAdded":"2021-11-03",
       "shortDescription":"Tenda AC7, AC9, and AC10 devices contain a command injection vulnerability.","requiredAction":"Apply updates.","notes":""},
      {"cveID":"CVE-2020-10987","vendorProject":"Tenda","product":"AC1900 Router AC15 Model","dateAdded":"2021-11-03",
       "shortDescription":"Tenda AC1900 Router AC15 Model contains an unspecified vulnerability.","requiredAction":"Apply updates.","notes":""},
      {"cveID":"CVE-2023-25280","vendorProject":"D-Link","product":"DIR-820 Router","dateAdded":"2024-09-30",
       "shortDescription":"D-Link DIR-820 routers contain an OS command injection vulnerability. More text.",
       "requiredAction":"The impacted product is end-of-life (EoL) and/or end-of-service (EoS). Users should discontinue utilization of the product.","notes":""},
      {"cveID":"CVE-2022-37055","vendorProject":"D-Link","product":"Routers","dateAdded":"2025-12-08",
       "shortDescription":"D-Link Routers contains a buffer overflow vulnerability.","requiredAction":"Apply mitigations.","notes":""},
      {"cveID":"CVE-2025-59374","vendorProject":"ASUS","product":"Live Update","dateAdded":"2025-12-17",
       "shortDescription":"ASUS Live Update contains an embedded malicious code vulnerability.","requiredAction":"Apply mitigations.","notes":""},
      {"cveID":"CVE-2026-67279","vendorProject":"MikroTik","product":"RouterOS","dateAdded":"2026-09-25",
       "shortDescription":"Mikrotik RouterOS contains an improper enforcement of behavioral workflow vulnerability.","requiredAction":"Apply mitigations.","notes":""},
      {"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","dateAdded":"2021-12-10",
       "shortDescription":"Apache Log4j2 contains a remote code execution vulnerability.","requiredAction":"Apply updates.","notes":""}
    ]}"#;

    fn device(vendor: &str, model: Option<&str>, kind: DeviceKind) -> Device {
        let mut d = Device::new(Ipv4Addr::new(192, 168, 1, 1), Some("AA:BB:CC:00:00:01".into()));
        d.vendor = Some(vendor.into());
        d.model = model.map(str::to_string);
        d.kind = kind;
        d.name = "Router".into();
        d
    }

    #[test]
    fn filters_the_catalog() {
        let c = from_kev(KEV).unwrap();
        assert_eq!(c.version, "2026.11.20");
        let cves: Vec<&str> = c.flaws.iter().map(|f| f.cve.as_str()).collect();
        assert!(!cves.contains(&"CVE-2022-37055"), "too vague to match");
        assert!(!cves.contains(&"CVE-2025-59374"), "not a device");
        assert!(!cves.contains(&"CVE-2021-44228"), "not a home brand");
        let ac7 = c.flaws.iter().find(|f| f.cve == "CVE-2018-14558").unwrap();
        assert_eq!(ac7.models, vec!["AC10", "AC7", "AC9"]);
        let tenda = c.flaws.iter().find(|f| f.cve == "CVE-2020-10987").unwrap();
        assert_eq!(tenda.models, vec!["AC15"], "speed classes aren't models");
        let dlink = c.flaws.iter().find(|f| f.cve == "CVE-2023-25280").unwrap();
        assert!(dlink.unsupported);
        assert_eq!(dlink.summary, "D-Link DIR-820 routers contain an OS command injection vulnerability");
    }

    #[test]
    fn matches_by_brand_and_model() {
        let c = from_kev(KEV).unwrap();
        let mut archer = device("TP-LINK TECHNOLOGIES CO.,LTD.", None, DeviceKind::Router);
        archer.upnp = Some(UpnpInfo { model: Some("Archer AX21".into()), ..Default::default() });
        let f = findings_with(&archer, &c);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].explanation.contains("CVE-2023-1389"));
        assert!(
            f[0].explanation.starts_with(
                "The US cybersecurity agency (CISA) lists a flaw in the TP-Link Archer AX21 that is being used"
            ),
            "{}",
            f[0].explanation
        );

        // Same model name, different brand: no match.
        let mut other = archer.clone();
        other.vendor = Some("ASUSTek COMPUTER INC.".into());
        assert!(findings_with(&other, &c).is_empty());

        // "AC15" mustn't match an "AC1500".
        assert!(findings_with(&device("Shenzhen Tenda Technology", Some("AC1500"), DeviceKind::Router), &c).is_empty());
        assert_eq!(
            findings_with(&device("Shenzhen Tenda Technology", Some("AC15 V2"), DeviceKind::Router), &c).len(),
            1
        );

        let old = findings_with(&device("D-Link International", Some("DIR-820L"), DeviceKind::Router), &c);
        assert_eq!(old[0].severity, Severity::High);
        assert!(old[0].fix.contains("no longer fixes"));
    }

    #[test]
    fn brand_wide_advice_needs_the_right_kind() {
        let c = from_kev(KEV).unwrap();
        let router = findings_with(&device("Routerboard.com", Some("hAP ax2"), DeviceKind::Router), &c);
        assert_eq!(router.len(), 1);
        assert_eq!(router[0].severity, Severity::Low);
        assert!(router[0].title.contains("MikroTik RouterOS"));
        assert!(findings_with(&device("Routerboard.com", None, DeviceKind::Computer), &c).is_empty());
    }

    #[test]
    fn built_in_list_loads() {
        let c: Catalog = serde_json::from_str(BUILT_IN).unwrap();
        assert!(c.flaws.len() > 50, "built-in list looks empty");
    }
}
