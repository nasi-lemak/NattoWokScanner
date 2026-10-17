//! "Check this room": look for hidden cameras on the Wi-Fi of a rental,
//! hotel or anywhere you're staying.
//!
//! Devices are sorted into "likely a camera", "can't tell, go and look" and
//! "fine", always with the reasons. Nothing here logs in to a device or opens
//! its video: it only finds things. A room check is not saved to the
//! inventory, so a stay somewhere doesn't fill up your device list.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::identify::{ONVIF, ONVIF_VIDEO};
use crate::model::{Device, DeviceKind, ScanReport};
use crate::scan::{self, Progress, ScanOptions};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Strong signs of a camera.
    Likely,
    /// Could hide a camera or microphone; worth finding and looking at.
    Unsure,
    Fine,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RoomDevice {
    pub id: String,
    pub name: String,
    pub ip: std::net::Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    pub kind: DeviceKind,
    pub verdict: Verdict,
    pub reasons: Vec<String>,
}

/// A nearby Wi-Fi network named like a camera's own hotspot.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Hotspot {
    pub ssid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_percent: Option<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RoomCheck {
    pub checked_at: DateTime<Utc>,
    /// The Wi-Fi name, or the address range when not on Wi-Fi.
    pub network: String,
    /// One line summing up the result.
    #[serde(default)]
    pub headline: String,
    pub on_wifi: bool,
    /// Devices are hidden from each other (common on hotel and guest Wi-Fi),
    /// so a camera on this network wouldn't show up.
    pub isolated: bool,
    /// Every other device seen, most suspicious first.
    pub devices: Vec<RoomDevice>,
    pub hotspots: Vec<Hotspot>,
    /// Suspicious devices from the previous check that have gone: the
    /// "unplug things one at a time" trick.
    #[serde(default)]
    pub gone: Vec<RoomDevice>,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// What a network scan can't see, said plainly so a clean result isn't
/// mistaken for a guarantee.
pub const CANT_SEE: &[&str] = &[
    "Cameras on a different network: the host's private Wi-Fi, a mobile-data (4G/5G) camera, or one that only records to a memory card.",
    "Bluetooth trackers such as AirTags. Your phone can warn you about those instead.",
    "Spying apps (stalkerware) on a phone.",
    "Audio-only bugs.",
    "Anything at all when the network hides devices from each other.",
];

/// Physical checks that catch what the network can't.
pub const CHECKLIST: &[(&str, &str)] = &[
    (
        "Look where a camera would see you",
        "Check anything facing the bed, shower or toilet: smoke detectors, clocks, USB chargers, power strips, air purifiers, picture frames, tissue boxes, and anything with a small hole in it.",
    ),
    (
        "Look for a lens",
        "Turn the lights off, turn your phone's flashlight on, hold it at eye level and slowly sweep the room. A camera lens reflects a tiny bright dot back at you.",
    ),
    (
        "Find which object a device is",
        "Unplug one gadget at a time and check again. The device that disappears from the list is the one you unplugged.",
    ),
    (
        "Check for trackers",
        "iPhones warn about unknown AirTags on their own. On Android, open Settings and search for \"unknown tracker\" to scan for one nearby.",
    ),
    (
        "If you find a camera",
        "Don't touch or break it. Take photos, leave if you feel unsafe, report it to the booking platform, and to the police if it watches a bedroom or bathroom.",
    ),
];

/// Wi-Fi chip makers whose modules are used in cheap smart gadgets and many
/// hidden cameras (matched against the manufacturer of the network chip).
const GADGET_CHIPS: &[&str] = &[
    "espressif",
    "tuya",
    "beken",
    "altobeam",
    "bilian",
    "fn-link",
    "hisilicon",
    "ingenic",
    "goke",
    "bouffalo",
    "xradio",
    "allwinner",
    "sonix",
    "novatek",
];

/// Generic chips also found in laptops and TVs: only suspicious when we
/// know nothing else about the device.
const GENERIC_CHIPS: &[&str] = &["realtek", "mediatek", "ralink"];

const CAMERA_WORDS: &[&str] =
    &["camera", "ipcam", "webcam", "netcam", "nvr", "dvr", "hikvision", "dahua", "onvif", "network video", "xmeye"];

fn words(text: &str) -> String {
    format!(
        " {} ",
        text.to_lowercase().chars().map(|c| if c.is_alphanumeric() || c == '-' { c } else { ' ' }).collect::<String>()
    )
}

fn vendor_has(vendor: Option<&str>, list: &[&str]) -> bool {
    let Some(v) = vendor else { return false };
    let w = words(v);
    list.iter().any(|needle| w.contains(&format!(" {needle} ")))
}

fn short_vendor(vendor: &str) -> String {
    vendor.split_whitespace().take(3).collect::<Vec<_>>().join(" ")
}

/// Sorts one device and says why.
pub fn assess(d: &Device) -> (Verdict, Vec<String>) {
    let mut strong = Vec::new();
    for a in &d.advertised {
        if a.service == ONVIF_VIDEO {
            strong.push("Answered as an ONVIF video device, the standard IP cameras use to announce themselves".into());
        } else if a.service == ONVIF {
            strong.push("Answered as an ONVIF security device (cameras and video recorders use this)".into());
        }
    }
    for p in &d.open_ports {
        match p.port {
            554 | 8554 => strong.push(format!("Has a video stream open (RTSP, port {})", p.port)),
            37777 => strong.push("Has the control port Dahua-made cameras and recorders use (37777)".into()),
            34567 => strong.push(
                "Has the control port of Xiongmai-based cameras and recorders, common in budget cameras (34567)".into(),
            ),
            _ => {}
        }
        if let Some(b) = &p.banner {
            let lower = b.to_lowercase();
            if let Some(w) = CAMERA_WORDS.iter().find(|w| lower.contains(*w)) {
                strong.push(format!("Its page on port {} mentions \"{w}\": \"{b}\"", p.port));
            }
        }
    }
    if d.kind == DeviceKind::Camera {
        let why: Vec<&str> = d.evidence.iter().take(2).map(|e| e.detail.as_str()).collect();
        if why.is_empty() {
            strong.push("Identified as a camera".into());
        } else {
            strong.push(format!("Identified as a camera: {}", why.join("; ")));
        }
    }
    if d.upnp.as_ref().and_then(|u| u.device_type.as_deref()).is_some_and(|t| t.contains("SecurityCamera")) {
        strong.push("Describes itself as a security camera (UPnP)".into());
    }
    strong.dedup();
    if !strong.is_empty() {
        return (Verdict::Likely, strong);
    }

    if d.is_gateway {
        return (Verdict::Fine, vec!["The network's router".into()]);
    }

    let mut unsure = Vec::new();
    let vendor = d.vendor.as_deref();
    if d.has_port(6668) {
        unsure.push(
            "Has the control port Tuya-based gadgets use: smart plugs and bulbs, but also many cheap cameras".into(),
        );
    }
    if vendor_has(vendor, GADGET_CHIPS) && matches!(d.kind, DeviceKind::Unknown | DeviceKind::SmartHome) {
        unsure.push(format!(
            "Its Wi-Fi chip is made by {}, which is used in many cheap smart gadgets and hidden cameras",
            short_vendor(vendor.unwrap_or_default())
        ));
    }
    match d.kind {
        DeviceKind::SmartHome => {
            unsure.push("A smart-home gadget. Most are harmless, but some contain a camera or microphone".into())
        }
        DeviceKind::Speaker => {
            unsure.push("A smart speaker: these usually have microphones. You can mute or unplug it".into())
        }
        DeviceKind::Unknown if d.private_mac => {
            return (
                Verdict::Fine,
                vec![
                    "Uses a private Wi-Fi address, which phones, tablets and laptops do and cameras generally don't"
                        .into(),
                ],
            );
        }
        DeviceKind::Unknown => {
            if vendor_has(vendor, GENERIC_CHIPS) && unsure.is_empty() {
                unsure.push(format!(
                    "Couldn't tell what this is; its Wi-Fi chip is a common {} one",
                    short_vendor(vendor.unwrap_or_default())
                ));
            } else if unsure.is_empty() {
                unsure.push("Couldn't tell what this is".into());
            }
        }
        _ => {}
    }
    if !unsure.is_empty() {
        return (Verdict::Unsure, unsure);
    }

    let mut fine = vec![d.kind.label().to_string()];
    if let Some(e) = d.evidence.first() {
        fine.push(e.detail.clone());
    }
    (Verdict::Fine, fine)
}

/// A Wi-Fi name that looks like a camera's own setup or streaming hotspot.
pub fn camera_ssid(ssid: &str) -> bool {
    const NEEDLES: &[&str] =
        &["cam", "camera", "ipcam", "ipc", "webcam", "spycam", "hdcam", "wificam", "minicam", "dvr", "nvr", "v380"];
    ssid.to_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|t| !t.is_empty()).any(|t| {
        NEEDLES.iter().any(|n| t == *n || t.strip_prefix(n).is_some_and(|r| r.chars().all(|c| c.is_ascii_digit())))
            || (t.ends_with("cam") && t.len() <= 10 && t != "scam")
    })
}

pub fn from_report(report: &ScanReport) -> RoomCheck {
    let mut devices: Vec<RoomDevice> = report
        .devices
        .iter()
        .filter(|d| !d.is_self)
        .map(|d| {
            let (verdict, reasons) = assess(d);
            RoomDevice {
                id: d.id.clone(),
                name: d.display_name().to_string(),
                ip: d.ip,
                vendor: d.vendor.clone(),
                kind: d.kind,
                verdict,
                reasons,
            }
        })
        .collect();
    devices.sort_by_key(|d| (d.verdict, d.ip));
    let others = report.devices.iter().filter(|d| !d.is_self && !d.is_gateway).count();
    let wifi = report.wifi.as_ref();
    let mut hotspots: Vec<Hotspot> = wifi
        .map(|w| {
            w.neighbors
                .iter()
                .filter_map(|n| {
                    let ssid = n.ssid.as_deref()?;
                    camera_ssid(ssid).then(|| Hotspot { ssid: ssid.to_string(), signal_percent: n.signal_percent })
                })
                .collect()
        })
        .unwrap_or_default();
    hotspots.sort_by(|a, b| b.signal_percent.cmp(&a.signal_percent).then(a.ssid.cmp(&b.ssid)));
    hotspots.dedup_by(|a, b| a.ssid == b.ssid);
    let mut notes = report.notes.clone();
    if wifi.is_none() {
        notes.push(if report.network.wireless {
            "Couldn't list nearby Wi-Fi networks, so camera hotspots weren't checked.".into()
        } else {
            "You're not on Wi-Fi, so nearby camera hotspots weren't checked.".into()
        });
    }
    let mut check = RoomCheck {
        checked_at: report.finished_at,
        network: wifi.and_then(|w| w.ssid.clone()).unwrap_or_else(|| report.network.scan_range.clone()),
        headline: String::new(),
        on_wifi: wifi.is_some(),
        isolated: others == 0,
        devices,
        hotspots,
        gone: Vec::new(),
        notes,
    };
    check.headline = headline(&check);
    check
}

/// The fixed advice shown with every result.
pub fn guide() -> serde_json::Value {
    serde_json::json!({
        "cant_see": CANT_SEE,
        "checklist": CHECKLIST.iter().map(|(title, text)| serde_json::json!({ "title": title, "text": text })).collect::<Vec<_>>(),
    })
}

/// Fills `gone` with suspicious devices from `previous` that have vanished
/// (only when it was the same network).
pub fn compare(previous: &RoomCheck, now: &mut RoomCheck) {
    if previous.network != now.network {
        return;
    }
    now.gone = previous
        .devices
        .iter()
        .filter(|d| d.verdict != Verdict::Fine && !now.devices.iter().any(|n| n.id == d.id))
        .cloned()
        .collect();
}

pub fn count(check: &RoomCheck, verdict: Verdict) -> usize {
    check.devices.iter().filter(|d| d.verdict == verdict).count()
}

/// One line for the top of the result.
pub fn headline(check: &RoomCheck) -> String {
    let likely = count(check, Verdict::Likely);
    let unsure = count(check, Verdict::Unsure) + check.hotspots.len();
    let plural = |n: usize, one: &str, many: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {many}") };
    match (likely, unsure) {
        (0, 0) if check.isolated => {
            "This network hides devices from each other, so it can't show cameras on it".to_string()
        }
        (0, 0) => "No cameras found on this network".to_string(),
        (0, u) => format!("No obvious cameras, but {} to look at", plural(u, "thing", "things")),
        (l, 0) => format!("Found {}", plural(l, "likely camera", "likely cameras")),
        (l, u) => format!(
            "Found {}, and {} to look at",
            plural(l, "likely camera", "likely cameras"),
            plural(u, "thing", "things")
        ),
    }
}

/// Runs a check and compares it with the previous one, which is kept
/// (only the latest) so the unplug trick works across runs.
pub async fn run(opts: &ScanOptions, progress: Progress, root: &Path) -> anyhow::Result<RoomCheck> {
    let report = scan::run(opts, progress).await?;
    let mut check = from_report(&report);
    if let Some(previous) = load_last(root) {
        compare(&previous, &mut check);
    }
    save_last(root, &check)?;
    Ok(check)
}

fn last_path(root: &Path) -> std::path::PathBuf {
    root.join("room-check.json")
}

pub fn load_last(root: &Path) -> Option<RoomCheck> {
    serde_json::from_str(&std::fs::read_to_string(last_path(root)).ok()?).ok()
}

fn save_last(root: &Path, check: &RoomCheck) -> anyhow::Result<()> {
    std::fs::create_dir_all(root)?;
    let path = last_path(root);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(check)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Advertised, OpenPort};
    use std::net::Ipv4Addr;

    fn device(last: u8, vendor: Option<&str>) -> Device {
        let mut d = Device::new(Ipv4Addr::new(192, 168, 1, last), Some(format!("AA:BB:CC:00:00:{last:02X}")));
        d.vendor = vendor.map(str::to_string);
        d
    }

    fn port(p: u16) -> OpenPort {
        OpenPort { port: p, service: crate::probe::service_name(p).into(), banner: None }
    }

    #[test]
    fn strong_signs_mean_likely() {
        let mut d = device(10, None);
        d.advertised.push(Advertised {
            service: ONVIF_VIDEO.into(),
            description: "ONVIF video".into(),
            instance: Some("IPC".into()),
            port: None,
        });
        assert_eq!(assess(&d).0, Verdict::Likely);

        let mut d = device(11, Some("Espressif"));
        d.open_ports.push(port(554));
        let (v, why) = assess(&d);
        assert_eq!(v, Verdict::Likely);
        assert!(why[0].contains("RTSP"));

        let mut d = device(12, None);
        d.open_ports.push(OpenPort {
            port: 80,
            service: "Web".into(),
            banner: Some("NETSurveillance WEB (XMEye)".into()),
        });
        assert_eq!(assess(&d).0, Verdict::Likely);
    }

    #[test]
    fn gadgets_need_a_look_and_phones_are_fine() {
        let mut gadget = device(20, Some("Tuya Smart"));
        gadget.kind = DeviceKind::SmartHome;
        let (v, why) = assess(&gadget);
        assert_eq!(v, Verdict::Unsure);
        assert!(why.iter().any(|r| r.contains("Tuya Smart")), "{why:?}");

        assert_eq!(assess(&device(21, None)).0, Verdict::Unsure, "unknown devices need a look");

        let mut phone = device(22, None);
        phone.private_mac = true;
        assert_eq!(assess(&phone).0, Verdict::Fine);

        let mut laptop = device(23, Some("REALTEK SEMICONDUCTOR"));
        laptop.kind = DeviceKind::Computer;
        assert_eq!(assess(&laptop).0, Verdict::Fine, "a Realtek chip alone isn't suspicious");

        let mut speaker = device(24, Some("Amazon Technologies"));
        speaker.kind = DeviceKind::Speaker;
        assert!(assess(&speaker).1[0].contains("microphone"));
    }

    #[test]
    fn spots_camera_hotspots() {
        for name in ["IPC-3F2A", "HDcam_8812", "V380-123456", "BabyCam", "cam01", "NVR_home"] {
            assert!(camera_ssid(name), "{name}");
        }
        for name in ["Campbell Family", "Cambridge-Guest", "TP-Link_5G", "Scam Likely", "Camden"] {
            assert!(!camera_ssid(name), "{name}");
        }
    }

    #[test]
    fn notices_unplugged_gadgets() {
        let mk = |ids: &[(&str, Verdict)]| RoomCheck {
            checked_at: Utc::now(),
            network: "Cosy Loft".into(),
            headline: String::new(),
            on_wifi: true,
            isolated: false,
            devices: ids
                .iter()
                .map(|(id, v)| RoomDevice {
                    id: id.to_string(),
                    name: id.to_string(),
                    ip: Ipv4Addr::new(10, 0, 0, 2),
                    vendor: None,
                    kind: DeviceKind::Unknown,
                    verdict: *v,
                    reasons: vec![],
                })
                .collect(),
            hotspots: vec![],
            gone: vec![],
            notes: vec![],
        };
        let before = mk(&[("clock", Verdict::Unsure), ("tv", Verdict::Fine), ("plug", Verdict::Unsure)]);
        let mut after = mk(&[("plug", Verdict::Unsure)]);
        compare(&before, &mut after);
        assert_eq!(after.gone.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["clock"]);
        assert_eq!(headline(&after), "No obvious cameras, but 1 thing to look at");
    }
}
