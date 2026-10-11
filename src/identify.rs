//! Explainable device identification.
//!
//! Every clue (vendor, hostname, advertised services, open ports, UPnP model)
//! adds weighted votes for a device kind *and* a sentence saying why. The
//! winner's reasons are shown to people, so "Unknown device" is never a dead
//! end and a wrong guess is easy to spot.

use std::collections::{BTreeMap, HashMap};

use crate::model::{Device, DeviceKind, Evidence};

use DeviceKind::*;

#[derive(Default)]
struct Votes {
    scores: HashMap<DeviceKind, u32>,
    reasons: Vec<(Option<DeviceKind>, Evidence)>,
}

impl Votes {
    fn add(&mut self, kind: DeviceKind, weight: u32, source: &str, detail: impl Into<String>) {
        *self.scores.entry(kind).or_default() += weight;
        self.reasons.push((Some(kind), Evidence { source: source.into(), detail: detail.into(), weight }));
    }

    fn many(&mut self, kinds: &[(DeviceKind, u32)], source: &str, detail: impl Into<String>) {
        let detail = detail.into();
        for (kind, weight) in kinds {
            self.add(*kind, *weight, source, detail.clone());
        }
    }

    fn note(&mut self, source: &str, detail: impl Into<String>) {
        self.reasons.push((None, Evidence { source: source.into(), detail: detail.into(), weight: 0 }));
    }
}

/// Apple hardware model identifiers (from mDNS TXT records) to kind and name.
pub fn apple_model(model: &str) -> Option<(DeviceKind, &'static str)> {
    let table: &[(&str, DeviceKind, &str)] = &[
        ("iPhone", Phone, "iPhone"),
        ("iPad", Tablet, "iPad"),
        ("iPod", Phone, "iPod touch"),
        ("MacBookPro", Computer, "MacBook Pro"),
        ("MacBookAir", Computer, "MacBook Air"),
        ("MacBook", Computer, "MacBook"),
        ("iMac", Computer, "iMac"),
        ("Macmini", Computer, "Mac mini"),
        ("MacPro", Computer, "Mac Pro"),
        ("AppleTV", Tv, "Apple TV"),
        ("AudioAccessory", Speaker, "HomePod"),
        ("Watch", Wearable, "Apple Watch"),
        ("AirPort", Router, "AirPort base station"),
        ("RealityDevice", Wearable, "Apple Vision Pro"),
    ];
    if let Some((_, kind, name)) = table.iter().find(|(p, _, _)| model.starts_with(p)) {
        return Some((*kind, name));
    }
    // Newer Macs just say "Mac14,3".
    let rest = model.strip_prefix("Mac")?;
    rest.starts_with(|c: char| c.is_ascii_digit()).then_some((Computer, "Mac"))
}

/// Keywords found in names, models and page titles.
const KEYWORDS: &[(&str, DeviceKind, u32)] = &[
    ("iphone", Phone, 45),
    ("android", Phone, 35),
    ("galaxy", Phone, 30),
    ("pixel", Phone, 35),
    ("oneplus", Phone, 40),
    ("redmi", Phone, 40),
    ("xiaomi", Phone, 20),
    ("oppo", Phone, 35),
    ("realme", Phone, 35),
    ("motorola", Phone, 30),
    ("moto", Phone, 20),
    ("phone", Phone, 35),
    ("sm", Phone, 20),
    ("ipad", Tablet, 45),
    ("tablet", Tablet, 40),
    ("tab", Tablet, 20),
    ("kindle", Tablet, 40),
    ("watch", Wearable, 35),
    ("macbook", Computer, 45),
    ("imac", Computer, 45),
    ("macmini", Computer, 45),
    ("mac", Computer, 25),
    ("desktop", Computer, 40),
    ("laptop", Computer, 40),
    ("pc", Computer, 30),
    ("thinkpad", Computer, 45),
    ("surface", Computer, 30),
    ("workstation", Computer, 35),
    ("chromebook", Computer, 45),
    ("ubuntu", Computer, 25),
    ("fedora", Computer, 25),
    ("debian", Computer, 20),
    ("linux", Computer, 15),
    ("appletv", Tv, 50),
    ("chromecast", Tv, 50),
    ("roku", Tv, 50),
    ("firetv", Tv, 50),
    ("fire tv", Tv, 50),
    ("bravia", Tv, 50),
    ("webos", Tv, 45),
    ("lgwebostv", Tv, 50),
    ("tv", Tv, 35),
    ("tizen", Tv, 35),
    ("shield", Tv, 30),
    ("vizio", Tv, 40),
    ("hisense", Tv, 35),
    ("androidtv", Tv, 50),
    ("googletv", Tv, 50),
    ("homepod", Speaker, 50),
    ("sonos", Speaker, 50),
    ("echo", Speaker, 40),
    ("alexa", Speaker, 40),
    ("googlehome", Speaker, 50),
    ("google home", Speaker, 50),
    ("nest mini", Speaker, 50),
    ("nest audio", Speaker, 50),
    ("bose", Speaker, 40),
    ("speaker", Speaker, 40),
    ("soundbar", Speaker, 45),
    ("printer", Printer, 50),
    ("npi", Printer, 35),
    ("epson", Printer, 45),
    ("brother", Printer, 40),
    ("canon", Printer, 30),
    ("hp", Printer, 25),
    ("laserjet", Printer, 55),
    ("officejet", Printer, 55),
    ("deskjet", Printer, 55),
    ("envy", Printer, 25),
    ("mfc", Printer, 40),
    ("lexmark", Printer, 50),
    ("xerox", Printer, 50),
    ("ricoh", Printer, 45),
    ("kyocera", Printer, 45),
    ("camera", Camera, 50),
    ("cam", Camera, 35),
    ("ipcam", Camera, 50),
    ("doorbell", Camera, 50),
    ("ring", Camera, 25),
    ("arlo", Camera, 45),
    ("wyze", Camera, 40),
    ("reolink", Camera, 50),
    ("hikvision", Camera, 50),
    ("dahua", Camera, 50),
    ("eufy", Camera, 35),
    ("blink", Camera, 30),
    ("nvr", Camera, 40),
    ("dvr", Camera, 35),
    ("esp", SmartHome, 35),
    ("tasmota", SmartHome, 55),
    ("shelly", SmartHome, 55),
    ("tuya", SmartHome, 45),
    ("wled", SmartHome, 55),
    ("hue", SmartHome, 35),
    ("nest", SmartHome, 20),
    ("ecobee", SmartHome, 50),
    ("lifx", SmartHome, 50),
    ("plug", SmartHome, 35),
    ("bulb", SmartHome, 40),
    ("thermostat", SmartHome, 50),
    ("smartthings", SmartHome, 50),
    ("hubitat", SmartHome, 50),
    ("homey", SmartHome, 45),
    ("roomba", SmartHome, 50),
    ("irobot", SmartHome, 50),
    ("vacuum", SmartHome, 40),
    ("sonoff", SmartHome, 50),
    ("meross", SmartHome, 45),
    ("kasa", SmartHome, 40),
    ("wemo", SmartHome, 45),
    ("myq", SmartHome, 45),
    ("playstation", GameConsole, 55),
    ("ps4", GameConsole, 50),
    ("ps5", GameConsole, 50),
    ("xbox", GameConsole, 55),
    ("nintendo", GameConsole, 55),
    ("switch", GameConsole, 15),
    ("steamdeck", GameConsole, 50),
    ("synology", Nas, 50),
    ("diskstation", Nas, 55),
    ("qnap", Nas, 55),
    ("nas", Nas, 40),
    ("readynas", Nas, 55),
    ("wdmycloud", Nas, 55),
    ("truenas", Nas, 55),
    ("unraid", Nas, 50),
    ("raspberrypi", Server, 45),
    ("server", Server, 35),
    ("homeassistant", Server, 50),
    ("hassio", Server, 50),
    ("pihole", Server, 50),
    ("proxmox", Server, 50),
    ("plex", Server, 30),
    ("octopi", Server, 40),
    ("router", Router, 50),
    ("gateway", Router, 40),
    ("eero", Router, 50),
    ("orbi", Router, 45),
    ("deco", Router, 30),
    ("unifi", Router, 35),
    ("openwrt", Router, 50),
    ("fritz", Router, 50),
    ("mikrotik", Router, 50),
    ("linksys", Router, 40),
    ("netgear", Router, 30),
    ("archer", Router, 35),
    ("velop", Router, 50),
    ("extender", Router, 45),
    ("repeater", Router, 45),
    ("mesh", Router, 25),
    ("rt", Router, 15),
    ("ap", Router, 15),
    ("vm", VirtualMachine, 25),
    ("vbox", VirtualMachine, 40),
    ("virtualbox", VirtualMachine, 50),
];

/// Short keywords match whole tokens only ("hp" must not match "iphone");
/// longer ones also match inside a token ("johnsmacbook").
fn keyword_hits(text: &str) -> Vec<(&'static str, DeviceKind, u32)> {
    let lower = text.to_lowercase();
    let squashed: String = lower.chars().filter(|c| c.is_alphanumeric() || *c == ' ').collect();
    let tokens: Vec<&str> = lower.split(|c: char| !c.is_alphanumeric()).filter(|t| !t.is_empty()).collect();
    let mut best: BTreeMap<DeviceKind, (&'static str, u32)> = BTreeMap::new();
    for &(needle, kind, weight) in KEYWORDS {
        let hit = if needle.len() <= 4 {
            // Allow digits after short keywords ("ps5", "tv2", "cam01").
            tokens
                .iter()
                .any(|t| *t == needle || t.strip_prefix(needle).is_some_and(|r| r.chars().all(|c| c.is_ascii_digit())))
        } else if needle.contains(' ') {
            lower.contains(needle)
        } else {
            squashed.replace(' ', "").contains(needle)
        };
        if hit && best.get(&kind).is_none_or(|(_, w)| weight > *w) {
            best.insert(kind, (needle, weight));
        }
    }
    best.into_iter().map(|(k, (n, w))| (n, k, w)).collect()
}

/// Vendor names (from the MAC address) to likely kinds. Many companies make
/// several kinds of product, so these are deliberately softer votes.
const VENDORS: &[(&str, &[(DeviceKind, u32)])] = &[
    ("apple", &[(Phone, 8), (Computer, 6), (Tablet, 4)]),
    ("samsung", &[(Phone, 12), (Tv, 10)]),
    ("lg electronics", &[(Tv, 15), (Phone, 5)]),
    ("lg innotek", &[(SmartHome, 15), (Tv, 10)]),
    ("lg", &[(Tv, 15), (Phone, 5)]),
    ("lge", &[(Tv, 15), (Phone, 5)]),
    ("sony interactive", &[(GameConsole, 45)]),
    ("sony", &[(Tv, 12), (GameConsole, 6)]),
    ("nintendo", &[(GameConsole, 45)]),
    ("valve", &[(GameConsole, 35)]),
    ("microsoft", &[(Computer, 10), (GameConsole, 8)]),
    ("google", &[(Speaker, 12), (Tv, 10), (Phone, 8)]),
    ("amazon", &[(Speaker, 15), (Tv, 12), (Tablet, 6)]),
    ("roku", &[(Tv, 45)]),
    ("sonos", &[(Speaker, 50)]),
    ("bose", &[(Speaker, 40)]),
    ("harman", &[(Speaker, 25)]),
    ("sound united", &[(Speaker, 30)]),
    ("vizio", &[(Tv, 35)]),
    ("hisense", &[(Tv, 30)]),
    ("tcl", &[(Tv, 25)]),
    ("hewlett packard enterprise", &[(Server, 30)]),
    ("hp", &[(Printer, 25), (Computer, 12)]),
    ("hewlett packard", &[(Printer, 25), (Computer, 12)]),
    ("brother", &[(Printer, 45)]),
    ("seiko epson", &[(Printer, 45)]),
    ("canon", &[(Printer, 40), (Camera, 8)]),
    ("lexmark", &[(Printer, 45)]),
    ("xerox", &[(Printer, 45)]),
    ("kyocera", &[(Printer, 45)]),
    ("ricoh", &[(Printer, 45)]),
    ("konica", &[(Printer, 40)]),
    ("hikvision", &[(Camera, 45)]),
    ("dahua", &[(Camera, 45)]),
    ("axis communications", &[(Camera, 45)]),
    ("amcrest", &[(Camera, 45)]),
    ("reolink", &[(Camera, 45)]),
    ("wyze", &[(Camera, 40)]),
    ("ring", &[(Camera, 35)]),
    ("arlo", &[(Camera, 45)]),
    ("vivotek", &[(Camera, 45)]),
    ("ezviz", &[(Camera, 45)]),
    ("espressif", &[(SmartHome, 35)]),
    ("tuya", &[(SmartHome, 40)]),
    ("allterco", &[(SmartHome, 45)]),
    ("shelly", &[(SmartHome, 45)]),
    ("signify", &[(SmartHome, 45)]),
    ("philips lighting", &[(SmartHome, 45)]),
    ("lifx", &[(SmartHome, 45)]),
    ("ecobee", &[(SmartHome, 45)]),
    ("nest labs", &[(SmartHome, 35)]),
    ("irobot", &[(SmartHome, 45)]),
    ("chamberlain", &[(SmartHome, 45)]),
    ("itead", &[(SmartHome, 45)]),
    ("lumi united", &[(SmartHome, 40)]),
    ("roborock", &[(SmartHome, 40)]),
    ("ecovacs", &[(SmartHome, 40)]),
    ("dyson", &[(SmartHome, 40)]),
    ("silicon laboratories", &[(SmartHome, 20)]),
    ("texas instruments", &[(SmartHome, 15)]),
    ("belkin", &[(SmartHome, 15), (Router, 10)]),
    ("tp-link", &[(Router, 15), (SmartHome, 12)]),
    ("xiaomi", &[(Phone, 15), (SmartHome, 12)]),
    ("huawei", &[(Router, 15), (Phone, 15)]),
    ("zte", &[(Router, 20), (Phone, 8)]),
    ("netgear", &[(Router, 30)]),
    ("asustek", &[(Router, 20), (Computer, 12)]),
    ("linksys", &[(Router, 35)]),
    ("ubiquiti", &[(Router, 35)]),
    ("eero", &[(Router, 45)]),
    ("mikrotik", &[(Router, 45)]),
    ("routerboard", &[(Router, 45)]),
    ("arris", &[(Router, 35)]),
    ("commscope", &[(Router, 35)]),
    ("technicolor", &[(Router, 35)]),
    ("sagemcom", &[(Router, 40)]),
    ("zyxel", &[(Router, 35)]),
    ("avm", &[(Router, 40)]),
    ("cisco", &[(Router, 30)]),
    ("aruba", &[(Router, 35)]),
    ("ruckus", &[(Router, 35)]),
    ("juniper", &[(Router, 30)]),
    ("d-link", &[(Router, 30), (Camera, 8)]),
    ("tenda", &[(Router, 35)]),
    ("calix", &[(Router, 40)]),
    ("actiontec", &[(Router, 40)]),
    ("plume design", &[(Router, 40)]),
    ("hitron", &[(Router, 40)]),
    ("compal broadband", &[(Router, 40)]),
    ("askey", &[(Router, 30)]),
    ("sercomm", &[(Router, 30)]),
    ("fortinet", &[(Router, 35)]),
    ("cradlepoint", &[(Router, 40)]),
    ("intel", &[(Computer, 30)]),
    ("realtek", &[(Computer, 18)]),
    ("dell", &[(Computer, 35)]),
    ("lenovo", &[(Computer, 30)]),
    ("liteon", &[(Computer, 25)]),
    ("azurewave", &[(Computer, 25)]),
    ("hon hai", &[(Computer, 15)]),
    ("micro-star", &[(Computer, 35)]),
    ("giga-byte", &[(Computer, 35)]),
    ("gigabyte", &[(Computer, 35)]),
    ("asrock", &[(Computer, 35)]),
    ("framework computer", &[(Computer, 40)]),
    ("acer", &[(Computer, 30)]),
    ("super micro", &[(Server, 40)]),
    ("oneplus", &[(Phone, 40)]),
    ("oppo", &[(Phone, 40)]),
    ("vivo mobile", &[(Phone, 40)]),
    ("motorola mobility", &[(Phone, 40)]),
    ("hmd global", &[(Phone, 40)]),
    ("fairphone", &[(Phone, 40)]),
    ("realme", &[(Phone, 40)]),
    ("synology", &[(Nas, 50)]),
    ("qnap", &[(Nas, 50)]),
    ("asustor", &[(Nas, 50)]),
    ("terramaster", &[(Nas, 50)]),
    ("western digital", &[(Nas, 30)]),
    ("raspberry pi", &[(Server, 45)]),
    ("vmware", &[(VirtualMachine, 50)]),
    ("xensource", &[(VirtualMachine, 50)]),
    ("parallels", &[(VirtualMachine, 50)]),
    ("pcs systemtechnik", &[(VirtualMachine, 50)]),
];

/// Well-known MAC prefixes of hypervisors, some of which are locally administered.
fn virtual_mac(mac: &str) -> Option<&'static str> {
    let prefix = mac.get(..8)?;
    Some(match prefix {
        "52:54:00" => "QEMU/KVM",
        "00:15:5D" => "Hyper-V",
        "08:00:27" => "VirtualBox",
        "00:1C:42" => "Parallels",
        "00:16:3E" => "Xen",
        "00:50:56" | "00:0C:29" | "00:05:69" => "VMware",
        _ if prefix.starts_with("02:42") => "Docker",
        _ => return None,
    })
}

fn port_votes(port: u16) -> &'static [(DeviceKind, u32)] {
    match port {
        62078 => &[(Phone, 35), (Tablet, 25)],
        9100 => &[(Printer, 45)],
        515 => &[(Printer, 35)],
        631 => &[(Printer, 30)],
        554 | 8554 => &[(Camera, 30)],
        3389 => &[(Computer, 35)],
        135 => &[(Computer, 25)],
        445 | 139 => &[(Computer, 12), (Nas, 10)],
        548 => &[(Nas, 15), (Computer, 10)],
        5900 => &[(Computer, 15)],
        8008 | 8009 => &[(Tv, 25), (Speaker, 15)],
        1400 => &[(Speaker, 45)],
        8060 => &[(Tv, 45)],
        7000 => &[(Tv, 10), (Computer, 8), (Speaker, 5)],
        32400 => &[(Server, 30)],
        8123 => &[(Server, 40)],
        1883 => &[(Server, 15), (SmartHome, 10)],
        5001 => &[(Nas, 20)],
        53 => &[(Router, 25)],
        2375 | 3306 | 5432 | 6379 | 27017 | 9200 => &[(Server, 20)],
        49152 => &[(Router, 8), (Tv, 5)],
        _ => &[],
    }
}

fn service_votes(service: &str) -> &'static [(DeviceKind, u32)] {
    match service {
        "_airplay._tcp" => &[(Tv, 25), (Computer, 10), (Speaker, 10)],
        "_raop._tcp" => &[(Speaker, 20), (Tv, 15)],
        "_googlecast._tcp" => &[(Tv, 40), (Speaker, 25)],
        "_spotify-connect._tcp" => &[(Speaker, 35)],
        "_sonos._tcp" => &[(Speaker, 60)],
        "_ipp._tcp" | "_ipps._tcp" | "_printer._tcp" | "_pdl-datastream._tcp" => &[(Printer, 60)],
        "_uscan._tcp" | "_scanner._tcp" => &[(Printer, 40)],
        "_hap._tcp" => &[(SmartHome, 50)],
        "_matter._tcp" | "_matterc._udp" => &[(SmartHome, 45)],
        "_hue._tcp" => &[(SmartHome, 60)],
        "_esphomelib._tcp" => &[(SmartHome, 60)],
        "_companion-link._tcp" => &[(Phone, 15), (Tablet, 10), (Computer, 10)],
        "_rfb._tcp" => &[(Computer, 30)],
        "_ssh._tcp" | "_sftp-ssh._tcp" => &[(Server, 15), (Computer, 10)],
        "_workstation._tcp" => &[(Computer, 25), (Server, 20)],
        "_smb._tcp" => &[(Computer, 20), (Nas, 20)],
        "_afpovertcp._tcp" => &[(Nas, 25), (Computer, 15)],
        "_adisk._tcp" => &[(Nas, 40)],
        "_amzn-wplay._tcp" | "_androidtvremote2._tcp" => &[(Tv, 55)],
        "_home-assistant._tcp" => &[(Server, 55)],
        "_mqtt._tcp" => &[(Server, 15)],
        "_nvstream._tcp" => &[(Computer, 40)],
        "_plexmediasvr._tcp" => &[(Server, 30), (Nas, 15)],
        _ => &[],
    }
}

fn cast_model(md: &str) -> Option<DeviceKind> {
    let l = md.to_lowercase();
    if l.contains("hub") {
        Some(SmartHome)
    } else if ["home", "nest mini", "nest audio", "speaker", "group", "audio"].iter().any(|k| l.contains(k)) {
        Some(Speaker)
    } else if ["chromecast", "tv", "shield", "streamer"].iter().any(|k| l.contains(k)) {
        Some(Tv)
    } else {
        None
    }
}

/// `48A6B8C2D1E0@Living Room` (AirPlay audio instance names) -> `Living Room`.
fn tidy_instance(instance: &str) -> String {
    match instance.split_once('@') {
        Some((prefix, rest)) if prefix.chars().all(|c| c.is_ascii_hexdigit()) => rest.to_string(),
        _ => instance.to_string(),
    }
}

/// Fills in `kind`, `confidence`, `evidence`, `model` and `name`.
pub fn identify(device: &mut Device, txt: &BTreeMap<String, String>) {
    let mut v = Votes::default();
    let mut model: Option<String> = None;

    if device.is_gateway {
        v.add(Router, 200, "Network", "It's the default gateway: your traffic to the internet goes through it");
    }
    if device.is_self {
        v.add(Computer, 200, "Network", "This is the computer running NattoWok");
    }

    // Hardware address.
    if let Some(mac) = device.mac.as_deref() {
        if let Some(hv) = virtual_mac(mac) {
            v.add(VirtualMachine, 70, "Hardware address", format!("Its MAC address belongs to {hv} virtual machines"));
        } else if device.private_mac {
            v.many(
                &[(Phone, 25), (Tablet, 10), (Computer, 10)],
                "Hardware address",
                "Uses a private (randomized) Wi-Fi address, a privacy feature that phones, tablets and laptops turn on by default",
            );
        }
    }
    if let Some(vendor) = device.vendor.as_deref() {
        let padded: String = format!(" {} ", vendor.to_lowercase())
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { ' ' })
            .collect();
        if let Some((_, votes)) = VENDORS.iter().find(|(needle, _)| padded.contains(&format!(" {needle} "))) {
            v.many(votes, "Manufacturer", format!("Network chip made by {vendor}"));
        } else {
            v.note("Manufacturer", format!("Network chip made by {vendor}"));
        }
    }

    // Advertised Bonjour services.
    for adv in &device.advertised {
        let votes = service_votes(&adv.service);
        if !votes.is_empty() {
            v.many(votes, "Bonjour", format!("Advertises {}", adv.description));
        }
    }
    for key in ["model", "am"] {
        if let Some((kind, name)) = txt.get(key).and_then(|m| apple_model(m)) {
            v.add(kind, 90, "Bonjour", format!("Reports Apple model {} ({name})", txt[key]));
            model.get_or_insert_with(|| name.to_string());
        }
    }
    if let Some(md) = txt.get("md") {
        if let Some(kind) = cast_model(md) {
            v.add(kind, 60, "Google Cast", format!("Reports model \"{md}\""));
        }
        model.get_or_insert_with(|| md.clone());
    }
    for key in ["ty", "usb_mdl", "product"] {
        if let Some(ty) = txt.get(key) {
            if device.advertised.iter().any(|a| service_votes(&a.service).iter().any(|(k, _)| *k == Printer)) {
                v.add(Printer, 50, "Bonjour", format!("Printer model \"{}\"", ty.trim_matches(['(', ')'])));
            }
            model.get_or_insert_with(|| ty.trim_matches(['(', ')']).to_string());
        }
    }

    // UPnP description.
    if let Some(upnp) = &device.upnp {
        if let Some(dt) = upnp.device_type.as_deref() {
            let votes: &[(DeviceKind, u32)] =
                if dt.contains("InternetGatewayDevice") || dt.contains("WANDevice") || dt.contains("WFADevice") {
                    &[(Router, 70)]
                } else if dt.contains("ZonePlayer") {
                    &[(Speaker, 60)]
                } else if dt.contains("MediaRenderer") {
                    &[(Tv, 30), (Speaker, 25)]
                } else if dt.contains("MediaServer") {
                    &[(Nas, 25), (Server, 20), (Computer, 10)]
                } else if dt.contains("Printer") {
                    &[(Printer, 50)]
                } else if dt.contains("SecurityCamera") {
                    &[(Camera, 60)]
                } else {
                    &[]
                };
            let short = dt.trim_start_matches("urn:").split(':').nth(2).unwrap_or(dt).to_string();
            v.many(votes, "UPnP", format!("Describes itself as a UPnP \"{short}\""));
        }
        for (label, text) in
            [("model", &upnp.model), ("manufacturer", &upnp.manufacturer), ("name", &upnp.friendly_name)]
        {
            if let Some(text) = text {
                for (needle, kind, weight) in keyword_hits(text) {
                    v.add(kind, weight, "UPnP", format!("Its UPnP {label} \"{text}\" mentions \"{needle}\""));
                }
            }
        }
        if let Some(m) = &upnp.model {
            model.get_or_insert_with(|| match &upnp.manufacturer {
                Some(mf) if !m.to_lowercase().contains(&mf.to_lowercase()) && mf.len() < 20 => format!("{mf} {m}"),
                _ => m.clone(),
            });
        }
    }

    // Names.
    let mut names: Vec<(&str, String)> = Vec::new();
    if let Some(h) = &device.hostname {
        names.push(("Hostname", h.clone()));
    }
    if let Some(n) = &device.netbios_name {
        names.push(("Windows name", n.clone()));
        v.many(
            &[(Computer, 25), (Nas, 10)],
            "Windows networking",
            format!("Answers Windows network-name queries as {n}"),
        );
    }
    if let Some(f) = txt.get("fn") {
        names.push(("Cast name", f.clone()));
    }
    for adv in &device.advertised {
        if let Some(inst) = &adv.instance {
            names.push(("Bonjour name", tidy_instance(inst)));
        }
    }
    names.sort();
    names.dedup();
    let mut seen_kinds = std::collections::HashSet::new();
    for (source, name) in &names {
        for (needle, kind, weight) in keyword_hits(name) {
            // Count each kind once from names: one device often repeats its name everywhere.
            if seen_kinds.insert(kind) {
                v.add(kind, weight, source, format!("Its name \"{name}\" contains \"{needle}\""));
            }
        }
    }

    // Open ports and page titles.
    for p in &device.open_ports {
        let votes = port_votes(p.port);
        if !votes.is_empty() {
            v.many(votes, "Open port", format!("Port {} is open ({})", p.port, p.service));
        }
        if let Some(banner) = &p.banner {
            for (_, kind, weight) in keyword_hits(banner) {
                v.add(kind, weight / 2 + 5, "Service banner", format!("Port {} says \"{banner}\"", p.port));
            }
        }
    }

    // Decide.
    let mut ranked: Vec<(DeviceKind, u32)> = v.scores.iter().map(|(k, s)| (*k, *s)).collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let (kind, top) = ranked.first().copied().unwrap_or((Unknown, 0));
    let second = ranked.get(1).map_or(0, |r| r.1);
    let confidence = if top == 0 {
        0
    } else {
        let base = 100.0 - 100.0 * 15.0 / (f64::from(top) + 15.0);
        let ambiguity = 35.0 * f64::from(second) / f64::from(top);
        (base - ambiguity).clamp(5.0, 99.0) as u8
    };
    device.kind = if confidence < 10 { Unknown } else { kind };
    device.confidence = confidence;
    let mut evidence: Vec<Evidence> =
        v.reasons.into_iter().filter(|(k, _)| k.is_none() || *k == Some(device.kind)).map(|(_, e)| e).collect();
    evidence.sort_by_key(|e| std::cmp::Reverse(e.weight));
    evidence.dedup_by(|a, b| a.detail == b.detail);
    device.evidence = evidence;
    device.model = model.filter(|m| !m.trim().is_empty());

    // Best display name.
    let instance = device
        .advertised
        .iter()
        .filter(|a| {
            matches!(
                a.service.as_str(),
                "_airplay._tcp"
                    | "_raop._tcp"
                    | "_companion-link._tcp"
                    | "_googlecast._tcp"
                    | "_ipp._tcp"
                    | "_printer._tcp"
                    | "_sonos._tcp"
                    | "_hap._tcp"
                    | "_spotify-connect._tcp"
            )
        })
        .filter_map(|a| a.instance.as_deref().map(tidy_instance))
        .find(|n| !n.is_empty() && !n.starts_with("Chromecast-") && !n.starts_with("Google-"));
    device.name = txt
        .get("fn")
        .cloned()
        .or_else(|| device.upnp.as_ref().and_then(|u| u.friendly_name.clone()))
        .or(instance)
        .or_else(|| device.hostname.clone())
        .or_else(|| device.netbios_name.clone())
        .or_else(|| device.model.clone())
        .or_else(|| {
            let vendor = device.vendor.as_deref().map(|v| v.split_whitespace().take(2).collect::<Vec<_>>().join(" "));
            match (vendor, device.kind) {
                (Some(v), Unknown) => Some(format!("{v} device")),
                (Some(v), k) => Some(format!("{v} {}", k.label().split(" /").next().unwrap_or("").to_lowercase())),
                (None, Unknown) if device.private_mac => Some("Private device".to_string()),
                (None, Unknown) => None,
                (None, _) if device.is_gateway => Some("Your router".to_string()),
                (None, _) if device.is_self => Some("This computer".to_string()),
                (None, k) => Some(k.label().to_string()),
            }
        })
        .unwrap_or_else(|| device.ip.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Advertised, OpenPort, UpnpInfo};
    use std::net::Ipv4Addr;

    fn device() -> Device {
        Device::new(Ipv4Addr::new(192, 168, 1, 20), Some("AA:BB:CC:00:00:01".into()))
    }

    #[test]
    fn apple_models() {
        assert_eq!(apple_model("iPhone15,2"), Some((Phone, "iPhone")));
        assert_eq!(apple_model("MacBookPro18,3"), Some((Computer, "MacBook Pro")));
        assert_eq!(apple_model("Mac14,3"), Some((Computer, "Mac")));
        assert_eq!(apple_model("AppleTV11,1"), Some((Tv, "Apple TV")));
        assert_eq!(apple_model("Machine"), None);
    }

    #[test]
    fn short_keywords_need_whole_tokens() {
        let hits = keyword_hits("Johns-iPhone");
        assert!(hits.iter().any(|(_, k, _)| *k == Phone));
        assert!(!hits.iter().any(|(_, k, _)| *k == Printer), "hp must not match inside iphone");
        assert!(keyword_hits("HP-LaserJet").iter().any(|(_, k, _)| *k == Printer));
        assert!(keyword_hits("ps5-living").iter().any(|(_, k, _)| *k == GameConsole));
        assert!(keyword_hits("DESKTOP-7GH2K1").iter().any(|(_, k, _)| *k == Computer));
    }

    #[test]
    fn gateway_is_router_with_high_confidence() {
        let mut d = device();
        d.is_gateway = true;
        d.vendor = Some("Netgear".into());
        identify(&mut d, &BTreeMap::new());
        assert_eq!(d.kind, Router);
        assert!(d.confidence > 90);
        assert!(d.evidence.iter().any(|e| e.detail.contains("default gateway")));
    }

    #[test]
    fn iphone_with_private_mac() {
        let mut d = device();
        d.mac = Some("DA:A1:19:00:00:01".into());
        d.private_mac = true;
        d.hostname = Some("Kims-iPhone".into());
        d.open_ports.push(OpenPort { port: 62078, service: "Apple device sync".into(), banner: None });
        identify(&mut d, &BTreeMap::new());
        assert_eq!(d.kind, Phone);
        assert_eq!(d.name, "Kims-iPhone");
        assert!(d.confidence >= 70, "confidence {}", d.confidence);
    }

    #[test]
    fn chromecast_speaker_vs_tv() {
        let mut d = device();
        d.vendor = Some("Google".into());
        d.advertised.push(Advertised {
            service: "_googlecast._tcp".into(),
            description: "Google Cast".into(),
            instance: Some("Google-Home-Mini-abc".into()),
            port: Some(8009),
        });
        let mut txt = BTreeMap::new();
        txt.insert("md".to_string(), "Google Home Mini".to_string());
        txt.insert("fn".to_string(), "Kitchen speaker".to_string());
        identify(&mut d, &txt);
        assert_eq!(d.kind, Speaker);
        assert_eq!(d.name, "Kitchen speaker");
        assert_eq!(d.model.as_deref(), Some("Google Home Mini"));
    }

    #[test]
    fn printer_from_ports_and_upnp() {
        let mut d = device();
        d.vendor = Some("Seiko Epson".into());
        d.open_ports.push(OpenPort { port: 9100, service: "Printer".into(), banner: None });
        d.upnp = Some(UpnpInfo {
            model: Some("ET-2850 Series".into()),
            manufacturer: Some("EPSON".into()),
            ..Default::default()
        });
        identify(&mut d, &BTreeMap::new());
        assert_eq!(d.kind, Printer);
        assert_eq!(d.model.as_deref(), Some("EPSON ET-2850 Series"));
    }

    #[test]
    fn unknown_without_clues_is_honest() {
        let mut d = device();
        identify(&mut d, &BTreeMap::new());
        assert_eq!(d.kind, Unknown);
        assert_eq!(d.confidence, 0);
        assert_eq!(d.name, "192.168.1.20");
    }

    #[test]
    fn virtual_machines() {
        let mut d = device();
        d.mac = Some("52:54:00:12:34:56".into());
        d.private_mac = true;
        identify(&mut d, &BTreeMap::new());
        assert_eq!(d.kind, VirtualMachine);
    }
}
