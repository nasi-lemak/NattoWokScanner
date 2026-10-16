//! Where common routers keep the settings NattoWok asks people to change.
//!
//! "Turn off UPnP in your router" is useless advice if you can't find it. We
//! recognise the router's brand from its hardware address, UPnP description
//! and admin page title, and point at the right menu. Menus move between
//! firmware versions, so the steps say "usually" and the generic fallback
//! explains how to find any setting.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{Device, FixTopic};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RouterGuide {
    pub brand: String,
    /// Where to log in.
    pub admin_url: String,
    /// Some routers are managed only through a phone app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    pub steps: BTreeMap<FixTopic, String>,
    /// True when we don't recognise the brand and the steps are general.
    #[serde(default)]
    pub generic: bool,
}

use FixTopic::*;

struct Brand {
    name: &'static str,
    needles: &'static [&'static str],
    admin: Option<&'static str>,
    app: Option<&'static str>,
    steps: &'static [(FixTopic, &'static str)],
}

const BRANDS: &[Brand] = &[
    Brand {
        name: "Netgear Orbi",
        needles: &["orbi"],
        admin: Some("http://orbilogin.com"),
        app: Some("Orbi app"),
        steps: &[
            (Upnp, "Advanced → Advanced Setup → UPnP → untick \"Turn UPnP On\" → Apply."),
            (GuestNetwork, "Guest Network (or Wireless → Guest Network) → enable it and set its own password."),
            (
                Sqm,
                "Orbi has no smart queue on most models. Advanced → Setup → QoS → limit upload/download to about 90% of your measured speed if offered.",
            ),
            (WifiSecurity, "Wireless (Wireless Settings) → Security Options → WPA2-PSK [AES] or WPA3."),
            (WifiChannel, "Wireless Settings → Channel. Orbi normally picks channels itself; try a restart first."),
            (Firmware, "Advanced → Administration → Firmware Update → Check."),
        ],
    },
    Brand {
        name: "TP-Link Deco",
        needles: &["deco"],
        admin: None,
        app: Some("Deco app"),
        steps: &[
            (Upnp, "Deco app → More → Advanced → NAT Forwarding → UPnP → off."),
            (GuestNetwork, "Deco app → More → Wi-Fi → Guest Network (newer apps also have an IoT Network) → on."),
            (
                Sqm,
                "Deco app → More → QoS → set your bandwidth to about 90% of the measured speed and prioritise devices for calls or games.",
            ),
            (WifiSecurity, "Deco app → More → Advanced → Wi-Fi → Security → WPA2/WPA3-Personal."),
            (
                WifiChannel,
                "Deco picks channels automatically; restart the Deco units, or move them away from other routers.",
            ),
            (Firmware, "Deco app → More → Update Deco."),
        ],
    },
    Brand {
        name: "eero",
        needles: &["eero"],
        admin: None,
        app: Some("eero app"),
        steps: &[
            (Upnp, "eero app → Settings → Network settings → UPnP → off."),
            (GuestNetwork, "eero app → Settings → Guest network → on."),
            (Sqm, "eero app → Settings → Network settings → \"Optimize for conferencing and gaming\" → on."),
            (WifiSecurity, "eero app → Settings → Network settings → WPA3 → on (WPA2 is used for older devices)."),
            (WifiChannel, "eero chooses channels itself; restart the eeros from the app (Settings → Troubleshooting)."),
            (Firmware, "eero app → Settings → Software updates."),
        ],
    },
    Brand {
        name: "Google / Nest Wifi",
        needles: &["google", "nest wifi", "onhub"],
        admin: None,
        app: Some("Google Home app"),
        steps: &[
            (Upnp, "Google Home app → Wi-Fi → Settings → Advanced networking → UPnP → off."),
            (GuestNetwork, "Google Home app → Wi-Fi → Guest network → set up."),
            (
                Sqm,
                "Nest Wifi has no manual queue setting; use Google Home app → Wi-Fi → Priority device during calls or games.",
            ),
            (WifiSecurity, "Google and Nest Wifi always use WPA2/WPA3; nothing to change."),
            (
                WifiChannel,
                "Channels are automatic; restart the network from Google Home app → Wi-Fi → Settings → Restart network.",
            ),
            (Firmware, "Updates are automatic."),
        ],
    },
    Brand {
        name: "AVM FRITZ!Box",
        needles: &["fritz", "avm"],
        admin: Some("http://fritz.box"),
        app: None,
        steps: &[
            (
                Upnp,
                "Internet → Permit Access → Port Sharing → untick \"Permit independent port sharing\" on each device (newer: Home Network → Network → Network Settings).",
            ),
            (GuestNetwork, "Wi-Fi → Guest Access → enable a private guest hotspot."),
            (Sqm, "Internet → Filters → Prioritization: add devices or apps for real-time use (calls, games)."),
            (WifiSecurity, "Wi-Fi → Security → WPA2 + WPA3."),
            (WifiChannel, "Wi-Fi → Wi-Fi Channel → adjust channel settings."),
            (Firmware, "System → Update → Check for new FRITZ!OS."),
        ],
    },
    Brand {
        name: "ASUS",
        needles: &["asus", "rt-ax", "rt-ac", "gt-ax", "zenwifi"],
        admin: Some("http://router.asus.com"),
        app: Some("ASUS Router app"),
        steps: &[
            (Upnp, "WAN → Internet Connection → \"Enable UPnP\" → No → Apply."),
            (GuestNetwork, "Guest Network → Enable on 2.4 GHz and 5 GHz; set \"Access Intranet\" to Disable."),
            (
                Sqm,
                "Adaptive QoS → QoS → enable QoS, type \"Traditional QoS\" (or \"Bandwidth Limiter\"), and enter about 90% of your measured speeds.",
            ),
            (WifiSecurity, "Wireless → General → Authentication Method → WPA2/WPA3-Personal."),
            (WifiChannel, "Wireless → General → Control Channel."),
            (Firmware, "Administration → Firmware Upgrade → Check."),
        ],
    },
    Brand {
        name: "TP-Link",
        needles: &["tp-link", "tplink", "archer"],
        admin: Some("http://tplinkwifi.net"),
        app: Some("Tether app"),
        steps: &[
            (Upnp, "Advanced → NAT Forwarding → UPnP → off."),
            (
                GuestNetwork,
                "Advanced → Guest Network (or Wireless → Guest Network) → enable, and leave \"See and access each other\" off.",
            ),
            (
                Sqm,
                "Advanced → QoS → enable, set upload/download to about 90% of your measured speeds, and add high-priority devices.",
            ),
            (WifiSecurity, "Advanced → Wireless → Wireless Settings → Security → WPA2/WPA3-Personal."),
            (WifiChannel, "Advanced → Wireless → Wireless Settings → Channel."),
            (Firmware, "Advanced → System → Firmware Update (older models: System Tools)."),
        ],
    },
    Brand {
        name: "Netgear",
        needles: &["netgear", "nighthawk"],
        admin: Some("http://routerlogin.net"),
        app: Some("Nighthawk app"),
        steps: &[
            (Upnp, "Advanced → Advanced Setup → UPnP → untick \"Turn UPnP On\" → Apply."),
            (GuestNetwork, "Guest Network → enable, and leave \"Allow guests to see each other\" off."),
            (Sqm, "Advanced → Setup → QoS → Dynamic QoS (or set bandwidth to about 90% of your measured speed)."),
            (WifiSecurity, "Wireless → Security Options → WPA2-PSK [AES] or WPA3-Personal."),
            (WifiChannel, "Wireless → Channel."),
            (Firmware, "Advanced → Administration → Firmware Update → Check."),
        ],
    },
    Brand {
        name: "Linksys",
        needles: &["linksys", "velop"],
        admin: Some("http://myrouter.local"),
        app: Some("Linksys app"),
        steps: &[
            (Upnp, "Connectivity → Administration → UPnP → off."),
            (GuestNetwork, "Guest Access → on."),
            (Sqm, "Media Prioritization (or Device Prioritization) → add devices used for calls and games."),
            (WifiSecurity, "Wi-Fi Settings → Security mode → WPA2/WPA3 Mixed Personal."),
            (WifiChannel, "Wi-Fi Settings → Advanced → channel."),
            (Firmware, "Connectivity → Basic → Router Firmware Update → Check for updates."),
        ],
    },
    Brand {
        name: "Ubiquiti UniFi",
        needles: &["unifi", "ubiquiti", "dream machine", "udm"],
        admin: Some("https://unifi.ui.com"),
        app: Some("UniFi app"),
        steps: &[
            (Upnp, "UniFi Network → Settings → Internet → your WAN → UPnP → off."),
            (
                GuestNetwork,
                "Settings → WiFi → create a network with \"Guest Hotspot\" or Client Device Isolation, on its own VLAN.",
            ),
            (Sqm, "Settings → Internet → your WAN → Smart Queues → on, with about 90% of your measured speeds."),
            (WifiSecurity, "Settings → WiFi → your network → Security Protocol → WPA2/WPA3."),
            (
                WifiChannel,
                "UniFi Devices → your access point → Settings → Radios → Channel (or run Wi-Fi AI/Nightly Channel Optimization).",
            ),
            (Firmware, "UniFi Devices → Update all."),
        ],
    },
    Brand {
        name: "MikroTik",
        needles: &["mikrotik", "routerboard", "routeros"],
        admin: None,
        app: Some("WinBox or the MikroTik app"),
        steps: &[
            (Upnp, "IP → UPnP → untick Enabled."),
            (
                GuestNetwork,
                "Wireless/WiFi → add a virtual interface for guests on its own bridge and DHCP network, with client-to-client forwarding off.",
            ),
            (
                Sqm,
                "Queues → add a Simple Queue with queue type fq-codel (or cake) at about 90% of your measured speeds.",
            ),
            (WifiSecurity, "Wireless/WiFi → Security Profiles → WPA2 PSK / WPA3 PSK, AES only."),
            (WifiChannel, "Wireless/WiFi → your interface → Frequency / Channel."),
            (Firmware, "System → Packages → Check For Updates, then System → RouterBOARD → Upgrade."),
        ],
    },
    Brand {
        name: "OpenWrt",
        needles: &["openwrt", "luci"],
        admin: None,
        app: None,
        steps: &[
            (
                Upnp,
                "Services → UPnP IGD & PCP → untick \"Start service\" (only present if luci-app-upnp is installed).",
            ),
            (
                GuestNetwork,
                "Network → Wireless → Add a guest SSID on its own interface and firewall zone without access to lan.",
            ),
            (
                Sqm,
                "Install luci-app-sqm, then Network → SQM QoS → enable on the WAN interface with \"cake\" at about 90% of your measured speeds.",
            ),
            (WifiSecurity, "Network → Wireless → Edit → Wireless Security → WPA2-PSK/WPA3-SAE mixed."),
            (WifiChannel, "Network → Wireless → Edit → Operating Frequency → Channel."),
            (Firmware, "System → Attended Sysupgrade (or flash a new image under System → Backup / Flash Firmware)."),
        ],
    },
    Brand {
        name: "D-Link",
        needles: &["d-link", "dlink"],
        admin: Some("http://dlinkrouter.local"),
        app: None,
        steps: &[
            (Upnp, "Features (or Advanced) → Advanced Network → UPnP → Disabled."),
            (GuestNetwork, "Settings → Wireless → Guest Zone → enable."),
            (Sqm, "Features → QoS Engine → set upload/download to about 90% of your measured speeds."),
            (WifiSecurity, "Settings → Wireless → Security Mode → WPA2/WPA3-Personal."),
            (WifiChannel, "Settings → Wireless → Advanced Settings → Wi-Fi Channel."),
            (Firmware, "Management → Upgrade → Check for New Firmware."),
        ],
    },
];

/// Router makers that are mostly supplied by internet providers.
const ISP_MAKERS: &[&str] = &[
    "arris",
    "commscope",
    "technicolor",
    "sagemcom",
    "huawei",
    "zte",
    "nokia",
    "calix",
    "sercomm",
    "askey",
    "hitron",
    "compal",
    "actiontec",
    "zyxel",
    "vantiva",
];

fn generic_steps(isp: bool) -> BTreeMap<FixTopic, String> {
    let login = if isp {
        "Log in to the router (the password is often on a sticker on it), or use your internet provider's app or customer portal, which often has these settings."
    } else {
        "Log in to the router (the password is often on a sticker on it)."
    };
    [
        (Upnp, "Look for \"UPnP\" under Advanced, NAT, Network or Firewall, and turn it off."),
        (GuestNetwork, "Look for \"Guest network\", \"Guest Wi-Fi\" or \"IoT network\" under Wireless/Wi-Fi, enable it with its own password, and turn off guests seeing each other if offered."),
        (Sqm, "Look for \"QoS\", \"Smart Queue\", \"SQM\" or \"Bandwidth control\", and set upload/download to about 90% of your measured speeds. Not every router has it; your provider may offer one that does."),
        (WifiSecurity, "Under Wireless/Wi-Fi security, choose WPA2-Personal (AES) or WPA3-Personal, never WEP or WPA/TKIP."),
        (WifiChannel, "Under Wireless/Wi-Fi settings, change the channel (on 2.4 GHz use 1, 6 or 11)."),
        (Firmware, "Look for \"Firmware\", \"Software update\" or \"Maintenance\" under System or Administration."),
    ]
    .into_iter()
    .map(|(t, s)| (t, format!("{login} {s}")))
    .collect()
}

/// Everything we know about the router, lower-cased, for brand matching.
fn fingerprint(gw: &Device) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.extend(gw.vendor.clone());
    parts.extend(gw.hostname.clone());
    parts.extend(gw.model.clone());
    if let Some(u) = &gw.upnp {
        parts.extend(u.manufacturer.clone());
        parts.extend(u.model.clone());
        parts.extend(u.friendly_name.clone());
        parts.extend(u.server.clone());
    }
    parts.extend(gw.open_ports.iter().filter_map(|p| p.banner.clone()));
    parts.join(" ").to_lowercase()
}

pub fn guide(gw: &Device) -> RouterGuide {
    let text = fingerprint(gw);
    let gateway_url = format!("http://{}/", gw.ip);
    if let Some(b) = BRANDS.iter().find(|b| b.needles.iter().any(|n| text.contains(n))) {
        return RouterGuide {
            brand: b.name.to_string(),
            admin_url: b.admin.map_or(gateway_url, str::to_string),
            app: b.app.map(str::to_string),
            steps: b.steps.iter().map(|(t, s)| (*t, (*s).to_string())).collect(),
            generic: false,
        };
    }
    let isp_maker = ISP_MAKERS.iter().find(|m| text.contains(*m));
    RouterGuide {
        brand: match isp_maker {
            Some(_) => format!("{} (likely from your internet provider)", gw.vendor.as_deref().unwrap_or("router")),
            None => "your router".to_string(),
        },
        admin_url: gateway_url,
        app: None,
        steps: generic_steps(isp_maker.is_some()),
        generic: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{OpenPort, UpnpInfo};
    use std::net::Ipv4Addr;

    fn gateway() -> Device {
        let mut d = Device::new(Ipv4Addr::new(192, 168, 1, 1), Some("00:11:22:33:44:55".into()));
        d.is_gateway = true;
        d
    }

    #[test]
    fn recognises_brands_from_any_clue() {
        let mut d = gateway();
        d.vendor = Some("ASUSTek Computer".into());
        let g = guide(&d);
        assert_eq!(g.brand, "ASUS");
        assert_eq!(g.admin_url, "http://router.asus.com");
        assert!(g.steps[&FixTopic::Upnp].contains("Enable UPnP"));
        assert!(!g.generic);

        // TP-Link makes both; the Deco model name wins over the vendor.
        let mut d = gateway();
        d.vendor = Some("TP-LINK".into());
        d.upnp = Some(UpnpInfo { model: Some("Deco X55".into()), ..Default::default() });
        assert_eq!(guide(&d).brand, "TP-Link Deco");

        let mut d = gateway();
        d.open_ports.push(OpenPort { port: 80, service: String::new(), banner: Some("OpenWrt - LuCI".into()) });
        assert_eq!(guide(&d).brand, "OpenWrt");
        assert_eq!(guide(&d).admin_url, "http://192.168.1.1/");
    }

    #[test]
    fn falls_back_to_general_steps() {
        let mut d = gateway();
        d.vendor = Some("Sagemcom Broadband".into());
        let g = guide(&d);
        assert!(g.generic);
        assert!(g.brand.contains("internet provider"));
        assert!(g.steps[&FixTopic::Sqm].contains("provider"));
        assert_eq!(g.steps.len(), 6);

        let g = guide(&gateway());
        assert_eq!(g.brand, "your router");
    }

    #[test]
    fn every_brand_covers_every_topic() {
        for b in BRANDS {
            assert_eq!(b.steps.len(), 6, "{}", b.name);
        }
    }
}
