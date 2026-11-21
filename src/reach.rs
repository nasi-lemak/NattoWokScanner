//! "Why can't I print or cast to it?" Checks the usual reasons a device
//! can't be used from this network (asleep, moved to a new address, its
//! service stopped, it no longer announces itself, the network hides devices
//! from each other) and says which one it is.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::doctor::{Check, Status};
use crate::model::{Device, DeviceKind, NetworkInfo};
use crate::store::Inventory;
use crate::{mdns, neighbors, netinfo, probe};

/// What was found out about the device just now.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Observations {
    /// Its last known address is in the range this computer is on.
    pub in_range: bool,
    /// Round trip at its last known address, if it answered.
    pub alive_ms: Option<f64>,
    /// Its hardware address was found answering at another address.
    pub moved_to: Option<Ipv4Addr>,
    /// Someone else now has its old address (their name, or a hardware address).
    pub other_at_ip: Option<String>,
    /// Ports it had open at the last scan, and the ones checked now that answer.
    pub was_open: Vec<u16>,
    pub open_now: Vec<u16>,
    /// What it announces via Bonjour/mDNS right now.
    pub announces: Vec<String>,
    /// It announced itself in earlier scans.
    pub announced_before: bool,
    /// How many devices answered discovery at all.
    pub discovery_heard: usize,
    /// The last scan saw devices other than this computer and the router.
    pub others_visible: bool,
    /// Distinct addresses it has had.
    pub addresses_used: usize,
}

#[derive(Serialize, Debug, Clone)]
pub struct Help {
    pub device_id: String,
    pub name: String,
    pub headline: String,
    pub status: Status,
    pub checks: Vec<Check>,
    /// Things to check on the phone or computer that can't connect.
    pub tips: Vec<String>,
}

/// Ports that matter for using a device of this kind.
fn service_ports(kind: DeviceKind) -> &'static [u16] {
    match kind {
        DeviceKind::Printer => &[631, 9100, 515, 80, 443],
        DeviceKind::Tv => &[8008, 8009, 7000, 8060],
        DeviceKind::Speaker => &[8009, 7000, 1400],
        DeviceKind::Nas => &[445, 548, 5000, 5001],
        _ => &[],
    }
}

fn offline_advice(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::Printer => {
            "Printers often fall into a deep sleep. Press a button on it, or switch it off and on. If its screen shows a Wi-Fi symbol with a cross, reconnect it to the Wi-Fi from its own menu."
        }
        DeviceKind::Tv => {
            "Turn the TV fully on: in standby many TVs drop off the network. If it's on, check its network settings show it connected to this Wi-Fi."
        }
        DeviceKind::Speaker => "Check it's powered on, then unplug it for 10 seconds and plug it back in.",
        _ => {
            "Check it's switched on. Wi-Fi gadgets also drop off when the signal is weak; try it closer to the router."
        }
    }
}

fn check(id: &str, title: &str, status: Status, detail: String, advice: Option<String>) -> Check {
    Check {
        id: id.into(),
        layer: "Device".into(),
        title: title.into(),
        status,
        detail,
        advice,
        latency: None,
        topic: None,
    }
}

fn port_list(ports: &[u16]) -> String {
    ports.iter().map(|p| format!("{p} ({})", probe::service_name(*p))).collect::<Vec<_>>().join(", ")
}

/// Turns what was observed into checks, most important first.
pub fn conclude(d: &Device, o: &Observations) -> Help {
    let name = d.display_name().to_string();
    let mut checks = Vec::new();
    let tips = vec![
        "The phone or computer that can't connect must be on the same Wi-Fi network, not a guest network.".into(),
        "Turn off any VPN on that phone or computer while you try.".into(),
        "Some routers keep their 2.4 GHz and 5 GHz networks apart for discovery. If they have different names, try both devices on the same one.".into(),
    ];

    if !o.in_range {
        checks.push(check(
            "network",
            "On this network",
            Status::Fail,
            format!("Its last address ({}) isn't on the network this computer is on now.", d.ip),
            Some("It may be on another network, such as a guest network or a second router. Connect it to the same Wi-Fi as the phone or computer you're using.".into()),
        ));
        return finish(d, name, checks, tips);
    }

    // Is it there at all?
    let reachable_at = if let Some(ms) = o.alive_ms {
        checks.push(check(
            "answering",
            "Switched on and connected",
            Status::Pass,
            format!("It answers at {} ({ms} ms).", d.ip),
            None,
        ));
        Some(d.ip)
    } else if let Some(new_ip) = o.moved_to {
        checks.push(check(
            "answering",
            "Switched on and connected",
            Status::Warn,
            format!("It's on, but it moved from {} to {new_ip}.", d.ip),
            Some(format!(
                "Anything set up with its old address (printers often are) needs updating to {new_ip}. To stop it changing, reserve an address for it in your router (look for \"DHCP reservation\" or \"address reservation\")."
            )),
        ));
        Some(new_ip)
    } else {
        let detail = match &o.other_at_ip {
            Some(other) => format!(
                "It isn't answering, and its old address {} now belongs to {other}. If it is switched on, two devices may be using the same address.",
                d.ip
            ),
            None => format!("It isn't answering at {} or anywhere else on this network.", d.ip),
        };
        let mut advice = offline_advice(d.kind).to_string();
        if o.other_at_ip.is_some() {
            advice.push_str(" If it has a fixed address set on the device itself, change it to automatic (DHCP).");
        }
        checks.push(check("answering", "Switched on and connected", Status::Fail, detail, Some(advice)));
        None
    };

    if !o.others_visible && !d.is_gateway {
        checks.push(check(
            "isolation",
            "Devices can see each other",
            Status::Warn,
            "The last scan found nothing here except the router. Either everything else was switched off, or this network hides devices from each other (common on guest and hotel Wi-Fi), and then phones and computers can't reach printers or TVs on it.".into(),
            Some("Connect both to the main network, or turn off \"AP isolation\" or \"client isolation\" in the router's Wi-Fi settings.".into()),
        ));
    }

    if let Some(ip) = reachable_at {
        // The service people actually use.
        let stopped: Vec<u16> = o.was_open.iter().copied().filter(|p| !o.open_now.contains(p)).collect();
        if !stopped.is_empty() {
            checks.push(check(
                "service",
                "Its services",
                Status::Warn,
                format!("It's on, but stopped answering on {}.", port_list(&stopped)),
                Some(
                    "The device is connected but the part that prints or plays isn't responding. Restart the device."
                        .into(),
                ),
            ));
        } else if !o.open_now.is_empty() {
            checks.push(check(
                "service",
                "Its services",
                Status::Pass,
                format!("Answering on {}.", port_list(&o.open_now)),
                None,
            ));
        }

        // Discovery: how phones and computers find it without an address.
        if !o.announces.is_empty() {
            checks.push(check(
                "discovery",
                "Can be found automatically",
                Status::Pass,
                format!("It announces itself: {}.", o.announces.join(", ")),
                None,
            ));
        } else if o.discovery_heard == 0
            && (o.announced_before || matches!(d.kind, DeviceKind::Printer | DeviceKind::Tv | DeviceKind::Speaker))
        {
            checks.push(check(
                "discovery",
                "Can be found automatically",
                Status::Warn,
                "No device on this network answered discovery (Bonjour/mDNS), so phones and computers can't find things like this automatically.".into(),
                Some("Something on the network is blocking discovery. In the router or mesh app, look for settings named \"multicast\", \"IGMP snooping\", \"mDNS\" or \"AP isolation\". Meanwhile you can add it by its address, {ip}.".replace("{ip}", &ip.to_string())),
            ));
        } else if o.announced_before {
            checks.push(check(
                "discovery",
                "Can be found automatically",
                Status::Warn,
                "It used to announce itself on the network but has stopped, so phones and computers won't list it."
                    .into(),
                Some(format!("Restart the device. Meanwhile you can add it by its address, {ip}.")),
            ));
        } else if matches!(d.kind, DeviceKind::Printer | DeviceKind::Tv | DeviceKind::Speaker) {
            checks.push(check(
                "discovery",
                "Can be found automatically",
                Status::Skip,
                "It doesn't announce itself, so it won't appear in lists automatically.".into(),
                Some(format!("Add it by its address, {ip}.")),
            ));
        }
    }

    if o.addresses_used > 1 && o.moved_to.is_none() && matches!(d.kind, DeviceKind::Printer | DeviceKind::Nas) {
        checks.push(check(
            "address",
            "Keeps the same address",
            Status::Warn,
            format!(
                "It has had {} different addresses. Anything set up by address breaks each time it changes.",
                o.addresses_used
            ),
            Some("Reserve an address for it in your router (\"DHCP reservation\" or \"address reservation\").".into()),
        ));
    }
    finish(d, name, checks, tips)
}

fn finish(d: &Device, name: String, checks: Vec<Check>, tips: Vec<String>) -> Help {
    let worst = match checks.iter().map(|c| c.status).max() {
        Some(Status::Skip) | None => Status::Pass,
        Some(s) => s,
    };
    let first = |s: Status| checks.iter().find(|c| c.status == s);
    let headline = match (first(Status::Fail), first(Status::Warn)) {
        (Some(c), _) | (None, Some(c)) => c.detail.clone(),
        (None, None) => {
            format!("{name} looks fine from this computer. If a phone still can't find it, check the tips below.")
        }
    };
    Help { device_id: d.id.clone(), name, headline, status: worst, checks, tips }
}

/// Probes the device and the network. Takes a few seconds.
pub async fn observe(d: &Device, known: &Inventory, info: &NetworkInfo) -> Observations {
    let timeout = Duration::from_millis(1000);
    let hosts = netinfo::hosts(&info.scan_range).unwrap_or_default();
    let in_range = hosts.contains(&d.ip) || d.ip == info.ip;
    let was_open: Vec<u16> = d.open_ports.iter().map(|p| p.port).collect();
    let mut o = Observations {
        in_range,
        was_open: was_open.clone(),
        announced_before: !d.advertised.is_empty(),
        addresses_used: known.devices.get(&d.id).map_or(1, |k| {
            let mut ips: Vec<_> = k.ip_history.iter().map(|(ip, _)| *ip).collect();
            ips.push(d.ip);
            ips.sort();
            ips.dedup();
            ips.len()
        }),
        others_visible: known
            .last_report
            .as_ref()
            .is_none_or(|r| r.devices.iter().any(|x| !x.is_self && !x.is_gateway)),
        ..Default::default()
    };
    if !in_range {
        return o;
    }
    let discovery = mdns::discover(info.ip, Duration::from_secs(3));
    let reach = async {
        let alive = probe::check_alive(d.ip, &was_open, timeout).await;
        // Not at its address: knock on every address so the neighbor table
        // shows where its hardware address went.
        if alive.is_none() {
            let limit = Arc::new(tokio::sync::Semaphore::new(128));
            let knocks = hosts.iter().copied().filter(|ip| *ip != info.ip).map(|ip| {
                let limit = limit.clone();
                async move {
                    let _p = limit.acquire_owned().await;
                    probe::knock(ip, Duration::from_millis(500)).await
                }
            });
            probe::futures_join_all(knocks).await;
        }
        (alive, neighbors::read_table().await)
    };
    let ((alive, arp), mdns_hosts): ((Option<f64>, HashMap<Ipv4Addr, String>), _) = tokio::join!(reach, discovery);
    o.alive_ms = alive;
    let mac = d.mac.as_deref().map(str::to_ascii_uppercase);
    if alive.is_none() {
        if let Some(mac) = &mac {
            o.moved_to = arp.iter().find(|(ip, m)| m.eq_ignore_ascii_case(mac) && **ip != d.ip).map(|(ip, _)| *ip);
        }
        if let Some(other) = arp.get(&d.ip).filter(|m| mac.as_deref().is_none_or(|mine| !m.eq_ignore_ascii_case(mine)))
        {
            o.other_at_ip = Some(
                known
                    .devices
                    .values()
                    .find(|k| k.snapshot.mac.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(other)))
                    .map_or_else(
                        || format!("another device ({other})"),
                        |k| k.custom_name.clone().unwrap_or_else(|| k.snapshot.name.clone()),
                    ),
            );
        }
    }
    let target = if alive.is_some() { Some(d.ip) } else { o.moved_to };
    if let Some(ip) = target {
        let mut ports = was_open.clone();
        ports.extend_from_slice(service_ports(d.kind));
        ports.sort_unstable();
        ports.dedup();
        let limit = Arc::new(tokio::sync::Semaphore::new(32));
        o.open_now = probe::scan_ports(ip, &ports, timeout, limit).await;
        if let Some(h) = mdns_hosts.get(&ip) {
            let mut seen: Vec<String> = h.services.iter().map(|s| s.description.clone()).collect();
            seen.sort();
            seen.dedup();
            o.announces = seen;
        }
    }
    o.discovery_heard = mdns_hosts.keys().filter(|ip| **ip != info.ip).count();
    o
}

pub async fn diagnose(d: &Device, known: &Inventory, info: &NetworkInfo) -> Help {
    conclude(d, &observe(d, known, info).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn printer() -> Device {
        let mut d = Device::new(Ipv4Addr::new(192, 168, 1, 30), Some("AA:BB:CC:00:00:30".into()));
        d.kind = DeviceKind::Printer;
        d.name = "Office printer".into();
        d
    }

    fn base() -> Observations {
        Observations { in_range: true, others_visible: true, addresses_used: 1, ..Default::default() }
    }

    #[test]
    fn all_good() {
        let o = Observations {
            alive_ms: Some(3.0),
            was_open: vec![631],
            open_now: vec![631],
            announces: vec!["Printing".into()],
            discovery_heard: 4,
            ..base()
        };
        let h = conclude(&printer(), &o);
        assert_eq!(h.status, Status::Pass);
        assert!(h.headline.contains("looks fine"));
    }

    #[test]
    fn asleep_or_moved() {
        let h = conclude(&printer(), &base());
        assert_eq!(h.status, Status::Fail);
        assert!(h.checks[0].advice.as_deref().unwrap().contains("deep sleep"));

        let o = Observations { moved_to: Some(Ipv4Addr::new(192, 168, 1, 77)), open_now: vec![631], ..base() };
        let h = conclude(&printer(), &o);
        assert_eq!(h.status, Status::Warn);
        assert!(h.headline.contains("moved from 192.168.1.30 to 192.168.1.77"), "{}", h.headline);

        let o = Observations { other_at_ip: Some("Sam's laptop".into()), ..base() };
        assert!(conclude(&printer(), &o).headline.contains("now belongs to Sam's laptop"));
    }

    #[test]
    fn service_and_discovery_trouble() {
        let o = Observations {
            alive_ms: Some(2.0),
            was_open: vec![631, 9100],
            open_now: vec![9100],
            announced_before: true,
            discovery_heard: 3,
            ..base()
        };
        let h = conclude(&printer(), &o);
        assert!(h.checks.iter().any(|c| c.id == "service" && c.status == Status::Warn));
        assert!(h.checks.iter().any(|c| c.id == "discovery" && c.detail.contains("stopped")));

        let o = Observations { alive_ms: Some(2.0), announced_before: true, discovery_heard: 0, ..base() };
        let h = conclude(&printer(), &o);
        let disc = h.checks.iter().find(|c| c.id == "discovery").unwrap();
        assert!(disc.advice.as_deref().unwrap().contains("192.168.1.30"));
    }

    #[test]
    fn isolation_and_other_networks() {
        let o = Observations { alive_ms: Some(2.0), others_visible: false, ..base() };
        assert!(conclude(&printer(), &o).checks.iter().any(|c| c.id == "isolation" && c.status == Status::Warn));
        let mut router = printer();
        router.is_gateway = true;
        assert!(!conclude(&router, &o).checks.iter().any(|c| c.id == "isolation"), "the router is always reachable");
        let o = Observations { in_range: false, ..base() };
        assert!(conclude(&printer(), &o).headline.contains("isn't on the network"));
    }
}
