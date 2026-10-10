//! Works out which network we are on: our address, the router, DNS servers.

use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result, bail};
use netdev::Interface;
use netdev::ipnet::Ipv4Net;
use netdev::prelude::InterfaceType;

use crate::model::NetworkInfo;
use crate::oui;

/// The largest range we scan without being asked to.
pub const DEFAULT_MAX_PREFIX: u8 = 22;
/// The largest range we scan at all (4096 addresses).
pub const HARD_MAX_PREFIX: u8 = 20;

fn pick_interface(name: Option<&str>) -> Result<Interface> {
    let all = netdev::get_interfaces();
    if let Some(name) = name {
        return all
            .into_iter()
            .find(|i| i.name == name || i.friendly_name.as_deref() == Some(name))
            .with_context(|| format!("no network interface called {name:?}"));
    }
    if let Ok(default) = netdev::get_default_interface()
        && !default.ipv4.is_empty()
    {
        return Ok(default);
    }
    all.into_iter()
        .filter(|i| i.is_up() && !i.is_loopback() && !i.ipv4.is_empty())
        .find(|i| i.gateway.is_some())
        .context("couldn't find a connected network interface with an IPv4 address")
}

fn resolv_conf_servers() -> Vec<IpAddr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

pub fn detect(interface: Option<&str>, target: Option<&str>) -> Result<NetworkInfo> {
    let iface = pick_interface(interface)?;
    let net = *iface
        .ipv4
        .iter()
        .find(|n| !n.addr().is_link_local())
        .or(iface.ipv4.first())
        .context("interface has no IPv4 address")?;
    let gateway = iface.gateway.as_ref();
    let mut dns_servers = iface.dns_servers.clone();
    if dns_servers.is_empty() {
        dns_servers = resolv_conf_servers();
    }
    let scan_range = match target {
        Some(t) => {
            let range: Ipv4Net = t
                .parse()
                .or_else(|_| t.parse::<Ipv4Addr>().map(|ip| Ipv4Net::new(ip, 32).expect("valid prefix")))
                .with_context(|| format!("{t:?} is not an IPv4 range like 192.168.1.0/24"))?;
            if range.prefix_len() < HARD_MAX_PREFIX {
                bail!("{range} has too many addresses; the largest range allowed is /{HARD_MAX_PREFIX}");
            }
            range.trunc()
        }
        None => default_range(net),
    };
    Ok(NetworkInfo {
        interface: iface.name.clone(),
        interface_label: iface.friendly_name.clone().or(iface.description.clone()),
        ip: net.addr(),
        prefix: net.prefix_len(),
        scan_range: scan_range.to_string(),
        mac: iface.mac_addr.and_then(|m| oui::normalize(&m.to_string())),
        gateway: gateway.and_then(|g| g.ipv4.first().copied()),
        gateway_mac: gateway.and_then(|g| oui::normalize(&g.mac_addr.to_string())),
        dns_servers,
        mtu: iface.mtu,
        link_speed_mbps: iface.receive_speed.or(iface.transmit_speed).map(|bps| bps / 1_000_000).filter(|m| *m > 0),
        wireless: matches!(iface.if_type, InterfaceType::Wireless80211)
            || iface.name.starts_with("wl")
            || iface.friendly_name.as_deref().is_some_and(|n| n.contains("Wi-Fi")),
    })
}

/// Our subnet, but never more than a /22 so a scan stays quick. Big corporate
/// subnets are narrowed to the /24 around us.
pub fn default_range(net: Ipv4Net) -> Ipv4Net {
    if net.prefix_len() >= DEFAULT_MAX_PREFIX {
        net.trunc()
    } else {
        Ipv4Net::new(net.addr(), 24).expect("valid prefix").trunc()
    }
}

/// Usable host addresses in a range.
pub fn hosts(range: &str) -> Result<Vec<Ipv4Addr>> {
    let net: Ipv4Net = range.parse()?;
    Ok(net.hosts().collect())
}

pub fn broadcast(info: &NetworkInfo) -> Ipv4Addr {
    Ipv4Net::new(info.ip, info.prefix).map(|n| n.broadcast()).unwrap_or(Ipv4Addr::BROADCAST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrows_big_subnets() {
        let home: Ipv4Net = "192.168.1.37/24".parse().unwrap();
        assert_eq!(default_range(home).to_string(), "192.168.1.0/24");
        let corp: Ipv4Net = "10.20.30.40/16".parse().unwrap();
        assert_eq!(default_range(corp).to_string(), "10.20.30.0/24");
        let mid: Ipv4Net = "10.0.5.9/22".parse().unwrap();
        assert_eq!(default_range(mid).to_string(), "10.0.4.0/22");
    }

    #[test]
    fn lists_hosts() {
        assert_eq!(hosts("192.168.1.0/24").unwrap().len(), 254);
        assert_eq!(hosts("192.168.1.9/32").unwrap(), vec![Ipv4Addr::new(192, 168, 1, 9)]);
    }
}
