//! Runs a full network scan: find devices, learn their names, check their
//! services, then identify them.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use tokio::sync::Semaphore;

use crate::model::{Device, ScanReport};
use crate::{dns, identify, mdns, neighbors, netbios, netinfo, oui, probe, ssdp, upnp};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub interface: Option<String>,
    /// A CIDR range or single address; defaults to the local subnet.
    pub target: Option<String>,
    /// Check each device for common open ports.
    pub ports: bool,
    pub timeout: Duration,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions { interface: None, target: None, ports: true, timeout: Duration::from_millis(900) }
    }
}

/// Called with a short phase description and overall progress from 0 to 1.
pub type Progress = Arc<dyn Fn(&str, f32) + Send + Sync>;

pub fn no_progress() -> Progress {
    Arc::new(|_, _| {})
}

/// Raises the open-file limit (macOS defaults to 256) and returns it, so we
/// know how many sockets we can have in flight.
pub fn raise_fd_limit() -> u64 {
    #[cfg(unix)]
    unsafe {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
            let want = lim.rlim_max.min(8192);
            if lim.rlim_cur < want {
                let raised = libc::rlimit { rlim_cur: want, rlim_max: lim.rlim_max };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &raised) == 0 {
                    return want;
                }
            }
            return lim.rlim_cur;
        }
        256
    }
    #[cfg(not(unix))]
    {
        2048
    }
}

/// Strips DHCP domain suffixes: `kims-iphone.lan` -> `kims-iphone`.
fn short_hostname(name: &str) -> String {
    let name = name.trim_end_matches('.');
    let first = name.split('.').next().unwrap_or(name);
    if first.is_empty() { name.to_string() } else { first.to_string() }
}

pub async fn run(opts: &ScanOptions, progress: Progress) -> Result<ScanReport> {
    let started_at = Utc::now();
    progress("Reading network settings", 0.01);
    let info = netinfo::detect(opts.interface.as_deref(), opts.target.as_deref())?;
    let targets = netinfo::hosts(&info.scan_range)?;
    let mut notes = Vec::new();
    if opts.target.is_none() && info.prefix < netinfo::DEFAULT_MAX_PREFIX {
        notes.push(format!(
            "Your network is very large (/{}), so only {} was scanned. Use --target to scan another part.",
            info.prefix, info.scan_range
        ));
    }

    let fd_limit = raise_fd_limit();
    let sockets = ((fd_limit.saturating_sub(128)) as usize).clamp(64, 1024);
    let host_parallelism = (sockets / probe::KNOCK_PORTS.len()).clamp(4, 96);

    // Phase 1: find live hosts, while listening for Bonjour and UPnP.
    progress("Looking for devices", 0.03);
    let done = Arc::new(AtomicUsize::new(0));
    let total = targets.len().max(1);
    let knock_limit = Arc::new(Semaphore::new(host_parallelism));
    let ping_limit = Arc::new(Semaphore::new(48));
    let use_ping = probe::ping_available();
    if !use_ping {
        notes.push("The `ping` command isn't available, so devices that only answer pings may be missed.".into());
    }
    let mut knocks = tokio::task::JoinSet::new();
    for &ip in &targets {
        if ip == info.ip {
            continue;
        }
        let (knock_limit, ping_limit, done, progress) =
            (knock_limit.clone(), ping_limit.clone(), done.clone(), progress.clone());
        let timeout = opts.timeout;
        knocks.spawn(async move {
            let knock = async {
                let _p = knock_limit.acquire_owned().await.ok()?;
                probe::knock(ip, timeout).await.map(|d| d.as_secs_f64() * 1000.0)
            };
            let ping = async {
                if !use_ping {
                    return None;
                }
                let _p = ping_limit.acquire_owned().await.ok()?;
                probe::system_ping(ip, timeout).await
            };
            let (k, p) = tokio::join!(knock, ping);
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n % 8 == 0 {
                progress("Looking for devices", 0.03 + 0.37 * n as f32 / total as f32);
            }
            p.or(k).map(|rtt| (ip, rtt))
        });
    }
    let listen = Duration::from_secs(3);
    let wireless = info.wireless;
    let wifi_read = async { if wireless { crate::wifi::read().await } else { None } };
    let (alive, mdns_hosts, ssdp_hosts, wifi) =
        tokio::join!(knocks.join_all(), mdns::discover(info.ip, listen), ssdp::discover(info.ip, listen), wifi_read);
    let mut latency: HashMap<Ipv4Addr, f64> = alive.into_iter().flatten().collect();

    // Phase 2: the ARP table now also knows silent devices we poked.
    progress("Reading the neighbor table", 0.42);
    let arp = neighbors::read_table().await;
    if arp.is_empty() {
        notes.push(
            "Couldn't read the system's neighbor (ARP) table, so hardware addresses and manufacturers may be missing."
                .into(),
        );
    }
    let in_range: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut ips: HashSet<Ipv4Addr> = latency.keys().copied().collect();
    ips.extend(arp.keys().filter(|ip| in_range.contains(ip)));
    ips.extend(mdns_hosts.keys().filter(|ip| in_range.contains(ip)));
    ips.extend(ssdp_hosts.keys().filter(|ip| in_range.contains(ip)));
    if let Some(gw) = info.gateway.filter(|g| in_range.contains(g)) {
        ips.insert(gw);
    }
    if in_range.contains(&info.ip) {
        ips.insert(info.ip);
    }
    let mut ips: Vec<Ipv4Addr> = ips.into_iter().collect();
    ips.sort();
    let others: Vec<Ipv4Addr> = ips.iter().copied().filter(|ip| *ip != info.ip).collect();

    // Phase 3: names.
    progress("Asking devices for their names", 0.48);
    let mut dns_candidates: Vec<SocketAddr> = info
        .gateway
        .into_iter()
        .map(IpAddr::V4)
        .chain(info.dns_servers.iter().copied().filter(|ip| match ip {
            IpAddr::V4(v4) => v4.is_private(),
            IpAddr::V6(_) => false,
        }))
        .map(|ip| SocketAddr::new(ip, 53))
        .collect();
    dns_candidates.dedup();
    let rdns = async {
        let mut set = tokio::task::JoinSet::new();
        let limit = Arc::new(Semaphore::new(32));
        for &ip in &ips {
            let (servers, limit) = (dns_candidates.clone(), limit.clone());
            set.spawn(async move {
                let _p = limit.acquire_owned().await.ok()?;
                for server in servers {
                    if let Some(name) = dns::reverse_lookup(server, ip, Duration::from_millis(700)).await {
                        return Some((ip, name));
                    }
                }
                None
            });
        }
        set.join_all().await.into_iter().flatten().collect::<HashMap<_, _>>()
    };
    let (rdns, nb, mdns_names) = tokio::join!(
        rdns,
        netbios::query_all(&others, Duration::from_millis(1500)),
        mdns::resolve_names(&others, Duration::from_millis(1500)),
    );

    // Phase 4: services.
    let mut ports: HashMap<Ipv4Addr, Vec<crate::model::OpenPort>> = HashMap::new();
    if opts.ports {
        progress("Checking which services each device offers", 0.58);
        let limit = Arc::new(Semaphore::new(sockets.min(512)));
        let done = Arc::new(AtomicUsize::new(0));
        let total = ips.len().max(1);
        let mut set = tokio::task::JoinSet::new();
        for &ip in &ips {
            let (limit, done, progress) = (limit.clone(), done.clone(), progress.clone());
            let timeout = opts.timeout;
            set.spawn(async move {
                let open = probe::scan_ports(ip, probe::QUICK_PORTS, timeout, limit).await;
                let described = probe::describe_ports(ip, &open).await;
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                progress("Checking which services each device offers", 0.58 + 0.27 * n as f32 / total as f32);
                (ip, described)
            });
        }
        ports = set.join_all().await.into_iter().collect();
    }

    // Phase 5: UPnP descriptions, then identification.
    progress("Identifying devices", 0.88);
    let descriptions = probe::futures_join_all(
        ssdp_hosts
            .iter()
            .filter(|(ip, _)| in_range.contains(ip))
            .map(|(ip, host)| async move { (*ip, ssdp::describe(*ip, host).await) }),
    );
    // Meanwhile, ask the router what it forwards in from the internet.
    let gateway_location = info.gateway.and_then(|gw| Some((gw, ssdp_hosts.get(&gw)?.location.clone()?)));
    let exposure = async {
        match &gateway_location {
            Some((gw, location)) => upnp::exposure(location, *gw).await,
            None => None,
        }
    };
    let (descriptions, exposure) = tokio::join!(descriptions, exposure);
    let upnp: HashMap<Ipv4Addr, crate::model::UpnpInfo> = descriptions.into_iter().collect();

    let mut devices = Vec::new();
    let mut used_ids = HashSet::new();
    let empty_txt = BTreeMap::new();
    // Handle the gateway first so it keeps its MAC as id if someone else claims it.
    let mut ordered = ips.clone();
    ordered.sort_by_key(|ip| (Some(*ip) != info.gateway, *ip));
    for ip in ordered {
        let is_self = ip == info.ip;
        let mac = if is_self { info.mac.clone() } else { arp.get(&ip).cloned() }
            .or_else(|| (Some(ip) == info.gateway).then(|| info.gateway_mac.clone()).flatten());
        let mut d = Device::new(ip, mac.clone());
        if !used_ids.insert(d.id.clone()) {
            d.id = format!("ip:{ip}");
            used_ids.insert(d.id.clone());
        }
        d.is_self = is_self;
        d.is_gateway = Some(ip) == info.gateway;
        if let Some(mac) = &mac {
            d.private_mac = oui::is_locally_administered(mac);
            d.vendor = oui::vendor(mac).map(str::to_string);
        }
        let mh = mdns_hosts.get(&ip);
        d.hostname = mdns_names
            .get(&ip)
            .cloned()
            .or_else(|| mh.and_then(|h| h.hostnames.iter().next().cloned()))
            .or_else(|| rdns.get(&ip).map(|n| short_hostname(n)))
            .or_else(|| is_self.then(hostname_of_this_machine).flatten())
            .filter(|n| !n.is_empty());
        d.netbios_name = nb.get(&ip).map(|n| n.name.clone());
        if let Some(h) = mh {
            d.advertised = h.services.iter().cloned().collect();
        }
        d.upnp = upnp.get(&ip).cloned();
        d.open_ports = ports.remove(&ip).unwrap_or_default();
        d.latency_ms = latency.remove(&ip).map(|ms| (ms * 10.0).round() / 10.0);
        identify::identify(&mut d, mh.map(|h| &h.txt).unwrap_or(&empty_txt));
        devices.push(d);
    }
    devices.sort_by_key(|d| d.ip);

    progress("Done", 1.0);
    Ok(ScanReport {
        started_at,
        finished_at: Utc::now(),
        network: info,
        devices,
        findings: Vec::new(),
        health_score: 100,
        notes,
        exposure,
        wifi,
        router_guide: None,
    })
}

fn hostname_of_this_machine() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        })
        .map(|s| short_hostname(s.trim()))
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortens_hostnames() {
        assert_eq!(short_hostname("kims-iphone.lan."), "kims-iphone");
        assert_eq!(short_hostname("printer"), "printer");
    }
}
