//! The device inventory: names people gave their devices, what's trusted, and
//! a timeline of what changed between scans. Stored as one JSON file.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{Device, NetworkInfo, ScanReport};
use crate::security;

const MAX_EVENTS: usize = 2000;
const MAX_IP_HISTORY: usize = 20;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KnownDevice {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub trusted: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub times_seen: u32,
    #[serde(default)]
    pub ip_history: Vec<(Ipv4Addr, DateTime<Utc>)>,
    /// The device as it looked when last seen.
    pub snapshot: Device,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Baseline,
    NewDevice,
    Returned,
    WentOffline,
    IpChanged,
    NewOpenPort,
    NewFinding,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Event {
    pub at: DateTime<Utc>,
    pub kind: EventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub message: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Inventory {
    #[serde(default)]
    pub devices: BTreeMap<String, KnownDevice>,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default)]
    pub ignored_findings: BTreeSet<String>,
    #[serde(default)]
    pub online: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_report: Option<ScanReport>,
    /// Set when this network's router replaced one seen before on the same
    /// network (same address range, same devices): MAC of the old router.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_router: Option<String>,
}

/// Fields people can change about a device.
#[derive(Deserialize, Debug, Default, Clone)]
pub struct DeviceUpdate {
    /// `Some("")` clears the name.
    pub custom_name: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub trusted: Option<bool>,
}

pub fn default_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("NATTOWOK_DATA") {
        return PathBuf::from(dir);
    }
    dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("nattowok")
}

/// Keeps a separate inventory per network, so a laptop that visits home,
/// the office and a café doesn't mix their devices together.
///
/// Networks are told apart by their router's hardware address, falling back
/// to the address range when that's unknown.
pub struct Workspace {
    root: PathBuf,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct LastNetwork {
    key: String,
    scan_range: String,
    gateway: Option<Ipv4Addr>,
}

#[derive(Serialize, Clone, Debug)]
pub struct NetworkSummary {
    pub key: String,
    pub scan_range: String,
    pub gateway: Option<Ipv4Addr>,
    pub devices: usize,
    pub last_scan: Option<DateTime<Utc>>,
    pub current: bool,
}

impl Workspace {
    pub fn new(root: PathBuf) -> Self {
        Workspace { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn dir(&self, key: &str) -> PathBuf {
        self.root.join("networks").join(key)
    }

    fn last(&self) -> Option<LastNetwork> {
        serde_json::from_str(&std::fs::read_to_string(self.root.join("last-network.json")).ok()?).ok()
    }

    fn remember(&self, key: &str, info: &NetworkInfo) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        let last = LastNetwork { key: key.to_string(), scan_range: info.scan_range.clone(), gateway: info.gateway };
        std::fs::write(self.root.join("last-network.json"), serde_json::to_vec_pretty(&last)?)?;
        Ok(())
    }

    fn key_from_router(mac: &str) -> String {
        format!("router-{}", mac.replace(':', "").to_lowercase())
    }

    /// Which network we're on. Without a router MAC (it isn't always in the
    /// ARP cache yet), reuse the last network if the addresses still match.
    pub fn key_for(&self, info: Option<&NetworkInfo>) -> String {
        let last = self.last();
        let Some(info) = info else {
            return last.map_or_else(|| "default".to_string(), |l| l.key);
        };
        if let Some(mac) = &info.gateway_mac {
            return Self::key_from_router(mac);
        }
        match last {
            Some(l) if l.scan_range == info.scan_range && l.gateway == info.gateway => l.key,
            _ => format!("range-{}", info.scan_range.replace(['/', '.'], "-")),
        }
    }

    /// The inventory of the network this computer is on now (or was on last).
    pub fn load_current(&self, interface: Option<&str>) -> Result<(String, Inventory)> {
        let info = crate::netinfo::detect(interface, None).ok();
        let key = self.key_for(info.as_ref());
        Ok((key.clone(), Inventory::load(&self.dir(&key))?))
    }

    pub fn save(&self, key: &str, inv: &Inventory) -> Result<()> {
        inv.save(&self.dir(key))
    }

    /// Files a finished scan under the right network and returns that
    /// network's key, its updated inventory and what changed.
    pub fn record_scan(&self, report: &mut ScanReport) -> Result<(String, Inventory, Vec<Event>)> {
        let router_mac = report.devices.iter().find(|d| d.is_gateway).and_then(|d| d.mac.clone());
        let key = match &router_mac {
            Some(mac) => Self::key_from_router(mac),
            None => self.key_for(Some(&report.network)),
        };
        let mut inv = Inventory::load(&self.dir(&key))?;
        if inv.devices.is_empty() {
            inv.previous_router = self.replaced_router(&key, report);
        }
        let events = inv.apply_scan(report);
        self.save(&key, &inv)?;
        self.remember(&key, &report.network)?;
        Ok((key, inv, events))
    }

    /// A "new" network that has the same addresses as the last one *and* the
    /// same devices is really the old network with a different router: either
    /// a replacement, or something impersonating it.
    fn replaced_router(&self, key: &str, report: &ScanReport) -> Option<String> {
        let last = self.last()?;
        if last.key == key || last.scan_range != report.network.scan_range || last.gateway != report.network.gateway {
            return None;
        }
        let previous = Inventory::load(&self.dir(&last.key)).ok()?;
        let familiar = report
            .devices
            .iter()
            .filter(|d| !d.is_gateway && !d.is_self && d.mac.is_some())
            .filter(|d| previous.devices.contains_key(&d.id))
            .count();
        if familiar == 0 {
            return None;
        }
        previous.last_report.as_ref().and_then(|r| r.devices.iter().find(|d| d.is_gateway)).and_then(|d| d.mac.clone())
    }

    pub fn networks(&self, current: &str) -> Vec<NetworkSummary> {
        let Ok(entries) = std::fs::read_dir(self.root.join("networks")) else {
            return Vec::new();
        };
        let mut out: Vec<NetworkSummary> = entries
            .flatten()
            .filter_map(|e| {
                let key = e.file_name().to_string_lossy().into_owned();
                let inv = Inventory::load(&e.path()).ok()?;
                let report = inv.last_report.as_ref();
                Some(NetworkSummary {
                    current: key == current,
                    scan_range: report.map(|r| r.network.scan_range.clone()).unwrap_or_default(),
                    gateway: report.and_then(|r| r.network.gateway),
                    devices: inv.devices.len(),
                    last_scan: report.map(|r| r.finished_at),
                    key,
                })
            })
            .collect();
        out.sort_by_key(|n| std::cmp::Reverse(n.last_scan));
        out
    }
}

impl Inventory {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("inventory.json")
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let path = Self::path(dir);
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).with_context(|| format!("{} is corrupted", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("couldn't read {}", path.display())),
        }
    }

    /// Writes atomically so a crash never leaves a half-written inventory.
    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).with_context(|| format!("couldn't create {}", dir.display()))?;
        let path = Self::path(dir);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn push_event(&mut self, at: DateTime<Utc>, kind: EventKind, device_id: Option<&str>, message: String) -> Event {
        let e = Event { at, kind, device_id: device_id.map(str::to_string), message };
        self.events.push(e.clone());
        if self.events.len() > MAX_EVENTS {
            let excess = self.events.len() - MAX_EVENTS;
            self.events.drain(..excess);
        }
        e
    }

    /// Copies people's labels onto freshly scanned devices.
    pub fn decorate(&self, d: &mut Device) {
        if let Some(k) = self.devices.get(&d.id) {
            d.custom_name = k.custom_name.clone();
            d.notes = k.notes.clone();
            d.tags = k.tags.clone();
            d.trusted = k.trusted;
            d.first_seen = Some(k.first_seen);
            d.last_seen = Some(k.last_seen);
        }
    }

    /// Merges a finished scan into the inventory, fills in labels, re-scores
    /// findings, and returns what changed.
    pub fn apply_scan(&mut self, report: &mut ScanReport) -> Vec<Event> {
        let at = report.finished_at;
        let first_scan = self.devices.is_empty();
        let mut events = Vec::new();
        let now_online: BTreeSet<String> = report.devices.iter().map(|d| d.id.clone()).collect();

        for d in &mut report.devices {
            match self.devices.get_mut(&d.id) {
                None => {
                    d.is_new = !first_scan;
                    self.devices.insert(
                        d.id.clone(),
                        KnownDevice {
                            id: d.id.clone(),
                            custom_name: None,
                            notes: None,
                            tags: Vec::new(),
                            trusted: d.is_self,
                            first_seen: at,
                            last_seen: at,
                            times_seen: 1,
                            ip_history: vec![(d.ip, at)],
                            snapshot: d.clone(),
                        },
                    );
                    if !first_scan {
                        let vendor = d.vendor.as_deref().map(|v| format!(" by {v}")).unwrap_or_default();
                        let msg = format!("New device joined: {} ({}{vendor}) at {}", d.name, d.kind.label(), d.ip);
                        events.push(self.push_event(at, EventKind::NewDevice, Some(&d.id), msg));
                    }
                }
                Some(known) => {
                    let label = known.custom_name.clone().unwrap_or_else(|| d.name.clone());
                    let mut changes = Vec::new();
                    if !self.online.contains(&d.id) {
                        changes.push((EventKind::Returned, format!("{label} is back online at {}", d.ip)));
                    }
                    if known.snapshot.ip != d.ip {
                        changes.push((
                            EventKind::IpChanged,
                            format!("{label} moved from {} to {}", known.snapshot.ip, d.ip),
                        ));
                        known.ip_history.push((d.ip, at));
                        if known.ip_history.len() > MAX_IP_HISTORY {
                            known.ip_history.remove(0);
                        }
                    }
                    // A device with no open ports last time may simply not have
                    // been port-scanned, so only compare against a real baseline.
                    if !known.snapshot.open_ports.is_empty() {
                        let before: BTreeSet<u16> = known.snapshot.open_ports.iter().map(|p| p.port).collect();
                        for p in d.open_ports.iter().filter(|p| !before.contains(&p.port)) {
                            changes.push((
                                EventKind::NewOpenPort,
                                format!("{label} opened port {} ({})", p.port, p.service),
                            ));
                        }
                    }
                    known.last_seen = at;
                    known.times_seen += 1;
                    known.snapshot = d.clone();
                    for (kind, msg) in changes {
                        events.push(self.push_event(at, kind, Some(&d.id), msg));
                    }
                }
            }
            self.decorate(d);
            d.findings = security::device_findings(d);
        }

        let offline: Vec<String> = self.online.difference(&now_online).cloned().collect();
        for id in offline {
            if let Some(k) = self.devices.get(&id) {
                let label = k.custom_name.clone().unwrap_or_else(|| k.snapshot.name.clone());
                let msg = format!("{label} went offline");
                events.push(self.push_event(at, EventKind::WentOffline, Some(&id), msg));
            }
        }

        if first_scan {
            let msg =
                format!("First scan: found {} devices. From now on you'll see what changes.", report.devices.len());
            events.push(self.push_event(at, EventKind::Baseline, None, msg));
        }

        // Re-evaluate network findings now that trust and history are known.
        report.findings = security::network_findings(&report.network, &report.devices, self.previous_router.as_deref());
        let previously_seen: BTreeSet<String> =
            self.last_report.as_ref().map(|r| r.all_findings().map(|f| f.id.clone()).collect()).unwrap_or_default();
        self.mark_ignored(report);
        let new_serious: Vec<(String, Option<String>)> = report
            .all_findings()
            .filter(|f| !f.ignored && f.severity >= crate::model::Severity::Medium && !previously_seen.contains(&f.id))
            .map(|f| (f.title.clone(), f.device_id.clone()))
            .collect();
        if !first_scan {
            for (title, device) in new_serious {
                events.push(self.push_event(
                    at,
                    EventKind::NewFinding,
                    device.as_deref(),
                    format!("New security issue: {title}"),
                ));
            }
        }

        self.online = now_online;
        self.last_report = Some(report.clone());
        events
    }

    pub fn mark_ignored(&self, report: &mut ScanReport) {
        for f in report.findings.iter_mut().chain(report.devices.iter_mut().flat_map(|d| d.findings.iter_mut())) {
            f.ignored = self.ignored_findings.contains(&f.id);
        }
        report.health_score = security::health_score(report.all_findings());
    }

    /// The last report with current labels, plus known devices that are offline.
    pub fn current_view(&self) -> Option<ScanReport> {
        let mut report = self.last_report.clone()?;
        for d in &mut report.devices {
            self.decorate(d);
            d.findings = security::device_findings(d);
        }
        // Trust and names may have changed since the scan.
        report.findings = security::network_findings(&report.network, &report.devices, self.previous_router.as_deref());
        self.mark_ignored(&mut report);
        let online: BTreeSet<&str> = report.devices.iter().map(|d| d.id.as_str()).collect();
        let mut offline: Vec<Device> = self
            .devices
            .values()
            .filter(|k| !online.contains(k.id.as_str()))
            .map(|k| {
                let mut d = k.snapshot.clone();
                d.online = false;
                d.is_new = false;
                d.findings.clear();
                self.decorate(&mut d);
                d
            })
            .collect();
        offline.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
        report.devices.extend(offline);
        Some(report)
    }

    /// Finds a device by id, MAC, IP, or (case-insensitive) name.
    pub fn resolve(&self, query: &str) -> Option<&KnownDevice> {
        let q = query.trim();
        let mac = crate::oui::normalize(q);
        self.devices
            .get(q)
            .or_else(|| mac.and_then(|m| self.devices.get(&m)))
            .or_else(|| {
                let ip: Ipv4Addr = q.parse().ok()?;
                self.devices.values().filter(|k| k.snapshot.ip == ip).max_by_key(|k| k.last_seen)
            })
            .or_else(|| {
                let lower = q.to_lowercase();
                self.devices.values().find(|k| {
                    k.custom_name.as_deref().is_some_and(|n| n.to_lowercase() == lower)
                        || k.snapshot.name.to_lowercase() == lower
                })
            })
    }

    pub fn update(&mut self, id: &str, update: DeviceUpdate) -> Option<&KnownDevice> {
        let k = self.devices.get_mut(id)?;
        if let Some(name) = update.custom_name {
            let name = name.trim().to_string();
            k.custom_name = (!name.is_empty()).then_some(name);
        }
        if let Some(notes) = update.notes {
            let notes = notes.trim().to_string();
            k.notes = (!notes.is_empty()).then_some(notes);
        }
        if let Some(tags) = update.tags {
            let mut tags: Vec<String> =
                tags.into_iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
            tags.sort();
            tags.dedup();
            k.tags = tags;
        }
        if let Some(trusted) = update.trusted {
            k.trusted = trusted;
        }
        Some(k)
    }

    pub fn forget(&mut self, id: &str) -> bool {
        self.online.remove(id);
        if let Some(r) = self.last_report.as_mut() {
            r.devices.retain(|d| d.id != id);
        }
        self.devices.remove(id).is_some()
    }

    pub fn trust_all_online(&mut self) -> usize {
        let mut n = 0;
        for id in &self.online {
            if let Some(k) = self.devices.get_mut(id)
                && !k.trusted
            {
                k.trusted = true;
                n += 1;
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{NetworkInfo, OpenPort};

    fn report(devices: Vec<Device>, minute: u32) -> ScanReport {
        let at = DateTime::parse_from_rfc3339(&format!("2026-01-01T10:{minute:02}:00Z")).unwrap().with_timezone(&Utc);
        ScanReport {
            started_at: at,
            finished_at: at,
            network: NetworkInfo {
                interface: "en0".into(),
                interface_label: None,
                ip: "192.168.1.2".parse().unwrap(),
                prefix: 24,
                scan_range: "192.168.1.0/24".into(),
                mac: None,
                gateway: None,
                gateway_mac: None,
                dns_servers: vec![],
                mtu: None,
                link_speed_mbps: None,
                wireless: false,
            },
            devices,
            findings: vec![],
            health_score: 100,
            notes: vec![],
        }
    }

    fn dev(ip: u8, mac: &str) -> Device {
        Device::new(Ipv4Addr::new(192, 168, 1, ip), Some(mac.into()))
    }

    #[test]
    fn tracks_changes_between_scans() {
        let mut inv = Inventory::default();
        let a = dev(10, "00:00:00:00:00:0A");
        let b = dev(11, "00:00:00:00:00:0B");
        let ev = inv.apply_scan(&mut report(vec![a.clone(), b.clone()], 0));
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::Baseline);

        let mut a2 = a.clone();
        a2.ip = Ipv4Addr::new(192, 168, 1, 40);
        let c = dev(12, "00:00:00:00:00:0C");
        let mut r = report(vec![a2, c], 1);
        let ev = inv.apply_scan(&mut r);
        let kinds: Vec<EventKind> = ev.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&EventKind::IpChanged));
        assert!(kinds.contains(&EventKind::NewDevice));
        assert!(kinds.contains(&EventKind::WentOffline));
        assert!(r.devices.iter().find(|d| d.id.ends_with("0C")).unwrap().is_new);

        let ev = inv.apply_scan(&mut report(vec![b], 2));
        assert!(ev.iter().any(|e| e.kind == EventKind::Returned));
    }

    #[test]
    fn reports_new_ports_and_keeps_labels() {
        let mut inv = Inventory::default();
        let mut a = dev(10, "00:00:00:00:00:0A");
        a.open_ports.push(OpenPort { port: 80, service: "web".into(), banner: None });
        inv.apply_scan(&mut report(vec![a.clone()], 0));
        inv.update(
            &a.id,
            DeviceUpdate { custom_name: Some("Hall camera".into()), trusted: Some(true), ..Default::default() },
        );

        a.open_ports.push(OpenPort { port: 23, service: "telnet".into(), banner: None });
        let mut r = report(vec![a], 1);
        let ev = inv.apply_scan(&mut r);
        assert!(ev.iter().any(|e| e.kind == EventKind::NewOpenPort && e.message.contains("Hall camera")));
        assert!(ev.iter().any(|e| e.kind == EventKind::NewFinding));
        assert_eq!(r.devices[0].custom_name.as_deref(), Some("Hall camera"));
        assert!(r.devices[0].trusted);
        assert!(r.health_score < 100);

        inv.ignored_findings.insert(r.devices[0].findings[0].id.clone());
        let view = inv.current_view().unwrap();
        assert_eq!(view.health_score, 100);
    }

    #[test]
    fn resolves_by_name_ip_and_mac() {
        let mut inv = Inventory::default();
        let a = dev(10, "00:00:00:00:00:0A");
        inv.apply_scan(&mut report(vec![a.clone()], 0));
        inv.update(&a.id, DeviceUpdate { custom_name: Some("NAS".into()), ..Default::default() });
        assert!(inv.resolve("nas").is_some());
        assert!(inv.resolve("192.168.1.10").is_some());
        assert!(inv.resolve("00-00-00-00-00-0a").is_some());
        assert!(inv.resolve("nope").is_none());
    }

    #[test]
    fn keeps_networks_apart_and_spots_replaced_routers() {
        let dir = std::env::temp_dir().join(format!("nattowok-ws-{}", std::process::id()));
        let ws = Workspace::new(dir.clone());
        let mut home_router = dev(1, "00:00:00:00:00:01");
        home_router.is_gateway = true;
        let laptop = dev(10, "00:00:00:00:00:0A");
        let (home, _, _) = ws.record_scan(&mut report(vec![home_router, laptop.clone()], 0)).unwrap();

        // A café on the same address range with none of our devices: a different network, no alarm.
        let mut cafe_router = dev(1, "00:00:00:00:00:CA");
        cafe_router.is_gateway = true;
        let (cafe, inv, _) = ws.record_scan(&mut report(vec![cafe_router], 1)).unwrap();
        assert_ne!(home, cafe);
        assert!(inv.previous_router.is_none());
        assert_eq!(ws.networks(&cafe).len(), 2);

        // Back home: same devices, but a router we've never seen.
        let mut home_router_a = dev(1, "00:00:00:00:00:01");
        home_router_a.is_gateway = true;
        ws.record_scan(&mut report(vec![home_router_a, laptop.clone()], 2)).unwrap();
        let mut new_router = dev(1, "00:00:00:00:00:EE");
        new_router.is_gateway = true;
        let (_, inv, _) = ws.record_scan(&mut report(vec![new_router, laptop], 3)).unwrap();
        assert_eq!(inv.previous_router.as_deref(), Some("00:00:00:00:00:01"));
        let view = inv.current_view().unwrap();
        assert!(view.findings.iter().any(|f| f.id.starts_with("gateway-changed")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn saves_and_loads() {
        let dir = std::env::temp_dir().join(format!("nattowok-test-{}", std::process::id()));
        let mut inv = Inventory::default();
        inv.apply_scan(&mut report(vec![dev(10, "00:00:00:00:00:0A")], 0));
        inv.save(&dir).unwrap();
        let loaded = Inventory::load(&dir).unwrap();
        assert_eq!(loaded.devices.len(), 1);
        assert!(loaded.last_report.is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
