//! The device inventory: names people gave their devices, what's trusted, and
//! a timeline of what changed between scans. Stored as one JSON file.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::matching;
use crate::model::{Device, NetworkInfo, PossibleMatch, ScanReport, Session};
use crate::security;

const MAX_EVENTS: usize = 2000;
const MAX_IP_HISTORY: usize = 20;
const MAX_SESSIONS: usize = 1500;
const MAX_SCAN_LOG: usize = 5000;
/// Scans further apart than this can't vouch for what happened in between.
pub const WATCH_GAP_HOURS: i64 = 6;
/// How much history the dashboard shows.
pub const PRESENCE_DAYS: i64 = 7;

/// Extends the current session if the device was also online in the
/// previous scan (and that scan was recent), otherwise starts a new one.
fn record_presence(sessions: &mut Vec<Session>, at: DateTime<Utc>, continuous: bool) {
    match sessions.last_mut() {
        Some(s) if continuous => s.to = at,
        _ => sessions.push(Session { from: at, to: at }),
    }
    if sessions.len() > MAX_SESSIONS {
        sessions.remove(0);
    }
}

/// Sorts sessions and joins overlapping ones (after a merge).
fn normalize_sessions(sessions: &mut Vec<Session>) {
    sessions.sort_by_key(|s| s.from);
    let mut out: Vec<Session> = Vec::with_capacity(sessions.len());
    for s in sessions.drain(..) {
        match out.last_mut() {
            Some(last) if s.from <= last.to => last.to = last.to.max(s.to),
            _ => out.push(s),
        }
    }
    *sessions = out;
}

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
    /// When it was online, from consecutive scans.
    #[serde(default)]
    pub sessions: Vec<Session>,
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
    /// A known device came back under a new hardware address.
    Recognized,
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
    /// Pairs of device ids people said are different devices, so we stop
    /// suggesting they're the same.
    #[serde(default)]
    pub not_same: BTreeSet<(String, String)>,
    /// When scans ran, so "offline" can be told apart from "not watching".
    #[serde(default)]
    pub scan_log: Vec<DateTime<Utc>>,
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
        let mut claimed = BTreeSet::new();
        let recent_previous_scan =
            self.scan_log.last().is_some_and(|last| at - *last <= chrono::Duration::hours(WATCH_GAP_HOURS));

        for d in &mut report.devices {
            // A stranger may be a known device with a new hardware address.
            let mut recognised = None;
            if !first_scan
                && !self.devices.contains_key(&d.id)
                && !d.is_gateway
                && !d.is_self
                && let Some((m, auto)) = self.best_match(d, &now_online, &claimed)
            {
                claimed.insert(m.id.clone());
                if auto {
                    self.rekey(&m.id, &d.id);
                    recognised = Some(m);
                } else {
                    d.possible_match = Some(m);
                }
            }
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
                            sessions: vec![Session { from: at, to: at }],
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
                    record_presence(&mut known.sessions, at, recent_previous_scan && self.online.contains(&d.id));
                    known.snapshot = d.clone();
                    if let Some(m) = &recognised {
                        changes.insert(
                            0,
                            (
                                EventKind::Recognized,
                                format!(
                                    "{label} came back with a new hardware address and was recognised ({})",
                                    m.reasons.iter().take(2).map(|r| r.to_lowercase()).collect::<Vec<_>>().join(", ")
                                ),
                            ),
                        );
                    }
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
        report.findings = security::network_findings(
            &report.network,
            &report.devices,
            report.exposure.as_ref(),
            report.wifi.as_ref(),
            self.previous_router.as_deref(),
        );
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

        self.scan_log.push(at);
        if self.scan_log.len() > MAX_SCAN_LOG {
            self.scan_log.remove(0);
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
        report.findings = security::network_findings(
            &report.network,
            &report.devices,
            report.exposure.as_ref(),
            report.wifi.as_ref(),
            self.previous_router.as_deref(),
        );
        self.mark_ignored(&mut report);
        let online: BTreeSet<String> = report.devices.iter().map(|d| d.id.clone()).collect();
        // Drop suggestions that no longer make sense: both are online (so they
        // can't be one device), the old entry is gone, or someone said no.
        let stale: Vec<String> = report
            .devices
            .iter()
            .filter(|d| {
                d.possible_match.as_ref().is_some_and(|m| {
                    online.contains(&m.id) || !self.devices.contains_key(&m.id) || self.is_not_same(&d.id, &m.id)
                })
            })
            .map(|d| d.id.clone())
            .collect();
        for d in &mut report.devices {
            if stale.contains(&d.id) {
                d.possible_match = None;
            } else if let Some(m) = d.possible_match.as_mut()
                && let Some(k) = self.devices.get(&m.id)
            {
                m.name = k.custom_name.clone().unwrap_or_else(|| k.snapshot.name.clone());
            }
        }
        let mut offline: Vec<Device> = self
            .devices
            .values()
            .filter(|k| !online.contains(&k.id))
            .map(|k| {
                let mut d = k.snapshot.clone();
                d.online = false;
                d.is_new = false;
                d.possible_match = None;
                d.findings.clear();
                self.decorate(&mut d);
                d
            })
            .collect();
        offline.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
        report.devices.extend(offline);
        let since = report.finished_at - chrono::Duration::days(PRESENCE_DAYS + 1);
        for d in &mut report.devices {
            d.presence = self
                .devices
                .get(&d.id)
                .map(|k| k.sessions.iter().filter(|s| s.to >= since).copied().collect())
                .unwrap_or_default();
        }
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

    fn is_not_same(&self, a: &str, b: &str) -> bool {
        let pair = if a < b { (a.to_string(), b.to_string()) } else { (b.to_string(), a.to_string()) };
        self.not_same.contains(&pair)
    }

    /// The offline known device a newcomer most resembles, and whether the
    /// match is certain enough to apply without asking.
    fn best_match(
        &self,
        d: &Device,
        now_online: &BTreeSet<String>,
        claimed: &BTreeSet<String>,
    ) -> Option<(PossibleMatch, bool)> {
        let mut scored: Vec<(u32, bool, Vec<String>, &KnownDevice)> = self
            .devices
            .values()
            .filter(|k| !now_online.contains(&k.id) && !claimed.contains(&k.id))
            .filter(|k| !k.snapshot.is_gateway && !k.snapshot.is_self && !self.is_not_same(&d.id, &k.id))
            .map(|k| {
                let (score, by_name, reasons) = matching::similarity(d, &k.snapshot);
                (score, by_name, reasons, k)
            })
            .filter(|(score, ..)| *score >= matching::SUGGEST)
            .collect();
        scored.sort_by_key(|(score, ..)| std::cmp::Reverse(*score));
        let runner_up = scored.get(1).map_or(0, |s| s.0);
        let (score, by_name, reasons, k) = scored.into_iter().next()?;
        // Only private addresses rotate, so only those are carried over silently.
        let auto = score >= matching::AUTO
            && by_name
            && d.private_mac
            && k.snapshot.private_mac
            && runner_up < matching::SUGGEST;
        let name = k.custom_name.clone().unwrap_or_else(|| k.snapshot.name.clone());
        Some((PossibleMatch { id: k.id.clone(), name, score, reasons }, auto))
    }

    /// Moves a known device to a new id, keeping its labels and history.
    fn rekey(&mut self, old: &str, new: &str) {
        let Some(mut k) = self.devices.remove(old) else { return };
        k.id = new.to_string();
        self.devices.insert(new.to_string(), k);
        if self.online.remove(old) {
            self.online.insert(new.to_string());
        }
        self.remap(old, new);
    }

    /// Points events, dismissed findings and suggestions at `new` instead of `old`.
    fn remap(&mut self, old: &str, new: &str) {
        for e in &mut self.events {
            if e.device_id.as_deref() == Some(old) {
                e.device_id = Some(new.to_string());
            }
        }
        let suffix = format!(":{old}");
        self.ignored_findings = self
            .ignored_findings
            .iter()
            .map(|f| f.strip_suffix(&suffix).map_or_else(|| f.clone(), |prefix| format!("{prefix}:{new}")))
            .collect();
        if let Some(r) = self.last_report.as_mut() {
            r.devices.retain(|d| d.id != old);
            for d in &mut r.devices {
                if d.possible_match.as_ref().is_some_and(|m| m.id == old) {
                    d.possible_match = None;
                }
            }
        }
    }

    /// People confirmed that `from` (an older entry) is the same device as
    /// `keep`: fold its name, notes, tags, trust and history into `keep`.
    pub fn merge(&mut self, keep: &str, from: &str) -> Result<String> {
        ensure!(keep != from, "those are the same entry already");
        let old = self.devices.get(from).cloned().context("the earlier device wasn't found")?;
        let k = self.devices.get_mut(keep).context("device not found")?;
        if k.custom_name.is_none() {
            k.custom_name = old.custom_name.clone();
        }
        k.notes = match (k.notes.take(), old.notes) {
            (Some(a), Some(b)) if a != b => Some(format!("{b}\n{a}")),
            (a, b) => a.or(b),
        };
        k.tags.extend(old.tags);
        k.tags.sort();
        k.tags.dedup();
        k.trusted |= old.trusted;
        k.first_seen = k.first_seen.min(old.first_seen);
        k.times_seen += old.times_seen;
        k.sessions.extend(old.sessions);
        normalize_sessions(&mut k.sessions);
        let mut history = old.ip_history;
        history.append(&mut k.ip_history);
        history.sort_by_key(|(_, at)| *at);
        history.dedup_by_key(|(ip, _)| *ip);
        let excess = history.len().saturating_sub(MAX_IP_HISTORY);
        k.ip_history = history.split_off(excess);
        k.snapshot.possible_match = None;
        k.snapshot.is_new = false;
        let label = k.custom_name.clone().unwrap_or_else(|| k.snapshot.name.clone());
        self.devices.remove(from);
        self.online.remove(from);
        self.remap(from, keep);
        if let Some(d) = self.last_report.as_mut().and_then(|r| r.devices.iter_mut().find(|d| d.id == keep)) {
            d.possible_match = None;
            d.is_new = false;
        }
        self.push_event(
            Utc::now(),
            EventKind::Recognized,
            Some(keep),
            format!("{label} was merged with its earlier entry"),
        );
        Ok(label)
    }

    /// People said these two are different devices.
    pub fn mark_not_same(&mut self, a: &str, b: &str) {
        let pair = if a < b { (a.to_string(), b.to_string()) } else { (b.to_string(), a.to_string()) };
        self.not_same.insert(pair);
        if let Some(r) = self.last_report.as_mut() {
            for d in r.devices.iter_mut().filter(|d| d.id == a || d.id == b) {
                d.possible_match = None;
            }
        }
        for id in [a, b] {
            if let Some(k) = self.devices.get_mut(id) {
                k.snapshot.possible_match = None;
            }
        }
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
            exposure: None,
            wifi: None,
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

    fn phone(ip: u8, mac: &str, host: &str) -> Device {
        let mut d = dev(ip, mac);
        d.private_mac = true;
        d.kind = crate::model::DeviceKind::Phone;
        d.hostname = Some(host.into());
        d.name = host.into();
        d
    }

    #[test]
    fn recognises_rotated_private_addresses() {
        let mut inv = Inventory::default();
        let other = dev(2, "00:00:00:00:00:02");
        let old = phone(23, "DA:00:00:00:00:01", "Kims-iPhone");
        inv.apply_scan(&mut report(vec![other.clone(), old.clone()], 0));
        inv.update(
            &old.id,
            DeviceUpdate { custom_name: Some("Kim's phone".into()), trusted: Some(true), ..Default::default() },
        );
        inv.apply_scan(&mut report(vec![other.clone()], 1)); // phone leaves

        let new = phone(23, "DA:00:00:00:00:99", "Kims-iPhone");
        let mut r = report(vec![other, new.clone()], 2);
        let ev = inv.apply_scan(&mut r);
        assert!(ev.iter().any(|e| e.kind == EventKind::Recognized), "{ev:?}");
        assert!(!ev.iter().any(|e| e.kind == EventKind::NewDevice));
        let d = r.devices.iter().find(|d| d.id == new.id).unwrap();
        assert_eq!(d.custom_name.as_deref(), Some("Kim's phone"));
        assert!(d.trusted);
        assert!(!d.is_new);
        assert!(!inv.devices.contains_key(&old.id));
        assert!(inv.events.iter().all(|e| e.device_id.as_deref() != Some(old.id.as_str())));
    }

    #[test]
    fn suggests_then_merges_or_dismisses() {
        let mut inv = Inventory::default();
        let mut old = dev(40, "00:80:92:00:00:01");
        old.kind = crate::model::DeviceKind::Printer;
        old.vendor = Some("Seiko Epson".into());
        inv.apply_scan(&mut report(vec![old.clone()], 0));
        inv.update(&old.id, DeviceUpdate { custom_name: Some("Office printer".into()), ..Default::default() });
        inv.apply_scan(&mut report(vec![], 1));

        // Same IP, kind and maker but a different (global) MAC: ask, don't assume.
        let mut new = dev(40, "00:80:92:00:00:02");
        new.kind = crate::model::DeviceKind::Printer;
        new.vendor = Some("Seiko Epson".into());
        let mut r = report(vec![new.clone()], 2);
        inv.apply_scan(&mut r);
        let m = r.devices[0].possible_match.clone().expect("suggestion");
        assert_eq!(m.id, old.id);
        assert_eq!(inv.current_view().unwrap().devices[0].possible_match.as_ref().unwrap().name, "Office printer");

        let mut no = inv.clone();
        no.mark_not_same(&new.id, &old.id);
        assert!(no.current_view().unwrap().devices[0].possible_match.is_none());

        assert_eq!(inv.merge(&new.id, &old.id).unwrap(), "Office printer");
        let view = inv.current_view().unwrap();
        assert_eq!(view.devices.len(), 1);
        assert_eq!(view.devices[0].custom_name.as_deref(), Some("Office printer"));
        assert!(view.devices[0].possible_match.is_none());
        assert!(!view.devices[0].is_new);
    }

    #[test]
    fn records_presence_sessions() {
        let mut inv = Inventory::default();
        let a = dev(10, "00:00:00:00:00:0A");
        let b = dev(11, "00:00:00:00:00:0B");
        inv.apply_scan(&mut report(vec![a.clone(), b.clone()], 0));
        inv.apply_scan(&mut report(vec![a.clone(), b.clone()], 15));
        inv.apply_scan(&mut report(vec![a.clone()], 30)); // b leaves
        inv.apply_scan(&mut report(vec![a.clone(), b.clone()], 45)); // b is back
        let sa = &inv.devices[&a.id].sessions;
        assert_eq!(sa.len(), 1, "continuously online: one session");
        assert_eq!((sa[0].to - sa[0].from).num_minutes(), 45);
        let sb = &inv.devices[&b.id].sessions;
        assert_eq!(sb.len(), 2);
        assert_eq!((sb[0].to - sb[0].from).num_minutes(), 15);
        assert_eq!(inv.scan_log.len(), 4);
        let view = inv.current_view().unwrap();
        assert_eq!(view.devices.iter().find(|d| d.id == b.id).unwrap().presence.len(), 2);

        let mut merged = vec![sb[1], sb[0], Session { from: sb[0].from, to: sb[0].to + chrono::Duration::minutes(1) }];
        normalize_sessions(&mut merged);
        assert_eq!(merged.len(), 2);
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
