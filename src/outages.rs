//! The outage log: checks the connection once a minute and records each
//! time the internet stopped working, how long for, and where the fault was
//! (this computer, the Wi-Fi or router, the internet provider, or DNS). The
//! report is something you can send to your provider's support.
//!
//! Off until turned on: it contacts Cloudflare, Google and Quad9 (a TCP
//! connect each) and your DNS server once a minute.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Local, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::probe::{self, TcpState};
use crate::store::Workspace;
use crate::{dns, netinfo};

/// How often the connection is checked while it works.
pub const CHECK_EVERY: Duration = Duration::from_secs(60);
/// How often it's checked during an outage, to time the end closely.
const DOWN_CHECK_EVERY: Duration = Duration::from_secs(15);
/// Failed checks are repeated this many times, this far apart, before an
/// outage is recorded, so one lost packet doesn't count.
const CONFIRM: (u32, Duration) = (2, Duration::from_secs(5));
/// A longer silence between checks means the computer slept or NattoWok
/// wasn't running: that time isn't counted either way.
const MAX_GAP: TimeDelta = TimeDelta::minutes(3);
const KEEP_DAYS: i64 = 90;

const INTERNET: &[(Ipv4Addr, u16)] =
    &[(Ipv4Addr::new(1, 1, 1, 1), 443), (Ipv4Addr::new(8, 8, 8, 8), 443), (Ipv4Addr::new(9, 9, 9, 9), 443)];

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    /// This computer had no usable connection (Wi-Fi off, no address).
    Local,
    /// The router stopped answering.
    Router,
    /// Nothing on the internet answered and the router never answers
    /// checks, so it could be either.
    RouterOrProvider,
    /// The router answered but nothing beyond it did.
    Provider,
    /// The internet answered but name lookups failed.
    Dns,
}

impl Cause {
    pub const ALL: [Cause; 5] = [Cause::Local, Cause::Router, Cause::RouterOrProvider, Cause::Provider, Cause::Dns];

    pub fn label(self) -> &'static str {
        match self {
            Cause::Local => "This computer",
            Cause::Router => "Your Wi-Fi or router",
            Cause::RouterOrProvider => "Router or internet provider",
            Cause::Provider => "Internet provider",
            Cause::Dns => "DNS (name lookups)",
        }
    }

    pub fn explain(self) -> &'static str {
        match self {
            Cause::Local => "This computer had no network connection (Wi-Fi off or disconnected, or no address).",
            Cause::Router => {
                "Your router stopped answering, so the problem was inside your home: the Wi-Fi or the router."
            }
            Cause::RouterOrProvider => {
                "Nothing on the internet answered, and the router didn't either. Some routers never answer checks, so it could be the router or the provider."
            }
            Cause::Provider => {
                "Your router answered, but nothing on the internet did: the fault was beyond your home network."
            }
            Cause::Dns => "The internet was reachable, but name lookups failed, so websites wouldn't open.",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    Up,
    Down(Cause),
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct Window {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Outage {
    pub started: DateTime<Utc>,
    /// `None` while it's still going on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<DateTime<Utc>>,
    pub cause: Cause,
    /// Monitoring stopped (sleep, shutdown) before the connection came back,
    /// so the real end is unknown; `ended` is the last failed check.
    #[serde(default)]
    pub cut_short: bool,
}

impl Outage {
    pub fn duration(&self, now: DateTime<Utc>) -> TimeDelta {
        self.ended.unwrap_or(now) - self.started
    }
}

/// Everything recorded for one network.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Log {
    /// When the connection was being checked.
    pub watched: Vec<Window>,
    pub outages: Vec<Outage>,
}

fn path(dir: &Path) -> PathBuf {
    dir.join("outages.json")
}

impl Log {
    pub fn load(dir: &Path) -> Log {
        std::fs::read_to_string(path(dir)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let p = path(dir);
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(self)?)?;
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }

    pub fn open_outage(&self) -> Option<&Outage> {
        self.outages.last().filter(|o| o.ended.is_none())
    }

    fn trim(&mut self, now: DateTime<Utc>) {
        let cutoff = now - TimeDelta::days(KEEP_DAYS);
        self.watched.retain(|w| w.to >= cutoff);
        self.outages.retain(|o| o.ended.is_none_or(|e| e >= cutoff));
    }

    /// Notes that the connection was checked at `now`: extends the current
    /// watch window, or starts a new one after a gap. An outage left open
    /// across a gap is closed at its last failed check.
    pub fn checked(&mut self, now: DateTime<Utc>) {
        match self.watched.last_mut() {
            Some(w) if now - w.to <= MAX_GAP && now >= w.to => w.to = now,
            last => {
                let gap_from = last.map(|w| w.to);
                if let (Some(from), Some(o)) = (gap_from, self.outages.last_mut())
                    && o.ended.is_none()
                {
                    o.ended = Some(from.max(o.started));
                    o.cut_short = true;
                }
                self.watched.push(Window { from: now, to: now });
            }
        }
        self.trim(now);
    }

    /// Records a confirmed failure first seen at `since`. Returns true when
    /// this starts a new outage.
    pub fn down(&mut self, since: DateTime<Utc>, cause: Cause) -> bool {
        if let Some(o) = self.outages.last_mut()
            && o.ended.is_none()
        {
            // The more specific inside-the-home cause wins if it changes.
            if cause < o.cause {
                o.cause = cause;
            }
            return false;
        }
        self.outages.push(Outage { started: since, ended: None, cause, cut_short: false });
        true
    }

    /// The connection works at `now`. Returns the outage this ends, if any.
    pub fn up(&mut self, now: DateTime<Utc>) -> Option<Outage> {
        let o = self.outages.last_mut().filter(|o| o.ended.is_none())?;
        o.ended = Some(now);
        Some(o.clone())
    }
}

/// Totals for a period, for the dashboard and the report.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Summary {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// Seconds the connection was being checked within the period.
    pub watched_secs: i64,
    pub period_secs: i64,
    pub outages: Vec<Outage>,
    pub down_secs: i64,
    /// Count and seconds by cause.
    pub by_cause: BTreeMap<Cause, (usize, i64)>,
    /// Share of checked time the internet worked, 0–100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_pct: Option<f64>,
}

fn clip(from: DateTime<Utc>, to: DateTime<Utc>, start: DateTime<Utc>, end: DateTime<Utc>) -> i64 {
    (to.min(end) - from.max(start)).num_seconds().max(0)
}

pub fn summarize(log: &Log, days: i64, now: DateTime<Utc>) -> Summary {
    let from = now - TimeDelta::days(days);
    let watched_secs: i64 = log.watched.iter().map(|w| clip(w.from, w.to, from, now)).sum();
    let outages: Vec<Outage> =
        log.outages.iter().filter(|o| o.ended.is_none_or(|e| e >= from) && o.started <= now).cloned().collect();
    let mut by_cause: BTreeMap<Cause, (usize, i64)> = BTreeMap::new();
    let mut down_secs = 0;
    for o in &outages {
        let secs = clip(o.started, o.ended.unwrap_or(now), from, now);
        down_secs += secs;
        let e = by_cause.entry(o.cause).or_default();
        e.0 += 1;
        e.1 += secs;
    }
    let uptime_pct = (watched_secs > 0).then(|| {
        let pct = 100.0 * (1.0 - down_secs as f64 / watched_secs as f64);
        (pct.clamp(0.0, 100.0) * 100.0).round() / 100.0
    });
    Summary {
        from,
        to: now,
        watched_secs,
        period_secs: (now - from).num_seconds(),
        outages,
        down_secs,
        by_cause,
        uptime_pct,
    }
}

/// "42 min", "1 h 5 min", "35 s".
pub fn human(secs: i64) -> String {
    match secs {
        s if s < 60 => format!("{s} s"),
        s if s < 3600 => format!("{} min", (s + 30) / 60),
        s => {
            let m = (s + 30) / 60;
            if m % 60 == 0 { format!("{} h", m / 60) } else { format!("{} h {} min", m / 60, m % 60) }
        }
    }
}

fn local(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%a %-d %b %Y, %H:%M").to_string()
}

/// A report to send to the internet provider: their outages first, with the
/// home-side ones listed separately so the report is fair.
pub fn report(summary: &Summary, network: &str) -> String {
    let mut out = String::new();
    let period = format!(
        "{} – {}",
        summary.from.with_timezone(&Local).format("%-d %b %Y"),
        summary.to.with_timezone(&Local).format("%-d %b %Y")
    );
    let coverage = if summary.period_secs > 0 {
        format!("{:.0}%", 100.0 * summary.watched_secs as f64 / summary.period_secs as f64)
    } else {
        "0%".into()
    };
    out.push_str("# Internet outage report\n\n");
    out.push_str(&format!("- Network: {network}\n- Period: {period}\n- Time monitored: {coverage} of the period\n"));
    let theirs: Vec<&Outage> =
        summary.outages.iter().filter(|o| matches!(o.cause, Cause::Provider | Cause::Dns)).collect();
    let unclear: Vec<&Outage> = summary.outages.iter().filter(|o| o.cause == Cause::RouterOrProvider).collect();
    let ours: Vec<&Outage> =
        summary.outages.iter().filter(|o| matches!(o.cause, Cause::Local | Cause::Router)).collect();
    let total = |list: &[&Outage]| list.iter().map(|o| o.duration(summary.to).num_seconds()).sum::<i64>();
    out.push_str(&format!("- Outages beyond the home network: {} (total {})\n\n", theirs.len(), human(total(&theirs))));
    out.push_str(
        "The connection was checked once a minute from a computer on this network. A failed check was repeated \
         twice, 5 seconds apart, before counting as an outage, and checked every 15 seconds until it recovered. \
         \"Beyond the home network\" means the home router answered, but Cloudflare (1.1.1.1), Google (8.8.8.8) and \
         Quad9 (9.9.9.9) all did not; or that those answered but the DNS server could not look up names.\n\n",
    );
    let table = |out: &mut String, list: &[&Outage]| {
        out.push_str("| Started | Ended | Duration | What failed |\n|---|---|---|---|\n");
        for o in list {
            let ended = match o.ended {
                Some(e) if o.cut_short => format!("{} (monitoring stopped)", local(e)),
                Some(e) => local(e),
                None => "still down".into(),
            };
            let what = if o.cause == Cause::Dns { "Name lookups (DNS)" } else { "Internet connection" };
            out.push_str(&format!(
                "| {} | {ended} | {} | {what} |\n",
                local(o.started),
                human(o.duration(summary.to).num_seconds())
            ));
        }
        out.push('\n');
    };
    if theirs.is_empty() {
        out.push_str("No outages beyond the home network were recorded in this period.\n\n");
    } else {
        out.push_str("## Outages beyond the home network\n\n");
        table(&mut out, &theirs);
    }
    if !unclear.is_empty() {
        out.push_str("## Outages that could be the router or the provider\n\n");
        out.push_str(
            "The router didn't answer during these either. Some routers never answer checks, so these can't be \
             placed for sure.\n\n",
        );
        table(&mut out, &unclear);
    }
    if !ours.is_empty() {
        out.push_str(&format!(
            "## Not counted: problems inside the home ({} totalling {})\n\n",
            ours.len(),
            human(total(&ours))
        ));
        out.push_str("The router itself stopped answering, or this computer was disconnected.\n\n");
    }
    out.push_str("_Recorded by NattoWok Scanner._\n");
    out
}

/// One check of the connection. `router_answers` is learned while the
/// internet works, so that a silent router only counts as down when it
/// normally answers.
pub async fn check(
    interface: Option<&str>,
    router_answers: &mut Option<bool>,
) -> (Option<crate::model::NetworkInfo>, Reading) {
    let info = match netinfo::detect(interface, None) {
        Ok(i) if !i.ip.is_link_local() && i.gateway.is_some() => i,
        Ok(i) => return (Some(i), Reading::Down(Cause::Local)),
        Err(_) => return (None, Reading::Down(Cause::Local)),
    };
    let gateway = info.gateway.expect("checked above");
    let timeout = Duration::from_secs(2);
    let internet = async {
        let tries = INTERNET.iter().map(|(ip, port)| probe::tcp_probe(SocketAddr::from((*ip, *port)), timeout));
        probe::futures_join_all(tries).await.iter().any(|(s, _)| *s == TcpState::Open)
    };
    let router = async {
        for port in [80, 443, 53] {
            if probe::tcp_probe(SocketAddr::from((gateway, port)), timeout).await.0 != TcpState::Silent {
                return true;
            }
        }
        probe::ping_available() && probe::system_ping(gateway, timeout).await.is_some()
    };
    let servers: Vec<IpAddr> = info.dns_servers.iter().copied().filter(IpAddr::is_ipv4).take(2).collect();
    let dns_ok = async {
        if servers.is_empty() {
            return true;
        }
        for s in &servers {
            // Any answer, "no such name" included, means DNS works.
            if let Ok((msg, _)) = dns::query(SocketAddr::new(*s, 53), "example.com", dns::TYPE_A, timeout).await
                && (msg.rcode == 0 || msg.rcode == 3)
            {
                return true;
            }
        }
        false
    };
    let (internet, router, dns_ok) = tokio::join!(internet, router, dns_ok);
    (Some(info), classify(internet, router, dns_ok, router_answers))
}

/// Where the fault is, from what answered.
fn classify(internet: bool, router: bool, dns_ok: bool, router_answers: &mut Option<bool>) -> Reading {
    match (internet, dns_ok) {
        (true, true) => {
            *router_answers = Some(router || router_answers.unwrap_or(false));
            Reading::Up
        }
        (true, false) => Reading::Down(Cause::Dns),
        (false, _) if router => Reading::Down(Cause::Provider),
        (false, _) if *router_answers == Some(true) => Reading::Down(Cause::Router),
        (false, _) => Reading::Down(Cause::RouterOrProvider),
    }
}

/// What the monitor tells whoever runs it.
#[derive(Debug, Clone)]
pub enum Update {
    Started { network: String, outage: Outage },
    Ended { network: String, outage: Outage },
}

/// Status shown in the dashboard while monitoring.
#[derive(Serialize, Clone, Debug, Default)]
pub struct Live {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_check: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down: Option<Outage>,
}

/// Keeps checking while `enabled()` is true, writing to each network's log.
pub async fn monitor(
    root: PathBuf,
    interface: Option<String>,
    enabled: impl Fn() -> bool,
    live: impl Fn(Live),
    on_update: impl Fn(Update),
) {
    let ws = Workspace::new(root);
    let mut key: Option<String> = None;
    let mut log = Log::default();
    let mut router_answers: Option<bool> = None;
    loop {
        if !enabled() {
            live(Live::default());
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        let first_at = Utc::now();
        let (info, mut reading) = check(interface.as_deref(), &mut router_answers).await;
        // The network we're on; while disconnected, the one we were on.
        let here = match (&info, &key) {
            (Some(i), _) if i.gateway.is_some() => ws.key_for(Some(i)),
            (_, Some(k)) => k.clone(),
            _ => ws.key_for(None),
        };
        if key.as_deref() != Some(&here) {
            if let Some(k) = &key {
                let _ = log.save(&ws.dir(k));
            }
            log = Log::load(&ws.dir(&here));
            router_answers = None;
            key = Some(here.clone());
        }
        if let Reading::Down(_) = reading
            && log.open_outage().is_none()
        {
            for _ in 0..CONFIRM.0 {
                tokio::time::sleep(CONFIRM.1).await;
                reading = check(interface.as_deref(), &mut router_answers).await.1;
                if reading == Reading::Up {
                    break;
                }
            }
        }
        let now = Utc::now();
        log.checked(now);
        match reading {
            Reading::Up => {
                if let Some(outage) = log.up(now) {
                    on_update(Update::Ended { network: here.clone(), outage });
                }
            }
            Reading::Down(cause) => {
                let since = log.open_outage().map_or(first_at, |o| o.started);
                if log.down(since, cause) {
                    let outage = log.open_outage().cloned().expect("just opened");
                    on_update(Update::Started { network: here.clone(), outage });
                }
            }
        }
        if let Err(e) = log.save(&ws.dir(&here)) {
            eprintln!("outage log: couldn't save: {e:#}");
        }
        live(Live { last_check: Some(now), down: log.open_outage().cloned() });
        let wait = if log.open_outage().is_some() { DOWN_CHECK_EVERY } else { CHECK_EVERY };
        tokio::time::sleep(wait).await;
    }
}

/// A name people recognise for a network: its Wi-Fi name, or its address range.
pub fn network_label(ws: &Workspace, key: &str) -> String {
    let inv = crate::store::Inventory::load(&ws.dir(key)).unwrap_or_default();
    let report = inv.last_report.as_ref();
    report
        .and_then(|r| r.wifi.as_ref().and_then(|w| w.ssid.clone()))
        .or_else(|| report.map(|r| r.network.scan_range.clone()))
        .unwrap_or_else(|| "this network".into())
}

/// Notification text for an outage that just ended.
pub fn ended_message(o: &Outage, now: DateTime<Utc>) -> (String, String) {
    let secs = o.duration(now).num_seconds();
    let title = format!("Internet was down for {}", human(secs));
    let body = format!(
        "From {} to {}. {}",
        o.started.with_timezone(&Local).format("%H:%M"),
        o.ended.unwrap_or(now).with_timezone(&Local).format("%H:%M"),
        o.cause.explain()
    );
    (title, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(min: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-02T08:00:00Z").unwrap().with_timezone(&Utc) + TimeDelta::minutes(min)
    }

    #[test]
    fn records_outages_and_gaps() {
        let mut log = Log::default();
        for m in 0..10 {
            log.checked(t(m));
        }
        log.checked(t(10));
        assert!(log.down(t(10), Cause::Provider));
        assert!(!log.down(t(10), Cause::Provider), "same outage continues");
        log.checked(t(11));
        log.down(t(10), Cause::Router);
        log.checked(t(14));
        let ended = log.up(t(14)).unwrap();
        assert_eq!(ended.duration(t(99)).num_minutes(), 4);
        assert_eq!(ended.cause, Cause::Router, "the home-side cause wins");
        assert_eq!(log.watched.len(), 1);

        // The laptop sleeps during an outage: it's closed at the last failed check.
        for m in 15..=20 {
            log.checked(t(m));
        }
        log.down(t(20), Cause::Provider);
        log.checked(t(60));
        assert_eq!(log.watched.len(), 2, "a gap starts a new window");
        let o = &log.outages[1];
        assert!(o.cut_short);
        assert_eq!(o.ended, Some(t(20)));
        assert_eq!(log.up(t(61)), None, "nothing left open");
    }

    #[test]
    fn summarizes_and_reports() {
        let mut log = Log::default();
        log.watched.push(Window { from: t(0), to: t(600) });
        log.outages.push(Outage { started: t(100), ended: Some(t(130)), cause: Cause::Provider, cut_short: false });
        log.outages.push(Outage { started: t(200), ended: Some(t(205)), cause: Cause::Router, cut_short: false });
        log.outages.push(Outage { started: t(300), ended: Some(t(301)), cause: Cause::Dns, cut_short: false });
        let s = summarize(&log, 7, t(600));
        assert_eq!(s.watched_secs, 600 * 60);
        assert_eq!(s.down_secs, 36 * 60);
        assert_eq!(s.by_cause[&Cause::Provider], (1, 1800));
        assert_eq!(s.uptime_pct, Some(94.0));
        let r = report(&s, "Home");
        assert!(r.contains("Outages beyond the home network: 2 (total 31 min)"), "{r}");
        assert!(r.contains("Not counted: problems inside the home (1 totalling 5 min)"), "{r}");
        assert!(r.contains("| 30 min | Internet connection |"), "{r}");
    }

    #[test]
    fn places_the_fault() {
        let mut answers = None;
        assert_eq!(classify(false, false, false, &mut answers), Reading::Down(Cause::RouterOrProvider));
        assert_eq!(classify(true, true, true, &mut answers), Reading::Up);
        assert_eq!(answers, Some(true), "learned that the router answers");
        assert_eq!(classify(false, true, false, &mut answers), Reading::Down(Cause::Provider));
        assert_eq!(classify(false, false, false, &mut answers), Reading::Down(Cause::Router));
        assert_eq!(classify(true, true, false, &mut answers), Reading::Down(Cause::Dns));
        // A router that never answers checks can't be blamed.
        let mut silent = None;
        classify(true, false, true, &mut silent);
        assert_eq!(classify(false, false, false, &mut silent), Reading::Down(Cause::RouterOrProvider));
    }

    #[test]
    fn formats_durations() {
        assert_eq!(human(35), "35 s");
        assert_eq!(human(42 * 60), "42 min");
        assert_eq!(human(65 * 60), "1 h 5 min");
        assert_eq!(human(120 * 60), "2 h");
    }

    #[test]
    fn keeps_ninety_days() {
        let mut log = Log::default();
        log.watched.push(Window { from: t(0), to: t(1) });
        log.outages.push(Outage { started: t(0), ended: Some(t(1)), cause: Cause::Provider, cut_short: false });
        log.checked(t(0) + TimeDelta::days(100));
        assert_eq!(log.watched.len(), 1);
        assert!(log.outages.is_empty());
    }
}
