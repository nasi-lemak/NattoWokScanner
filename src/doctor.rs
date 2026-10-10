//! "Why is my internet slow?" Tests each hop from this computer outwards
//! (local link, router, internet, DNS) and says which one is the problem, in
//! plain words, with something to try.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::NetworkInfo;
use crate::probe::{self, TcpState};
use crate::scan::Progress;
use crate::wifi::{self, Quality, SecurityRisk, WifiInfo};
use crate::{dns, http, netinfo};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Skip,
    Warn,
    Fail,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Latency {
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub min_ms: f64,
    pub avg_ms: f64,
    pub max_ms: f64,
    /// Mean difference between consecutive samples.
    pub jitter_ms: f64,
}

impl Latency {
    pub fn from_samples(samples: &[Option<f64>]) -> Option<Latency> {
        let got: Vec<f64> = samples.iter().flatten().copied().collect();
        let sent = samples.len() as u32;
        if sent == 0 {
            return None;
        }
        let received = got.len() as u32;
        let loss_pct = 100.0 * f64::from(sent - received) / f64::from(sent);
        if got.is_empty() {
            return Some(Latency { sent, received, loss_pct, min_ms: 0.0, avg_ms: 0.0, max_ms: 0.0, jitter_ms: 0.0 });
        }
        let r = |x: f64| (x * 10.0).round() / 10.0;
        let jitter = if got.len() > 1 {
            got.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (got.len() - 1) as f64
        } else {
            0.0
        };
        Some(Latency {
            sent,
            received,
            loss_pct: r(loss_pct),
            min_ms: r(got.iter().copied().fold(f64::INFINITY, f64::min)),
            avg_ms: r(got.iter().sum::<f64>() / got.len() as f64),
            max_ms: r(got.iter().copied().fold(0.0, f64::max)),
            jitter_ms: r(jitter),
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Check {
    pub id: String,
    pub layer: String,
    pub title: String,
    pub status: Status,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advice: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<Latency>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DnsResult {
    pub server: IpAddr,
    pub label: String,
    pub configured: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub median_ms: Option<f64>,
    pub failures: u32,
    pub queries: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Diagnosis {
    pub at: DateTime<Utc>,
    pub status: Status,
    pub headline: String,
    pub summary: String,
    pub checks: Vec<Check>,
    pub dns: Vec<DnsResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wifi: Option<WifiInfo>,
}

const PUBLIC_DNS: &[(Ipv4Addr, &str)] = &[
    (Ipv4Addr::new(1, 1, 1, 1), "Cloudflare"),
    (Ipv4Addr::new(8, 8, 8, 8), "Google"),
    (Ipv4Addr::new(9, 9, 9, 9), "Quad9"),
];
const INTERNET_TARGETS: &[(Ipv4Addr, &str)] = &[
    (Ipv4Addr::new(1, 1, 1, 1), "Cloudflare"),
    (Ipv4Addr::new(8, 8, 8, 8), "Google"),
    (Ipv4Addr::new(9, 9, 9, 9), "Quad9"),
];
const DNS_TEST_NAMES: &[&str] =
    &["www.google.com", "www.wikipedia.org", "www.amazon.com", "www.apple.com", "www.netflix.com"];

/// Finds a port that answers (open or reset) and measures repeated connects.
async fn tcp_series(ip: Ipv4Addr, ports: &[u16], count: usize, gap: Duration) -> Option<Vec<Option<f64>>> {
    let timeout = Duration::from_millis(1000);
    let mut port = None;
    for &p in ports {
        let (state, _) = probe::tcp_probe(SocketAddr::from((ip, p)), timeout).await;
        if state != TcpState::Silent {
            port = Some(p);
            break;
        }
    }
    let port = port?;
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        let (state, rtt) = probe::tcp_probe(SocketAddr::from((ip, port)), timeout).await;
        samples.push((state != TcpState::Silent).then_some(rtt.as_secs_f64() * 1000.0));
        tokio::time::sleep(gap).await;
    }
    Some(samples)
}

async fn ping_series(ip: Ipv4Addr, count: usize, gap: Duration) -> Option<Vec<Option<f64>>> {
    if !probe::ping_available() {
        return None;
    }
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        samples.push(probe::system_ping(ip, Duration::from_secs(1)).await);
        tokio::time::sleep(gap).await;
    }
    Some(samples)
}

fn median(mut v: Vec<f64>) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Some((v[v.len() / 2] * 10.0).round() / 10.0)
}

async fn bench_dns(server: IpAddr) -> (Option<f64>, u32, u32) {
    let mut times = Vec::new();
    let mut failures = 0;
    for name in DNS_TEST_NAMES {
        match dns::query(SocketAddr::new(server, 53), name, dns::TYPE_A, Duration::from_secs(2)).await {
            Ok((msg, rtt)) if msg.rcode == 0 => times.push(rtt.as_secs_f64() * 1000.0),
            _ => failures += 1,
        }
    }
    (median(times), failures, DNS_TEST_NAMES.len() as u32)
}

/// Returns `Some(true)` when a captive portal intercepts plain HTTP.
async fn captive_portal() -> Option<bool> {
    let host = "connectivitycheck.gstatic.com";
    let addr = tokio::net::lookup_host((host, 80)).await.ok()?.find(|a| a.is_ipv4())?;
    let resp = http::get(addr, host, "/generate_204", Duration::from_secs(3)).await.ok()?;
    // Portals answer with their own page (200) or a redirect to it. Anything
    // else (a proxy error, say) doesn't tell us a sign-in is needed.
    match resp.status {
        204 => Some(false),
        200 | 300..=399 => Some(true),
        _ => None,
    }
}

pub async fn run(interface: Option<&str>, progress: Progress) -> Result<Diagnosis> {
    let mut checks = Vec::new();
    progress("Checking this computer's connection", 0.02);
    let info = netinfo::detect(interface, None);

    // 1. Local link.
    let info = match info {
        Ok(info) => info,
        Err(e) => {
            checks.push(Check {
                id: "local".into(),
                layer: "This computer".into(),
                title: "Network connection".into(),
                status: Status::Fail,
                detail: format!("{e:#}"),
                advice: Some(
                    "Check that Wi-Fi is turned on and connected, or that the network cable is plugged in.".into(),
                ),
                latency: None,
            });
            return Ok(conclude(checks, Vec::new(), None));
        }
    };
    let mut local = Check {
        id: "local".into(),
        layer: "This computer".into(),
        title: "Network connection".into(),
        status: Status::Pass,
        detail: format!(
            "Connected via {} with address {}{}",
            info.interface_label.clone().unwrap_or_else(|| info.interface.clone()),
            info.ip,
            info.link_speed_mbps.map(|s| format!(", link speed {s} Mbps")).unwrap_or_default()
        ),
        advice: None,
        latency: None,
    };
    if info.ip.is_link_local() {
        local.status = Status::Fail;
        local.detail = format!("Your address {} means the router never gave this computer an address.", info.ip);
        local.advice = Some("Turn Wi-Fi off and on again, or restart the router.".into());
    } else if info.gateway.is_none() {
        local.status = Status::Fail;
        local.detail = "This computer has no default gateway, so it doesn't know how to reach the internet.".into();
        local.advice = Some(
            "Reconnect to the network. If you set a manual IP address, add the router's address as gateway.".into(),
        );
    } else if let Some(speed) = info.link_speed_mbps.filter(|s| *s < 50) {
        local.status = Status::Warn;
        local.detail.push_str(&format!(". {speed} Mbps is a slow link"));
        local.advice = Some(if info.wireless {
            "Your Wi-Fi link is slow, usually because of distance or walls. Move closer to the router, use the 5 GHz network, or add a mesh point.".into()
        } else {
            "The cable link negotiated a low speed. Try a different cable or port (look for Cat5e or better).".into()
        });
    } else if info.mtu.is_some_and(|m| m < 1400) {
        local.status = Status::Warn;
        local.detail.push_str(&format!(". MTU is unusually low ({})", info.mtu.unwrap_or_default()));
        local.advice = Some(
            "A low MTU often comes from a VPN. If you're not using one, reset the network adapter settings.".into(),
        );
    }
    let local_failed = local.status == Status::Fail;
    checks.push(local);
    if local_failed {
        return Ok(conclude(checks, Vec::new(), Some(info)));
    }

    // 2. Router, internet and DNS run together to keep the doctor quick.
    progress("Measuring your router, internet and DNS", 0.1);
    let gateway = info.gateway.expect("checked above");
    let router =
        async {
            let series =
                match tcp_series(gateway, &[80, 443, 53, 22, 8080, 8443, 5000, 49152], 20, Duration::from_millis(100))
                    .await
                {
                    Some(s) => Some(s),
                    None => ping_series(gateway, 20, Duration::from_millis(100)).await,
                };
            series.and_then(|s| Latency::from_samples(&s))
        };
    let internet = async {
        let futs = INTERNET_TARGETS.iter().map(|(ip, label)| async move {
            let s = tcp_series(*ip, &[443, 53, 80], 10, Duration::from_millis(150)).await;
            (*label, s.and_then(|s| Latency::from_samples(&s)))
        });
        probe::futures_join_all(futs).await
    };
    let mut dns_servers: Vec<(IpAddr, String, bool)> = Vec::new();
    for s in &info.dns_servers {
        if !dns_servers.iter().any(|(ip, _, _)| ip == s) {
            let label = if Some(*s) == info.gateway.map(IpAddr::V4) {
                "Your router".to_string()
            } else {
                PUBLIC_DNS
                    .iter()
                    .find(|(ip, _)| IpAddr::V4(*ip) == *s)
                    .map_or_else(|| "Your current DNS".to_string(), |(_, l)| l.to_string())
            };
            dns_servers.push((*s, label, true));
        }
    }
    for (ip, label) in PUBLIC_DNS {
        if !dns_servers.iter().any(|(s, _, _)| *s == IpAddr::V4(*ip)) {
            dns_servers.push((IpAddr::V4(*ip), label.to_string(), false));
        }
    }
    let dns_bench = probe::futures_join_all(dns_servers.iter().map(|(ip, label, configured)| async move {
        let (median_ms, failures, queries) = bench_dns(*ip).await;
        DnsResult { server: *ip, label: label.clone(), configured: *configured, median_ms, failures, queries }
    }));
    let wireless = info.wireless;
    let wifi_read = async { if wireless { wifi::read().await } else { None } };
    let (router, internet, dns_results, portal, wifi_info) =
        tokio::join!(router, internet, dns_bench, captive_portal(), wifi_read);
    progress("Putting it together", 0.95);

    // Router verdict.
    let mut rc = Check {
        id: "router".into(),
        layer: "Router".into(),
        title: format!("Connection to your router ({gateway})"),
        status: Status::Pass,
        detail: String::new(),
        advice: None,
        latency: router.clone(),
    };
    match &router {
        None => {
            rc.status = Status::Skip;
            rc.detail =
                "The router didn't answer our probes. Some routers ignore them, so this isn't necessarily a problem."
                    .into();
        }
        Some(l) if l.loss_pct >= 20.0 => {
            rc.status = Status::Fail;
            rc.detail = format!("{}% of messages to the router were lost.", l.loss_pct);
            rc.advice = Some(wifi_advice(info.wireless));
        }
        Some(l) if l.loss_pct > 2.0 || l.avg_ms > 30.0 || l.jitter_ms > 20.0 => {
            rc.status = Status::Warn;
            rc.detail = format!(
                "Average {} ms, jitter {} ms, {}% loss. A healthy home network is under 10 ms with no loss.",
                l.avg_ms, l.jitter_ms, l.loss_pct
            );
            rc.advice = Some(wifi_advice(info.wireless));
        }
        Some(l) => {
            rc.detail = format!("Average {} ms with {}% loss: healthy.", l.avg_ms, l.loss_pct);
        }
    }
    let router_avg = router.as_ref().filter(|l| l.received > 0).map(|l| l.avg_ms);
    if let Some(w) = &wifi_info {
        checks.push(wifi_check(w, matches!(rc.status, Status::Warn | Status::Fail)));
    }
    checks.push(rc);

    // Internet verdict: use the best-performing target.
    let best = internet
        .iter()
        .filter_map(|(label, l)| l.as_ref().filter(|l| l.received > 0).map(|l| (*label, l.clone())))
        .min_by(|a, b| a.1.avg_ms.partial_cmp(&b.1.avg_ms).unwrap_or(std::cmp::Ordering::Equal));
    let mut ic = Check {
        id: "internet".into(),
        layer: "Internet provider".into(),
        title: "Connection to the internet".into(),
        status: Status::Pass,
        detail: String::new(),
        advice: None,
        latency: best.as_ref().map(|b| b.1.clone()),
    };
    match &best {
        None => {
            ic.status = Status::Fail;
            ic.detail = "None of Cloudflare, Google or Quad9 could be reached.".into();
            ic.advice = Some(if portal == Some(true) {
                "This network wants you to sign in first. Open a browser and visit any website to get the sign-in page."
                    .into()
            } else {
                "Your router is reachable but the internet isn't. Restart the modem and router (unplug both for 30 seconds), and check your provider's outage page.".into()
            });
        }
        Some((label, l)) => {
            let isp = router_avg.map(|r| ((l.avg_ms - r).max(0.0) * 10.0).round() / 10.0);
            let isp_part = isp.map(|ms| format!(" (about {ms} ms of that is beyond your router)")).unwrap_or_default();
            if l.loss_pct > 2.0 || l.avg_ms > 100.0 || l.jitter_ms > 30.0 {
                ic.status = Status::Warn;
                ic.detail = format!(
                    "{label}: average {} ms{isp_part}, jitter {} ms, {}% loss.",
                    l.avg_ms, l.jitter_ms, l.loss_pct
                );
                ic.advice = Some("The delay is being added after your router. Restart the modem; if it keeps happening at the same times of day, your provider's network is congested. Note the times and contact them.".into());
            } else {
                ic.detail = format!("{label}: average {} ms{isp_part} with {}% loss: healthy.", l.avg_ms, l.loss_pct);
            }
        }
    }
    checks.push(ic);

    if portal == Some(true) {
        checks.push(Check {
            id: "captive".into(),
            layer: "Internet provider".into(),
            title: "Sign-in page".into(),
            status: Status::Fail,
            detail: "Web requests are being redirected, which means this network needs you to sign in or accept terms."
                .into(),
            advice: Some("Open a browser and visit any website to see the sign-in page.".into()),
            latency: None,
        });
    }

    // DNS verdict.
    let configured: Vec<&DnsResult> = dns_results.iter().filter(|d| d.configured).collect();
    let fastest = dns_results
        .iter()
        .filter(|d| d.failures < d.queries / 2 + 1)
        .filter_map(|d| d.median_ms.map(|m| (d, m)))
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let current = configured
        .iter()
        .filter_map(|d| d.median_ms.map(|m| (*d, m)))
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut dc = Check {
        id: "dns".into(),
        layer: "DNS".into(),
        title: "Looking up website names (DNS)".into(),
        status: Status::Pass,
        detail: String::new(),
        advice: None,
        latency: None,
    };
    match current {
        None if configured.is_empty() => {
            dc.status = Status::Skip;
            dc.detail = "Couldn't tell which DNS server this computer uses.".into();
        }
        None => {
            dc.status = Status::Fail;
            dc.detail = "Your DNS server didn't answer. Websites won't load even though the connection works.".into();
            dc.advice = Some(match fastest {
                Some((f, _)) => format!("Set your DNS to {} ({}) on this computer or the router.", f.label, f.server),
                None => "Restart the router; it usually provides DNS.".into(),
            });
        }
        Some((cur, ms)) => {
            let failures: u32 = configured.iter().map(|d| d.failures).sum();
            dc.detail = format!("{} answers in about {ms} ms.", cur.label);
            if ms > 150.0 || failures > 1 {
                dc.status = Status::Warn;
                dc.detail.push_str(" That's slow, so every new website takes longer to start loading.");
            }
            if let Some((f, fms)) = fastest.filter(|(f, fms)| !f.configured && ms - fms >= 20.0 && *fms < ms * 0.7) {
                dc.advice = Some(format!(
                    "{} ({}) answered in {fms} ms, about {} ms faster. You can switch to it in your router's or computer's DNS settings.",
                    f.label,
                    f.server,
                    ((ms - fms) * 10.0).round() / 10.0
                ));
            }
        }
    }
    checks.push(dc);

    let mut diagnosis = conclude(checks, dns_results, Some(info));
    diagnosis.wifi = wifi_info;
    Ok(diagnosis)
}

/// Judges the Wi-Fi link. Crowding and a so-so signal only count as the
/// problem when the router connection is actually struggling.
pub fn wifi_check(w: &WifiInfo, router_trouble: bool) -> Check {
    let quality = w.quality();
    let crowd = w.crowding();
    let crowded = if w.is_2ghz() { crowd >= 5 } else { crowd >= 3 };

    let mut detail = match &w.ssid {
        Some(ssid) => format!("Connected to \"{ssid}\""),
        None => "Connected".to_string(),
    };
    if let Some(c) = w.channel {
        detail.push_str(&format!(" on channel {c}"));
        if let Some(b) = &w.band {
            detail.push_str(&format!(" ({b})"));
        }
    }
    if let Some(q) = quality {
        let reading = match (w.rssi_dbm, w.signal_percent) {
            (Some(dbm), _) => format!("{dbm} dBm"),
            (None, Some(p)) => format!("{p}%"),
            _ => String::new(),
        };
        detail.push_str(&format!(", signal {} ({reading})", q.label()));
    }
    if let Some(r) = w.rate_mbps {
        detail.push_str(&format!(", link speed {r} Mbps"));
    }
    detail.push('.');
    if crowd > 0 {
        detail.push_str(&format!(
            " {crowd} other network{} nearby use{} the same or an overlapping channel.",
            if crowd == 1 { "" } else { "s" },
            if crowd == 1 { "s" } else { "" }
        ));
    }

    let channel_tip = match w.best_2ghz_channel() {
        Some((best, busy)) if Some(best) != w.channel => format!(
            "In your router's Wi-Fi settings, switch the 2.4 GHz channel to {best} (only {busy} nearby network{} use{} it), or connect to the router's 5 GHz network, which has far more room.",
            if busy == 1 { "" } else { "s" },
            if busy == 1 { "s" } else { "" }
        ),
        Some(_) => {
            "Connect to your router's 5 GHz network if it has one; it has far more room than 2.4 GHz.".to_string()
        }
        None => {
            "Set your router's 5 GHz channel to Auto, or pick a different one, so it moves away from the neighbours."
                .to_string()
        }
    };

    let (status, title, mut advice) = match quality {
        Some(Quality::Weak) => (
            Status::Warn,
            "Your Wi-Fi signal is weak".to_string(),
            Some(if w.is_2ghz() {
                "Move closer to the router or put fewer walls between you. If this spot matters (a desk, the TV), a mesh point or a cable fixes it for good.".to_string()
            } else {
                "5 GHz is fast but doesn't reach far. Move closer to the router, or try the 2.4 GHz network here, which reaches further. A mesh point fixes weak spots for good.".to_string()
            }),
        ),
        _ if crowded && router_trouble => (Status::Warn, "Your Wi-Fi channel is crowded".to_string(), Some(channel_tip)),
        Some(Quality::Fair) if router_trouble => (
            Status::Warn,
            "Your Wi-Fi signal could be stronger".to_string(),
            Some("Moving closer to the router, or raising it off the floor and away from metal and fish tanks, usually helps.".to_string()),
        ),
        _ => (Status::Pass, "Wi-Fi signal".to_string(), crowded.then(|| format!("Tip: the airwaves are busy here. {channel_tip}"))),
    };

    // Security doesn't slow you down, so it never decides the verdict, but say it.
    let security_note = match w.security_risk() {
        Some(SecurityRisk::Open) => Some(
            "This Wi-Fi has no password: anyone nearby can join and watch unencrypted traffic. On your own network, turn on WPA2 or WPA3 in the router; elsewhere, use a VPN.",
        ),
        Some(SecurityRisk::Outdated) => Some(
            "This Wi-Fi uses outdated security (WEP or WPA1) that can be cracked in minutes. Switch the router to WPA2 or WPA3.",
        ),
        None => None,
    };
    if let Some(note) = security_note {
        advice = Some(match advice {
            Some(a) => format!("{a} {note}"),
            None => note.to_string(),
        });
    }
    Check { id: "wifi".into(), layer: "Wi-Fi".into(), title, status, detail, advice, latency: None }
}

fn wifi_advice(wireless: bool) -> String {
    if wireless {
        "The problem is between this device and the router, which usually means weak Wi-Fi or interference. Move closer to the router, switch to the 5 GHz network, restart the router, or use a cable for things that matter.".into()
    } else {
        "The problem is between this computer and the router. Try another cable or router port, and restart the router."
            .into()
    }
}

/// Picks the innermost failing layer as the headline: a weak Wi-Fi link makes
/// everything beyond it look bad too.
fn conclude(checks: Vec<Check>, dns: Vec<DnsResult>, network: Option<NetworkInfo>) -> Diagnosis {
    let worst = checks.iter().map(|c| c.status).max().unwrap_or(Status::Pass);
    let culprit =
        checks.iter().find(|c| c.status == Status::Fail).or_else(|| checks.iter().find(|c| c.status == Status::Warn));
    let (headline, summary) = match culprit {
        None => (
            "Everything looks healthy".to_string(),
            "Your connection, router, internet provider and DNS all responded quickly. If something still feels slow, it's likely the specific website or app, or your plan's bandwidth.".to_string(),
        ),
        Some(c) => {
            let headline = match (c.id.as_str(), c.status) {
                ("wifi", _) => c.title.as_str(),
                ("local", _) => "This computer isn't properly connected",
                ("router", Status::Fail) => "The connection to your router is failing",
                ("router", _) => "Your Wi-Fi or local network is the weak spot",
                ("captive", _) => "This network needs you to sign in",
                ("internet", Status::Fail) => "Your internet connection is down",
                ("internet", _) => "Your internet provider's connection is slow",
                ("dns", Status::Fail) => "Website names aren't being looked up",
                ("dns", _) => "Website lookups (DNS) are slow",
                _ => "Something needs attention",
            };
            (headline.to_string(), c.advice.clone().unwrap_or_else(|| c.detail.clone()))
        }
    };
    Diagnosis { at: Utc::now(), status: worst, headline, summary, checks, dns, network, wifi: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_stats() {
        let l = Latency::from_samples(&[Some(2.0), Some(4.0), None, Some(3.0)]).unwrap();
        assert_eq!(l.sent, 4);
        assert_eq!(l.received, 3);
        assert_eq!(l.loss_pct, 25.0);
        assert_eq!(l.min_ms, 2.0);
        assert_eq!(l.max_ms, 4.0);
        assert_eq!(l.avg_ms, 3.0);
        assert_eq!(l.jitter_ms, 1.5);
        let dead = Latency::from_samples(&[None, None]).unwrap();
        assert_eq!(dead.loss_pct, 100.0);
    }

    fn check(id: &str, status: Status) -> Check {
        Check {
            id: id.into(),
            layer: String::new(),
            title: String::new(),
            status,
            detail: "d".into(),
            advice: Some(format!("fix {id}")),
            latency: None,
        }
    }

    #[test]
    fn judges_wifi() {
        let base = WifiInfo {
            ssid: Some("Home".into()),
            rssi_dbm: Some(-58),
            channel: Some(6),
            band: Some("2.4 GHz".into()),
            security: Some("WPA2".into()),
            ..Default::default()
        };
        assert_eq!(wifi_check(&base, false).status, Status::Pass);

        let weak = WifiInfo { rssi_dbm: Some(-80), ..base.clone() };
        let c = wifi_check(&weak, false);
        assert_eq!(c.status, Status::Warn);
        assert_eq!(c.title, "Your Wi-Fi signal is weak");

        let neighbours =
            (0..6).map(|i| wifi::Neighbor { ssid: Some(format!("n{i}")), channel: 6, signal_percent: None });
        let mut busy = WifiInfo { neighbors: neighbours.collect(), ..base.clone() };
        busy.neighbors.push(wifi::Neighbor { ssid: Some("far".into()), channel: 1, signal_percent: None });
        // Crowded but working fine: just a tip.
        let c = wifi_check(&busy, false);
        assert_eq!(c.status, Status::Pass);
        assert!(c.advice.as_deref().unwrap().contains("channel to 11"));
        // Crowded and the router link is struggling: that's the culprit.
        let c = wifi_check(&busy, true);
        assert_eq!(c.status, Status::Warn);
        let d = conclude(vec![check("local", Status::Pass), c, check("router", Status::Warn)], vec![], None);
        assert_eq!(d.headline, "Your Wi-Fi channel is crowded");

        let open = WifiInfo { security: Some("--".into()), ..base };
        let c = wifi_check(&open, false);
        assert_eq!(c.status, Status::Pass, "security never decides the speed verdict");
        assert!(c.advice.unwrap().contains("no password"));
    }

    #[test]
    fn innermost_problem_wins() {
        let d = conclude(
            vec![check("local", Status::Pass), check("router", Status::Warn), check("internet", Status::Fail)],
            vec![],
            None,
        );
        assert_eq!(d.headline, "Your internet connection is down");
        let d = conclude(
            vec![check("local", Status::Pass), check("router", Status::Warn), check("internet", Status::Warn)],
            vec![],
            None,
        );
        assert_eq!(d.headline, "Your Wi-Fi or local network is the weak spot");
        assert_eq!(d.summary, "fix router");
        let d = conclude(vec![check("local", Status::Pass), check("router", Status::Skip)], vec![], None);
        assert_eq!(d.headline, "Everything looks healthy");
    }
}
