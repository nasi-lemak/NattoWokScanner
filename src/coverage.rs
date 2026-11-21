//! Wi-Fi coverage walk: carry the laptop from room to room, measure in
//! each, and get a room-by-room picture with advice on where a mesh point
//! would help or what to move.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::netinfo;
use crate::probe::{self, TcpState};
use crate::wifi::{self, Quality, WifiInfo};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Spot {
    pub room: String,
    pub at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rssi_dbm: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality: Option<Quality>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub band: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<u32>,
    /// Which access point it was connected to (mesh unit), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_mbps: Option<u32>,
    /// Median time for a message to reach the router and back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_pct: Option<f64>,
    /// The reading this one replaced, to show what changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<Box<Spot>>,
}

impl Spot {
    /// 0–100 for comparing rooms and drawing bars: the percentage when the
    /// OS gives one, otherwise dBm mapped from -90 (0) to -30 (100).
    pub fn strength(&self) -> Option<u8> {
        self.signal_percent
            .or_else(|| self.rssi_dbm.map(|d| ((f64::from(d) + 90.0) / 60.0 * 100.0).clamp(0.0, 100.0) as u8))
    }

    /// "-56 dBm" or "72%".
    pub fn reading(&self) -> String {
        match (self.rssi_dbm, self.signal_percent) {
            (Some(d), _) => format!("{d} dBm"),
            (None, Some(p)) => format!("{p}%"),
            _ => "?".into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Survey {
    pub spots: Vec<Spot>,
}

fn path(dir: &Path) -> PathBuf {
    dir.join("coverage.json")
}

impl Survey {
    pub fn load(dir: &Path) -> Survey {
        std::fs::read_to_string(path(dir)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(path(dir), serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    /// Adds a reading, replacing an earlier one for the same room (kept as
    /// `previous` so improvements show).
    pub fn record(&mut self, mut spot: Spot) {
        if let Some(i) = self.spots.iter().position(|s| s.room.eq_ignore_ascii_case(&spot.room)) {
            let mut old = self.spots.remove(i);
            old.previous = None;
            spot.previous = Some(Box::new(old));
            self.spots.insert(i, spot);
        } else {
            self.spots.push(spot);
        }
    }

    pub fn remove(&mut self, room: &str) -> bool {
        let before = self.spots.len();
        self.spots.retain(|s| !s.room.eq_ignore_ascii_case(room));
        self.spots.len() != before
    }
}

async fn router_series(gateway: Ipv4Addr) -> (Option<f64>, Option<f64>) {
    let timeout = Duration::from_millis(800);
    let mut port = None;
    for p in [80, 443, 53] {
        if probe::tcp_probe(SocketAddr::from((gateway, p)), timeout).await.0 != TcpState::Silent {
            port = Some(p);
            break;
        }
    }
    let mut samples = Vec::new();
    for _ in 0..10 {
        let rtt = match port {
            Some(p) => {
                let (state, rtt) = probe::tcp_probe(SocketAddr::from((gateway, p)), timeout).await;
                (state != TcpState::Silent).then_some(rtt.as_secs_f64() * 1000.0)
            }
            None => probe::system_ping(gateway, timeout).await,
        };
        samples.push(rtt);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if port.is_none() && samples.iter().all(Option::is_none) {
        return (None, None);
    }
    let mut got: Vec<f64> = samples.iter().flatten().copied().collect();
    got.sort_by(f64::total_cmp);
    let loss = 100.0 * (samples.len() - got.len()) as f64 / samples.len() as f64;
    let median = got.get(got.len() / 2).map(|m| (m * 10.0).round() / 10.0);
    (median, Some(loss.round()))
}

/// Measures Wi-Fi here: a few signal readings averaged, plus how reliably
/// messages reach the router.
pub async fn measure(room: &str, interface: Option<&str>) -> Result<Spot> {
    let room = room.trim();
    if room.is_empty() {
        bail!("give the room a name, e.g. \"Kitchen\"");
    }
    let info = netinfo::detect(interface, None)?;
    if !info.wireless {
        bail!("this computer isn't on Wi-Fi ({}); connect over Wi-Fi to measure coverage", info.interface);
    }
    let router = async {
        match info.gateway {
            Some(gw) => router_series(gw).await,
            None => (None, None),
        }
    };
    let readings = async {
        let mut out: Vec<WifiInfo> = Vec::new();
        for i in 0..3 {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(900)).await;
            }
            if let Some(w) = wifi::read().await {
                out.push(w);
            }
        }
        out
    };
    let ((router_ms, loss_pct), readings) = tokio::join!(router, readings);
    let Some(last) = readings.last().cloned() else {
        bail!("couldn't read the Wi-Fi signal (is Wi-Fi connected?)");
    };
    let avg = |f: fn(&WifiInfo) -> Option<f64>| {
        let v: Vec<f64> = readings.iter().filter_map(f).collect();
        (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64)
    };
    let rssi_dbm = avg(|w| w.rssi_dbm.map(f64::from)).map(|x| x.round() as i32);
    let signal_percent = avg(|w| w.signal_percent.map(f64::from)).map(|x| x.round() as u8);
    let quality = WifiInfo { rssi_dbm, signal_percent, ..Default::default() }.quality();
    Ok(Spot {
        room: room.to_string(),
        at: Utc::now(),
        signal_percent,
        rssi_dbm,
        quality,
        band: last.band,
        channel: last.channel,
        bssid: last.bssid,
        rate_mbps: last.rate_mbps,
        router_ms,
        loss_pct,
        previous: None,
    })
}

fn names(spots: &[&Spot]) -> String {
    let n: Vec<&str> = spots.iter().map(|s| s.room.as_str()).collect();
    match n.len() {
        0 => String::new(),
        1 => n[0].to_string(),
        _ => format!("{} and {}", n[..n.len() - 1].join(", "), n[n.len() - 1]),
    }
}

/// A one-line summary and plain advice for the rooms measured so far.
pub fn advise(survey: &Survey) -> (String, Vec<String>) {
    let spots: Vec<&Spot> = survey.spots.iter().collect();
    if spots.is_empty() {
        return (
            "No rooms measured yet".into(),
            vec!["Start next to the router, then measure in the rooms where Wi-Fi is a problem.".into()],
        );
    }
    let weak: Vec<&Spot> = spots.iter().copied().filter(|s| s.quality == Some(Quality::Weak)).collect();
    let fair: Vec<&Spot> = spots.iter().copied().filter(|s| s.quality == Some(Quality::Fair)).collect();
    let strong: Vec<&Spot> =
        spots.iter().copied().filter(|s| matches!(s.quality, Some(Quality::Good | Quality::Excellent))).collect();
    let mut advice = Vec::new();

    let headline = match (weak.len(), fair.len()) {
        (0, 0) if spots.len() == 1 => format!("Good Wi-Fi in {}", spots[0].room),
        (0, 0) => format!("Good Wi-Fi in all {} rooms measured", spots.len()),
        (0, _) => format!("Fair in {}, good elsewhere", names(&fair)),
        _ => format!("Weak Wi-Fi in {}", names(&weak)),
    };

    if !weak.is_empty() && !strong.is_empty() {
        let middle = if fair.is_empty() {
            "where the signal is still good".to_string()
        } else {
            format!("where the signal is still decent (such as {})", names(&fair))
        };
        advice.push(format!(
            "A mesh point or extender about halfway between the router and {}, {middle}, would cover {}. Placed in the weak room itself, it would only repeat a weak signal.",
            names(&weak),
            if weak.len() == 1 { "it" } else { "them" }
        ));
    } else if strong.is_empty() && spots.len() > 1 {
        advice.push(
            "The signal isn't good anywhere you measured. Move the router somewhere central and high, out of cupboards, and away from TVs, microwaves, mirrors and fish tanks. If it's provided by your internet company and stuck in a corner, a mesh system fixes this best.".into(),
        );
    }

    for s in &weak {
        if s.band.as_deref().is_some_and(|b| b.starts_with('5') || b.starts_with('6')) {
            advice.push(format!(
                "In {} this computer used {}, which is faster but doesn't get through walls as well. 2.4 GHz reaches further, at lower speed; if your router has separate names for the two, try the 2.4 GHz one there.",
                s.room,
                s.band.as_deref().unwrap_or_default()
            ));
        }
    }

    for s in &spots {
        let good_signal = matches!(s.quality, Some(Quality::Good | Quality::Excellent | Quality::Fair));
        if good_signal && s.loss_pct.is_some_and(|l| l >= 10.0) {
            advice.push(format!(
                "{} has a usable signal but {}% of messages to the router were lost. That points to interference or a crowded channel rather than distance: see the Wi-Fi advice in the Internet doctor.",
                s.room,
                s.loss_pct.unwrap_or_default()
            ));
        } else if good_signal && s.router_ms.is_some_and(|ms| ms >= 30.0) {
            advice.push(format!(
                "{} has a usable signal but the router took {} ms to answer, which is slow for Wi-Fi. Usually interference or a busy network.",
                s.room,
                s.router_ms.unwrap_or_default()
            ));
        }
    }

    // Mesh: a weak room still on the same unit as the strongest room.
    let mut bssids: Vec<&str> = spots.iter().filter_map(|s| s.bssid.as_deref()).collect();
    bssids.sort_unstable();
    bssids.dedup();
    if bssids.len() >= 2
        && let Some(best) = spots.iter().max_by_key(|s| s.strength())
    {
        let sticky: Vec<&Spot> = weak
            .iter()
            .copied()
            .filter(|s| s.bssid.is_some() && s.bssid == best.bssid && s.room != best.room)
            .collect();
        if !sticky.is_empty() {
            advice.push(format!(
                "You have {} access points, but in {} this computer stayed connected to the same one as in {}. Devices sometimes cling to a far unit: turning Wi-Fi off and on in that room makes it pick the nearest.",
                bssids.len(),
                names(&sticky),
                best.room
            ));
        }
    }

    for s in &spots {
        if let (Some(prev), Some(now)) = (s.previous.as_ref().and_then(|p| p.strength()), s.strength()) {
            let diff = i32::from(now) - i32::from(prev);
            if diff.abs() >= 10 {
                advice.push(format!(
                    "{}: {} than before ({} → {}).",
                    s.room,
                    if diff > 0 { "stronger" } else { "weaker" },
                    s.previous.as_ref().map(|p| p.reading()).unwrap_or_default(),
                    s.reading()
                ));
            }
        }
    }
    (headline, advice)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spot(room: &str, rssi: i32, band: &str, bssid: &str) -> Spot {
        Spot {
            room: room.into(),
            at: Utc::now(),
            signal_percent: None,
            rssi_dbm: Some(rssi),
            quality: WifiInfo { rssi_dbm: Some(rssi), ..Default::default() }.quality(),
            band: Some(band.into()),
            channel: None,
            bssid: Some(bssid.into()),
            rate_mbps: None,
            router_ms: Some(4.0),
            loss_pct: Some(0.0),
            previous: None,
        }
    }

    #[test]
    fn advises_a_mesh_point_halfway() {
        let mut s = Survey::default();
        s.record(spot("Living room", -48, "5 GHz", "AA"));
        s.record(spot("Hallway", -70, "5 GHz", "AA"));
        s.record(spot("Bedroom", -82, "5 GHz", "AA"));
        let (headline, advice) = advise(&s);
        assert_eq!(headline, "Weak Wi-Fi in Bedroom");
        assert!(advice[0].contains("halfway between the router and Bedroom"), "{advice:?}");
        assert!(advice[0].contains("such as Hallway"));
        assert!(advice.iter().any(|a| a.contains("2.4 GHz reaches further")));
    }

    #[test]
    fn spots_sticky_mesh_and_interference() {
        let mut s = Survey::default();
        s.record(spot("Office", -45, "5 GHz", "AA"));
        s.record(spot("Garden room", -80, "2.4 GHz", "AA"));
        s.record(spot("Upstairs", -55, "5 GHz", "BB"));
        let mut kitchen = spot("Kitchen", -55, "2.4 GHz", "BB");
        kitchen.loss_pct = Some(20.0);
        s.record(kitchen);
        let (_, advice) = advise(&s);
        assert!(
            advice
                .iter()
                .any(|a| a.contains("in Garden room this computer stayed connected to the same one as in Office")),
            "{advice:?}"
        );
        assert!(advice.iter().any(|a| a.starts_with("Kitchen has a usable signal but 20% of messages")));
    }

    #[test]
    fn remembers_the_previous_reading() {
        let mut s = Survey::default();
        s.record(spot("Bedroom", -82, "2.4 GHz", "AA"));
        s.record(spot("bedroom", -60, "2.4 GHz", "BB"));
        assert_eq!(s.spots.len(), 1);
        assert_eq!(s.spots[0].previous.as_ref().unwrap().rssi_dbm, Some(-82));
        let (headline, advice) = advise(&s);
        assert_eq!(headline, "Good Wi-Fi in bedroom");
        assert!(advice.iter().any(|a| a == "bedroom: stronger than before (-82 dBm → -60 dBm)."), "{advice:?}");
        assert!(s.remove("BEDROOM"));
        assert_eq!(advise(&s).0, "No rooms measured yet");
    }

    #[test]
    fn maps_dbm_to_a_bar() {
        let mut s = spot("x", -60, "5 GHz", "AA");
        assert_eq!(s.strength(), Some(50));
        s.signal_percent = Some(80);
        assert_eq!(s.strength(), Some(80));
    }
}
