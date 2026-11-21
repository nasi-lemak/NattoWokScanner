//! Wi-Fi link details: signal strength, channel, how crowded the airwaves
//! are, and the security in use. Read with tools each OS already ships:
//! `nmcli` (Linux), `system_profiler` (macOS), `netsh` (Windows).

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Neighbor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    pub channel: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_percent: Option<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct WifiInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rssi_dbm: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub band: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// The access point (radio) this computer is connected to; on mesh
    /// systems, which unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    /// Other networks within range.
    #[serde(default)]
    pub neighbors: Vec<Neighbor>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Quality {
    Weak,
    Fair,
    Good,
    Excellent,
}

impl Quality {
    pub fn label(self) -> &'static str {
        match self {
            Quality::Weak => "weak",
            Quality::Fair => "fair",
            Quality::Good => "good",
            Quality::Excellent => "excellent",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityRisk {
    /// No password at all.
    Open,
    /// WEP or WPA1/TKIP: crackable in minutes.
    Outdated,
}

fn band_for_channel(channel: u32) -> &'static str {
    if channel <= 14 { "2.4 GHz" } else { "5 GHz" }
}

fn band_for_mhz(mhz: u32) -> Option<&'static str> {
    match mhz {
        2400..=2500 => Some("2.4 GHz"),
        4900..=5900 => Some("5 GHz"),
        5925..=7125 => Some("6 GHz"),
        _ => None,
    }
}

impl WifiInfo {
    pub fn connected(&self) -> bool {
        self.ssid.is_some() || self.rssi_dbm.is_some() || self.signal_percent.is_some()
    }

    pub fn quality(&self) -> Option<Quality> {
        if let Some(dbm) = self.rssi_dbm {
            return Some(match dbm {
                d if d >= -60 => Quality::Excellent,
                d if d >= -67 => Quality::Good,
                d if d >= -75 => Quality::Fair,
                _ => Quality::Weak,
            });
        }
        self.signal_percent.map(|p| match p {
            80.. => Quality::Excellent,
            60..80 => Quality::Good,
            40..60 => Quality::Fair,
            _ => Quality::Weak,
        })
    }

    pub fn is_2ghz(&self) -> bool {
        self.band.as_deref() == Some("2.4 GHz") || (self.band.is_none() && self.channel.is_some_and(|c| c <= 14))
    }

    /// Other networks sharing (or overlapping) our channel. On 2.4 GHz,
    /// channels closer than 5 apart interfere. Our own access points (same
    /// network name) don't count.
    pub fn crowding(&self) -> usize {
        let Some(ch) = self.channel else { return 0 };
        self.neighbors
            .iter()
            .filter(|n| self.ssid.is_none() || n.ssid != self.ssid)
            .filter(|n| if self.is_2ghz() { n.channel <= 14 && n.channel.abs_diff(ch) < 5 } else { n.channel == ch })
            .count()
    }

    /// The least crowded of the non-overlapping 2.4 GHz channels.
    pub fn best_2ghz_channel(&self) -> Option<(u32, usize)> {
        if !self.is_2ghz() {
            return None;
        }
        [1u32, 6, 11]
            .into_iter()
            .map(|c| {
                let busy = self
                    .neighbors
                    .iter()
                    .filter(|n| n.ssid != self.ssid && n.channel <= 14 && n.channel.abs_diff(c) < 5)
                    .count();
                (c, busy)
            })
            .min_by_key(|(_, busy)| *busy)
    }

    pub fn security_risk(&self) -> Option<SecurityRisk> {
        let s = self.security.as_deref()?.to_ascii_lowercase();
        if s.is_empty() || s == "--" || s.contains("open") || s.contains("none") {
            Some(SecurityRisk::Open)
        } else if s.contains("wep")
            || s.contains("tkip")
            || ((s.contains("wpa1") || s.contains("wpa ") || s == "wpa" || s.contains("wpa-personal"))
                && !s.contains("wpa2")
                && !s.contains("wpa3"))
        {
            Some(SecurityRisk::Outdated)
        } else {
            None
        }
    }
}

async fn output(program: &str, args: &[&str]) -> Option<String> {
    let fut = tokio::process::Command::new(program).args(args).kill_on_drop(true).output();
    let out = tokio::time::timeout(Duration::from_secs(10), fut).await.ok()?.ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Reads the current Wi-Fi connection, if there is one.
pub async fn read() -> Option<WifiInfo> {
    let info = if cfg!(target_os = "macos") {
        parse_system_profiler(&output("system_profiler", &["SPAirPortDataType", "-json"]).await?)
    } else if cfg!(windows) {
        let mut info = parse_netsh_interfaces(&output("netsh", &["wlan", "show", "interfaces"]).await?)?;
        if let Some(networks) = output("netsh", &["wlan", "show", "networks", "mode=bssid"]).await {
            info.neighbors = parse_netsh_networks(&networks);
        }
        Some(info)
    } else {
        let fields = "ACTIVE,SSID,SIGNAL,CHAN,FREQ,RATE,SECURITY,BSSID";
        let mut info =
            parse_nmcli(&output("nmcli", &["-t", "-f", fields, "device", "wifi", "list", "--rescan", "no"]).await?);
        // nmcli's signal comes from the last scan; the kernel's is live.
        if let (Some(i), Ok(text)) = (info.as_mut(), tokio::fs::read_to_string("/proc/net/wireless").await) {
            i.rssi_dbm = parse_proc_wireless(&text).or(i.rssi_dbm);
        }
        info
    };
    info.filter(WifiInfo::connected)
}

/// Signal level in dBm from `/proc/net/wireless` (first wireless interface).
pub fn parse_proc_wireless(text: &str) -> Option<i32> {
    text.lines().skip(2).find_map(|line| {
        let (_, rest) = line.split_once(':')?;
        let level: f64 = rest.split_whitespace().nth(2)?.trim_end_matches('.').parse().ok()?;
        // Drivers without dBm report 0 or a positive "quality" here.
        (level < 0.0 && level > -110.0).then_some(level.round() as i32)
    })
}

/// Splits nmcli's terse output, where `:` separates fields and `\:` is a literal colon.
fn nmcli_fields(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    fields.last_mut().expect("non-empty").push(next);
                }
            }
            ':' => fields.push(String::new()),
            _ => fields.last_mut().expect("non-empty").push(c),
        }
    }
    fields
}

fn leading_number(s: &str) -> Option<u32> {
    let digits: String = s.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

pub fn parse_nmcli(text: &str) -> Option<WifiInfo> {
    let mut info: Option<WifiInfo> = None;
    let mut neighbors = Vec::new();
    for line in text.lines() {
        let f = nmcli_fields(line);
        if f.len() < 7 {
            continue;
        }
        let ssid = Some(f[1].clone()).filter(|s| !s.is_empty());
        let signal = f[2].parse().ok();
        let channel = f[3].parse().ok();
        if f[0] == "yes" && info.is_none() {
            info = Some(WifiInfo {
                ssid,
                signal_percent: signal,
                rssi_dbm: None,
                channel,
                band: leading_number(&f[4])
                    .and_then(band_for_mhz)
                    .or(channel.map(band_for_channel))
                    .map(str::to_string),
                rate_mbps: leading_number(&f[5]),
                security: Some(f[6].clone()),
                bssid: f.get(7).filter(|b| !b.is_empty()).map(|b| b.to_ascii_uppercase()),
                neighbors: Vec::new(),
            });
        } else if let Some(channel) = channel {
            neighbors.push(Neighbor { ssid, channel, signal_percent: signal });
        }
    }
    info.map(|mut i| {
        i.neighbors = neighbors;
        i
    })
}

/// `"-55 dBm / -92 dBm"` -> -55.
fn dbm(value: &serde_json::Value) -> Option<i32> {
    let s = value.as_str()?;
    s.split_whitespace().next()?.parse().ok()
}

/// `"36 (5GHz, 80MHz)"` or `36` -> (36, Some("5 GHz")).
fn mac_channel(value: &serde_json::Value) -> Option<(u32, Option<String>)> {
    if let Some(n) = value.as_u64() {
        let c = u32::try_from(n).ok()?;
        return Some((c, Some(band_for_channel(c).to_string())));
    }
    let s = value.as_str()?;
    let c = leading_number(s)?;
    let band = if s.contains("6GHz") {
        "6 GHz"
    } else if s.contains("5GHz") {
        "5 GHz"
    } else if s.contains("2GHz") || s.contains("2.4GHz") {
        "2.4 GHz"
    } else {
        band_for_channel(c)
    };
    Some((c, Some(band.to_string())))
}

pub fn parse_system_profiler(json: &str) -> Option<WifiInfo> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let interfaces = v
        .get("SPAirPortDataType")?
        .as_array()?
        .iter()
        .filter_map(|e| e.get("spairport_airport_interfaces")?.as_array());
    for list in interfaces {
        for iface in list {
            let Some(cur) = iface.get("spairport_current_network_information") else { continue };
            let (channel, band) = cur.get("spairport_network_channel").and_then(mac_channel).unzip();
            let neighbors = iface
                .get("spairport_airport_other_local_wireless_networks")
                .and_then(|n| n.as_array())
                .map(|nets| {
                    nets.iter()
                        .filter_map(|n| {
                            let (channel, _) = n.get("spairport_network_channel").and_then(mac_channel)?;
                            Some(Neighbor {
                                ssid: n.get("_name").and_then(|s| s.as_str()).map(str::to_string),
                                channel,
                                signal_percent: None,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let security = cur.get("spairport_security_mode").and_then(|s| s.as_str()).map(|s| {
                s.trim_start_matches("spairport_security_mode_").replace('_', " ").replace("personal", "Personal")
            });
            return Some(WifiInfo {
                // Newer macOS hides the name unless the app has Location access.
                ssid: cur.get("_name").and_then(|s| s.as_str()).filter(|s| *s != "<redacted>").map(str::to_string),
                signal_percent: None,
                rssi_dbm: cur.get("spairport_signal_noise").and_then(dbm),
                channel,
                band: band.flatten(),
                rate_mbps: cur
                    .get("spairport_network_rate")
                    .and_then(|r| r.as_u64().or_else(|| r.as_str().and_then(leading_number).map(u64::from)))
                    .and_then(|r| u32::try_from(r).ok()),
                security,
                bssid: None,
                neighbors,
            });
        }
    }
    None
}

fn netsh_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let (k, v) = line.split_once(':')?;
    (k.trim() == key).then(|| v.trim())
}

pub fn parse_netsh_interfaces(text: &str) -> Option<WifiInfo> {
    let mut info = WifiInfo::default();
    let mut connected = false;
    for line in text.lines() {
        if let Some(state) = netsh_value(line, "State") {
            connected = state.eq_ignore_ascii_case("connected");
        } else if let Some(v) = netsh_value(line, "SSID") {
            info.ssid = Some(v.to_string()).filter(|s| !s.is_empty());
        } else if let Some(v) = netsh_value(line, "Signal") {
            info.signal_percent = leading_number(v).and_then(|p| u8::try_from(p).ok());
        } else if let Some(v) = netsh_value(line, "Channel") {
            info.channel = leading_number(v);
        } else if let Some(v) = netsh_value(line, "Receive rate (Mbps)") {
            info.rate_mbps = leading_number(v);
        } else if let Some(v) = netsh_value(line, "Authentication") {
            info.security = Some(v.to_string());
        } else if let Some(v) = netsh_value(line, "Band") {
            info.band = Some(v.to_string());
        } else if let Some(v) = netsh_value(line, "BSSID") {
            info.bssid = Some(v.to_ascii_uppercase()).filter(|b| !b.is_empty());
        }
    }
    if info.band.is_none() {
        info.band = info.channel.map(|c| band_for_channel(c).to_string());
    }
    connected.then_some(info)
}

pub fn parse_netsh_networks(text: &str) -> Vec<Neighbor> {
    let mut out = Vec::new();
    let mut ssid: Option<String> = None;
    let mut signal = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim(), v.trim());
        // "SSID 1 : name" starts a network; its access points are "BSSID n".
        if k.starts_with("SSID") {
            ssid = Some(v.to_string()).filter(|s| !s.is_empty());
        } else if k == "Signal" {
            signal = leading_number(v).and_then(|p| u8::try_from(p).ok());
        } else if k == "Channel"
            && let Some(channel) = leading_number(v)
        {
            out.push(Neighbor { ssid: ssid.clone(), channel, signal_percent: signal });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nmcli() {
        let text = "yes:Home\\:Net:42:6:2437 MHz:130 Mbit/s:WPA2:AA\\:BB\\:CC\\:00\\:11\\:22\n\
                    no:Home\\:Net:30:1:2412 MHz:130 Mbit/s:WPA2\n\
                    no:Neighbour:70:6:2437 MHz:54 Mbit/s:WPA2\n\
                    no:Other:50:4:2427 MHz:54 Mbit/s:WPA1\n\
                    no:Far:20:11:2462 MHz:54 Mbit/s:WPA2\n\
                    no:Fiver:80:36:5180 MHz:540 Mbit/s:WPA3\n";
        let w = parse_nmcli(text).unwrap();
        assert_eq!(w.ssid.as_deref(), Some("Home:Net"));
        assert_eq!(w.signal_percent, Some(42));
        assert_eq!(w.channel, Some(6));
        assert_eq!(w.band.as_deref(), Some("2.4 GHz"));
        assert_eq!(w.rate_mbps, Some(130));
        assert_eq!(w.bssid.as_deref(), Some("AA:BB:CC:00:11:22"));
        assert_eq!(w.quality(), Some(Quality::Fair));
        assert_eq!(w.neighbors.len(), 5);
        // Neighbour (6) and Other (4) overlap; our own AP on 1 doesn't count; 11 and 5 GHz don't overlap.
        assert_eq!(w.crowding(), 2);
        assert_eq!(w.best_2ghz_channel(), Some((1, 1)));
        assert_eq!(w.security_risk(), None);
    }

    #[test]
    fn parses_macos_system_profiler() {
        let json = r#"{"SPAirPortDataType":[{"spairport_airport_interfaces":[
            {"_name":"en0","spairport_current_network_information":{"_name":"Home","spairport_network_channel":"36 (5GHz, 80MHz)",
              "spairport_network_rate":866,"spairport_security_mode":"spairport_security_mode_wpa2_personal",
              "spairport_signal_noise":"-71 dBm / -92 dBm"},
             "spairport_airport_other_local_wireless_networks":[
              {"_name":"Neighbour","spairport_network_channel":"36 (5GHz, 80MHz)","spairport_signal_noise":"-80 dBm / -92 dBm"},
              {"_name":"Old","spairport_network_channel":"6 (2GHz, 20MHz)"}]}]}]}"#;
        let w = parse_system_profiler(json).unwrap();
        assert_eq!(w.ssid.as_deref(), Some("Home"));
        assert_eq!(w.rssi_dbm, Some(-71));
        assert_eq!(w.channel, Some(36));
        assert_eq!(w.band.as_deref(), Some("5 GHz"));
        assert_eq!(w.rate_mbps, Some(866));
        assert_eq!(w.quality(), Some(Quality::Fair));
        assert_eq!(w.crowding(), 1);
        assert_eq!(w.security.as_deref(), Some("wpa2 Personal"));
        assert_eq!(w.security_risk(), None);
    }

    #[test]
    fn parses_windows_netsh() {
        let iface = "There is 1 interface on the system:\n\n    Name                   : Wi-Fi\n    State                  : connected\n    SSID                   : Cafe\n    BSSID                  : aa:bb:cc:dd:ee:ff\n    Radio type             : 802.11n\n    Authentication         : Open\n    Channel                : 11\n    Receive rate (Mbps)    : 72\n    Signal                 : 35%\n";
        let w = parse_netsh_interfaces(iface).unwrap();
        assert_eq!(w.ssid.as_deref(), Some("Cafe"));
        assert_eq!(w.channel, Some(11));
        assert_eq!(w.signal_percent, Some(35));
        assert_eq!(w.bssid.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(w.quality(), Some(Quality::Weak));
        assert_eq!(w.security_risk(), Some(SecurityRisk::Open));
        assert!(parse_netsh_interfaces("    State                  : disconnected\n").is_none());

        let nets = "SSID 1 : Cafe\n    Authentication : Open\n    BSSID 1 : aa:bb\n         Signal : 35%\n         Channel : 11\nSSID 2 : Shop\n    BSSID 1 : cc:dd\n         Signal : 60%\n         Channel : 9\n";
        let n = parse_netsh_networks(nets);
        assert_eq!(
            n,
            vec![
                Neighbor { ssid: Some("Cafe".into()), channel: 11, signal_percent: Some(35) },
                Neighbor { ssid: Some("Shop".into()), channel: 9, signal_percent: Some(60) },
            ]
        );
    }

    #[test]
    fn reads_live_signal() {
        let text = "Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n \
                    face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n \
                    wlan0: 0000   54.  -56.  -256        0      0      0      0     36        0\n";
        assert_eq!(parse_proc_wireless(text), Some(-56));
        assert_eq!(parse_proc_wireless("a\nb\n"), None);
    }

    #[test]
    fn rates_security() {
        let w = |s: &str| WifiInfo { security: Some(s.into()), ..Default::default() };
        assert_eq!(w("WEP").security_risk(), Some(SecurityRisk::Outdated));
        assert_eq!(w("WPA1").security_risk(), Some(SecurityRisk::Outdated));
        assert_eq!(w("WPA-Personal").security_risk(), Some(SecurityRisk::Outdated));
        assert_eq!(w("WPA1 WPA2").security_risk(), None);
        assert_eq!(w("WPA2-Personal").security_risk(), None);
        assert_eq!(w("WPA3 SAE").security_risk(), None);
        assert_eq!(w("--").security_risk(), Some(SecurityRisk::Open));
    }
}
