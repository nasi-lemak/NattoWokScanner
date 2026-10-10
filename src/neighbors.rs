//! Reads the operating system's ARP (neighbor) table.
//!
//! Every connection attempt we make to a local address forces the OS to ARP
//! for it, so after probing, this table reveals devices that ignore pings and
//! drop every TCP packet but still have to answer ARP to be on the network.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::oui;

pub async fn read_table() -> HashMap<Ipv4Addr, String> {
    if (cfg!(target_os = "linux") || cfg!(target_os = "android"))
        && let Ok(text) = tokio::fs::read_to_string("/proc/net/arp").await
    {
        return parse_proc_arp(&text);
    }
    let args: &[&str] = if cfg!(windows) { &["-a"] } else { &["-an"] };
    match tokio::process::Command::new("arp").args(args).output().await {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            if cfg!(windows) { parse_windows_arp(&text) } else { parse_bsd_arp(&text) }
        }
        Err(_) => HashMap::new(),
    }
}

fn keep(mac: &str) -> Option<String> {
    let mac = oui::normalize(mac)?;
    (!oui::is_multicast(&mac)).then_some(mac)
}

/// Linux `/proc/net/arp`. Flags `0x0` marks an incomplete entry.
pub fn parse_proc_arp(text: &str) -> HashMap<Ipv4Addr, String> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 || cols[2] == "0x0" {
                return None;
            }
            Some((cols[0].parse().ok()?, keep(cols[3])?))
        })
        .collect()
}

/// macOS / BSD `arp -an`: `? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]`.
pub fn parse_bsd_arp(text: &str) -> HashMap<Ipv4Addr, String> {
    text.lines()
        .filter_map(|line| {
            let open = line.find('(')?;
            let close = line[open..].find(')')? + open;
            let ip = line[open + 1..close].parse().ok()?;
            let rest = line[close..].split_whitespace().collect::<Vec<_>>();
            let at = rest.iter().position(|w| *w == "at")?;
            Some((ip, keep(rest.get(at + 1)?)?))
        })
        .collect()
}

/// Windows `arp -a`: `  192.168.1.1           00-11-22-33-44-55     dynamic`.
pub fn parse_windows_arp(text: &str) -> HashMap<Ipv4Addr, String> {
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 2 {
                return None;
            }
            Some((cols[0].parse().ok()?, keep(cols[1])?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.1      0x1         0x2         a4:2b:b0:11:22:33     *        wlan0\n\
                    192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        wlan0\n\
                    192.168.1.60     0x1         0x2         b8:27:eb:01:02:03     *        wlan0\n";
        let t = parse_proc_arp(text);
        assert_eq!(t.len(), 2);
        assert_eq!(t[&"192.168.1.1".parse().unwrap()], "A4:2B:B0:11:22:33");
    }

    #[test]
    fn parses_macos() {
        let text = "? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]\n\
                    ? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n\
                    ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n\
                    ? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n";
        let t = parse_bsd_arp(text);
        assert_eq!(t.len(), 1);
        assert_eq!(t[&"192.168.1.1".parse().unwrap()], "00:11:22:33:44:55");
    }

    #[test]
    fn parses_windows() {
        let text = "\nInterface: 192.168.1.20 --- 0x5\n  Internet Address      Physical Address      Type\n  \
                    192.168.1.1           a4-2b-b0-11-22-33     dynamic\n  \
                    192.168.1.255         ff-ff-ff-ff-ff-ff     static\n";
        let t = parse_windows_arp(text);
        assert_eq!(t.len(), 1);
        assert_eq!(t[&"192.168.1.1".parse().unwrap()], "A4:2B:B0:11:22:33");
    }
}
