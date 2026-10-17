//! Unprivileged liveness and port probing.
//!
//! A TCP connect that is *refused* proves a host is alive just as well as one
//! that succeeds, so we can find devices without raw sockets or root.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::model::OpenPort;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Open,
    /// The host answered with a reset: alive, port closed.
    Closed,
    /// No answer, or the host is unreachable.
    Silent,
}

pub async fn tcp_probe(addr: SocketAddr, timeout: Duration) -> (TcpState, Duration) {
    let start = Instant::now();
    let state = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => TcpState::Open,
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => TcpState::Closed,
        _ => TcpState::Silent,
    };
    (state, start.elapsed())
}

/// Ports that nearly every kind of device answers on, open or closed.
pub const KNOCK_PORTS: &[u16] = &[80, 443, 22, 445, 62078, 8080, 7000, 554, 139, 9100];

/// Returns the fastest round-trip time if the host proved it is alive.
pub async fn knock(ip: Ipv4Addr, timeout: Duration) -> Option<Duration> {
    let probes = KNOCK_PORTS.iter().map(|&port| tcp_probe(SocketAddr::new(IpAddr::V4(ip), port), timeout));
    futures_join_all(probes).await.into_iter().filter(|(s, _)| *s != TcpState::Silent).map(|(_, rtt)| rtt).min()
}

/// Runs futures concurrently on the current task.
pub async fn futures_join_all<F: std::future::Future>(futs: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let futs: Vec<_> = futs.into_iter().map(Box::pin).collect();
    let mut results: Vec<Option<F::Output>> = futs.iter().map(|_| None).collect();
    let mut pending: Vec<(usize, _)> = futs.into_iter().enumerate().collect();
    std::future::poll_fn(|cx| {
        pending.retain_mut(|(i, fut)| match fut.as_mut().poll(cx) {
            std::task::Poll::Ready(out) => {
                results[*i] = Some(out);
                false
            }
            std::task::Poll::Pending => true,
        });
        if pending.is_empty() { std::task::Poll::Ready(()) } else { std::task::Poll::Pending }
    })
    .await;
    results.into_iter().map(|r| r.expect("every future completed")).collect()
}

/// Quick "is it there right now?" check used by live mode: the device's own
/// open ports plus the usual knock ports, and ping when available. Returns
/// the round-trip time in milliseconds.
pub async fn check_alive(ip: Ipv4Addr, known_open: &[u16], timeout: Duration) -> Option<f64> {
    let mut ports: Vec<u16> = Vec::new();
    for &p in known_open.iter().chain(KNOCK_PORTS) {
        if !ports.contains(&p) && ports.len() < 16 {
            ports.push(p);
        }
    }
    let knock = async {
        futures_join_all(ports.iter().map(|&p| tcp_probe(SocketAddr::new(IpAddr::V4(ip), p), timeout)))
            .await
            .into_iter()
            .filter(|(s, _)| *s != TcpState::Silent)
            .map(|(_, rtt)| rtt.as_secs_f64() * 1000.0)
            .min_by(f64::total_cmp)
    };
    let (k, p) = tokio::join!(knock, system_ping(ip, timeout));
    p.or(k).map(|ms| (ms * 10.0).round() / 10.0)
}

/// Checks many devices at once. Keys are whatever the caller uses to tell
/// devices apart.
pub async fn check_many(targets: Vec<(String, Ipv4Addr, Vec<u16>)>, timeout: Duration) -> Vec<(String, Option<f64>)> {
    let limit = Arc::new(Semaphore::new(32));
    let mut set = tokio::task::JoinSet::new();
    for (key, ip, ports) in targets {
        let limit = limit.clone();
        set.spawn(async move {
            let _permit = limit.acquire_owned().await;
            (key, check_alive(ip, &ports, timeout).await)
        });
    }
    set.join_all().await
}

pub fn ping_available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        std::process::Command::new("ping")
            .arg(if cfg!(windows) { "/?" } else { "-V" })
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
    })
}

/// One ICMP echo via the system `ping` command. Returns RTT in milliseconds.
pub async fn system_ping(ip: Ipv4Addr, timeout: Duration) -> Option<f64> {
    if !ping_available() {
        return None;
    }
    let ms = timeout.as_millis().max(1000);
    let mut cmd = tokio::process::Command::new("ping");
    if cfg!(windows) {
        cmd.args(["-n", "1", "-w", &ms.to_string()]);
    } else if cfg!(target_os = "macos") {
        cmd.args(["-c", "1", "-W", &ms.to_string()]);
    } else {
        cmd.args(["-c", "1", "-W", &ms.div_ceil(1000).to_string()]);
    }
    let out = cmd.arg(ip.to_string()).kill_on_drop(true).output().await.ok()?;
    if !out.status.success() {
        return None;
    }
    parse_ping_time(&String::from_utf8_lossy(&out.stdout))
}

/// Extracts `time=1.23 ms` / `time<1ms` from ping output on any platform.
pub fn parse_ping_time(text: &str) -> Option<f64> {
    let idx = text.find("time=").map(|i| i + 5).or_else(|| text.find("time<").map(|i| i + 5))?;
    let num: String = text[idx..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    num.parse().ok()
}

/// Ports checked on every live device: enough to identify it and spot risks.
pub const QUICK_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 135, 139, 443, 445, 515, 548, 554, 631, 1400, 1883, 2375, 3000, 3306, 3389, 5000, 5001,
    5432, 5900, 6379, 6668, 7000, 8000, 8008, 8009, 8060, 8080, 8123, 8443, 8554, 8883, 9000, 9100, 9200, 27017, 32400,
    34567, 37777, 49152, 62078,
];

/// A broader list for on-demand deep scans of a single device.
pub fn deep_ports() -> Vec<u16> {
    let mut ports: Vec<u16> = (1..=1024).collect();
    ports.extend_from_slice(&[
        1080, 1194, 1433, 1521, 1723, 1883, 1900, 2049, 2082, 2083, 2222, 2375, 2376, 3000, 3128, 3268, 3306, 3389,
        3478, 4000, 4443, 4567, 5000, 5001, 5060, 5222, 5353, 5357, 5432, 5555, 5601, 5672, 5900, 5901, 5985, 5986,
        6000, 6379, 6443, 6667, 7000, 7070, 7547, 7681, 8000, 8001, 8008, 8009, 8060, 8080, 8081, 8086, 8088, 8123,
        8200, 8291, 8443, 8554, 8728, 8843, 8880, 8883, 8888, 9000, 9001, 9080, 9090, 9091, 9100, 9200, 9443, 9999,
        10000, 10001, 11211, 15672, 17500, 20000, 25565, 27017, 28017, 32400, 32469, 34567, 37777, 49152, 49153, 50000,
        51413, 55443, 62078,
    ]);
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub fn service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP file transfer",
        22 => "SSH remote login",
        23 => "Telnet remote login (unencrypted)",
        25 | 587 => "SMTP mail",
        53 => "DNS",
        67 | 68 => "DHCP",
        80 | 81 | 8000 | 8080 | 8081 | 8888 | 9000 => "Web page (HTTP)",
        110 => "POP3 mail",
        111 => "RPC portmapper",
        135 => "Windows RPC",
        139 => "Windows file sharing (NetBIOS)",
        143 => "IMAP mail",
        443 | 8443 | 9443 | 4443 => "Secure web page (HTTPS)",
        445 => "Windows file sharing (SMB)",
        515 => "Printer (LPD)",
        548 => "Apple file sharing (AFP)",
        554 | 8554 => "Video stream (RTSP)",
        6668 => "Tuya smart-device control",
        34567 => "Camera / video recorder control (Xiongmai)",
        37777 => "Camera / video recorder control (Dahua)",
        631 => "Printer (IPP)",
        1400 => "Sonos control",
        1433 => "Microsoft SQL Server",
        1521 => "Oracle database",
        1723 => "PPTP VPN",
        1883 => "MQTT smart-home messaging",
        1900 => "UPnP",
        2049 => "NFS file sharing",
        2375 => "Docker API (unencrypted)",
        2376 => "Docker API",
        3000 => "Web app / dashboard",
        3306 => "MySQL database",
        3389 => "Windows Remote Desktop",
        5000 | 5001 => "Web admin (often Synology / UPnP)",
        5060 => "SIP VoIP",
        5353 => "mDNS",
        5357 => "Windows network discovery",
        5432 => "PostgreSQL database",
        5555 => "Android debug bridge (ADB)",
        5900 | 5901 => "VNC screen sharing",
        5985 | 5986 => "Windows remote management",
        6379 => "Redis database",
        7000 => "AirPlay",
        7547 => "ISP remote management (TR-069)",
        8008 | 8009 => "Google Cast",
        8060 => "Roku control",
        8123 => "Home Assistant",
        8883 => "MQTT over TLS",
        9100 => "Printer (raw / JetDirect)",
        9200 => "Elasticsearch",
        11211 => "Memcached",
        25565 => "Minecraft server",
        27017 => "MongoDB database",
        32400 => "Plex media server",
        49152 | 49153 => "UPnP device control",
        62078 => "Apple device sync (iPhone / iPad)",
        _ => "Unknown service",
    }
}

/// Scans `ports` on one host, returning the open ones in order.
pub async fn scan_ports(ip: Ipv4Addr, ports: &[u16], timeout: Duration, limit: Arc<Semaphore>) -> Vec<u16> {
    let mut set = tokio::task::JoinSet::new();
    for &port in ports {
        let limit = limit.clone();
        set.spawn(async move {
            let _permit = limit.acquire_owned().await.ok()?;
            let (state, _) = tcp_probe(SocketAddr::new(IpAddr::V4(ip), port), timeout).await;
            (state == TcpState::Open).then_some(port)
        });
    }
    let mut open: Vec<u16> = set.join_all().await.into_iter().flatten().collect();
    open.sort_unstable();
    open
}

fn is_http_port(port: u16) -> bool {
    matches!(port, 80 | 81 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8123 | 8888 | 9000 | 32400)
}

/// A short, human-useful banner: the HTTP page title / server, or the first
/// line a service greets us with (SSH, FTP, SMTP, Telnet...).
pub async fn banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    if is_http_port(port) {
        let resp = crate::http::get(addr, &ip.to_string(), "/", Duration::from_millis(1500)).await.ok()?;
        let title = resp.title();
        let server = resp.header("server");
        return match (title, server) {
            (Some(t), Some(s)) => Some(format!("{t} ({s})")),
            (Some(t), None) => Some(t),
            (None, Some(s)) => Some(s.to_string()),
            (None, None) => None,
        };
    }
    if !matches!(port, 21 | 22 | 23 | 25 | 110 | 143) {
        return None;
    }
    let mut stream = tokio::time::timeout(Duration::from_millis(800), TcpStream::connect(addr)).await.ok()?.ok()?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_millis(1200), stream.read(&mut buf)).await.ok()?.ok()?;
    let _ = stream.shutdown().await;
    let text: String = String::from_utf8_lossy(&buf[..n]).chars().filter(|c| !c.is_control() || *c == '\n').collect();
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    Some(line.chars().take(120).collect())
}

pub async fn describe_ports(ip: Ipv4Addr, open: &[u16]) -> Vec<OpenPort> {
    futures_join_all(open.iter().map(|&port| async move {
        OpenPort { port, service: service_name(port).to_string(), banner: banner(ip, port).await }
    }))
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ping_output() {
        assert_eq!(parse_ping_time("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.4 ms"), Some(12.4));
        assert_eq!(parse_ping_time("Reply from 192.168.1.1: bytes=32 time<1ms TTL=64"), Some(1.0));
        assert_eq!(parse_ping_time("Reply from 192.168.1.1: bytes=32 time=3ms TTL=64"), Some(3.0));
        assert_eq!(parse_ping_time("Request timed out."), None);
    }

    #[tokio::test]
    async fn refused_connection_counts_as_alive() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (state, _) = tcp_probe(SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(1)).await;
        assert_eq!(state, TcpState::Open);
        drop(listener);
        let (state, _) = tcp_probe(SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(1)).await;
        assert_eq!(state, TcpState::Closed);
    }

    #[tokio::test]
    async fn join_all_keeps_order() {
        let out = futures_join_all((0..5u64).map(|i| async move {
            tokio::time::sleep(Duration::from_millis(50 - i * 10)).await;
            i
        }))
        .await;
        assert_eq!(out, vec![0, 1, 2, 3, 4]);
    }
}
