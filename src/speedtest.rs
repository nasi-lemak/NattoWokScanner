//! Speed test with a "lag under load" (bufferbloat) check.
//!
//! Uses Cloudflare's public speed-test endpoints over HTTPS. Besides download
//! and upload speed, it measures how much the delay to the internet grows
//! while the connection is busy. That growth is why video calls stutter when
//! someone else is streaming, and it's usually fixable in the router.
//!
//! Only runs when someone asks for it: it is the one feature that moves real
//! amounts of data.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::probe::{self, TcpState};
use crate::scan::Progress;

pub const HOST: &str = "speed.cloudflare.com";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    /// Grades the extra delay under load, in milliseconds.
    pub fn from_increase(ms: f64) -> Grade {
        match ms {
            m if m < 30.0 => Grade::A,
            m if m < 60.0 => Grade::B,
            m if m < 200.0 => Grade::C,
            m if m < 400.0 => Grade::D,
            _ => Grade::F,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SpeedResult {
    pub at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub idle_ms: f64,
    pub loaded_down_ms: f64,
    pub loaded_up_ms: f64,
    pub grade: Grade,
    pub data_used_mb: f64,
    pub verdict: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advice: Option<String>,
    /// Run on a schedule rather than by hand.
    #[serde(default)]
    pub scheduled: bool,
    /// Whether this computer was on Wi-Fi (which can limit the result).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wifi: Option<bool>,
    /// The network it ran on (see `Workspace::key_for`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SpeedOptions {
    pub download: Duration,
    pub upload: Duration,
    pub streams: usize,
    /// Stop early once this much has moved; fast lines don't need the full
    /// duration for an accurate number, and data caps are real.
    pub max_download_bytes: u64,
    pub max_upload_bytes: u64,
}

impl Default for SpeedOptions {
    fn default() -> Self {
        SpeedOptions {
            download: Duration::from_secs(8),
            upload: Duration::from_secs(6),
            streams: 4,
            max_download_bytes: 300_000_000,
            max_upload_bytes: 150_000_000,
        }
    }
}

fn tls() -> Result<TlsConnector> {
    crate::fetch::connector()
}

async fn resolve() -> Result<SocketAddr> {
    tokio::net::lookup_host((HOST, 443))
        .await
        .with_context(|| format!("couldn't look up {HOST}"))?
        .find(SocketAddr::is_ipv4)
        .with_context(|| format!("{HOST} has no IPv4 address"))
}

async fn connect(tls: &TlsConnector, addr: SocketAddr) -> Result<TlsStream<TcpStream>> {
    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await.context("timed out")??;
    tcp.set_nodelay(true)?;
    let name = ServerName::try_from(HOST)?.to_owned();
    Ok(tokio::time::timeout(Duration::from_secs(5), tls.connect(name, tcp)).await.context("TLS timed out")??)
}

/// Reads one HTTP response head; returns (status, content-length, location header).
async fn read_head(stream: &mut TlsStream<TcpStream>) -> Result<(u16, Option<u64>, Option<String>)> {
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            bail!("connection closed");
        }
        head.push(byte[0]);
        if head.len() > 16 * 1024 {
            bail!("response header too large");
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.lines();
    let status = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut length = None;
    let mut colo = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => length = v.trim().parse().ok(),
                "cf-meta-colo" => colo = Some(v.trim().to_string()),
                "cf-ray" if colo.is_none() => colo = v.trim().rsplit('-').next().map(str::to_string),
                _ => {}
            }
        }
    }
    Ok((status, length, colo))
}

/// Downloads repeatedly on one connection until `stop`, counting bytes.
async fn download_stream(
    tls: TlsConnector,
    addr: SocketAddr,
    bytes: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> Result<Option<String>> {
    let mut stream = connect(&tls, addr).await?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut colo = None;
    while !stop.load(Ordering::Relaxed) {
        let req = format!(
            "GET /__down?bytes=25000000 HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: NattoWokScanner/{}\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );
        stream.write_all(req.as_bytes()).await?;
        let (status, length, c) = read_head(&mut stream).await?;
        if status != 200 {
            bail!("the speed test server answered {status}");
        }
        colo = colo.or(c);
        let mut left = length.context("no content length")?;
        while left > 0 {
            if stop.load(Ordering::Relaxed) {
                return Ok(colo);
            }
            let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            let n = stream.read(&mut buf[..want]).await?;
            if n == 0 {
                bail!("connection closed mid-download");
            }
            bytes.fetch_add(n as u64, Ordering::Relaxed);
            left -= n as u64;
        }
    }
    Ok(colo)
}

/// Uploads repeatedly on one connection until `stop`, counting bytes.
async fn upload_stream(
    tls: TlsConnector,
    addr: SocketAddr,
    bytes: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    const BODY: u64 = 10_000_000;
    let chunk = vec![0u8; 64 * 1024];
    while !stop.load(Ordering::Relaxed) {
        // A fresh connection per upload, since we may stop mid-body.
        let mut stream = connect(&tls, addr).await?;
        let head = format!(
            "POST /__up HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: NattoWokScanner/{}\r\nContent-Type: application/octet-stream\r\nContent-Length: {BODY}\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );
        stream.write_all(head.as_bytes()).await?;
        let mut sent = 0u64;
        while sent < BODY {
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            let n = chunk.len().min(usize::try_from(BODY - sent).unwrap_or(usize::MAX));
            stream.write_all(&chunk[..n]).await?;
            sent += n as u64;
            bytes.fetch_add(n as u64, Ordering::Relaxed);
        }
        stream.flush().await?;
        let _ = read_head(&mut stream).await;
    }
    Ok(())
}

/// Round-trip time of a TCP handshake: a clean latency sample that queues
/// behind any traffic already filling the line.
async fn rtt(addr: SocketAddr) -> Option<f64> {
    let (state, d) = probe::tcp_probe(addr, Duration::from_secs(2)).await;
    (state != TcpState::Silent).then_some(d.as_secs_f64() * 1000.0)
}

fn median(mut v: Vec<f64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

struct Phase {
    mbps: f64,
    loaded_ms: f64,
    bytes: u64,
    colo: Option<String>,
}

/// Runs transfer streams for `duration` while sampling latency. Throughput
/// ignores the first second, while connections ramp up.
async fn run_phase(
    upload: bool,
    tls: &TlsConnector,
    addr: SocketAddr,
    opts: &SpeedOptions,
    progress: &Progress,
    (p_from, p_to): (f32, f32),
) -> Result<Phase> {
    let duration = if upload { opts.upload } else { opts.download };
    let budget = if upload { opts.max_upload_bytes } else { opts.max_download_bytes };
    let bytes = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let alive = Arc::new(AtomicUsize::new(opts.streams));
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..opts.streams {
        let (tls, bytes, stop, alive) = (tls.clone(), bytes.clone(), stop.clone(), alive.clone());
        set.spawn(async move {
            let r = if upload {
                upload_stream(tls, addr, bytes, stop).await.map(|_| None)
            } else {
                download_stream(tls, addr, bytes, stop).await
            };
            alive.fetch_sub(1, Ordering::Relaxed);
            r
        });
    }
    let warmup = Duration::from_secs(1);
    let start = Instant::now();
    let mut samples = Vec::new();
    let mut mark: Option<(Instant, u64)> = None;
    let label = if upload { "Testing upload speed" } else { "Testing download speed" };
    while start.elapsed() < duration {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if mark.is_none() && start.elapsed() >= warmup {
            mark = Some((Instant::now(), bytes.load(Ordering::Relaxed)));
        }
        if start.elapsed() >= warmup
            && let Some(ms) = rtt(addr).await
        {
            samples.push(ms);
        }
        let frac = (start.elapsed().as_secs_f32() / duration.as_secs_f32()).min(1.0);
        progress(label, p_from + (p_to - p_from) * frac);
        // Every stream failed: no point waiting out the clock.
        if alive.load(Ordering::Relaxed) == 0 {
            break;
        }
        if bytes.load(Ordering::Relaxed) >= budget && start.elapsed() >= Duration::from_millis(1500) {
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let total = bytes.load(Ordering::Relaxed);
    let (t0, b0) = mark.unwrap_or((start, 0));
    let secs = t0.elapsed().as_secs_f64().max(0.001);
    let mbps = (total.saturating_sub(b0) as f64 * 8.0) / secs / 1_000_000.0;
    let mut colo = None;
    let mut first_error = None;
    while let Some(r) = tokio::time::timeout(Duration::from_secs(3), set.join_next()).await.ok().flatten() {
        match r {
            Ok(Ok(c)) => colo = colo.or(c),
            Ok(Err(e)) => first_error = first_error.or(Some(e)),
            Err(_) => {}
        }
    }
    set.abort_all();
    if total == 0 {
        return Err(first_error.unwrap_or_else(|| anyhow::anyhow!("no data got through")));
    }
    Ok(Phase { mbps, loaded_ms: median(samples), bytes: total, colo })
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// Turns the numbers into a verdict and, when it helps, advice.
pub fn judge(download: f64, upload: f64, idle: f64, loaded: f64) -> (Grade, String, Option<String>) {
    let grade = Grade::from_increase((loaded - idle).max(0.0));
    let speed = match download {
        d if d >= 200.0 => "Fast enough for anything a household does at once",
        d if d >= 50.0 => "Fast enough for several 4K streams and video calls at once",
        d if d >= 15.0 => "Fine for HD streaming and video calls, but busy households will notice",
        d if d >= 5.0 => "Slow: one HD stream or call at a time",
        _ => "Very slow: expect buffering and choppy calls",
    };
    let verdict = format!("{speed}. Responsiveness under load: grade {grade:?}.");
    let advice = match grade {
        Grade::A | Grade::B => (upload < 3.0).then(|| {
            "Upload is low, so video calls may look blurry to others and backups crawl. Check whether your plan includes faster upload.".to_string()
        }),
        _ => Some(format!(
            "When the connection is busy, delay grows by about {} ms (\"bufferbloat\"). That's why calls and games lag while someone streams or uploads. Turn on Smart Queue / SQM / Adaptive QoS in your router (often under QoS or Traffic), set to a bit below your measured speeds ({:.0} down / {:.0} up Mbps).",
            (loaded - idle).round(),
            download * 0.9,
            upload * 0.9
        )),
    };
    (grade, verdict, advice)
}

pub async fn run(opts: &SpeedOptions, progress: Progress) -> Result<SpeedResult> {
    progress("Measuring idle latency", 0.02);
    let tls = tls()?;
    let addr = resolve().await?;
    let mut idle = Vec::new();
    for _ in 0..8 {
        if let Some(ms) = rtt(addr).await {
            idle.push(ms);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if idle.is_empty() {
        bail!("couldn't reach {HOST}");
    }
    let idle_ms = median(idle);
    let down = run_phase(false, &tls, addr, opts, &progress, (0.1, 0.55)).await?;
    let up = run_phase(true, &tls, addr, opts, &progress, (0.55, 0.98)).await?;
    let loaded = down.loaded_ms.max(up.loaded_ms);
    let (grade, verdict, advice) = judge(down.mbps, up.mbps, idle_ms, loaded);
    progress("Done", 1.0);
    Ok(SpeedResult {
        at: Utc::now(),
        location: down.colo,
        download_mbps: round1(down.mbps),
        upload_mbps: round1(up.mbps),
        idle_ms: round1(idle_ms),
        loaded_down_ms: round1(down.loaded_ms),
        loaded_up_ms: round1(up.loaded_ms),
        grade,
        data_used_mb: round1((down.bytes + up.bytes) as f64 / 1_000_000.0),
        verdict,
        advice,
        scheduled: false,
        wifi: crate::netinfo::detect(None, None).ok().map(|i| i.wireless),
        network: None,
    })
}

/// Past results, newest last, kept next to the inventory.
pub fn load_history(root: &std::path::Path) -> Vec<SpeedResult> {
    std::fs::read_to_string(root.join("speedtests.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save_result(root: &std::path::Path, result: &SpeedResult) -> Result<()> {
    let mut history = load_history(root);
    history.push(result.clone());
    // Enough for a month of scheduled tests.
    let excess = history.len().saturating_sub(400);
    history.drain(..excess);
    std::fs::create_dir_all(root)?;
    std::fs::write(root.join("speedtests.json"), serde_json::to_vec_pretty(&history)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grades_bufferbloat() {
        assert_eq!(Grade::from_increase(5.0), Grade::A);
        assert_eq!(Grade::from_increase(45.0), Grade::B);
        assert_eq!(Grade::from_increase(150.0), Grade::C);
        assert_eq!(Grade::from_increase(300.0), Grade::D);
        assert_eq!(Grade::from_increase(900.0), Grade::F);
    }

    #[test]
    fn judges_results() {
        let (g, verdict, advice) = judge(300.0, 50.0, 12.0, 20.0);
        assert_eq!(g, Grade::A);
        assert!(verdict.starts_with("Fast enough for anything"));
        assert!(advice.is_none());

        let (g, _, advice) = judge(100.0, 10.0, 15.0, 260.0);
        assert_eq!(g, Grade::D);
        let advice = advice.unwrap();
        assert!(advice.contains("245 ms"), "{advice}");
        assert!(advice.contains("90 down / 9 up"), "{advice}");

        let (_, _, advice) = judge(80.0, 1.5, 10.0, 15.0);
        assert!(advice.unwrap().contains("Upload is low"));
    }
}
