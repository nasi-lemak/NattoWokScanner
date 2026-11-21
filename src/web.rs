//! The local dashboard: a small JSON API plus an embedded single-page UI.
//!
//! It binds to localhost by default. Because any website you visit could try
//! to talk to localhost, every API call must carry a per-run secret token
//! (which other sites can't read), and the Host header is checked to block
//! DNS-rebinding tricks.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use anyhow::Result;
use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::doctor::{self, Diagnosis};
use crate::model::OpenPort;
use crate::room::RoomCheck;
use crate::scan::{self, ScanOptions};
use crate::settings::Settings;
#[cfg(feature = "tls")]
use crate::speedtest;
use crate::store::{DeviceUpdate, Inventory, Workspace};
use crate::{alerts, netinfo, notify, probe, report, security, wol};

const INDEX: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const STYLE: &str = include_str!("../web/style.css");
const ICON: &str = include_str!("../web/icon.svg");

#[derive(Serialize, Clone, Default)]
pub struct Job {
    pub running: bool,
    pub phase: String,
    pub progress: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
}

/// The network being shown and its inventory.
///
/// The file on disk is the source of truth: the CLI may change it while the
/// dashboard (or background service) runs, so it's re-read when it changes.
struct Current {
    key: String,
    inv: Inventory,
    mtime: Option<SystemTime>,
}

fn modified(ws: &Workspace, key: &str) -> Option<SystemTime> {
    std::fs::metadata(Inventory::path(&ws.dir(key))).and_then(|m| m.modified()).ok()
}

impl Current {
    fn new(ws: &Workspace, key: String, inv: Inventory) -> Self {
        let mtime = modified(ws, &key);
        Current { key, inv, mtime }
    }

    fn refresh(&mut self, ws: &Workspace) {
        let now = modified(ws, &self.key);
        if now.is_some()
            && now != self.mtime
            && let Ok(inv) = Inventory::load(&ws.dir(&self.key))
        {
            self.inv = inv;
            self.mtime = now;
        }
    }

    fn save(&mut self, ws: &Workspace) -> Result<()> {
        ws.save(&self.key, &self.inv)?;
        self.mtime = modified(ws, &self.key);
        Ok(())
    }
}

pub struct AppState {
    workspace: Workspace,
    current: Mutex<Current>,
    scan: Arc<Mutex<Job>>,
    doctor: Arc<Mutex<Job>>,
    diagnosis: Mutex<Option<Diagnosis>>,
    speed: Arc<Mutex<Job>>,
    room: Arc<Mutex<Job>>,
    room_check: Mutex<Option<RoomCheck>>,
    /// What the outage monitor saw last.
    outage_live: Mutex<crate::outages::Live>,
    scan_opts: ScanOptions,
    settings: Mutex<SettingsCell>,
    /// The extra listener on the local network for phones, when on.
    phone: Mutex<Option<PhoneListener>>,
    /// The port the dashboard listens on, once bound.
    port: std::sync::OnceLock<u16>,
    /// Started by `nattowok service install` rather than by hand.
    service_mode: bool,
    token: String,
    remote: bool,
}

type Shared = Arc<AppState>;

/// Preferences, re-read when the CLI changes the file (e.g. `nattowok alerts`).
pub struct SettingsCell {
    value: Settings,
    mtime: Option<SystemTime>,
}

fn settings_mtime(root: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(Settings::path_in(root)).and_then(|m| m.modified()).ok()
}

impl SettingsCell {
    fn new(root: &std::path::Path) -> Self {
        SettingsCell { value: Settings::load(root), mtime: settings_mtime(root) }
    }

    fn save(&mut self, root: &std::path::Path) -> Result<()> {
        self.value.save(root)?;
        self.mtime = settings_mtime(root);
        Ok(())
    }
}

impl std::ops::Deref for SettingsCell {
    type Target = Settings;
    fn deref(&self) -> &Settings {
        &self.value
    }
}

impl std::ops::DerefMut for SettingsCell {
    fn deref_mut(&mut self) -> &mut Settings {
        &mut self.value
    }
}

fn settings(state: &AppState) -> MutexGuard<'_, SettingsCell> {
    let mut s = state.settings.lock().unwrap();
    let now = settings_mtime(state.workspace.root());
    if now.is_some() && now != s.mtime {
        s.value = Settings::load(state.workspace.root());
        s.mtime = now;
    }
    s
}

/// The current network's inventory, re-read first if the CLI changed it.
fn current(state: &AppState) -> MutexGuard<'_, Current> {
    let mut cur = state.current.lock().unwrap();
    cur.refresh(&state.workspace);
    cur
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn not_found(what: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, format!("{what} not found"))
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the OS random number generator is unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn host_is_local(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let name = if host.starts_with('[') {
        host.split(']').next().map(|h| format!("{h}]")).unwrap_or_default()
    } else {
        host.split(':').next().unwrap_or_default().to_string()
    };
    matches!(name.as_str(), "localhost" | "127.0.0.1" | "[::1]")
}

/// Who a listener serves.
#[derive(Clone)]
pub enum Access {
    /// This computer, via localhost (or everyone, with `--listen` and a key).
    Local,
    /// Devices on the local network, addressed exactly as `host`, with the
    /// phone key from the settings.
    Phone { host: String },
}

/// The token a request must carry, decided by the guard.
#[derive(Clone)]
struct PageAccess {
    token: String,
    require_key: bool,
}

async fn guard(State((state, access)): State<(Shared, Access)>, mut req: Request, next: Next) -> Response {
    let page = match &access {
        Access::Local => {
            if !state.remote && !host_is_local(req.headers()) {
                return (StatusCode::FORBIDDEN, "NattoWok only answers requests addressed to localhost.")
                    .into_response();
            }
            PageAccess { token: state.token.clone(), require_key: state.remote }
        }
        Access::Phone { host } => {
            // Exact Host match blocks DNS-rebinding, as for localhost.
            if req.headers().get(header::HOST).and_then(|h| h.to_str().ok()) != Some(host.as_str()) {
                return (StatusCode::FORBIDDEN, format!("NattoWok only answers requests addressed to {host}."))
                    .into_response();
            }
            // Read live, so turning access off or making a new link applies at once.
            let s = settings(&state);
            match s.phone_key.clone().filter(|_| s.phone_access) {
                Some(key) => PageAccess { token: key, require_key: true },
                None => return (StatusCode::FORBIDDEN, "Phone access to NattoWok is turned off.").into_response(),
            }
        }
    };
    if req.uri().path().starts_with("/api/") {
        let token = req.headers().get("x-nattowok-token").and_then(|v| v.to_str().ok());
        if token != Some(page.token.as_str()) {
            return ApiError(StatusCode::UNAUTHORIZED, "missing or wrong access token; reload the page".into())
                .into_response();
        }
    }
    req.extensions_mut().insert(page);
    next.run(req).await
}

#[derive(Deserialize)]
struct KeyQuery {
    key: Option<String>,
}

async fn index(Extension(page): Extension<PageAccess>, Query(q): Query<KeyQuery>) -> Response {
    if page.require_key && q.key.as_deref() != Some(page.token.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Html(
                "<p>This link is missing its access key or has been replaced. Scan the QR code in NattoWok again.</p>",
            ),
        )
            .into_response();
    }
    let page = INDEX.replace("__NATTOWOK_TOKEN__", &page.token).replace("__VERSION__", env!("CARGO_PKG_VERSION"));
    ([(header::CACHE_CONTROL, "no-store")], Html(page)).into_response()
}

pub struct PhoneListener {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

/// This computer's address on the local network.
fn lan_ip(state: &AppState) -> Result<std::net::Ipv4Addr> {
    let ip = netinfo::detect(state.scan_opts.interface.as_deref(), None)?.ip;
    anyhow::ensure!(!ip.is_loopback() && !ip.is_link_local(), "this computer has no usable local network address");
    Ok(ip)
}

/// The link phones open, when phone access is on.
fn phone_link(state: &AppState) -> Option<String> {
    let port = *state.port.get()?;
    let ip = lan_ip(state).ok()?;
    if state.remote {
        return Some(format!("http://{ip}:{port}/?key={}", state.token));
    }
    let s = settings(state);
    let key = s.phone_key.clone().filter(|_| s.phone_access)?;
    Some(format!("http://{ip}:{port}/?key={key}"))
}

/// Starts, moves or stops the phone listener to match the settings and the
/// computer's current address. Safe to call often.
async fn sync_phone(state: &Shared) {
    let wanted = {
        let s = settings(state);
        s.phone_access && s.phone_key.is_some()
    };
    let Some(&port) = state.port.get() else { return };
    // With --listen on all addresses, the main listener already serves phones.
    if state.remote {
        return;
    }
    let target = if wanted { lan_ip(state).ok().map(|ip| SocketAddr::from((ip, port))) } else { None };
    let running = state.phone.lock().unwrap().as_ref().map(|p| p.addr);
    if running == target {
        return;
    }
    if let Some(old) = state.phone.lock().unwrap().take() {
        old.task.abort();
    }
    let Some(addr) = target else { return };
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            let app = router(state.clone(), Access::Phone { host: addr.to_string() });
            let task = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            *state.phone.lock().unwrap() = Some(PhoneListener { addr, task });
        }
        Err(e) => eprintln!("couldn't open phone access on {addr}: {e}"),
    }
}

fn qr_svg(text: &str) -> Option<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(200, 200)
            .dark_color(svg::Color("#000"))
            .light_color(svg::Color("#fff"))
            .build(),
    )
}

async fn phone_status(State(state): State<Shared>) -> Json<serde_json::Value> {
    let link = phone_link(&state);
    Json(json!({
        "enabled": link.is_some(),
        "always_on": state.remote,
        "url": link,
        "qr_svg": link.as_deref().and_then(qr_svg),
    }))
}

#[derive(Deserialize)]
struct PhoneUpdate {
    enabled: Option<bool>,
    #[serde(default)]
    new_key: bool,
}

async fn update_phone(
    State(state): State<Shared>,
    Json(update): Json<PhoneUpdate>,
) -> ApiResult<Json<serde_json::Value>> {
    {
        let mut s = settings(&state);
        if let Some(on) = update.enabled {
            s.phone_access = on;
        }
        if update.new_key || (s.phone_access && s.phone_key.is_none()) {
            s.phone_key = Some(random_token());
        }
        s.save(state.workspace.root())?;
    }
    sync_phone(&state).await;
    Ok(phone_status(State(state)).await)
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

async fn state_json(State(state): State<Shared>) -> Json<serde_json::Value> {
    let cur = current(&state);
    let events: Vec<_> = cur.inv.events.iter().rev().take(300).cloned().collect();
    let since = Utc::now() - chrono::Duration::days(crate::store::PRESENCE_DAYS + 1);
    let scan_log: Vec<_> = cur.inv.scan_log.iter().filter(|t| **t >= since).collect();
    let settings = settings(&state).clone();
    let next_scan_at = next_scan_due(&state, &cur, &settings);
    // Alert targets hold tokens; the page only ever sees descriptions.
    let settings_view = json!({
        "auto_scan_minutes": settings.auto_scan_minutes,
        "notifications": settings.notifications,
        "outage_log": settings.outage_log,
        "alerts": settings.alerts.iter().map(|a| a.describe()).collect::<Vec<_>>(),
    });
    Json(json!({
        "settings": settings_view,
        "scan_log": scan_log,
        "watch_gap_hours": crate::store::WATCH_GAP_HOURS,
        "next_scan_at": next_scan_at,
        "service_mode": state.service_mode,
        "version": env!("CARGO_PKG_VERSION"),
        "network_key": cur.key,
        "networks": state.workspace.networks(&cur.key).len(),
        "report": cur.inv.current_view(),
        "events": events,
        "scan": *state.scan.lock().unwrap(),
        "doctor": *state.doctor.lock().unwrap(),
        "speed": *state.speed.lock().unwrap(),
        "speed_history": speed_history(&state),
        "diagnosis": *state.diagnosis.lock().unwrap(),
        "room": *state.room.lock().unwrap(),
        "room_check": *state.room_check.lock().unwrap(),
        "room_guide": crate::room::guide(),
        "outages": outage_view(&state, &cur.key, Some(7)),
    }))
}

fn progress_into(job: Arc<Mutex<Job>>) -> scan::Progress {
    Arc::new(move |phase: &str, p: f32| {
        let mut j = job.lock().unwrap();
        j.phase = phase.to_string();
        j.progress = p;
    })
}

fn begin(job: &Mutex<Job>) -> ApiResult<()> {
    let mut j = job.lock().unwrap();
    if j.running {
        return Err(ApiError(StatusCode::CONFLICT, "already running".into()));
    }
    *j = Job { running: true, phase: "Starting".into(), ..Default::default() };
    Ok(())
}

fn finish(job: &Mutex<Job>, error: Option<String>) {
    let mut j = job.lock().unwrap();
    j.running = false;
    j.progress = 1.0;
    j.error = error;
    j.finished_at = Some(Utc::now());
}

/// Starts a scan in the background. Automatic scans notify about changes
/// (when enabled); someone pressing "Scan" is already looking.
fn spawn_scan(state: Shared, automatic: bool) -> ApiResult<()> {
    begin(&state.scan)?;
    tokio::spawn(async move {
        let result = scan::run(&state.scan_opts, progress_into(state.scan.clone())).await;
        let mut events = Vec::new();
        let error = match result {
            Ok(mut report) => match state.workspace.record_scan(&mut report) {
                Ok((key, inv, changes)) => {
                    *state.current.lock().unwrap() = Current::new(&state.workspace, key, inv);
                    events = changes;
                    None
                }
                Err(e) => Some(format!("Scan finished but couldn't be saved: {e:#}")),
            },
            Err(e) => Some(format!("{e:#}")),
        };
        finish(&state.scan, error);
        if automatic {
            let settings = settings(&state).clone();
            if settings.notifications {
                notify::send_for(&events).await;
            }
            alerts::send_all(&settings.alerts, &events).await;
        }
    });
    Ok(())
}

/// When the next automatic scan is due, if they're on.
fn next_scan_due(state: &AppState, cur: &Current, settings: &Settings) -> Option<DateTime<Utc>> {
    if settings.auto_scan_minutes == 0 {
        return None;
    }
    let last_scan = cur.inv.last_report.as_ref().map(|r| r.finished_at);
    let last_attempt = state.scan.lock().unwrap().finished_at;
    let last = last_scan.max(last_attempt)?;
    Some(last + chrono::Duration::minutes(i64::from(settings.auto_scan_minutes)))
}

/// Runs automatic scans on schedule for as long as the server is up.
async fn auto_scan_loop(state: Shared) {
    loop {
        tokio::time::sleep(Duration::from_secs(20)).await;
        // Picks up `nattowok phone` and address changes.
        sync_phone(&state).await;
        let settings = settings(&state).clone();
        if settings.auto_scan_minutes == 0 {
            continue;
        }
        let due = {
            let cur = current(&state);
            next_scan_due(&state, &cur, &settings).is_none_or(|at| at <= Utc::now())
        };
        if due {
            let _ = spawn_scan(state.clone(), true);
        }
    }
}

#[derive(Deserialize)]
struct SettingsUpdate {
    auto_scan_minutes: Option<u32>,
    notifications: Option<bool>,
    outage_log: Option<bool>,
}

async fn update_settings(State(state): State<Shared>, Json(update): Json<SettingsUpdate>) -> ApiResult<StatusCode> {
    let mut s = settings(&state);
    if let Some(m) = update.auto_scan_minutes {
        s.auto_scan_minutes = m.min(24 * 60);
    }
    if let Some(n) = update.notifications {
        s.notifications = n;
    }
    if let Some(o) = update.outage_log {
        s.outage_log = o;
    }
    s.save(state.workspace.root())?;
    // Never echo settings back: they hold alert tokens and the phone key.
    Ok(StatusCode::NO_CONTENT)
}

async fn add_alert(State(state): State<Shared>, Json(target): Json<alerts::AlertTarget>) -> ApiResult<StatusCode> {
    target.validate().map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    let mut s = settings(&state);
    s.alerts.push(target);
    s.save(state.workspace.root())?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_alert(State(state): State<Shared>, Path(index): Path<usize>) -> ApiResult<StatusCode> {
    let mut s = settings(&state);
    if index >= s.alerts.len() {
        return Err(not_found("alert"));
    }
    s.alerts.remove(index);
    s.save(state.workspace.root())?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sends a test to every alert target and reports each result.
async fn test_alerts(State(state): State<Shared>) -> Json<Vec<serde_json::Value>> {
    let targets = settings(&state).alerts.clone();
    let mut out = Vec::new();
    for t in &targets {
        let r = alerts::send(t, "NattoWok test", "Alerts from NattoWok will arrive here.", &[]).await;
        out.push(json!({ "target": t.describe(), "error": r.err().map(|e| format!("{e:#}")) }));
    }
    Json(out)
}

async fn test_notification() -> ApiResult<StatusCode> {
    notify::send("NattoWok notifications are on", "You'll hear about new devices and security issues here.")
        .await
        .map_err(|e| ApiError(StatusCode::SERVICE_UNAVAILABLE, format!("{e:#}")))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn start_scan(State(state): State<Shared>) -> ApiResult<StatusCode> {
    spawn_scan(state, false)?;
    Ok(StatusCode::ACCEPTED)
}

async fn start_doctor(State(state): State<Shared>) -> ApiResult<StatusCode> {
    begin(&state.doctor)?;
    tokio::spawn(async move {
        let result = doctor::run(state.scan_opts.interface.as_deref(), progress_into(state.doctor.clone())).await;
        let error = match result {
            Ok(d) => {
                *state.diagnosis.lock().unwrap() = Some(d);
                None
            }
            Err(e) => Some(format!("{e:#}")),
        };
        finish(&state.doctor, error);
    });
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize)]
struct DaysQuery {
    days: Option<i64>,
}

/// Callers pass the network key so they never lock `current` twice.
fn outage_summary(state: &AppState, key: &str, days: Option<i64>) -> crate::outages::Summary {
    let log = crate::outages::Log::load(&state.workspace.dir(key));
    crate::outages::summarize(&log, days.unwrap_or(7).clamp(1, 90), Utc::now())
}

async fn outages(State(state): State<Shared>, Query(q): Query<DaysQuery>) -> Json<serde_json::Value> {
    let key = current(&state).key.clone();
    Json(outage_view(&state, &key, q.days))
}

fn outage_view(state: &AppState, key: &str, days: Option<i64>) -> serde_json::Value {
    let summary = outage_summary(state, key, days);
    let live = state.outage_live.lock().unwrap().clone();
    let by_cause: Vec<_> = summary
        .by_cause
        .iter()
        .map(|(c, (n, secs))| json!({ "cause": c, "label": c.label(), "count": n, "secs": secs }))
        .collect();
    let log = crate::outages::Log::load(&state.workspace.dir(key));
    let since = Utc::now() - chrono::TimeDelta::days(days.unwrap_or(7).clamp(1, 90));
    let watched: Vec<_> = log.watched.iter().filter(|w| w.to >= since).collect();
    let causes: Vec<_> = crate::outages::Cause::ALL
        .iter()
        .map(|c| json!({ "cause": c, "label": c.label(), "explain": c.explain() }))
        .collect();
    json!({
        "enabled": settings(state).outage_log,
        "network": crate::outages::network_label(&state.workspace, key),
        "live": live,
        "summary": summary,
        "by_cause": by_cause,
        "watched": watched,
        "causes": causes,
    })
}

async fn outage_report(State(state): State<Shared>, Query(q): Query<DaysQuery>) -> Response {
    let key = current(&state).key.clone();
    let summary = outage_summary(&state, &key, Some(q.days.unwrap_or(30)));
    let body = crate::outages::report(&summary, &crate::outages::network_label(&state.workspace, &key));
    let disposition = format!("attachment; filename=\"outage-report-{}.md\"", Utc::now().format("%Y-%m-%d"));
    (
        [
            (header::CONTENT_TYPE, "text/markdown; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        body,
    )
        .into_response()
}

/// Runs the outage monitor for as long as the server is up; it idles while
/// the setting is off.
fn spawn_outage_monitor(state: Shared) {
    let root = state.workspace.root().to_path_buf();
    let interface = state.scan_opts.interface.clone();
    let (s1, s2, s3) = (state.clone(), state.clone(), state);
    tokio::spawn(crate::outages::monitor(
        root,
        interface,
        move || settings(&s1).outage_log,
        move |live| *s2.outage_live.lock().unwrap() = live,
        move |update| {
            let crate::outages::Update::Ended { outage, .. } = update else { return };
            // Short blips aren't worth interrupting anyone for; they're in the log.
            if outage.duration(Utc::now()).num_seconds() < 60 || outage.cut_short {
                return;
            }
            let settings = settings(&s3).clone();
            tokio::spawn(async move {
                let (title, body) = crate::outages::ended_message(&outage, Utc::now());
                if settings.notifications {
                    let _ = notify::send(&title, &body).await;
                }
                for target in &settings.alerts {
                    if let Err(e) = alerts::send(target, &title, &body, &[]).await {
                        eprintln!("alert: {e:#}");
                    }
                }
            });
        },
    ));
}

async fn start_room_check(State(state): State<Shared>) -> ApiResult<StatusCode> {
    begin(&state.room)?;
    tokio::spawn(async move {
        let result =
            crate::room::run(&state.scan_opts, progress_into(state.room.clone()), state.workspace.root()).await;
        let error = match result {
            Ok(check) => {
                *state.room_check.lock().unwrap() = Some(check);
                None
            }
            Err(e) => Some(format!("{e:#}")),
        };
        finish(&state.room, error);
    });
    Ok(StatusCode::ACCEPTED)
}

#[cfg(feature = "tls")]
fn speed_history(state: &AppState) -> Vec<speedtest::SpeedResult> {
    speedtest::load_history(state.workspace.root()).into_iter().rev().take(10).collect()
}

#[cfg(not(feature = "tls"))]
fn speed_history(_: &AppState) -> Vec<()> {
    Vec::new()
}

#[cfg(feature = "tls")]
async fn start_speedtest(State(state): State<Shared>) -> ApiResult<StatusCode> {
    begin(&state.speed)?;
    tokio::spawn(async move {
        let result = speedtest::run(&speedtest::SpeedOptions::default(), progress_into(state.speed.clone())).await;
        let error = match result {
            Ok(r) => speedtest::save_result(state.workspace.root(), &r).err().map(|e| format!("{e:#}")),
            Err(e) => Some(format!("Speed test failed: {e:#}")),
        };
        finish(&state.speed, error);
    });
    Ok(StatusCode::ACCEPTED)
}

async fn start_speedtest_route(State(state): State<Shared>) -> ApiResult<StatusCode> {
    #[cfg(feature = "tls")]
    return start_speedtest(State(state)).await;
    #[cfg(not(feature = "tls"))]
    {
        let _ = state;
        Err(ApiError(StatusCode::NOT_IMPLEMENTED, "this build of NattoWok has no speed test".into()))
    }
}

async fn update_device(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(update): Json<DeviceUpdate>,
) -> ApiResult<StatusCode> {
    let mut cur = current(&state);
    cur.inv.update(&id, update).ok_or_else(|| not_found("device"))?;
    cur.save(&state.workspace)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn forget_device(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let mut cur = current(&state);
    if !cur.inv.forget(&id) {
        return Err(not_found("device"));
    }
    cur.save(&state.workspace)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn wake_device(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Json<serde_json::Value>> {
    let (mac, broadcast) = {
        let cur = current(&state);
        let inv = &cur.inv;
        let known = inv.devices.get(&id).ok_or_else(|| not_found("device"))?;
        let mac = known
            .snapshot
            .mac
            .clone()
            .ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "this device's hardware address is unknown".into()))?;
        let broadcast =
            inv.last_report.as_ref().map(|r| netinfo::broadcast(&r.network)).unwrap_or(std::net::Ipv4Addr::BROADCAST);
        (mac, broadcast)
    };
    wol::wake(&mac, broadcast).await?;
    Ok(Json(json!({ "sent_to": mac })))
}

async fn deep_scan(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Json<Vec<OpenPort>>> {
    let ip = {
        let cur = current(&state);
        cur.inv.devices.get(&id).ok_or_else(|| not_found("device"))?.snapshot.ip
    };
    let limit = Arc::new(tokio::sync::Semaphore::new(256));
    let open = probe::scan_ports(ip, &probe::deep_ports(), std::time::Duration::from_millis(800), limit).await;
    let described = probe::describe_ports(ip, &open).await;
    let mut cur = current(&state);
    let inv = &mut cur.inv;
    if let Some(report) = inv.last_report.as_mut()
        && let Some(d) = report.devices.iter_mut().find(|d| d.id == id)
    {
        d.open_ports = described.clone();
        d.findings = security::device_findings(d);
    }
    if let Some(k) = inv.devices.get_mut(&id) {
        k.snapshot.open_ports = described.clone();
    }
    cur.save(&state.workspace)?;
    Ok(Json(described))
}

/// "Why can't I print or cast to it?"
async fn why_device(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Json<crate::reach::Help>> {
    let (device, inv) = {
        let cur = current(&state);
        let view = cur.inv.current_view().ok_or_else(|| not_found("scan"))?;
        let device = view.devices.into_iter().find(|d| d.id == id).ok_or_else(|| not_found("device"))?;
        (device, cur.inv.clone())
    };
    let info = netinfo::detect(state.scan_opts.interface.as_deref(), None)
        .map_err(|e| ApiError(StatusCode::SERVICE_UNAVAILABLE, format!("{e:#}")))?;
    Ok(Json(crate::reach::diagnose(&device, &inv, &info).await))
}

#[derive(Deserialize)]
struct OtherDevice {
    other: String,
}

/// "These two entries are the same device": keep `id`, fold `other` into it.
async fn merge_devices(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(body): Json<OtherDevice>,
) -> ApiResult<Json<serde_json::Value>> {
    let mut cur = current(&state);
    let name = cur.inv.merge(&id, &body.other).map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("{e:#}")))?;
    cur.save(&state.workspace)?;
    Ok(Json(json!({ "name": name })))
}

async fn not_same(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(body): Json<OtherDevice>,
) -> ApiResult<StatusCode> {
    let mut cur = current(&state);
    cur.inv.mark_not_same(&id, &body.other);
    cur.save(&state.workspace)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Live mode: is each known device answering right now?
async fn presence(State(state): State<Shared>) -> Json<serde_json::Value> {
    let targets: Vec<(String, std::net::Ipv4Addr, Vec<u16>)> = {
        let cur = current(&state);
        cur.inv
            .current_view()
            .map(|r| {
                r.devices
                    .iter()
                    .filter(|d| !d.is_self)
                    .map(|d| (d.id.clone(), d.ip, d.open_ports.iter().map(|p| p.port).collect()))
                    .collect()
            })
            .unwrap_or_default()
    };
    let results = probe::check_many(targets, std::time::Duration::from_millis(900)).await;
    let map: serde_json::Map<String, serde_json::Value> =
        results.into_iter().map(|(id, rtt)| (id, json!(rtt))).collect();
    Json(json!({ "at": Utc::now(), "devices": map }))
}

async fn trust_all(State(state): State<Shared>) -> ApiResult<Json<serde_json::Value>> {
    let mut cur = current(&state);
    let n = cur.inv.trust_all_online();
    cur.save(&state.workspace)?;
    Ok(Json(json!({ "trusted": n })))
}

async fn ignore_finding(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let mut cur = current(&state);
    cur.inv.ignored_findings.insert(id);
    cur.save(&state.workspace)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unignore_finding(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let mut cur = current(&state);
    cur.inv.ignored_findings.remove(&id);
    cur.save(&state.workspace)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn export(State(state): State<Shared>, Path(format): Path<String>) -> ApiResult<Response> {
    let cur = current(&state);
    let report = cur.inv.current_view().ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "run a scan first".into()))?;
    let stamp = report.finished_at.format("%Y%m%d-%H%M");
    let (body, mime, ext) = match format.as_str() {
        "csv" => (report::to_csv(&report), "text/csv; charset=utf-8", "csv"),
        "md" => (report::to_markdown(&report), "text/markdown; charset=utf-8", "md"),
        "json" => (serde_json::to_string_pretty(&report).map_err(anyhow::Error::from)?, "application/json", "json"),
        "anonymised" => (report::to_anonymised_json(&report), "application/json", "anonymised.json"),
        _ => return Err(ApiError(StatusCode::BAD_REQUEST, "format must be csv, md, json or anonymised".into())),
    };
    let disposition = format!("attachment; filename=\"network-{stamp}.{ext}\"");
    Ok(([(header::CONTENT_TYPE, mime.to_string()), (header::CONTENT_DISPOSITION, disposition)], body).into_response())
}

pub fn router(state: Shared, access: Access) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(|| async { asset("text/javascript; charset=utf-8", APP_JS) }))
        .route("/style.css", get(|| async { asset("text/css; charset=utf-8", STYLE) }))
        .route("/icon.svg", get(|| async { asset("image/svg+xml", ICON) }))
        .route("/api/state", get(state_json))
        .route("/api/scan", post(start_scan))
        .route("/api/doctor", post(start_doctor))
        .route("/api/speedtest", post(start_speedtest_route))
        .route("/api/room-check", post(start_room_check))
        .route("/api/outages", get(outages))
        .route("/api/outages/report", get(outage_report))
        .route("/api/trust-all", post(trust_all))
        .route("/api/devices/{id}", patch(update_device).delete(forget_device))
        .route("/api/devices/{id}/wake", post(wake_device))
        .route("/api/devices/{id}/deep-scan", post(deep_scan))
        .route("/api/devices/{id}/why", post(why_device))
        .route("/api/devices/{id}/merge", post(merge_devices))
        .route("/api/devices/{id}/not-same", post(not_same))
        .route("/api/presence", get(presence))
        .route("/api/findings/{id}/ignore", post(ignore_finding).delete(unignore_finding))
        .route("/api/export/{format}", get(export))
        .route("/api/settings", patch(update_settings))
        .route("/api/notify-test", post(test_notification))
        .route("/api/alerts", post(add_alert))
        .route("/api/alerts/test", post(test_alerts))
        .route("/api/alerts/{index}", axum::routing::delete(remove_alert))
        .route("/api/phone", get(phone_status).post(update_phone))
        .layer(middleware::from_fn_with_state((state.clone(), access), guard))
        .with_state(state)
}

pub struct ServeOptions {
    pub listen: SocketAddr,
    pub open_browser: bool,
    pub scan_on_start: bool,
    pub scan_opts: ScanOptions,
    pub data_dir: PathBuf,
    pub service_mode: bool,
}

/// Whether a NattoWok dashboard is already answering at `addr`.
async fn already_running(addr: SocketAddr) -> bool {
    let probe_addr = if addr.ip().is_unspecified() { SocketAddr::from(([127, 0, 0, 1], addr.port())) } else { addr };
    crate::http::get(probe_addr, &format!("localhost:{}", addr.port()), "/", Duration::from_secs(2))
        .await
        .is_ok_and(|r| r.body.contains("nattowok-token"))
}

pub async fn serve(opts: ServeOptions) -> Result<()> {
    let workspace = Workspace::new(opts.data_dir);
    let (key, inventory) = workspace.load_current(opts.scan_opts.interface.as_deref())?;
    let settings = SettingsCell::new(workspace.root());
    let current = Current::new(&workspace, key, inventory.clone());
    let remote = !opts.listen.ip().is_loopback();
    let token = random_token();
    let has_report = inventory.last_report.is_some();
    let last_room_check = crate::room::load_last(workspace.root());
    let state = Arc::new(AppState {
        workspace,
        current: Mutex::new(current),
        scan: Arc::default(),
        doctor: Arc::default(),
        diagnosis: Mutex::new(None),
        speed: Arc::default(),
        room: Arc::default(),
        room_check: Mutex::new(last_room_check),
        outage_live: Mutex::default(),
        scan_opts: opts.scan_opts,
        settings: Mutex::new(settings),
        phone: Mutex::new(None),
        port: std::sync::OnceLock::new(),
        service_mode: opts.service_mode,
        token: token.clone(),
        remote,
    });
    let listener = match tokio::net::TcpListener::bind(opts.listen).await {
        Ok(l) => l,
        // Most likely the background service: just open that one.
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && already_running(opts.listen).await => {
            let url = format!("http://localhost:{}/", opts.listen.port());
            println!("NattoWok is already running (probably in the background): {url}");
            if opts.open_browser {
                open_browser(&url);
            }
            return Ok(());
        }
        Err(e) => anyhow::bail!(
            "couldn't listen on {}: {e}. Another program is using that port; try --listen 127.0.0.1:0",
            opts.listen
        ),
    };
    let addr = listener.local_addr()?;
    let _ = state.port.set(addr.port());
    let url = if remote { format!("http://{addr}/?key={token}") } else { format!("http://localhost:{}/", addr.port()) };
    println!("NattoWok dashboard: {url}");
    if remote {
        println!("Anyone with this link can see your scan results. Press Ctrl+C to stop.");
    } else {
        println!("Only this computer can open it. Press Ctrl+C to stop.");
    }
    if opts.open_browser {
        open_browser(&url);
    }
    if opts.scan_on_start || !has_report {
        let _ = spawn_scan(state.clone(), opts.service_mode);
    }
    sync_phone(&state).await;
    if let Some(link) = phone_link(&state) {
        println!("Phones on your network can open: {link}");
    }
    tokio::spawn(auto_scan_loop(state.clone()));
    spawn_outage_monitor(state.clone());
    axum::serve(listener, router(state, Access::Local))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn open_browser(url: &str) {
    let result = if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).spawn()
    } else if cfg!(windows) {
        std::process::Command::new("cmd").args(["/C", "start", "", url]).spawn()
    } else {
        std::process::Command::new("xdg-open").arg(url).spawn()
    };
    if result.is_err() {
        println!("(Couldn't open a browser automatically; copy the link above.)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    fn test_state() -> Shared {
        Arc::new(AppState {
            workspace: Workspace::new(std::env::temp_dir().join(format!("nattowok-web-{}", std::process::id()))),
            current: Mutex::new(Current { key: "test".into(), inv: Inventory::default(), mtime: None }),
            settings: Mutex::new(SettingsCell { value: Settings::default(), mtime: None }),
            phone: Mutex::new(None),
            port: std::sync::OnceLock::new(),
            service_mode: false,
            scan: Arc::default(),
            doctor: Arc::default(),
            diagnosis: Mutex::new(None),
            speed: Arc::default(),
            room: Arc::default(),
            room_check: Mutex::default(),
            outage_live: Mutex::default(),
            scan_opts: ScanOptions::default(),
            token: "secret".into(),
            remote: false,
        })
    }

    async fn status(req: HttpRequest<Body>) -> StatusCode {
        router(test_state(), Access::Local).oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn serves_index_with_token() {
        let resp = router(test_state(), Access::Local)
            .oneshot(HttpRequest::get("/").header("host", "localhost:7878").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("secret"));
    }

    #[tokio::test]
    async fn blocks_dns_rebinding() {
        let req = HttpRequest::get("/").header("host", "evil.example:7878").body(Body::empty()).unwrap();
        assert_eq!(status(req).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn api_requires_token() {
        let req = HttpRequest::get("/api/state").header("host", "127.0.0.1:7878").body(Body::empty()).unwrap();
        assert_eq!(status(req).await, StatusCode::UNAUTHORIZED);
        let req = HttpRequest::get("/api/state")
            .header("host", "127.0.0.1:7878")
            .header("x-nattowok-token", "secret")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(req).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn presence_and_merge_endpoints() {
        let req = HttpRequest::get("/api/presence")
            .header("host", "localhost")
            .header("x-nattowok-token", "secret")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(req).await, StatusCode::OK);
        let req = HttpRequest::post("/api/devices/AA:AA:AA:AA:AA:AA/merge")
            .header("host", "localhost")
            .header("x-nattowok-token", "secret")
            .header("content-type", "application/json")
            .body(Body::from("{\"other\":\"BB:BB:BB:BB:BB:BB\"}"))
            .unwrap();
        assert_eq!(status(req).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn phone_access_needs_its_own_key_and_address() {
        let state = test_state();
        {
            let mut s = state.settings.lock().unwrap();
            s.value.phone_access = true;
            s.value.phone_key = Some("phonekey".into());
        }
        let app = || router(state.clone(), Access::Phone { host: "192.168.1.10:7878".into() });
        let get = |path: &str, host: &str, token: Option<&str>| {
            let mut r = HttpRequest::get(path).header("host", host);
            if let Some(t) = token {
                r = r.header("x-nattowok-token", t);
            }
            r.body(Body::empty()).unwrap()
        };
        let code = |r: Response| r.status();
        // Rebinding attempt with another host name.
        assert_eq!(
            code(app().oneshot(get("/?key=phonekey", "evil.example:7878", None)).await.unwrap()),
            StatusCode::FORBIDDEN
        );
        // No key, wrong key, the desktop token: all refused.
        assert_eq!(code(app().oneshot(get("/", "192.168.1.10:7878", None)).await.unwrap()), StatusCode::UNAUTHORIZED);
        assert_eq!(
            code(app().oneshot(get("/api/state", "192.168.1.10:7878", Some("secret"))).await.unwrap()),
            StatusCode::UNAUTHORIZED
        );
        // The phone key works, and the page carries it.
        let resp = app().oneshot(get("/?key=phonekey", "192.168.1.10:7878", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("phonekey"));
        assert_eq!(
            code(app().oneshot(get("/api/state", "192.168.1.10:7878", Some("phonekey"))).await.unwrap()),
            StatusCode::OK
        );
        // Turning it off applies immediately.
        state.settings.lock().unwrap().value.phone_access = false;
        assert_eq!(
            code(app().oneshot(get("/api/state", "192.168.1.10:7878", Some("phonekey"))).await.unwrap()),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn settings_are_never_echoed() {
        let state = test_state();
        state.settings.lock().unwrap().value.phone_key = Some("phonekey".into());
        let req = HttpRequest::get("/api/state")
            .header("host", "localhost")
            .header("x-nattowok-token", "secret")
            .body(Body::empty())
            .unwrap();
        let resp = router(state, Access::Local).oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("phonekey"));
    }

    #[tokio::test]
    async fn unknown_device_is_404() {
        let req = HttpRequest::patch("/api/devices/AA:BB:CC:DD:EE:FF")
            .header("host", "localhost")
            .header("x-nattowok-token", "secret")
            .header("content-type", "application/json")
            .body(Body::from("{\"trusted\":true}"))
            .unwrap();
        assert_eq!(status(req).await, StatusCode::NOT_FOUND);
    }
}
