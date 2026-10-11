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
use axum::extract::{Path, Query, Request, State};
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
use crate::scan::{self, ScanOptions};
use crate::settings::Settings;
#[cfg(feature = "tls")]
use crate::speedtest;
use crate::store::{DeviceUpdate, Inventory, Workspace};
use crate::{netinfo, notify, probe, report, security, wol};

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
    scan_opts: ScanOptions,
    settings: Mutex<Settings>,
    /// Started by `nattowok service install` rather than by hand.
    service_mode: bool,
    token: String,
    remote: bool,
}

type Shared = Arc<AppState>;

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

async fn guard(State(state): State<Shared>, req: Request, next: Next) -> Response {
    if !state.remote && !host_is_local(req.headers()) {
        return (StatusCode::FORBIDDEN, "NattoWok only answers requests addressed to localhost.").into_response();
    }
    let path = req.uri().path();
    if path.starts_with("/api/") {
        let token = req.headers().get("x-nattowok-token").and_then(|v| v.to_str().ok());
        if token != Some(state.token.as_str()) {
            return ApiError(StatusCode::UNAUTHORIZED, "missing or wrong access token; reload the page".into())
                .into_response();
        }
    }
    next.run(req).await
}

#[derive(Deserialize)]
struct KeyQuery {
    key: Option<String>,
}

async fn index(State(state): State<Shared>, Query(q): Query<KeyQuery>) -> Response {
    if state.remote && q.key.as_deref() != Some(state.token.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Html("<p>Open the link printed in the terminal (it includes an access key).</p>"),
        )
            .into_response();
    }
    let page = INDEX.replace("__NATTOWOK_TOKEN__", &state.token).replace("__VERSION__", env!("CARGO_PKG_VERSION"));
    ([(header::CACHE_CONTROL, "no-store")], Html(page)).into_response()
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

async fn state_json(State(state): State<Shared>) -> Json<serde_json::Value> {
    let cur = current(&state);
    let events: Vec<_> = cur.inv.events.iter().rev().take(300).cloned().collect();
    let since = Utc::now() - chrono::Duration::days(crate::store::PRESENCE_DAYS + 1);
    let scan_log: Vec<_> = cur.inv.scan_log.iter().filter(|t| **t >= since).collect();
    let settings = state.settings.lock().unwrap().clone();
    let next_scan_at = next_scan_due(&state, &cur, &settings);
    Json(json!({
        "settings": settings,
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
        if automatic && state.settings.lock().unwrap().notifications {
            notify::send_for(&events).await;
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
        let settings = state.settings.lock().unwrap().clone();
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
}

async fn update_settings(State(state): State<Shared>, Json(update): Json<SettingsUpdate>) -> ApiResult<Json<Settings>> {
    let mut s = state.settings.lock().unwrap();
    if let Some(m) = update.auto_scan_minutes {
        s.auto_scan_minutes = m.min(24 * 60);
    }
    if let Some(n) = update.notifications {
        s.notifications = n;
    }
    s.save(state.workspace.root())?;
    Ok(Json(s.clone()))
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
        _ => return Err(ApiError(StatusCode::BAD_REQUEST, "format must be csv, md or json".into())),
    };
    let disposition = format!("attachment; filename=\"network-{stamp}.{ext}\"");
    Ok(([(header::CONTENT_TYPE, mime.to_string()), (header::CONTENT_DISPOSITION, disposition)], body).into_response())
}

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(|| async { asset("text/javascript; charset=utf-8", APP_JS) }))
        .route("/style.css", get(|| async { asset("text/css; charset=utf-8", STYLE) }))
        .route("/icon.svg", get(|| async { asset("image/svg+xml", ICON) }))
        .route("/api/state", get(state_json))
        .route("/api/scan", post(start_scan))
        .route("/api/doctor", post(start_doctor))
        .route("/api/speedtest", post(start_speedtest_route))
        .route("/api/trust-all", post(trust_all))
        .route("/api/devices/{id}", patch(update_device).delete(forget_device))
        .route("/api/devices/{id}/wake", post(wake_device))
        .route("/api/devices/{id}/deep-scan", post(deep_scan))
        .route("/api/devices/{id}/merge", post(merge_devices))
        .route("/api/devices/{id}/not-same", post(not_same))
        .route("/api/presence", get(presence))
        .route("/api/findings/{id}/ignore", post(ignore_finding).delete(unignore_finding))
        .route("/api/export/{format}", get(export))
        .route("/api/settings", patch(update_settings))
        .route("/api/notify-test", post(test_notification))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
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
    let settings = Settings::load(workspace.root());
    let current = Current::new(&workspace, key, inventory.clone());
    let remote = !opts.listen.ip().is_loopback();
    let token = random_token();
    let has_report = inventory.last_report.is_some();
    let state = Arc::new(AppState {
        workspace,
        current: Mutex::new(current),
        scan: Arc::default(),
        doctor: Arc::default(),
        diagnosis: Mutex::new(None),
        speed: Arc::default(),
        scan_opts: opts.scan_opts,
        settings: Mutex::new(settings),
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
    tokio::spawn(auto_scan_loop(state.clone()));
    axum::serve(listener, router(state))
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
            settings: Mutex::new(Settings::default()),
            service_mode: false,
            scan: Arc::default(),
            doctor: Arc::default(),
            diagnosis: Mutex::new(None),
            speed: Arc::default(),
            scan_opts: ScanOptions::default(),
            token: "secret".into(),
            remote: false,
        })
    }

    async fn status(req: HttpRequest<Body>) -> StatusCode {
        router(test_state()).oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn serves_index_with_token() {
        let resp = router(test_state())
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
