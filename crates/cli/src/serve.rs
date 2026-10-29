//! `portscan --serve <addr>`: the dashboard. Serves the built web page from
//! `--web` and the API it runs on:
//!
//! - `GET /api/scans`: every kept scan, newest first, with counts, and for
//!   one still going, its `progress` (see `progress.rs`)
//! - `POST /api/scans` `{ command }`: start one. `command` is what you'd type
//!   in a terminal, `@ 192.168.1.10 --no-discovery`; the `@` may be left out
//! - `GET /api/scans/{id}`: one scan with its full report, or its progress
//! - `DELETE /api/scans/{id}`: forget a finished scan
//!
//! There is no sign-in, so only requests addressed to this computer
//! (`localhost`, `127.0.0.1`, `[::1]`) are answered; `PORTSCAN_HOSTS` adds
//! more names. That also stops a web page from reaching the API by pointing
//! its own domain at this computer.
//!
//! In a container, `localhost` is the container itself. `PORTSCAN_LOCALHOST`
//! names the host to scan instead when a scan asks for `localhost`, such as
//! `host.docker.internal`.

use std::collections::{HashMap, VecDeque};
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Request, State};
use axum::http::{header, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use clap::error::ErrorKind;
use clap::Parser;
use scanner::target::Target;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{Mutex, Semaphore};

use crate::progress::Progress;
use crate::cli::Cli;
use crate::{scan_options, scan_target, ScanOptions};

/// Scans kept, newest first; older ones are dropped.
const KEEP: usize = 100;
/// Scans running at once; the rest wait their turn.
const RUNNING: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Queued,
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Scan {
    id: String,
    target: String,
    /// The line it was started with.
    #[serde(default)]
    command: String,
    status: Status,
    /// Unix milliseconds.
    created: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    finished: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    report: Option<Value>,
}

impl Scan {
    /// The row a scans list shows: everything but the report, with counts
    /// of what it found.
    fn summary(&self) -> Value {
        let report = self.report.as_ref();
        let count = |key: &str| report.and_then(|r| r[key].as_array()).map_or(0, Vec::len);
        let (mut high, mut medium, mut low, mut info) = (0, 0, 0, 0);
        for f in report
            .and_then(|r| r["findings"].as_array())
            .into_iter()
            .flatten()
        {
            match f["severity"].as_str() {
                Some("high") => high += 1,
                Some("medium") => medium += 1,
                Some("low") => low += 1,
                _ => info += 1,
            }
        }
        json!({
            "id": self.id,
            "target": self.target,
            "command": self.command,
            "status": self.status,
            "created": self.created,
            "finished": self.finished,
            "error": self.error,
            "resolved_ip": report.and_then(|r| r["resolved_ip"].as_str()),
            "open_ports": count("open_ports"),
            "endpoints": count("endpoints"),
            "findings": { "high": high, "medium": medium, "low": low, "info": info },
        })
    }
}

struct App {
    scans: Mutex<VecDeque<Scan>>,
    web: Option<PathBuf>,
    data: Option<PathBuf>,
    slots: Semaphore,
    /// Where each scan still going is.
    live: std::sync::Mutex<HashMap<String, Arc<Progress>>>,
    /// Host names requests may be addressed to.
    hosts: Vec<String>,
    /// The host a scan of `localhost` goes to instead, when set.
    localhost: Option<String>,
}

impl App {
    /// A scan's row, with its progress while it's going.
    fn row(&self, s: &Scan) -> Value {
        let mut v = s.summary();
        let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = live.get(&s.id) {
            v["progress"] = p.snapshot();
        }
        v
    }

    async fn update(&self, id: &str, f: impl FnOnce(&mut Scan)) {
        let mut scans = self.scans.lock().await;
        if let Some(s) = scans.iter_mut().find(|s| s.id == id) {
            f(s);
        }
        self.save(&scans);
    }

    /// Writes the scans to the data folder, when there is one.
    fn save(&self, scans: &VecDeque<Scan>) {
        let Some(dir) = &self.data else { return };
        let tmp = dir.join("scans.json.tmp");
        if let Ok(b) = serde_json::to_vec(scans) {
            if std::fs::write(&tmp, b).is_ok() {
                let _ = std::fs::rename(&tmp, dir.join("scans.json"));
            }
        }
    }

    /// The target a scan actually runs against: `localhost` swapped for
    /// `PORTSCAN_LOCALHOST`, when that is set.
    fn scan_target(&self, target: &Target, raw: &str) -> String {
        let Some(alias) = &self.localhost else {
            return raw.to_string();
        };
        if !matches!(target.host.as_str(), "localhost" | "127.0.0.1" | "::1") {
            return raw.to_string();
        }
        match target.port {
            Some(p) => format!("{alias}:{p}"),
            None => alias.clone(),
        }
    }
}

pub async fn run(addr: &str, web: Option<PathBuf>, data: Option<PathBuf>) -> anyhow::Result<()> {
    let mut scans: VecDeque<Scan> = VecDeque::new();
    if let Some(dir) = &data {
        std::fs::create_dir_all(dir)?;
        if let Ok(b) = std::fs::read(dir.join("scans.json")) {
            scans = serde_json::from_slice(&b).unwrap_or_default();
        }
    }
    // A scan cut off by a restart can't pick up where it was.
    for s in scans.iter_mut() {
        if matches!(s.status, Status::Queued | Status::Running) {
            s.status = Status::Failed;
            s.error = Some("stopped by a restart".into());
        }
    }
    let mut hosts: Vec<String> = ["localhost", "127.0.0.1", "[::1]"]
        .map(String::from)
        .to_vec();
    if let Ok(extra) = std::env::var("PORTSCAN_HOSTS") {
        hosts.extend(
            extra
                .split(',')
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty()),
        );
    }
    let localhost = std::env::var("PORTSCAN_LOCALHOST")
        .ok()
        .filter(|h| !h.trim().is_empty());
    let app = Arc::new(App {
        scans: Mutex::new(scans),
        web,
        data,
        slots: Semaphore::new(RUNNING),
        live: std::sync::Mutex::new(HashMap::new()),
        hosts,
        localhost,
    });

    let router = Router::new()
        .route("/health", get(|| async { Json(json!({ "ok": true })) }))
        .route("/api/scans", get(list).post(create))
        .route("/api/scans/{id}", get(show).delete(remove))
        .fallback(static_file)
        .layer(middleware::from_fn_with_state(app.clone(), local_only))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("portscan: dashboard on http://{addr}");
    axum::serve(listener, router).await?;
    Ok(())
}

/// Answers only requests addressed to a name in `hosts`.
async fn local_only(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    // Drop the port: `[::1]:8090` -> `[::1]`, `localhost:8090` -> `localhost`.
    let name = match host.rfind(':') {
        Some(i) if !host[i..].contains(']') => &host[..i],
        _ => host.as_str(),
    };
    if req.uri().path() != "/health" && !app.hosts.iter().any(|h| h == name) {
        return error(
            StatusCode::FORBIDDEN,
            "open the dashboard at localhost, or add this name to PORTSCAN_HOSTS",
        );
    }
    next.run(req).await
}

fn error(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

/// Serves the dashboard's files, and its page for any other path.
async fn static_file(State(app): State<Arc<App>>, uri: Uri) -> Response {
    let Some(dir) = &app.web else {
        return error(StatusCode::NOT_FOUND, "not found");
    };
    let rel = uri.path().trim_start_matches('/');
    if rel.starts_with("api/") {
        return error(StatusCode::NOT_FOUND, "not found");
    }
    let safe = !rel.split('/').any(|p| p == ".." || p.contains('\\'));
    let file = dir.join(rel);
    let path = if safe && !rel.is_empty() && file.is_file() {
        file
    } else {
        dir.join("index.html")
    };
    let Ok(body) = std::fs::read(&path) else {
        return error(StatusCode::NOT_FOUND, "not found");
    };
    // Built assets carry a content hash in their name, so they never change.
    let cache = if rel.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    (
        [
            (header::CONTENT_TYPE, content_type(&path)),
            (header::CACHE_CONTROL, cache),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

fn content_type(path: &FsPath) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

async fn list(State(app): State<Arc<App>>) -> Json<Value> {
    let scans = app.scans.lock().await;
    Json(json!({ "scans": scans.iter().map(|s| app.row(s)).collect::<Vec<_>>() }))
}

async fn show(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let scans = app.scans.lock().await;
    match scans.iter().find(|s| s.id == id) {
        Some(s) => {
            let mut v = app.row(s);
            v["report"] = s.report.clone().unwrap_or(Value::Null);
            Json(v).into_response()
        }
        None => error(StatusCode::NOT_FOUND, "no such scan"),
    }
}

async fn remove(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let mut scans = app.scans.lock().await;
    let Some(i) = scans.iter().position(|s| s.id == id) else {
        return error(StatusCode::NOT_FOUND, "no such scan");
    };
    if matches!(scans[i].status, Status::Queued | Status::Running) {
        return error(StatusCode::CONFLICT, "the scan is still running");
    }
    scans.remove(i);
    app.save(&scans);
    Json(json!({ "ok": true })).into_response()
}

#[derive(Deserialize)]
struct NewScan {
    command: String,
}

/// Reads a line typed into the dashboard the way the terminal would: `@`, a
/// target and any of the CLI's options. The `@` may be left out.
fn parse_command(line: &str) -> Result<Cli, String> {
    let mut words: Vec<&str> = line.split_whitespace().collect();
    if words.first() == Some(&"@") {
        words.remove(0);
    }
    let argv = std::iter::once("@").chain(words);
    let args = Cli::try_parse_from(argv).map_err(|e| match e.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            "the options are listed in the README".to_string()
        }
        _ => {
            let text = e.to_string();
            let first = text.lines().next().unwrap_or("");
            first.trim_start_matches("error: ").to_string()
        }
    })?;
    if args.serve.is_some() || args.paths.is_some() {
        return Err("--serve and --paths only work in a terminal".into());
    }
    Ok(args)
}

async fn create(State(app): State<Arc<App>>, Json(req): Json<NewScan>) -> Response {
    let args = match parse_command(&req.command) {
        Ok(a) => a,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    let parsed = match Target::parse(&args.target) {
        Ok(t) => t,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    let mut opts = scan_options(&args, None);
    opts.target = app.scan_target(&parsed, &args.target);
    let scan = Scan {
        id: new_id(),
        target: args.target.trim_start_matches('@').trim().to_string(),
        command: req.command.trim().to_string(),
        status: Status::Queued,
        created: now_ms(),
        finished: None,
        error: None,
        report: None,
    };
    let id = scan.id.clone();
    let summary = scan.summary();
    app.live
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.clone(), Arc::new(Progress::default()));
    {
        let mut scans = app.scans.lock().await;
        scans.push_front(scan);
        scans.truncate(KEEP);
        app.save(&scans);
    }
    tokio::spawn(execute(app, id, opts, parsed.host));
    (StatusCode::ACCEPTED, Json(summary)).into_response()
}

/// Runs one scan once a slot is free. The scan itself runs on its own
/// thread and runtime, so a long one never holds up the API. `host` is the
/// host as typed, which the report names even when `localhost` was swapped.
async fn execute(app: Arc<App>, id: String, opts: ScanOptions, host: String) {
    let _slot = app.slots.acquire().await;
    let progress = app
        .live
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&id)
        .cloned()
        .unwrap_or_default();
    app.update(&id, |s| s.status = Status::Running).await;
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<Value, String>>();
    std::thread::spawn(move || {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())
            .and_then(|rt| {
                rt.block_on(async {
                    scan_target(&opts, &progress)
                        .await
                        .map(|out| serde_json::to_value(&out.report).unwrap_or(Value::Null))
                        .map_err(|e| format!("{e:#}"))
                })
            });
        let _ = tx.send(result);
    });
    let result = rx
        .await
        .unwrap_or_else(|_| Err("the scan stopped unexpectedly".into()));
    app.live
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
    app.update(&id, |s| {
        s.finished = Some(now_ms());
        match result {
            Ok(mut report) => {
                report["target"] = json!(host);
                s.status = Status::Done;
                s.report = Some(report);
            }
            Err(e) => {
                s.status = Status::Failed;
                s.error = Some(e);
            }
        }
    })
    .await;
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// A scan id: the time it was made and a counter, in hex.
fn new_id() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!(
        "{:x}{:04x}",
        now_ms(),
        N.fetch_add(1, Ordering::Relaxed) & 0xffff
    )
}
