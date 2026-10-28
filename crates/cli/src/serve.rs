//! `@ --serve <addr>`: the scanner as an HTTP service, so a dashboard such as
//! truebrew can start scans and build its tables from the reports.
//!
//! Every route but `/health` needs `Authorization: Bearer <key>`, the key
//! being the contents of `--key-file`. The file is read on each request, so
//! it may appear after startup; without one those routes refuse everything.
//!
//! - `GET /api/scans`: every kept scan, newest first, with counts, and for
//!   one still going, its `progress` (see `progress.rs`)
//! - `POST /api/scans` `{ target, no_discovery?, probe_rate_limit?, strict_tls? }`: start one
//! - `GET /api/scans/{id}`: one scan with its full report, or its progress
//! - `DELETE /api/scans/{id}`: forget a finished scan

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use scanner::target::Target;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{Mutex, Semaphore};

use crate::progress::Progress;
use crate::{scan_target, ScanOptions};

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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Options {
    #[serde(default)]
    no_discovery: bool,
    #[serde(default)]
    probe_rate_limit: bool,
    #[serde(default)]
    strict_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Scan {
    id: String,
    target: String,
    options: Options,
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
    /// The row a scans table shows: everything but the report, with counts
    /// of what it found.
    fn summary(&self) -> Value {
        let report = self.report.as_ref();
        let count = |key: &str| {
            report
                .and_then(|r| r[key].as_array())
                .map_or(0, Vec::len)
        };
        let (mut high, mut medium, mut low, mut info) = (0, 0, 0, 0);
        for f in report.and_then(|r| r["findings"].as_array()).into_iter().flatten() {
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
            "options": self.options,
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
    key_file: Option<PathBuf>,
    data: Option<PathBuf>,
    slots: Semaphore,
    /// Where each scan still going is.
    live: std::sync::Mutex<HashMap<String, Arc<Progress>>>,
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
}

pub async fn run(
    addr: &str,
    key_file: Option<PathBuf>,
    data: Option<PathBuf>,
) -> anyhow::Result<()> {
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
    if key_file.is_none() {
        eprintln!("@: warning: no --key-file, so the API refuses every request");
    }
    let app = Arc::new(App {
        scans: Mutex::new(scans),
        key_file,
        data,
        slots: Semaphore::new(RUNNING),
        live: std::sync::Mutex::new(HashMap::new()),
    });

    let api = Router::new()
        .route("/api/scans", get(list).post(create))
        .route("/api/scans/{id}", get(show).delete(remove))
        .route_layer(middleware::from_fn_with_state(app.clone(), authorize))
        .with_state(app);
    let router = Router::new()
        .route("/health", get(|| async { Json(json!({ "ok": true })) }))
        .merge(api);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("@: serving on {addr}");
    axum::serve(listener, router).await?;
    Ok(())
}

async fn authorize(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    let key = app
        .key_file
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty());
    let ok = match key {
        Some(k) => req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|given| same(k.as_bytes(), given.as_bytes())),
        None => false,
    };
    if !ok {
        return error(StatusCode::UNAUTHORIZED, "missing or wrong key");
    }
    next.run(req).await
}

/// Compares in constant time for equal lengths.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn error(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
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
    target: String,
    #[serde(flatten)]
    options: Options,
}

async fn create(State(app): State<Arc<App>>, Json(req): Json<NewScan>) -> Response {
    let target = req.target.trim().to_string();
    if target.is_empty() {
        return error(StatusCode::BAD_REQUEST, "enter a host, host:port or IP");
    }
    if let Err(e) = Target::parse(&target) {
        return error(StatusCode::BAD_REQUEST, &e);
    }
    let scan = Scan {
        id: new_id(),
        target: target.clone(),
        options: req.options.clone(),
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
    tokio::spawn(execute(app, id, target, req.options));
    (StatusCode::ACCEPTED, Json(summary)).into_response()
}

/// Runs one scan once a slot is free. The scan itself runs on its own
/// thread and runtime, so a long one never holds up the API.
async fn execute(app: Arc<App>, id: String, target: String, o: Options) {
    let _slot = app.slots.acquire().await;
    let progress = app
        .live
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&id)
        .cloned()
        .unwrap_or_default();
    app.update(&id, |s| s.status = Status::Running).await;
    let opts = ScanOptions {
        target,
        no_discovery: o.no_discovery,
        connect_timeout: Duration::from_millis(800),
        http_timeout: Duration::from_secs(6),
        concurrency: 256,
        probe_rate_limit: o.probe_rate_limit,
        burst: 15,
        strict_tls: o.strict_tls,
        paths: None,
    };
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
    let result = rx.await.unwrap_or_else(|_| Err("the scan stopped unexpectedly".into()));
    app.live.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    app.update(&id, |s| {
        s.finished = Some(now_ms());
        match result {
            Ok(report) => {
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
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// A scan id: the time it was made and a counter, in hex.
fn new_id() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!("{:x}{:04x}", now_ms(), N.fetch_add(1, Ordering::Relaxed) & 0xffff)
}
