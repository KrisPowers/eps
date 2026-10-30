//! HTTP(S) endpoint discovery and security-posture checks.
//!
//! For each HTTP-speaking port we:
//!   1. decide the scheme (honoring the port's catalog hint, else probing),
//!   2. request each conventional path (redirects are *not* followed, so we can
//!      see a login redirect for what it is), and
//!   3. classify what we got back: is it reachable without auth, is it served
//!      over TLS, and does it advertise/enforce rate limiting.
//!
//! Every request is a plain `GET`. Nothing is written, submitted, or mutated.
//! An HTTPS service's certificate and legacy TLS support are read too (see
//! [`tls`]).

use std::time::Duration;

use futures::stream::{self, StreamExt};
use reqwest::{redirect::Policy, Client, StatusCode};

pub mod paths;
pub mod tls;

/// Response headers that indicate rate limiting is advertised or active.
const RATE_LIMIT_HEADERS: &[&str] = &[
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "retry-after",
    "x-envoy-ratelimited",
];

/// One conventional path to probe.
#[derive(Debug, Clone)]
pub struct PathSpec {
    pub path: String,
    pub sensitive: bool,
    pub note: String,
}

/// Configuration for the HTTP phase.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub timeout: Duration,
    pub concurrency: usize,
    pub paths: Vec<PathSpec>,
    /// When true, send a small bounded burst to each open endpoint to observe
    /// whether throttling actually kicks in (opt-in; passive detection is always on).
    pub active_rate_probe: bool,
    pub active_rate_count: usize,
    /// Reject invalid/self-signed certs (default: accept them so internal
    /// services can still be inspected; the scheme is reported either way).
    pub strict_tls: bool,
    pub user_agent: String,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            timeout: Duration::from_secs(6),
            concurrency: 16,
            paths: default_paths(),
            active_rate_probe: false,
            active_rate_count: 15,
            strict_tls: false,
            user_agent: concat!("portscan/", env!("CARGO_PKG_VERSION"), " (read-only recon)").to_string(),
        }
    }
}

/// The built-in conventional path list.
pub fn default_paths() -> Vec<PathSpec> {
    paths::DEFAULT
        .iter()
        .map(|k| PathSpec {
            path: k.path.to_string(),
            sensitive: k.sensitive,
            note: k.note.to_string(),
        })
        .collect()
}

/// How an endpoint responded to an unauthenticated request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// 2xx without credentials - reachable by anyone.
    Open,
    /// 401/403 - an auth or authorization gate is in place.
    Protected,
    /// 3xx - redirected (often to a login page).
    Redirected,
    /// 429 - rate limited on the first hit.
    RateLimited,
    /// Exists but returned a server/other status (405, 5xx, ...).
    Present,
}

impl AuthState {
    pub fn label(self) -> &'static str {
        match self {
            AuthState::Open => "OPEN (no auth)",
            AuthState::Protected => "protected",
            AuthState::Redirected => "redirect",
            AuthState::RateLimited => "rate-limited",
            AuthState::Present => "present",
        }
    }
}

/// Passive + optional active rate-limit observations for one endpoint.
#[derive(Debug, Clone, Default)]
pub struct RateLimitInfo {
    /// Rate-limit-related headers seen on the response.
    pub headers_seen: Vec<String>,
    /// Value of `Retry-After`, if present.
    pub retry_after: Option<String>,
    /// If an active burst was run: `Some((requests_sent, throttled))`.
    pub active: Option<(usize, bool)>,
}

impl RateLimitInfo {
    /// Whether any rate limiting was advertised or observed.
    pub fn any_signal(&self) -> bool {
        !self.headers_seen.is_empty()
            || self.retry_after.is_some()
            || matches!(self.active, Some((_, true)))
    }
}

/// A single discovered, existing endpoint and its posture.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub url: String,
    pub path: String,
    pub status: u16,
    pub auth: AuthState,
    pub tls: bool,
    pub sensitive: bool,
    pub note: String,
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub www_authenticate: Option<String>,
    pub location: Option<String>,
    pub rate_limit: RateLimitInfo,
}

/// Result of inspecting one HTTP(S) service (one port).
#[derive(Debug, Clone)]
pub struct ServiceReport {
    pub port: u16,
    pub scheme: String,
    pub reachable: bool,
    pub endpoints: Vec<Endpoint>,
    /// For HTTPS, what its TLS showed.
    pub tls: Option<tls::TlsReport>,
}

fn build_client(cfg: &HttpConfig) -> anyhow::Result<Client> {
    Ok(Client::builder()
        .user_agent(cfg.user_agent.clone())
        .timeout(cfg.timeout)
        .connect_timeout(cfg.timeout)
        .redirect(Policy::none())
        .danger_accept_invalid_certs(!cfg.strict_tls)
        .tls_info(true)
        .tcp_nodelay(true)
        .build()?)
}

fn authority(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

/// Decide whether a port speaks HTTP and over which scheme, with the
/// certificate it presented over HTTPS. `hint` is the catalog guess:
/// `Some(true)` HTTPS, `Some(false)` HTTP, `None` unknown.
async fn detect_scheme(
    client: &Client,
    host: &str,
    port: u16,
    hint: Option<bool>,
) -> Option<(&'static str, Option<Vec<u8>>)> {
    let order: &[&str] = match hint {
        Some(true) => &["https"],
        Some(false) => &["http"],
        None => &["https", "http"],
    };
    for scheme in order {
        let url = format!("{scheme}://{}/", authority(host, port));
        // Any HTTP response (even an error status) proves the scheme speaks HTTP.
        if let Ok(resp) = client.get(&url).send().await {
            let cert = resp
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .and_then(|t| t.peer_certificate())
                .map(<[u8]>::to_vec);
            return Some((scheme, cert));
        }
    }
    None
}

fn classify(status: StatusCode) -> Option<AuthState> {
    match status.as_u16() {
        404 | 410 => None, // does not exist here
        s if (200..300).contains(&s) => Some(AuthState::Open),
        401 | 403 => Some(AuthState::Protected),
        429 => Some(AuthState::RateLimited),
        s if (300..400).contains(&s) => Some(AuthState::Redirected),
        _ => Some(AuthState::Present),
    }
}

fn header_str(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn collect_rate_headers(resp: &reqwest::Response) -> RateLimitInfo {
    let mut info = RateLimitInfo::default();
    for name in RATE_LIMIT_HEADERS {
        if resp.headers().contains_key(*name) {
            info.headers_seen.push((*name).to_string());
        }
    }
    info.retry_after = header_str(resp, "retry-after");
    info
}

/// Send a small sequential burst to `url`, returning how many requests were
/// sent and whether a `429` was observed. Stops early on the first throttle.
async fn active_rate_probe(client: &Client, url: &str, count: usize) -> (usize, bool) {
    let mut sent = 0;
    for _ in 0..count {
        sent += 1;
        match client.get(url).send().await {
            Ok(resp) if resp.status().as_u16() == 429 => return (sent, true),
            Ok(_) => {}
            Err(_) => return (sent, false),
        }
    }
    (sent, false)
}

async fn inspect_path(
    client: &Client,
    scheme: &str,
    host: &str,
    port: u16,
    spec: &PathSpec,
    cfg: &HttpConfig,
    tls: bool,
) -> Option<Endpoint> {
    let url = format!("{scheme}://{}{}", authority(host, port), spec.path);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status();
    let auth = classify(status)?;

    let mut rate_limit = collect_rate_headers(&resp);
    let server = header_str(&resp, "server");
    let content_type = header_str(&resp, "content-type");
    let www_authenticate = header_str(&resp, "www-authenticate");
    let location = header_str(&resp, "location");

    // Optional active throttling probe - only for openly reachable endpoints,
    // and only when the user explicitly opted in.
    if cfg.active_rate_probe && auth == AuthState::Open {
        rate_limit.active = Some(active_rate_probe(client, &url, cfg.active_rate_count).await);
    }

    Some(Endpoint {
        url,
        path: spec.path.clone(),
        status: status.as_u16(),
        auth,
        tls,
        sensitive: spec.sensitive,
        note: spec.note.clone(),
        server,
        content_type,
        www_authenticate,
        location,
        rate_limit,
    })
}

/// Inspect one HTTP-capable port end to end.
pub async fn inspect_service(
    host: &str,
    port: u16,
    hint: Option<bool>,
    cfg: &HttpConfig,
) -> anyhow::Result<ServiceReport> {
    let client = build_client(cfg)?;

    let (scheme, cert) = match detect_scheme(&client, host, port, hint).await {
        Some(found) => found,
        None => {
            return Ok(ServiceReport {
                port,
                scheme: "http".to_string(),
                reachable: false,
                endpoints: Vec::new(),
                tls: None,
            })
        }
    };
    let tls = scheme == "https";
    let tls_report = if tls {
        Some(tls::TlsReport {
            cert: cert.as_deref().and_then(tls::parse),
            legacy: tls::legacy(host, port, cfg.timeout.min(Duration::from_secs(3))).await,
        })
    } else {
        None
    };

    let endpoints: Vec<Endpoint> = stream::iter(cfg.paths.iter())
        .map(|spec| {
            let client = &client;
            async move { inspect_path(client, scheme, host, port, spec, cfg, tls).await }
        })
        .buffer_unordered(cfg.concurrency.max(1))
        .filter_map(|e| async move { e })
        .collect()
        .await;

    let mut endpoints = endpoints;
    endpoints.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(ServiceReport {
        port,
        scheme: scheme.to_string(),
        reachable: true,
        endpoints,
        tls: tls_report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_statuses() {
        assert_eq!(classify(StatusCode::OK), Some(AuthState::Open));
        assert_eq!(
            classify(StatusCode::UNAUTHORIZED),
            Some(AuthState::Protected)
        );
        assert_eq!(classify(StatusCode::FORBIDDEN), Some(AuthState::Protected));
        assert_eq!(
            classify(StatusCode::TEMPORARY_REDIRECT),
            Some(AuthState::Redirected)
        );
        assert_eq!(
            classify(StatusCode::TOO_MANY_REQUESTS),
            Some(AuthState::RateLimited)
        );
        assert_eq!(classify(StatusCode::NOT_FOUND), None);
        assert_eq!(
            classify(StatusCode::INTERNAL_SERVER_ERROR),
            Some(AuthState::Present)
        );
    }

    #[test]
    fn rate_signal_detection() {
        let mut info = RateLimitInfo::default();
        assert!(!info.any_signal());
        info.headers_seen.push("x-ratelimit-limit".to_string());
        assert!(info.any_signal());
    }

    #[test]
    fn default_paths_nonempty_and_tagged() {
        let p = default_paths();
        assert!(p.len() > 20);
        assert!(p.iter().any(|s| s.sensitive));
        assert!(p.iter().any(|s| s.path == "/actuator/env" && s.sensitive));
    }
}
