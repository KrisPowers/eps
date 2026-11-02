//! HTTP(S) endpoint discovery and security-posture checks.
//!
//! For each HTTP-speaking port we:
//!   1. decide the scheme (honoring the port's catalog hint, else probing),
//!   2. request each conventional path (redirects are *not* followed, so we can
//!      see a login redirect for what it is), and
//!   3. classify what we got back: is it reachable without auth, is it served
//!      over TLS, does it advertise/enforce rate limiting, and which security
//!      headers and cookie flags it sends.
//!
//! Every request is a plain `GET`. Nothing is written, submitted, or mutated.
//! An HTTPS service's certificate and legacy TLS support are read too (see
//! [`tls`]), any OpenAPI or Swagger document it serves openly ([`api`]), and
//! the website on it: its paths, and what its pages would do in a visitor's
//! browser ([`site`]).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use futures::stream::{self, StreamExt};
use reqwest::{redirect::Policy, Client, StatusCode};

pub mod api;
pub mod code;
pub mod names;
pub mod paths;
pub mod site;
pub mod tls;
pub mod wordpress;

/// The most of a response body any check reads. A service can answer with
/// an endless or decompression-bomb body; the scan keeps only this much.
pub const MOST_BODY: usize = 8 * 1024 * 1024;

/// A response's body, read up to `max` bytes and no further.
pub async fn capped(mut resp: reqwest::Response, max: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.ok()? {
        let room = max - out.len();
        out.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if out.len() >= max {
            break;
        }
    }
    Some(out)
}

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
    /// Paths the site's crawl starts from besides `/`, such as a URL's own.
    pub start: Vec<String>,
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
            user_agent: concat!("eps/", env!("CARGO_PKG_VERSION"), " (read-only recon)")
                .to_string(),
            start: Vec::new(),
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

/// The security headers a response carried, as sent.
#[derive(Debug, Clone, Default)]
pub struct SecurityHeaders {
    pub hsts: Option<String>,
    pub csp: Option<String>,
    pub frame_options: Option<String>,
    pub content_type_options: Option<String>,
    /// `Access-Control-Allow-Origin`.
    pub cors_origin: Option<String>,
    /// `Access-Control-Allow-Credentials: true`.
    pub cors_credentials: bool,
    pub cookies: Vec<Cookie>,
}

/// A cookie a response set, with the flags that protect it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
}

/// Reads one `Set-Cookie` value. `None` when it names no cookie.
pub fn cookie(line: &str) -> Option<Cookie> {
    let mut parts = line.split(';');
    let name = parts.next()?.split('=').next()?.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let mut c = Cookie {
        name,
        secure: false,
        http_only: false,
        same_site: None,
    };
    for attr in parts {
        let (key, value) = attr.split_once('=').unwrap_or((attr, ""));
        let key = key.trim();
        if key.eq_ignore_ascii_case("secure") {
            c.secure = true;
        } else if key.eq_ignore_ascii_case("httponly") {
            c.http_only = true;
        } else if key.eq_ignore_ascii_case("samesite") {
            c.same_site = Some(value.trim().to_string());
        }
    }
    Some(c)
}

fn security_headers(resp: &reqwest::Response) -> SecurityHeaders {
    SecurityHeaders {
        hsts: header_str(resp, "strict-transport-security"),
        csp: header_str(resp, "content-security-policy"),
        frame_options: header_str(resp, "x-frame-options"),
        content_type_options: header_str(resp, "x-content-type-options"),
        cors_origin: header_str(resp, "access-control-allow-origin"),
        cors_credentials: header_str(resp, "access-control-allow-credentials")
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("true")),
        cookies: resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(cookie)
            .collect(),
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
    /// `X-Powered-By`, which often names the language or framework.
    pub powered_by: Option<String>,
    pub content_type: Option<String>,
    pub www_authenticate: Option<String>,
    pub location: Option<String>,
    pub rate_limit: RateLimitInfo,
    pub headers: SecurityHeaders,
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
    /// The API documents it serves without auth.
    pub apis: Vec<api::ApiSpec>,
    /// The website on it, mapped and read.
    pub site: Option<site::Site>,
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

/// A path no site has, asked for to see how the service answers what isn't
/// there.
const NOWHERE: &str = "/eps-7f3a9c1e-no-such-path";

/// How a service answers a path that can't exist. A single-page app or
/// catch-all serves the same page for every path, and an HTTP service that
/// upgrades to HTTPS redirects every path the same way, so a path answered
/// like one that can't exist isn't really there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Baseline {
    /// The same page for any path.
    Page { status: u16, len: usize, hash: u64 },
    /// A redirect for any path: to the same path elsewhere (`mirror`, as an
    /// HTTPS upgrade does), or always to `to`.
    Redirect {
        status: u16,
        mirror: bool,
        to: String,
    },
}

impl Baseline {
    fn page(status: u16, body: &[u8]) -> Self {
        let mut h = DefaultHasher::new();
        body.hash(&mut h);
        Baseline::Page {
            status,
            len: body.len(),
            hash: h.finish(),
        }
    }

    /// Whether a page is the same one, byte for byte or within 2% of its
    /// size (for pages that carry a token or timestamp).
    pub fn matches_page(&self, status: u16, body: &[u8]) -> bool {
        let (
            Baseline::Page {
                status: s,
                len,
                hash,
            },
            Baseline::Page {
                len: l, hash: h, ..
            },
        ) = (self, Baseline::page(status, body))
        else {
            return false;
        };
        status == *s && (h == *hash || len.abs_diff(l) * 50 <= (*len).max(1))
    }

    /// Whether a redirect from `path` to `location` is the blanket one.
    pub fn matches_redirect(&self, status: u16, path: &str, location: &str) -> bool {
        let Baseline::Redirect {
            status: s,
            mirror,
            to,
        } = self
        else {
            return false;
        };
        status == *s && (location == to || (*mirror && location_path(location) == path))
    }
}

/// The path a `Location` points at, absolute or relative, without query.
fn location_path(location: &str) -> String {
    match reqwest::Url::parse(location) {
        Ok(u) => u.path().to_string(),
        Err(_) => location.split(['?', '#']).next().unwrap_or("").to_string(),
    }
}

/// How the service answers [`NOWHERE`]; `None` when it says it isn't there.
async fn baseline(client: &Client, base: &str) -> Option<Baseline> {
    let resp = client.get(format!("{base}{NOWHERE}")).send().await.ok()?;
    let status = resp.status().as_u16();
    if (300..400).contains(&status) {
        let to = header_str(&resp, "location")?;
        let mirror = location_path(&to) == NOWHERE;
        return Some(Baseline::Redirect { status, mirror, to });
    }
    if !(200..300).contains(&status) {
        return None;
    }
    let body = capped(resp, MOST_BODY).await?;
    Some(Baseline::page(status, &body))
}

#[allow(clippy::too_many_arguments)]
async fn inspect_path(
    client: &Client,
    scheme: &str,
    host: &str,
    port: u16,
    spec: &PathSpec,
    cfg: &HttpConfig,
    tls: bool,
    soft404: Option<&Baseline>,
) -> Option<Endpoint> {
    let url = format!("{scheme}://{}{}", authority(host, port), spec.path);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status();
    let auth = classify(status)?;

    let mut rate_limit = collect_rate_headers(&resp);
    let server = header_str(&resp, "server");
    let powered_by = header_str(&resp, "x-powered-by");
    let content_type = header_str(&resp, "content-type");
    let www_authenticate = header_str(&resp, "www-authenticate");
    let location = header_str(&resp, "location");
    let headers = security_headers(&resp);

    // On a service that answers every path, a path answered just like one
    // that can't exist isn't there. The root is always there: it's the site.
    if let Some(base) = soft404.filter(|_| spec.path != "/") {
        if status.is_redirection() {
            if base.matches_redirect(
                status.as_u16(),
                &spec.path,
                location.as_deref().unwrap_or(""),
            ) {
                return None;
            }
        } else if status.is_success() && matches!(base, Baseline::Page { .. }) {
            let body = capped(resp, MOST_BODY).await?;
            if base.matches_page(status.as_u16(), &body) {
                return None;
            }
        }
    }

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
        powered_by,
        content_type,
        www_authenticate,
        location,
        rate_limit,
        headers,
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
                apis: Vec::new(),
                site: None,
            })
        }
    };
    let tls = scheme == "https";
    let soft404 = baseline(&client, &format!("{scheme}://{}", authority(host, port))).await;
    let soft404 = soft404.as_ref();
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
            async move { inspect_path(client, scheme, host, port, spec, cfg, tls, soft404).await }
        })
        .buffer_unordered(cfg.concurrency.max(1))
        .filter_map(|e| async move { e })
        .collect()
        .await;

    let mut endpoints = endpoints;
    endpoints.sort_by(|a, b| a.path.cmp(&b.path));

    // Read each API document it serves openly, once per distinct document.
    let mut apis: Vec<api::ApiSpec> = Vec::new();
    let docs = endpoints
        .iter()
        .filter(|e| e.auth == AuthState::Open && api::SPEC_PATHS.contains(&e.path.as_str()));
    for ep in docs {
        let Ok(resp) = client.get(&ep.url).send().await else {
            continue;
        };
        let Some(body) = capped(resp, MOST_BODY).await else {
            continue;
        };
        if let Some(spec) = api::parse(&ep.url, &String::from_utf8_lossy(&body)) {
            let same = |a: &api::ApiSpec| a.title == spec.title && a.operations == spec.operations;
            if !apis.iter().any(same) {
                apis.push(spec);
            }
        }
    }

    let site = site::explore(
        &client,
        &format!("{scheme}://{}", authority(host, port)),
        &cfg.start,
        soft404,
    )
    .await;

    Ok(ServiceReport {
        port,
        scheme: scheme.to_string(),
        reachable: true,
        endpoints,
        tls: tls_report,
        apis,
        site: Some(site),
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
    fn baseline_matches_the_same_page() {
        let page = b"<html><div id=app></div></html>".repeat(40);
        let base = Baseline::page(200, &page);
        assert!(base.matches_page(200, &page));
        let mut nonce = page.clone();
        nonce.extend_from_slice(b"<!-- 1a2b -->");
        assert!(base.matches_page(200, &nonce));
        assert!(!base.matches_page(200, b"DB_PASSWORD=hunter2"));
        assert!(!base.matches_page(404, &page));
    }

    #[test]
    fn baseline_matches_a_blanket_redirect() {
        let upgrade = Baseline::Redirect {
            status: 301,
            mirror: true,
            to: format!("https://shop.example{NOWHERE}"),
        };
        assert!(upgrade.matches_redirect(301, "/.env", "https://shop.example/.env"));
        assert!(!upgrade.matches_redirect(301, "/.env", "https://shop.example/login"));
        assert!(!upgrade.matches_redirect(302, "/.env", "https://shop.example/.env"));
        let login = Baseline::Redirect {
            status: 302,
            mirror: false,
            to: "/login".to_string(),
        };
        assert!(login.matches_redirect(302, "/admin", "/login"));
        assert!(!login.matches_redirect(302, "/admin", "/admin/home"));
    }

    #[test]
    fn cookie_flags() {
        let c = cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax").unwrap();
        assert_eq!(c.name, "sid");
        assert!(c.secure && c.http_only);
        assert_eq!(c.same_site.as_deref(), Some("Lax"));
        let bare = cookie("theme=dark").unwrap();
        assert!(!bare.secure && !bare.http_only && bare.same_site.is_none());
        assert_eq!(cookie("=x; Secure"), None);
    }

    #[test]
    fn default_paths_nonempty_and_tagged() {
        let p = default_paths();
        assert!(p.len() > 20);
        assert!(p.iter().any(|s| s.sensitive));
        assert!(p.iter().any(|s| s.path == "/actuator/env" && s.sensitive));
    }
}
