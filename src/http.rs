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

use std::time::Duration;

use futures::stream::{self, StreamExt};
use reqwest::{redirect::Policy, Client, StatusCode};

use crate::paths;

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
            user_agent: concat!("at/", env!("CARGO_PKG_VERSION"), " (read-only recon)").to_string(),
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
