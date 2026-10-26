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
