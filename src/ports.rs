//! Curated catalog of common service ports and HTTP-likely hints.
//!
//! The default scan covers this list rather than all 65,535 ports so a bare
//! `at @host` stays fast and polite. Use `--full` for an exhaustive sweep or
//! `--ports` to supply your own set.

/// A well-known port with its usual service label and whether it typically
/// speaks HTTP (and if so, over TLS).
pub struct KnownPort {
    pub port: u16,
    pub service: &'static str,
    /// `Some(true)` = HTTPS, `Some(false)` = plaintext HTTP, `None` = not HTTP.
    pub http_tls: Option<bool>,
}

