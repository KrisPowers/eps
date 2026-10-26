//! Catalog of conventional, framework-published endpoint paths.
//!
//! These are well-known paths that application runtimes and frameworks expose
//! by default (health probes, metrics, API docs, management consoles). Probing
//! them is a conventional discovery step, not brute force. Paths flagged
//! `sensitive` are ones that frequently leak configuration, internals, or
//! control surfaces when left unauthenticated.

/// A conventional endpoint path and whether exposure without auth is notable.
pub struct KnownPath {
    pub path: &'static str,
    /// True when an unauthenticated 2xx here is a meaningful finding.
    pub sensitive: bool,
    /// Short note on what the path usually is.
    pub note: &'static str,
}

