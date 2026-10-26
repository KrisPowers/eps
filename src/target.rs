//! Parsing of the `@host[:port]` target syntax.
//!
//! Accepted forms (the leading `@` is the tool's signature prefix and is
//! optional but canonical):
//!
//! ```text
//! @192.168.1.10          -> scan common ports on an IPv4 host
//! @192.168.1.10:8080     -> inspect a single port
//! @example.internal      -> hostnames are resolved via the system resolver
//! @[2001:db8::1]:443      -> bracketed IPv6 with a port
//! @2001:db8::1           -> bare IPv6 (no port)
//! ```

use std::net::{IpAddr, Ipv6Addr};

/// A parsed scan target: a host and an optional single port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Host as written, with any `@` prefix and IPv6 brackets stripped.
    pub host: String,
    /// A specific port, when the user pinned one (`:443`).
    pub port: Option<u16>,
    /// Whether `host` is a literal IPv6 address (affects URL formatting).
    pub is_ipv6: bool,
}

