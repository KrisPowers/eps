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

impl Target {
    /// Parse a raw argument such as `@10.0.0.1:8080` into a [`Target`].
    pub fn parse(raw: &str) -> Result<Target, String> {
        let s = raw.trim().strip_prefix('@').unwrap_or(raw.trim());
        if s.is_empty() {
            return Err("empty target".to_string());
        }

        // Bracketed IPv6, optionally with a port: [::1] or [::1]:443
        if let Some(rest) = s.strip_prefix('[') {
            let (inside, after) = rest
                .split_once(']')
                .ok_or_else(|| format!("unterminated IPv6 bracket in `{raw}`"))?;
            let addr: Ipv6Addr = inside
                .parse()
                .map_err(|_| format!("`{inside}` is not a valid IPv6 address"))?;
            let port = match after {
                "" => None,
                p => Some(parse_port(p.strip_prefix(':').unwrap_or(p))?),
            };
            return Ok(Target {
                host: addr.to_string(),
                port,
                is_ipv6: true,
            });
        }

        // Bare IPv6 (contains multiple colons and no brackets) -> no port allowed.
        if s.matches(':').count() > 1 {
            let addr: Ipv6Addr = s.parse().map_err(|_| {
                format!(
                    "`{s}` looks like IPv6 but did not parse; wrap it as [addr]:port to add a port"
                )
            })?;
            return Ok(Target {
                host: addr.to_string(),
                port: None,
                is_ipv6: true,
            });
        }

        // host[:port] for IPv4 or hostname.
        let (host, port) = match s.split_once(':') {
            Some((h, p)) => (h, Some(parse_port(p)?)),
            None => (s, None),
        };
        if host.is_empty() {
            return Err(format!("missing host in `{raw}`"));
        }

        let is_ipv6 = matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_)));
        Ok(Target {
            host: host.to_string(),
            port,
            is_ipv6,
        })
    }

    /// Format the host for use inside a URL authority (brackets IPv6).
    pub fn url_host(&self) -> String {
        if self.is_ipv6 {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }
}

