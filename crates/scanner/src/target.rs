//! Parsing of the `host[:port]` target syntax.
//!
//! Accepted forms (a leading `@`, the command's own name, is optional and
//! ignored, so `@10.0.0.1` and `10.0.0.1` are the same target):
//!
//! ```text
//! @192.168.1.10          -> scan every port on an IPv4 host
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
        let s = raw.trim();
        let s = s.strip_prefix('@').unwrap_or(s).trim_start();
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

fn parse_port(p: &str) -> Result<u16, String> {
    p.parse::<u16>()
        .map_err(|_| format!("`{p}` is not a valid port (expected 1-65535)"))
        .and_then(|n| {
            if n == 0 {
                Err("port 0 is not valid".to_string())
            } else {
                Ok(n)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_no_port() {
        let t = Target::parse("@192.168.1.10").unwrap();
        assert_eq!(t.host, "192.168.1.10");
        assert_eq!(t.port, None);
        assert!(!t.is_ipv6);
    }

    #[test]
    fn at_with_space() {
        let t = Target::parse("@ 192.168.1.10:8080").unwrap();
        assert_eq!(t.host, "192.168.1.10");
        assert_eq!(t.port, Some(8080));
    }

    #[test]
    fn ipv4_with_port() {
        let t = Target::parse("@192.168.1.10:8080").unwrap();
        assert_eq!(t.host, "192.168.1.10");
        assert_eq!(t.port, Some(8080));
    }

    #[test]
    fn prefix_is_optional() {
        assert_eq!(Target::parse("10.0.0.1").unwrap().host, "10.0.0.1");
    }

    #[test]
    fn hostname() {
        let t = Target::parse("@example.internal:443").unwrap();
        assert_eq!(t.host, "example.internal");
        assert_eq!(t.port, Some(443));
        assert!(!t.is_ipv6);
    }

    #[test]
    fn bracketed_ipv6_with_port() {
        let t = Target::parse("@[2001:db8::1]:443").unwrap();
        assert_eq!(t.host, "2001:db8::1");
        assert_eq!(t.port, Some(443));
        assert!(t.is_ipv6);
        assert_eq!(t.url_host(), "[2001:db8::1]");
    }

    #[test]
    fn bare_ipv6_no_port() {
        let t = Target::parse("@2001:db8::1").unwrap();
        assert!(t.is_ipv6);
        assert_eq!(t.port, None);
    }

    #[test]
    fn rejects_bad_port() {
        assert!(Target::parse("@10.0.0.1:0").is_err());
        assert!(Target::parse("@10.0.0.1:70000").is_err());
        assert!(Target::parse("@10.0.0.1:abc").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(Target::parse("@").is_err());
        assert!(Target::parse("").is_err());
    }
}
