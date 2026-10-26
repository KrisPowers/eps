//! TCP connect port scanning.
//!
//! This uses a normal `connect()` (the same operation any TCP client performs),
//! so it needs no elevated privileges and sends no crafted packets. A port is
//! reported *open* when the connection completes, *filtered* when it times out,
//! and otherwise *closed*.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::ports;

/// Outcome of probing a single port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    /// Connection attempt timed out (likely dropped by a firewall).
    Filtered,
}

/// A port that responded as open, with its best-guess service label.
#[derive(Debug, Clone)]
pub struct OpenPort {
    pub port: u16,
    pub service: &'static str,
    /// HTTP hint from the catalog: `Some(true)` HTTPS, `Some(false)` HTTP.
    pub http_tls: Option<bool>,
}

/// Resolve `host` to a set of socket addresses on an arbitrary port, returning
/// the distinct IPs the system resolver hands back.
pub async fn resolve(host: &str, is_ipv6: bool) -> anyhow::Result<Vec<IpAddr>> {
    // Literal IPs skip the resolver entirely.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let _ = is_ipv6;
    let addrs = tokio::net::lookup_host(format!("{host}:0")).await?;
    let mut ips: Vec<IpAddr> = addrs.map(|s| s.ip()).collect();
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        anyhow::bail!("could not resolve `{host}` to any address");
    }
    Ok(ips)
}

async fn probe(addr: SocketAddr, per_port_timeout: Duration) -> PortState {
    match timeout(per_port_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => PortState::Open,
        Ok(Err(_)) => PortState::Closed,
        Err(_) => PortState::Filtered,
    }
}

/// Scan `ports` on `ip`, probing up to `concurrency` ports at once. Returns the
/// open ports, sorted ascending, annotated with catalog hints.
pub async fn scan_ports(
    ip: IpAddr,
    ports_to_scan: &[u16],
    concurrency: usize,
    per_port_timeout: Duration,
) -> Vec<OpenPort> {
    let results = stream::iter(ports_to_scan.iter().copied())
        .map(|port| async move {
            let state = probe(SocketAddr::new(ip, port), per_port_timeout).await;
            (port, state)
        })
        .buffer_unordered(concurrency.max(1))
        .collect::<Vec<_>>()
        .await;

    let mut open: Vec<OpenPort> = results
        .into_iter()
        .filter(|(_, state)| *state == PortState::Open)
        .map(|(port, _)| OpenPort {
            port,
            service: ports::service_name(port),
            http_tls: ports::http_hint(port),
        })
        .collect();
    open.sort_by_key(|o| o.port);
    open
}

/// The default port set (the curated common list).
pub fn common_port_list() -> Vec<u16> {
    ports::COMMON.iter().map(|k| k.port).collect()
}

/// Every port, 1..=65535, for `--full`.
pub fn full_port_list() -> Vec<u16> {
    (1..=u16::MAX).collect()
}

/// Parse a `--ports` spec like `80,443,8000-8100` into a sorted, de-duplicated
/// port list.
pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((a, b)) => {
                let start: u16 = a
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid port `{a}` in range"))?;
                let end: u16 = b
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid port `{b}` in range"))?;
                if start == 0 || end == 0 {
                    return Err("port 0 is not valid".to_string());
                }
                if start > end {
                    return Err(format!("range `{part}` is backwards"));
                }
                out.extend(start..=end);
            }
            None => {
                let n: u16 = part.parse().map_err(|_| format!("invalid port `{part}`"))?;
                if n == 0 {
                    return Err("port 0 is not valid".to_string());
                }
                out.push(n);
            }
        }
    }
    if out.is_empty() {
        return Err("no ports in spec".to_string());
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

