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
