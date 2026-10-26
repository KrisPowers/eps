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

/// Every TCP port, 1..=65535.
pub fn all_ports() -> Vec<u16> {
    (1..=u16::MAX).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_ports_covers_full_range() {
        let ports = all_ports();
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports.first(), Some(&1));
        assert_eq!(ports.last(), Some(&u16::MAX));
    }

    #[tokio::test]
    async fn resolve_literal_ip() {
        let ips = resolve("127.0.0.1", false).await.unwrap();
        assert_eq!(ips, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn closed_port_on_loopback() {
        // Port 1 is almost certainly not listening on loopback.
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let open = scan_ports(ip, &[1], 1, Duration::from_millis(300)).await;
        assert!(open.is_empty());
    }
}
