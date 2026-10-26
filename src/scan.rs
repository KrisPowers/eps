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
