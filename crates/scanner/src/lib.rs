//! Core of portscan: parsing the `host[:port]` target, the well-known service
//! catalog, the async TCP connect port scanner, and service greetings.

pub mod banner;
pub mod ports;
pub mod scan;
pub mod target;
