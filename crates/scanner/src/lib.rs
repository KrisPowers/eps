//! Core of EPS: parsing the `host[:port]` target, the well-known service
//! catalog, the async TCP connect port scanner, service greetings, and DNS.

pub mod banner;
pub mod dns;
pub mod ports;
pub mod scan;
pub mod target;
