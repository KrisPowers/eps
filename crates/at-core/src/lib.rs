//! Core of `@`: parsing the `@host[:port]` target, the well-known service
//! catalog, and the async TCP connect port scanner.

pub mod ports;
pub mod scan;
pub mod target;
