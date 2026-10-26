//! `@` - a read-only reconnaissance CLI (the crate compiles as `at`; the
//! binary is installed as `@`, which is the command you type).
//!
//! Point it at a single host and it reports what is
//! exposed: open ports, discoverable HTTP endpoints, and whether those
//! endpoints are authenticated, served over TLS, and rate limited. It performs
//! only ordinary TCP connections and HTTP GET requests; it never writes,
//! submits, or changes anything on the target. Use it on infrastructure you
//! own or are explicitly authorized to assess.

mod cli;
mod http;
mod paths;
mod ports;
mod report;
mod scan;
mod target;

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use crate::cli::Cli;
use crate::http::{HttpConfig, PathSpec, ServiceReport};
use crate::target::Target;

#[tokio::main]
async fn main() -> ExitCode {
    let args = Cli::parse();
    match run(args).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("@: error: {e:#}");
            ExitCode::from(1)
        }
    }
}

