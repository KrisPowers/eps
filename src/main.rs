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

async fn run(args: Cli) -> anyhow::Result<ExitCode> {
    let target = Target::parse(&args.target).map_err(|e| anyhow::anyhow!(e))?;

    // Resolve the host. Literal IPs pass straight through.
    let ips = scan::resolve(&target.host, target.is_ipv6).await?;
    let ip = ips[0];
    if ips.len() > 1 {
        eprintln!(
            "@: note: `{}` resolved to {} addresses; scanning {}",
            target.host,
            ips.len(),
            ip
        );
    }

    // Decide which ports to scan.
    let ports_to_scan: Vec<u16> = if let Some(port) = target.port {
        vec![port]
    } else if let Some(spec) = &args.ports {
        scan::parse_port_spec(spec).map_err(|e| anyhow::anyhow!(e))?
    } else if args.full {
        scan::full_port_list()
    } else {
        scan::common_port_list()
    };

    // Port scan.
    let open_ports = scan::scan_ports(
        ip,
        &ports_to_scan,
        args.concurrency,
        Duration::from_millis(args.connect_timeout),
    )
    .await;

    // HTTP endpoint discovery + posture checks.
    let services: Vec<ServiceReport> = if args.no_discovery {
        Vec::new()
    } else {
        let cfg = build_http_config(&args)?;
        let mut reports = Vec::new();
        for op in &open_ports {
            // Inspect ports that are known HTTP, or unknown (could be any app),
            // but skip ports whose catalog service is a known non-HTTP protocol.
            let inspect = op.http_tls.is_some() || op.service == "unknown";
            if !inspect {
                continue;
            }
            match http::inspect_service(&target.url_host(), op.port, op.http_tls, &cfg).await {
                Ok(r) => reports.push(r),
                Err(e) => eprintln!("@: note: HTTP inspection of port {} failed: {e}", op.port),
            }
        }
        reports
    };

    // Assemble and render.
    let rendered_ip = ip.to_string();
    let report = report::assemble(&target.host, &rendered_ip, &open_ports, &services);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", report::render_human(&report, &services));
    }

    let has_high = report
        .findings
        .iter()
        .any(|f| f.severity == report::Severity::High);
    if args.fail_on_high && has_high {
        return Ok(ExitCode::from(2));
    }
    Ok(ExitCode::SUCCESS)
}

