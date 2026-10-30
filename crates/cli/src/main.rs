//! portscan - a read-only reconnaissance CLI. The compiled binary is
//! `portscan`; it is installed as `@`, which is the command you type.
//!
//! Point it at a single host and it reports what is
//! exposed: open ports, discoverable HTTP endpoints, and whether those
//! endpoints are authenticated, served over TLS, and rate limited. It performs
//! only ordinary TCP connections and HTTP GET requests; it never writes,
//! submits, or changes anything on the target. Use it on infrastructure you
//! own or are explicitly authorized to assess.

mod cli;
mod progress;
mod serve;

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use endpoints::{HttpConfig, PathSpec, ServiceReport};
use scanner::scan;
use scanner::target::Target;

use crate::cli::Cli;
use crate::progress::{Phase, Progress};

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
    if let Some(addr) = &args.serve {
        serve::run(addr, args.web.clone(), args.data.clone()).await?;
        return Ok(ExitCode::SUCCESS);
    }
    let paths = match &args.paths {
        Some(file) => Some(load_paths(file)?),
        None => None,
    };
    let opts = scan_options(&args, paths);
    let out = scan_target(&opts, &Progress::default()).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&out.report)?);
    } else {
        print!("{}", report::render_human(&out.report, &out.services, out.pinned));
    }

    let has_high = out
        .report
        .findings
        .iter()
        .any(|f| f.severity == report::Severity::High);
    if args.fail_on_high && has_high {
        return Ok(ExitCode::from(2));
    }
    Ok(ExitCode::SUCCESS)
}

/// Everything one scan needs, from the command line or a service request.
#[derive(Debug, Clone)]
pub(crate) struct ScanOptions {
    pub target: String,
    pub no_discovery: bool,
    pub connect_timeout: Duration,
    pub http_timeout: Duration,
    pub concurrency: usize,
    pub probe_rate_limit: bool,
    pub burst: usize,
    pub strict_tls: bool,
    /// Replaces the built-in endpoint paths when set.
    pub paths: Option<Vec<PathSpec>>,
}

/// The scan a command line asks for, with the `--paths` list already read.
pub(crate) fn scan_options(args: &Cli, paths: Option<Vec<PathSpec>>) -> ScanOptions {
    ScanOptions {
        target: args.target.clone(),
        no_discovery: args.no_discovery,
        connect_timeout: Duration::from_millis(args.connect_timeout),
        http_timeout: Duration::from_secs(args.http_timeout),
        concurrency: args.concurrency,
        probe_rate_limit: args.probe_rate_limit,
        burst: args.burst,
        strict_tls: args.strict_tls,
        paths,
    }
}

pub(crate) struct ScanOutput {
    pub report: report::Report,
    pub services: Vec<ServiceReport>,
    /// The port the target pinned, if any.
    pub pinned: Option<u16>,
}

/// Scans one target: every port (or the pinned one), then HTTP endpoint
/// discovery and posture checks on the ports that may speak HTTP. Where it
/// is goes into `progress` as it goes.
pub(crate) async fn scan_target(
    opts: &ScanOptions,
    progress: &Progress,
) -> anyhow::Result<ScanOutput> {
    let target = Target::parse(&opts.target).map_err(|e| anyhow::anyhow!(e))?;
    progress.set_phase(Phase::Resolving);

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

    // Scan every port, unless the target pins a single one.
    let ports_to_scan: Vec<u16> = match target.port {
        Some(port) => vec![port],
        None => scan::all_ports(),
    };

    // Port scan.
    progress.start_ports(&ip.to_string(), ports_to_scan.len());
    let on_port = |port: u16, state: scan::PortState| {
        progress.port_done(port, state == scan::PortState::Open)
    };
    let open_ports = scan::scan_ports_with(
        ip,
        &ports_to_scan,
        opts.concurrency,
        opts.connect_timeout,
        &on_port,
    )
    .await;

    // What one port exposes, its endpoints and findings, goes into
    // `progress` as soon as nothing more is coming for it.
    let rendered_ip = ip.to_string();
    let checked = |op: &scan::OpenPort, svc: &[ServiceReport]| {
        let r = report::assemble(&target.host, &rendered_ip, std::slice::from_ref(op), svc);
        let found = serde_json::json!({ "endpoints": r.endpoints, "findings": r.findings });
        progress.checked(op.port, found);
    };

    // HTTP endpoint discovery + posture checks.
    let services: Vec<ServiceReport> = if opts.no_discovery {
        open_ports.iter().for_each(|op| checked(op, &[]));
        Vec::new()
    } else {
        let cfg = build_http_config(opts);
        let mut reports = Vec::new();
        // Inspect ports that are known HTTP, or unknown (could be any app),
        // but skip ports whose catalog service is a known non-HTTP protocol.
        let (candidates, rest): (Vec<_>, Vec<_>) = open_ports
            .iter()
            .partition(|op| op.http_tls.is_some() || op.service == "unknown");
        rest.into_iter().for_each(|op| checked(op, &[]));
        progress.start_endpoints(candidates.len());
        for op in candidates {
            progress.inspecting(op.port);
            match endpoints::inspect_service(&target.url_host(), op.port, op.http_tls, &cfg).await {
                Ok(r) => {
                    checked(op, std::slice::from_ref(&r));
                    reports.push(r);
                }
                Err(e) => {
                    checked(op, &[]);
                    eprintln!("@: note: HTTP inspection of port {} failed: {e}", op.port);
                }
            }
            progress.inspected();
        }
        reports
    };

    let report = report::assemble(&target.host, &rendered_ip, &open_ports, &services);
    progress.set_phase(Phase::Done);
    Ok(ScanOutput {
        report,
        services,
        pinned: target.port,
    })
}

fn build_http_config(opts: &ScanOptions) -> HttpConfig {
    HttpConfig {
        timeout: opts.http_timeout,
        concurrency: 16,
        paths: opts.paths.clone().unwrap_or_else(endpoints::default_paths),
        active_rate_probe: opts.probe_rate_limit,
        active_rate_count: opts.burst,
        strict_tls: opts.strict_tls,
        ..HttpConfig::default()
    }
}

/// Load a custom path list: one path per line, `#` comments ignored, a leading
/// `!` marks the path sensitive.
fn load_paths(file: &str) -> anyhow::Result<Vec<PathSpec>> {
    let contents = std::fs::read_to_string(file)
        .map_err(|e| anyhow::anyhow!("reading paths file `{file}`: {e}"))?;
    let mut specs = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (sensitive, raw) = match line.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, line),
        };
        let path = if raw.starts_with('/') {
            raw.to_string()
        } else {
            format!("/{raw}")
        };
        specs.push(PathSpec {
            path,
            sensitive,
            note: "custom".to_string(),
        });
    }
    if specs.is_empty() {
        anyhow::bail!("paths file `{file}` contained no usable paths");
    }
    Ok(specs)
}
