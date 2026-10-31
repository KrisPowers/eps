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

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use endpoints::{HttpConfig, PathSpec, ServiceReport};
use futures::stream::{FuturesUnordered, StreamExt};
use scanner::scan;
use scanner::target::Target;
use tokio::sync::{mpsc, Semaphore};

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
    if let Some(ips) = scanner::target::range(&opts.target) {
        let ips = ips.map_err(|e| anyhow::anyhow!(e))?;
        return Ok(scan_range(opts, progress, &ips).await);
    }
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

    // Three things run at once: the sweep; the checks on each open port,
    // started as soon as the sweep finds it; and DNS. Each puts what it
    // finds into `progress` as it goes.
    progress.start_ports(&ip.to_string(), ports_to_scan.len());
    let rendered_ip = ip.to_string();
    let ctx = Checks {
        ip,
        host: target.host.clone(),
        url_host: target.url_host(),
        rendered_ip: rendered_ip.clone(),
        http: (!opts.no_discovery).then(|| {
            let mut cfg = build_http_config(opts);
            // A URL's own path is checked along with the usual ones, and
            // the site's crawl starts from it as well as from `/`.
            if let Some(path) = &target.path {
                cfg.start.push(path.clone());
                if !cfg.paths.iter().any(|p| &p.path == path) {
                    cfg.paths.push(PathSpec {
                        path: path.clone(),
                        sensitive: false,
                        note: "from the URL".to_string(),
                    });
                }
            }
            cfg
        }),
        connect: opts.connect_timeout,
        slots: Semaphore::new(SERVICES_AT_ONCE),
        progress,
    };
    let (found_tx, mut found_rx) = mpsc::unbounded_channel::<scan::OpenPort>();

    let sweep = async {
        let on_port = move |port: u16, state: scan::PortState| {
            let open = state == scan::PortState::Open;
            progress.port_done(port, open);
            if open {
                let _ = found_tx.send(scan::OpenPort {
                    port,
                    service: scanner::ports::service_name(port),
                    http_tls: scanner::ports::http_hint(port),
                });
            }
        };
        let open = scan::scan_ports_with(
            ip,
            &ports_to_scan,
            opts.concurrency,
            opts.connect_timeout,
            &on_port,
        )
        .await;
        // Dropping the sender tells the checks no more ports are coming.
        drop(on_port);
        progress.set_phase(Phase::Endpoints);
        open
    };

    let checks = async {
        let mut running = FuturesUnordered::new();
        let mut done = Vec::new();
        let mut sweeping = true;
        while sweeping || !running.is_empty() {
            tokio::select! {
                next = found_rx.recv(), if sweeping => match next {
                    Some(op) => running.push(check(op, &ctx)),
                    None => sweeping = false,
                },
                Some(found) = running.next(), if !running.is_empty() => done.push(found),
            }
        }
        done
    };

    let dns = async {
        let records = scanner::dns::lookup(&target.host, ip).await;
        let (views, findings) = report::dns_report(&target.host, &records);
        progress.dns(serde_json::json!({ "records": views, "findings": findings }));
        records
    };

    let (open_ports, mut checked, records) = tokio::join!(sweep, checks, dns);
    checked.sort_by_key(|c: &Checked| c.port);
    let banners: HashMap<u16, String> = checked
        .iter()
        .filter_map(|c| Some((c.port, c.banner.clone()?)))
        .collect();
    let services: Vec<ServiceReport> = checked.into_iter().filter_map(|c| c.service).collect();

    let mut report = report::assemble(&target.host, &rendered_ip, &open_ports, &services);
    for p in &mut report.open_ports {
        p.banner = banners.get(&p.port).cloned();
    }
    report.technologies = report::technologies(&report.open_ports, &services);
    report::add_dns(&mut report, &target.host, &records);
    if ips.len() > 1 {
        report.addresses = ips.iter().map(ToString::to_string).collect();
    }
    progress.set_phase(Phase::Done);
    Ok(ScanOutput {
        report,
        services,
        pinned: target.port,
    })
}

/// HTTP services inspected at once, each with its own requests in flight.
const SERVICES_AT_ONCE: usize = 4;

/// What the checks on each open port share.
struct Checks<'a> {
    ip: IpAddr,
    /// The host as typed, which the report names.
    host: String,
    /// The host as a URL authority, IPv6 bracketed.
    url_host: String,
    rendered_ip: String,
    /// The HTTP phase's settings, or `None` with `--no-discovery`.
    http: Option<HttpConfig>,
    connect: Duration,
    slots: Semaphore,
    progress: &'a Progress,
}

/// What the checks found on one open port.
struct Checked {
    port: u16,
    banner: Option<String>,
    service: Option<ServiceReport>,
}

/// One open port's checks, started as soon as the sweep finds it: its
/// greeting and, for a port that may speak HTTP, its endpoints, TLS and API
/// documents, at the same time. What it found goes into `progress` as one.
async fn check(op: scan::OpenPort, ctx: &Checks<'_>) -> Checked {
    // Ports that are known HTTP, or unknown (could be any app); not ones whose
    // catalog service is a known non-HTTP protocol.
    let http = ctx
        .http
        .as_ref()
        .filter(|_| op.http_tls.is_some() || op.service == "unknown");
    let inspect = async {
        let cfg = http?;
        ctx.progress.service_found();
        let _slot = ctx.slots.acquire().await.ok();
        ctx.progress.inspecting(op.port);
        let result = endpoints::inspect_service(&ctx.url_host, op.port, op.http_tls, cfg).await;
        ctx.progress.inspected(op.port);
        result
            .map_err(|e| eprintln!("@: note: HTTP inspection of port {} failed: {e}", op.port))
            .ok()
    };
    let greeting = scanner::banner::grab(ctx.ip, op.port, ctx.connect);
    let (banner, service) = tokio::join!(greeting, inspect);
    if let Some(text) = &banner {
        ctx.progress.banner(op.port, text);
    }

    let svc = service.as_slice();
    let mut one = report::assemble(&ctx.host, &ctx.rendered_ip, std::slice::from_ref(&op), svc);
    one.open_ports[0].banner = banner.clone();
    let technologies = report::technologies(&one.open_ports, svc);
    ctx.progress.checked(
        op.port,
        serde_json::json!({
            "endpoints": one.endpoints,
            "findings": one.findings,
            "tls": one.open_ports[0].tls,
            "apis": one.apis,
            "technologies": technologies,
            "site": one.sites.first(),
        }),
    );
    Checked {
        port: op.port,
        banner,
        service,
    }
}

/// Scans a range: the catalog's ports on every address in it, to find the
/// hosts that are up and what they serve. There is no HTTP inspection; a
/// host found this way can be scanned on its own.
async fn scan_range(opts: &ScanOptions, progress: &Progress, ips: &[IpAddr]) -> ScanOutput {
    let ports = scanner::ports::catalog();
    progress.start_ports(&opts.target, ips.len() * ports.len());
    let on_probe = |_: IpAddr, port: u16, _: scan::PortState| progress.port_done(port, false);
    let hosts = scan::sweep(ips, &ports, opts.concurrency, opts.connect_timeout, &on_probe).await;
    let target = opts.target.trim_start_matches('@').trim();
    let report = report::assemble_range(target, &hosts);
    progress.set_phase(Phase::Done);
    ScanOutput {
        report,
        services: Vec::new(),
        pinned: None,
    }
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
