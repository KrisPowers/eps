//! Command-line interface.

use clap::Parser;

/// @ - point it at a host and it reports what's exposed.
///
/// Read-only recon for your own infrastructure: scans every TCP port, discovers
/// conventional HTTP endpoints, and checks each for auth, TLS, and rate
/// limiting. It never writes, submits, or mutates anything.
#[derive(Parser, Debug)]
#[command(
    name = "@",
    version,
    about = "Read-only recon: `@ <host>[:port]` reports exposed ports and endpoint posture.",
    long_about = None,
    after_help = "EXAMPLES:\n  @                        scan this machine (localhost)\n  @ 192.168.1.10           scan all 65535 ports + inspect HTTP services\n  @ 192.168.1.10:8080      inspect a single port\n  @ 10.0.0.5 --json        machine-readable output\n\nUse only against hosts you own or are explicitly authorized to test."
)]
pub struct Cli {
    /// Target host, host:port, or [ipv6]:port.
    /// Defaults to this machine.
    #[arg(default_value = "localhost")]
    pub target: String,

    /// Emit JSON instead of the human-readable report.
    #[arg(long)]
    pub json: bool,

    /// Skip HTTP endpoint discovery; report open ports only.
    #[arg(long)]
    pub no_discovery: bool,

    /// Per-port TCP connect timeout, in milliseconds.
    #[arg(long, default_value_t = 800, value_name = "MS")]
    pub connect_timeout: u64,

    /// Per-request HTTP timeout, in seconds.
    #[arg(long, default_value_t = 6, value_name = "SECS")]
    pub http_timeout: u64,

    /// Max concurrent port probes.
    #[arg(long, default_value_t = 256, value_name = "N")]
    pub concurrency: usize,

    /// Actively send a small burst to each open endpoint to observe throttling
    /// (opt-in; passive header detection is always on).
    #[arg(long)]
    pub probe_rate_limit: bool,

    /// Number of requests in the active burst, when --probe-rate-limit is set.
    #[arg(long, default_value_t = 15, value_name = "N")]
    pub burst: usize,

    /// Reject invalid/self-signed TLS certs instead of inspecting anyway.
    #[arg(long)]
    pub strict_tls: bool,

    /// Read endpoint paths from a file (one per line; prefix `!` marks a path
    /// sensitive). Replaces the built-in list.
    #[arg(long, value_name = "FILE")]
    pub paths: Option<String>,

    /// Exit with code 2 if any HIGH finding is reported (useful in CI).
    #[arg(long)]
    pub fail_on_high: bool,

    /// Run the dashboard on this address instead of scanning: a web page for
    /// starting scans and reading their reports (see docs/dashboard.md).
    #[arg(long, value_name = "ADDR")]
    pub serve: Option<String>,

    /// With --serve: folder holding the built dashboard (`ui/dist`). Without
    /// it only the API is served.
    #[arg(long, value_name = "DIR", requires = "serve")]
    pub web: Option<std::path::PathBuf>,

    /// With --serve: folder to keep scan results in across restarts.
    #[arg(long, value_name = "DIR", requires = "serve")]
    pub data: Option<std::path::PathBuf>,
}
