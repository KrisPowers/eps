//! Turn raw scan data into prioritized findings and render them.
//!
//! The tool reports *exposure and posture*, never intent - it cannot know
//! whether a given host is meant to be public. Severities reflect potential
//! impact so an engineer can triage quickly; the decision is theirs.

use std::io::IsTerminal;

use serde::Serialize;

use crate::http::{AuthState, Endpoint, ServiceReport};
use crate::scan::OpenPort;

/// Impact tier for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW ",
            Severity::Medium => "MED ",
            Severity::High => "HIGH",
        }
    }
    fn color(self) -> &'static str {
        match self {
            Severity::Info => "\x1b[36m",   // cyan
            Severity::Low => "\x1b[34m",    // blue
            Severity::Medium => "\x1b[33m", // yellow
            Severity::High => "\x1b[31m",   // red
        }
    }
}

/// A single actionable observation.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub location: String,
    pub detail: String,
}

/// The full machine-readable result.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub target: String,
    pub resolved_ip: String,
    pub open_ports: Vec<PortView>,
    pub endpoints: Vec<EndpointView>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortView {
    pub port: u16,
    pub service: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointView {
    pub url: String,
    pub status: u16,
    pub auth: String,
    pub tls: bool,
    pub sensitive: bool,
    pub rate_limited: bool,
    pub note: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// Non-HTTP services whose public exposure is usually a serious problem, with
/// the severity to assign and a short rationale.
fn risky_service(port: u16, _service: &str) -> Option<(Severity, &'static str)> {
    let high = Severity::High;
    let med = Severity::Medium;
    match port {
        3306 | 5432 | 1433 | 1521 => Some((high, "database directly reachable")),
        6379 => Some((high, "Redis is unauthenticated by default")),
        11211 => Some((high, "Memcached has no auth and is amplification-prone")),
        27017 | 27018 | 28017 => Some((high, "MongoDB directly reachable")),
        9200 | 9300 => Some((high, "Elasticsearch directly reachable")),
        5984 => Some((high, "CouchDB directly reachable")),
        7000 | 9042 => Some((high, "Cassandra directly reachable")),
        2375 => Some((high, "Docker API grants remote root")),
        2379 | 2380 => Some((high, "etcd holds cluster secrets")),
        10250 => Some((high, "kubelet API can expose workloads")),
        23 => Some((high, "Telnet is cleartext")),
        3389 => Some((med, "RDP exposed to the network")),
        5900 => Some((med, "VNC exposed to the network")),
        445 | 139 => Some((med, "SMB exposed to the network")),
        21 => Some((med, "FTP is cleartext")),
        9092 => Some((med, "Kafka broker reachable")),
        5672 => Some((med, "AMQP broker reachable")),
        _ => None,
    }
}

/// Build the prioritized finding list from raw scan data.
pub fn build_findings(open_ports: &[OpenPort], services: &[ServiceReport]) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Exposed non-HTTP services of note.
    for op in open_ports {
        if op.http_tls.is_some() {
            continue; // HTTP ports are covered by endpoint findings below.
        }
        if let Some((sev, why)) = risky_service(op.port, op.service) {
            findings.push(Finding {
                severity: sev,
                title: format!("Exposed {} service", op.service),
                location: format!("port {}", op.port),
                detail: format!(
                    "{why}. Confirm this port should be reachable from where you are scanning; restrict it to a trusted network or add authentication if not."
                ),
            });
        }
    }

    // 2. Per-endpoint posture.
    for svc in services {
        for ep in &svc.endpoints {
            findings.extend(endpoint_findings(svc, ep));
        }

        // Cleartext transport note, raised once per plaintext service that has
        // any openly reachable endpoint.
        if svc.reachable
            && svc.scheme == "http"
            && svc.endpoints.iter().any(|e| e.auth == AuthState::Open)
        {
            findings.push(Finding {
                severity: Severity::Low,
                title: "Cleartext HTTP service".to_string(),
                location: format!("port {} (http)", svc.port),
                detail: "Endpoints are served over plaintext HTTP; traffic and any tokens are exposed on the wire. Prefer HTTPS.".to_string(),
            });
        }
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings
}

fn endpoint_findings(svc: &ServiceReport, ep: &Endpoint) -> Vec<Finding> {
    let mut out = Vec::new();
    let loc = format!("{} (port {})", ep.url, svc.port);

    match ep.auth {
        AuthState::Open if ep.sensitive => {
            out.push(Finding {
                severity: Severity::High,
                title: format!("Unauthenticated sensitive endpoint: {}", ep.note),
                location: loc.clone(),
                detail: format!(
                    "Returned {} with no authentication. This path commonly leaks configuration, internals, or control. Put it behind auth or stop exposing it.",
                    ep.status
                ),
            });
        }
        AuthState::Open => {
            // Non-sensitive open endpoint: note only the missing throttling, and
            // only for API-ish surfaces, to keep health checks quiet.
            if !ep.rate_limit.any_signal() && is_api_like(&ep.path) {
                out.push(Finding {
                    severity: Severity::Low,
                    title: "No rate limiting advertised on open API endpoint".to_string(),
                    location: loc.clone(),
                    detail: "No RateLimit/Retry-After headers were returned. Verify throttling exists upstream to limit abuse.".to_string(),
                });
            }
        }
        AuthState::Protected if ep.sensitive => {
            // Positive signal: a sensitive path is correctly gated.
            let scheme = ep
                .www_authenticate
                .as_deref()
                .map(|w| format!(" ({})", w.split(' ').next().unwrap_or(w)))
                .unwrap_or_default();
            out.push(Finding {
                severity: Severity::Info,
                title: format!("Sensitive endpoint is protected{scheme}: {}", ep.note),
                location: loc.clone(),
                detail: format!(
                    "Returned {} without credentials - an auth gate is in place.",
                    ep.status
                ),
            });
        }
        _ => {}
    }

    // If an active burst actually drew a 429, that's a good signal worth noting.
    if let Some((sent, throttled)) = ep.rate_limit.active {
        if !throttled {
            out.push(Finding {
                severity: Severity::Low,
                title: "No throttling observed under burst".to_string(),
                location: loc.clone(),
                detail: format!(
                    "Sent {sent} rapid requests to an open endpoint without being throttled (no 429). Confirm rate limiting is enforced."
                ),
            });
        }
    }

    out
}

fn is_api_like(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    p.is_empty()
        || p.starts_with("api")
        || p.starts_with('v')
        || p.starts_with("graphql")
        || p.starts_with("rest")
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

/// Assemble a serializable report (used for JSON and as the render source).
pub fn assemble(
    target: &str,
    resolved_ip: &str,
    open_ports: &[OpenPort],
    services: &[ServiceReport],
) -> Report {
    let findings = build_findings(open_ports, services);

    let open_ports_view = open_ports
        .iter()
        .map(|o| PortView {
            port: o.port,
            service: o.service.to_string(),
        })
        .collect();

    let mut endpoints = Vec::new();
    for svc in services {
        for ep in &svc.endpoints {
            endpoints.push(EndpointView {
                url: ep.url.clone(),
                status: ep.status,
                auth: ep.auth.label().to_string(),
                tls: ep.tls,
                sensitive: ep.sensitive,
                rate_limited: ep.rate_limit.any_signal(),
                note: ep.note.clone(),
                server: ep.server.clone(),
                content_type: ep.content_type.clone(),
                location: ep.location.clone(),
            });
        }
    }

    Report {
        target: target.to_string(),
        resolved_ip: resolved_ip.to_string(),
        open_ports: open_ports_view,
        endpoints,
        findings,
    }
}

/// Render the report as readable text for a terminal.
pub fn render_human(report: &Report, services: &[ServiceReport]) -> String {
    let color = use_color();
    let bold = if color { "\x1b[1m" } else { "" };
    let dim = if color { "\x1b[2m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };

    let mut s = String::new();

    s.push_str(&format!(
        "\n{bold}@ {}{reset} {dim}({}){reset}\n",
        report.target, report.resolved_ip
    ));

    // Open ports.
    if report.open_ports.is_empty() {
        s.push_str(&format!(
            "\n  {dim}No open ports found in the scanned range.{reset}\n"
        ));
    } else {
        s.push_str(&format!("\n{bold}Open ports{reset}\n"));
        for p in &report.open_ports {
            s.push_str(&format!("  {:>5}/tcp  {}\n", p.port, p.service));
        }
    }

    // Endpoints per service.
    for svc in services {
        if !svc.reachable || svc.endpoints.is_empty() {
            continue;
        }
        s.push_str(&format!(
            "\n{bold}Endpoints on {}:{}{reset} {dim}({}){reset}\n",
            svc.scheme, svc.port, svc.scheme
        ));
        for ep in &svc.endpoints {
            let auth_col = if color {
                match ep.auth {
                    AuthState::Open if ep.sensitive => "\x1b[31m",
                    AuthState::Open => "\x1b[33m",
                    AuthState::Protected => "\x1b[32m",
                    _ => "\x1b[2m",
                }
            } else {
                ""
            };
            let rl = if ep.rate_limit.any_signal() {
                "rate-limited"
            } else {
                "no-ratelimit"
            };
            // Extra context: redirect target, auth challenge scheme, or server.
            let mut extra = String::new();
            if ep.auth == AuthState::Redirected {
                if let Some(loc) = &ep.location {
                    extra = format!("-> {loc}");
                }
            } else if ep.auth == AuthState::Protected {
                if let Some(w) = &ep.www_authenticate {
                    extra = format!("challenge: {}", w.split(',').next().unwrap_or(w));
                }
            } else if let Some(srv) = &ep.server {
                extra = srv.clone();
            }
            s.push_str(&format!(
                "  {:>3}  {auth_col}{:<14}{reset} {:<12} {dim}{}{reset}  {}  {dim}{}{reset}\n",
                ep.status,
                ep.auth.label(),
                rl,
                ep.path,
                ep.note,
                extra,
            ));
        }
    }

    // Findings.
    s.push_str(&format!("\n{bold}Findings{reset}\n"));
    if report.findings.is_empty() {
        s.push_str(&format!(
            "  {dim}Nothing notable - no exposed risky services or unauthenticated sensitive endpoints.{reset}\n"
        ));
    } else {
        for f in &report.findings {
            let col = if color { f.severity.color() } else { "" };
            s.push_str(&format!(
                "  {col}{}{reset}  {bold}{}{reset}\n        {dim}{}{reset}\n        {}\n",
                f.severity.label(),
                f.title,
                f.location,
                f.detail,
            ));
        }
    }

    // Summary counts.
    let (mut high, mut med, mut low) = (0, 0, 0);
    for f in &report.findings {
        match f.severity {
            Severity::High => high += 1,
            Severity::Medium => med += 1,
            Severity::Low => low += 1,
            Severity::Info => {}
        }
    }
    s.push_str(&format!(
        "\n{dim}Summary: {high} high | {med} medium | {low} low. Read-only scan - exposure is reported, not judged.{reset}\n"
    ));

    s
}

