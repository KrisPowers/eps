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

