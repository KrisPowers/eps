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
