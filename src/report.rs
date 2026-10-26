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
