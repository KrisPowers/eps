//! Terminal rendering of a report: a summary card up top, then ports,
//! endpoints and findings as aligned, color-coded sections.

use std::io::IsTerminal;

use endpoints::{AuthState, Endpoint, ServiceReport};

use crate::{risky_service, Report, Severity};

/// Columns the output is laid out in.
const WIDTH: usize = 78;

/// Column the body of a finding is indented to, past its badge.
const INDENT: usize = 10;

/// Severities in the order they are counted, most severe first.
const ORDER: [Severity; 4] = [
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

/// Whether ANSI styling is emitted. Off when piped or when `NO_COLOR` is set.
#[derive(Clone, Copy)]
struct Paint(bool);

impl Paint {
    fn detect() -> Self {
        let on = std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
        Paint(on)
    }
}

/// One output line, tracking its visible width apart from escape codes.
struct Row {
    paint: Paint,
    text: String,
    width: usize,
}

impl Row {
    fn new(paint: Paint) -> Self {
        Row {
            paint,
            text: String::new(),
            width: 0,
        }
    }

    /// Append `s` styled with the SGR `codes` ("" for plain).
    fn add(&mut self, codes: &str, s: &str) -> &mut Self {
        if self.paint.0 && !codes.is_empty() {
            self.text.push_str(&format!("\x1b[{codes}m{s}\x1b[0m"));
        } else {
            self.text.push_str(s);
        }
        self.width += cols(s);
        self
    }

    /// Pad with spaces out to column `to`.
    fn pad_to(&mut self, to: usize) -> &mut Self {
        let n = to.saturating_sub(self.width);
        self.add("", &" ".repeat(n))
    }

    fn finish(&self, out: &mut String) {
        out.push_str(self.text.trim_end());
        out.push('\n');
    }
}

fn cols(s: &str) -> usize {
    s.chars().count()
}

/// Cut `s` to at most `max` columns, marking the cut with an ellipsis.
fn fit(s: &str, max: usize) -> String {
    if cols(s) <= max {
        return s.to_string();
    }
    let mut cut: String = s.chars().take(max.saturating_sub(1)).collect();
    if max > 0 {
        cut.push('…');
    }
    cut
}

/// Greedy word wrap to `max` columns.
fn wrap(text: &str, max: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && cols(&line) + 1 + cols(word) > max {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn tally(report: &Report, sev: Severity) -> usize {
    let f = &report.findings;
    f.iter().filter(|x| x.severity == sev).count()
}

/// Foreground for text tinted by severity.
fn tint(sev: Severity) -> &'static str {
    match sev {
        Severity::High => "1;31",
        Severity::Medium => "1;33",
        Severity::Low => "1;34",
        Severity::Info => "1;36",
    }
}

fn sev_name(sev: Severity) -> &'static str {
    match sev {
        Severity::High => "high",
        Severity::Medium => "med",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// A fixed-width severity badge: a colored block, or `[HIGH]` without color.
fn badge(row: &mut Row, sev: Severity) {
    let (name, codes) = match sev {
        Severity::High => ("HIGH", "1;97;41"),
        Severity::Medium => ("MED", "1;30;43"),
        Severity::Low => ("LOW", "1;97;44"),
        Severity::Info => ("INFO", "1;30;46"),
    };
    if row.paint.0 {
        row.add(codes, &format!(" {name:<4} "));
    } else {
        row.add("", &format!("[{name:<4}]"));
    }
}

fn status_tint(status: u16) -> &'static str {
    match status {
        200..=299 => "32",
        300..=399 => "36",
        400..=499 => "33",
        _ => "31",
    }
}

/// Label and color for how an endpoint answered without credentials.
fn auth_style(ep: &Endpoint) -> (&'static str, &'static str) {
    match ep.auth {
        AuthState::Open if ep.sensitive => ("OPEN", "1;31"),
        AuthState::Open => ("OPEN", "33"),
        AuthState::Protected => ("PROTECTED", "32"),
        AuthState::Redirected => ("REDIRECT", "36"),
        AuthState::RateLimited => ("THROTTLED", "32"),
        AuthState::Present => ("PRESENT", "2"),
    }
}

/// Context shown after an endpoint's note: where it redirects, the auth
/// challenge it sent, or the server that answered.
fn extra(ep: &Endpoint) -> Option<String> {
    match ep.auth {
        AuthState::Redirected => ep.location.as_ref().map(|loc| format!("→ {loc}")),
        AuthState::Protected => ep
            .www_authenticate
            .as_deref()
            .map(|w| w.split(',').next().unwrap_or(w).to_string()),
        _ => ep.server.clone(),
    }
}

/// A section heading ruled out to the full width: `  PORTS ───────`.
fn heading(paint: Paint, title: &str, aside: &str, out: &mut String) {
    let mut row = Row::new(paint);
    row.add("1", &format!("  {title}"));
    if !aside.is_empty() {
        row.add("36", &format!("  {}", fit(aside, WIDTH - 16)));
    }
    row.add("", " ");
    let rest = WIDTH.saturating_sub(row.width);
    row.add("2", &"─".repeat(rest));
    out.push('\n');
    row.finish(out);
}

/// The summary card: target and address, then the counts at a glance.
fn card(paint: Paint, report: &Report, out: &mut String) {
    let inner = WIDTH - 4;
    let rule = "─".repeat(WIDTH - 2);

    let mut top = Row::new(paint);
    top.add("2", &format!("╭{rule}╮"));
    top.finish(out);

    let ip = if report.resolved_ip == report.target {
        ""
    } else {
        report.resolved_ip.as_str()
    };
    let title = fit(&format!("@ {}", report.target), inner - cols(ip) - 1);
    let mut head = Row::new(paint);
    head.add("2", "│ ");
    head.add("1", &title);
    head.pad_to(2 + inner - cols(ip));
    head.add("2", ip);
    head.add("2", " │");
    head.finish(out);

    let ports = plural(report.open_ports.len(), "open port", "open ports");
    let endpoints = plural(report.endpoints.len(), "endpoint", "endpoints");
    let mut counts = Row::new(paint);
    counts.add("2", "│ ");
    counts.add("", &ports);
    counts.add("2", "  ·  ");
    counts.add("", &endpoints);
    counts.add("2", "  ·  ");
    for sev in ORDER {
        let n = tally(report, sev);
        let codes = if n > 0 { tint(sev) } else { "2" };
        counts.add(codes, &format!("{n} {}", sev_name(sev)));
        counts.add("", "  ");
    }
    counts.pad_to(WIDTH - 2);
    counts.add("2", " │");
    counts.finish(out);

    let mut bottom = Row::new(paint);
    bottom.add("2", &format!("╰{rule}╯"));
    bottom.finish(out);
}

/// Open ports, with risky services tinted by severity and the reason beside.
fn port_section(paint: Paint, report: &Report, out: &mut String) {
    heading(paint, "PORTS", "", out);
    if report.open_ports.is_empty() {
        let mut row = Row::new(paint);
        row.add("2", "  No open ports found in the scanned range.");
        row.finish(out);
        return;
    }
    for p in &report.open_ports {
        let mut row = Row::new(paint);
        row.add("1", &format!("  {:>5}", p.port));
        row.add("2", "/tcp   ");
        match risky_service(p.port, &p.service) {
            Some((sev, why)) => {
                row.add(tint(sev), &p.service);
                row.pad_to(32);
                row.add("2", why);
            }
            None => {
                row.add("", &p.service);
            }
        }
        row.finish(out);
    }
}

/// One HTTP service's endpoints as aligned columns: status, auth, rate
/// limiting, path, then the note and any extra context.
fn endpoint_section(paint: Paint, svc: &ServiceReport, out: &mut String) {
    let base = svc
        .endpoints
        .first()
        .and_then(|ep| ep.url.strip_suffix(ep.path.as_str()))
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}:{}", svc.scheme, svc.port));
    heading(paint, "ENDPOINTS", &base, out);

    let path_width = svc
        .endpoints
        .iter()
        .map(|ep| cols(&ep.path))
        .max()
        .unwrap_or(0)
        .min(28);

    for ep in &svc.endpoints {
        let (label, codes) = auth_style(ep);
        let mut row = Row::new(paint);
        row.add("", "  ");
        row.add(status_tint(ep.status), &ep.status.to_string());
        row.add("", "  ");
        row.add(codes, &format!("{label:<9}"));
        row.add("", "  ");
        if ep.rate_limit.any_signal() {
            row.add("32", "limited ");
        } else {
            row.add("2", "no limit");
        }
        row.add("", "  ");

        let end = row.width + path_width + 2;
        let path_codes = if ep.sensitive { "1" } else { "" };
        row.add(path_codes, &fit(&ep.path, path_width));
        row.pad_to(end);

        let note = fit(&ep.note, WIDTH.saturating_sub(row.width));
        row.add("", &note);
        if let Some(extra) = extra(ep) {
            let room = WIDTH.saturating_sub(row.width);
            row.add("2", &fit(&format!("  {extra}"), room));
        }
        row.finish(out);
    }
}

/// Findings, most severe first: badge and title, location, wrapped detail.
fn finding_section(paint: Paint, report: &Report, out: &mut String) {
    heading(paint, "FINDINGS", "", out);
    if report.findings.is_empty() {
        let mut row = Row::new(paint);
        row.add(
            "32",
            "  ✓ Nothing notable. No risky services or open sensitive endpoints.",
        );
        row.finish(out);
        return;
    }
    for (i, f) in report.findings.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        for (j, line) in wrap(&f.title, WIDTH - INDENT).iter().enumerate() {
            let mut row = Row::new(paint);
            if j == 0 {
                row.add("", "  ");
                badge(&mut row, f.severity);
            }
            row.pad_to(INDENT);
            row.add("1", line);
            row.finish(out);
        }

        let mut row = Row::new(paint);
        row.pad_to(INDENT);
        row.add("2", &fit(&f.location, WIDTH - INDENT));
        row.finish(out);

        for line in wrap(&f.detail, WIDTH - INDENT) {
            let mut row = Row::new(paint);
            row.pad_to(INDENT);
            row.add("", &line);
            row.finish(out);
        }
    }
}

/// Render the report for a terminal.
pub fn render_human(report: &Report, services: &[ServiceReport]) -> String {
    let paint = Paint::detect();
    let mut out = String::from("\n");
    card(paint, report, &mut out);
    port_section(paint, report, &mut out);
    for svc in services {
        if svc.reachable && !svc.endpoints.is_empty() {
            endpoint_section(paint, svc, &mut out);
        }
    }
    finding_section(paint, report, &mut out);

    let footer = "  Read-only scan - exposure is reported, not judged.";
    let mut row = Row::new(paint);
    row.add("2", footer);
    out.push('\n');
    row.finish(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_cuts_with_ellipsis() {
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(fit("abc", 4), "abc");
    }

    #[test]
    fn wrap_respects_width() {
        let lines = wrap("one two three four five", 9);
        assert_eq!(lines, ["one two", "three", "four five"]);
    }

    #[test]
    fn rows_pad_by_visible_width() {
        let mut row = Row::new(Paint(true));
        row.add("1", "ab");
        row.pad_to(5);
        assert_eq!(row.width, 5);
        assert_eq!(row.text, "\x1b[1mab\x1b[0m   ");
    }
}
