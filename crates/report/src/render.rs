//! Terminal rendering of a report: a summary card up top, the open ports,
//! then one card per endpoint with a color-coded verdict for each security
//! control.

use std::io::IsTerminal;

use endpoints::{AuthState, Endpoint, ServiceReport};
use serde::Serialize;

use crate::{risky_service, Report};

/// Columns the output is laid out in.
const WIDTH: usize = 78;

/// Color for borders, rules and secondary details.
const ACCENT: &str = "36";

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

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn status_tint(status: u16) -> &'static str {
    match status {
        200..=299 => "1;32",
        300..=399 => "1;36",
        400..=499 => "1;33",
        _ => "1;31",
    }
}

/// How far a security control is set up on one endpoint.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Posture {
    /// Set up and holding.
    Configured,
    /// Set up, but bypassable or weakened.
    Insecure,
    /// Not set up at all.
    Missing,
    /// The response does not show either way.
    Unknown,
}

impl Posture {
    /// Background highlight. Text is never bold: bold black renders gray.
    fn codes(self) -> &'static str {
        match self {
            Posture::Configured => "30;42",
            Posture::Insecure => "30;43",
            Posture::Missing => "97;41",
            Posture::Unknown => "30;107",
        }
    }

    /// Stands in for the color when output is piped.
    fn mark(self) -> char {
        match self {
            Posture::Configured => '+',
            Posture::Insecure => '~',
            Posture::Missing => '-',
            Posture::Unknown => '?',
        }
    }
}

/// A block highlighted in the color of `posture`: ` AUTH `, or `[AUTH+]`
/// without color.
fn chip(row: &mut Row, posture: Posture, text: &str) {
    if row.paint.0 {
        row.add(posture.codes(), &format!(" {text} "));
    } else {
        row.add("", &format!("[{text}{}]", posture.mark()));
    }
}

/// Redirect targets that mean "go log in first".
const LOGIN_WORDS: &[&str] = &["login", "signin", "sign-in", "auth", "sso"];

fn is_login_redirect(ep: &Endpoint) -> bool {
    let to = ep.location.as_deref().unwrap_or("").to_ascii_lowercase();
    ep.auth == AuthState::Redirected && LOGIN_WORDS.iter().any(|w| to.contains(w))
}

/// The scheme named in an endpoint's auth challenge, e.g. `Basic`.
fn challenge(ep: &Endpoint) -> Option<&str> {
    let w = ep.www_authenticate.as_deref()?;
    w.split_whitespace().next()
}

fn scheme_is(ep: &Endpoint, name: &str) -> bool {
    challenge(ep).is_some_and(|s| s.eq_ignore_ascii_case(name))
}

/// A credential gate (401/403 or a login redirect). Basic over plain HTTP is
/// insecure: the password crosses the wire readable.
pub(crate) fn auth(ep: &Endpoint) -> Posture {
    match ep.auth {
        AuthState::Protected if !ep.tls && scheme_is(ep, "basic") => Posture::Insecure,
        AuthState::Protected => Posture::Configured,
        AuthState::Redirected if is_login_redirect(ep) => Posture::Configured,
        AuthState::Open => Posture::Missing,
        _ => Posture::Unknown,
    }
}

/// Bearer-token (JWT) auth, insecure when the token travels in the clear.
pub(crate) fn jwt(ep: &Endpoint) -> Posture {
    if !scheme_is(ep, "bearer") {
        Posture::Missing
    } else if ep.tls {
        Posture::Configured
    } else {
        Posture::Insecure
    }
}

/// Rate limiting: enforced (a 429 seen) or advertised by headers, insecure
/// when advertised but not holding under the opt-in burst.
pub(crate) fn rate(ep: &Endpoint) -> Posture {
    let rl = &ep.rate_limit;
    let advertised = !rl.headers_seen.is_empty() || rl.retry_after.is_some();
    match rl.active {
        _ if ep.auth == AuthState::RateLimited => Posture::Configured,
        Some((_, true)) => Posture::Configured,
        Some((_, false)) if advertised => Posture::Insecure,
        None if advertised => Posture::Configured,
        _ => Posture::Missing,
    }
}

pub(crate) fn https(ep: &Endpoint) -> Posture {
    if ep.tls {
        Posture::Configured
    } else {
        Posture::Missing
    }
}

/// A section heading ruled out to the full width: `PORTS ───────`.
fn heading(paint: Paint, title: &str, aside: &str, out: &mut String) {
    let mut row = Row::new(paint);
    row.add("1", title);
    if !aside.is_empty() {
        row.add(ACCENT, &format!("  {}", fit(aside, WIDTH - 16)));
    }
    row.add("", " ");
    let rest = WIDTH.saturating_sub(row.width);
    row.add(ACCENT, &"─".repeat(rest));
    out.push('\n');
    row.finish(out);
}

/// A highlighted status line in place of a section's content.
fn notice(paint: Paint, text: &str, out: &mut String) {
    let mut row = Row::new(paint);
    row.add(Posture::Unknown.codes(), &format!(" {text} "));
    row.finish(out);
}

/// The summary card: target and address, then the counts at a glance. A
/// pinned `port` is shown on the target and leaves the port count out.
fn card(paint: Paint, report: &Report, port: Option<u16>, out: &mut String) {
    let inner = WIDTH - 4;
    let rule = "─".repeat(WIDTH - 2);

    let mut top = Row::new(paint);
    top.add(ACCENT, &format!("┌{rule}┐"));
    top.finish(out);

    let ip = if report.resolved_ip == report.target {
        ""
    } else {
        report.resolved_ip.as_str()
    };
    let target = match port {
        Some(p) if report.target.contains(':') => format!("[{}]:{p}", report.target),
        Some(p) => format!("{}:{p}", report.target),
        None => report.target.clone(),
    };
    let title = fit(&format!("@ {target}"), inner - cols(ip) - 1);
    let mut head = Row::new(paint);
    head.add(ACCENT, "│ ");
    head.add("1", &title);
    head.pad_to(2 + inner - cols(ip));
    head.add(ACCENT, ip);
    head.add(ACCENT, " │");
    head.finish(out);

    let mut counts = Row::new(paint);
    counts.add(ACCENT, "│ ");
    if port.is_none() {
        let ports = plural(report.open_ports.len(), "open port", "open ports");
        counts.add("", &ports);
        counts.add(ACCENT, "  ·  ");
    }
    let endpoints = plural(report.endpoints.len(), "endpoint", "endpoints");
    counts.add("", &endpoints);
    counts.pad_to(WIDTH - 2);
    counts.add(ACCENT, " │");
    counts.finish(out);

    let mut bottom = Row::new(paint);
    bottom.add(ACCENT, &format!("└{rule}┘"));
    bottom.finish(out);
}

/// Open ports, with risky services highlighted and the reason beside.
fn port_section(paint: Paint, report: &Report, out: &mut String) {
    heading(paint, "PORTS", "", out);
    if report.open_ports.is_empty() {
        notice(paint, "No open ports found in the scanned range.", out);
        return;
    }
    for p in &report.open_ports {
        let mut row = Row::new(paint);
        row.add("1", &p.port.to_string());
        row.add("", "/tcp");
        row.pad_to(11);
        match risky_service(p.port, &p.service) {
            Some((_, why)) => {
                row.add("1;33", &p.service);
                row.pad_to(28);
                row.add("", why);
            }
            None => {
                row.add("", &p.service);
            }
        }
        row.finish(out);
    }
}

/// One HTTP service: a legend, then a line per endpoint with its status, a
/// colored block for each security control, its path and note.
fn endpoint_section(paint: Paint, svc: &ServiceReport, out: &mut String) {
    let base = svc
        .endpoints
        .first()
        .and_then(|ep| ep.url.strip_suffix(ep.path.as_str()))
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}:{}", svc.scheme, svc.port));
    heading(paint, "ENDPOINTS", &base, out);

    let mut legend = Row::new(paint);
    chip(&mut legend, Posture::Configured, "configured");
    legend.add("", " ");
    chip(&mut legend, Posture::Insecure, "insecure");
    legend.add("", " ");
    chip(&mut legend, Posture::Missing, "not configured");
    legend.add("", " ");
    chip(&mut legend, Posture::Unknown, "not shown");
    legend.finish(out);
    out.push('\n');

    let path_width = svc
        .endpoints
        .iter()
        .map(|ep| cols(&ep.path))
        .max()
        .unwrap_or(0)
        .min(24);

    for ep in &svc.endpoints {
        let mut row = Row::new(paint);
        row.add(status_tint(ep.status), &ep.status.to_string());
        row.add("", "  ");
        chip(&mut row, auth(ep), "AUTH");
        row.add("", " ");
        chip(&mut row, jwt(ep), "JWT");
        row.add("", " ");
        chip(&mut row, rate(ep), "RATE");
        row.add("", " ");
        chip(&mut row, https(ep), "HTTPS");
        row.add("", "  ");

        let end = row.width + path_width + 2;
        row.add("1", &fit(&ep.path, path_width));
        row.pad_to(end);
        // The note only goes in whole; a cut-off note reads as noise.
        if cols(&ep.note) <= WIDTH.saturating_sub(row.width) {
            row.add("", &ep.note);
        }
        row.finish(out);
    }
}

/// Render the report for a terminal. When the target pinned a `port`, the
/// ports section is left out: the scan was for that port's endpoints.
pub fn render_human(report: &Report, services: &[ServiceReport], port: Option<u16>) -> String {
    let paint = Paint::detect();
    let mut out = String::from("\n");
    card(paint, report, port, &mut out);
    if port.is_none() {
        port_section(paint, report, &mut out);
    }

    let served: Vec<&ServiceReport> = services
        .iter()
        .filter(|s| s.reachable && !s.endpoints.is_empty())
        .collect();
    if served.is_empty() {
        heading(paint, "ENDPOINTS", "", &mut out);
        notice(paint, "No HTTP endpoints found.", &mut out);
    }
    for svc in served {
        endpoint_section(paint, svc, &mut out);
    }
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
    fn rows_pad_by_visible_width() {
        let mut row = Row::new(Paint(true));
        row.add("1", "ab");
        row.pad_to(5);
        assert_eq!(row.width, 5);
        assert_eq!(row.text, "\x1b[1mab\x1b[0m   ");
    }

    #[test]
    fn chips_mark_posture_without_color() {
        let mut row = Row::new(Paint(false));
        chip(&mut row, Posture::Missing, "JWT");
        assert_eq!(row.text, "[JWT-]");
    }
}
