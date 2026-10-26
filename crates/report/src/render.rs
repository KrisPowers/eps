//! Terminal rendering of a report: a summary card up top, then ports,
//! endpoints and a per-control security verdict as aligned, color-coded
//! sections.

use std::io::IsTerminal;

use endpoints::{AuthState, Endpoint, ServiceReport};

use crate::{is_api_like, risky_service, Report};

/// Columns the output is laid out in.
const WIDTH: usize = 78;

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

/// The summary card: target and address, then the counts at a glance. A
/// pinned `port` is shown on the target and leaves the port count out.
fn card(paint: Paint, report: &Report, port: Option<u16>, out: &mut String) {
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
    let target = match port {
        Some(p) if report.target.contains(':') => format!("[{}]:{p}", report.target),
        Some(p) => format!("{}:{p}", report.target),
        None => report.target.clone(),
    };
    let title = fit(&format!("@ {target}"), inner - cols(ip) - 1);
    let mut head = Row::new(paint);
    head.add("2", "│ ");
    head.add("1", &title);
    head.pad_to(2 + inner - cols(ip));
    head.add("2", ip);
    head.add("2", " │");
    head.finish(out);

    let mut counts = Row::new(paint);
    counts.add("2", "│ ");
    if port.is_none() {
        let ports = plural(report.open_ports.len(), "open port", "open ports");
        counts.add("", &ports);
        counts.add("2", "  ·  ");
    }
    let endpoints = plural(report.endpoints.len(), "endpoint", "endpoints");
    counts.add("", &endpoints);
    counts.pad_to(WIDTH - 2);
    counts.add("2", " │");
    counts.finish(out);

    let mut bottom = Row::new(paint);
    bottom.add("2", &format!("╰{rule}╯"));
    bottom.finish(out);
}

/// Open ports, with risky services highlighted and the reason beside.
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
            Some((_, why)) => {
                row.add("1;33", &p.service);
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

/// How far a security control is set up, as far as the scan can see.
#[derive(Clone, Copy)]
enum Posture {
    /// Set up and holding.
    Configured,
    /// Set up, but bypassable or weakened.
    Insecure,
    /// Not set up at all.
    Missing,
}

/// The highlighted verdict block: green, yellow or red.
fn chip(row: &mut Row, posture: Posture) {
    let (label, codes) = match posture {
        Posture::Configured => ("CONFIGURED", "1;30;42"),
        Posture::Insecure => ("INSECURE", "1;30;43"),
        Posture::Missing => ("NOT CONFIGURED", "1;97;41"),
    };
    if row.paint.0 {
        row.add(codes, &format!(" {label:<14} "));
    } else {
        row.add("", &format!("[{label:<14}]"));
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

/// Paths joined for a sentence, cut to the first few.
fn paths(eps: &[&Endpoint]) -> String {
    let shown: Vec<&str> = eps.iter().take(5).map(|ep| ep.path.as_str()).collect();
    let mut s = shown.join(", ");
    if eps.len() > 5 {
        s.push_str(&format!(" and {} more", eps.len() - 5));
    }
    s
}

/// Credential gates (401/403 or a login redirect), and whether any
/// sensitive path slips past them.
fn authentication(eps: &[&Endpoint]) -> (Posture, String) {
    let gated: Vec<&Endpoint> = eps
        .iter()
        .copied()
        .filter(|ep| ep.auth == AuthState::Protected || is_login_redirect(ep))
        .collect();
    let exposed: Vec<&Endpoint> = eps
        .iter()
        .copied()
        .filter(|ep| ep.auth == AuthState::Open && ep.sensitive)
        .collect();

    if gated.is_empty() {
        let mut text = "No endpoint asks for credentials.".to_string();
        if !exposed.is_empty() {
            let list = paths(&exposed);
            text.push_str(&format!(" Sensitive paths answer openly: {list}."));
        }
        return (Posture::Missing, text);
    }

    let mut schemes: Vec<&str> = gated.iter().filter_map(|ep| challenge(ep)).collect();
    schemes.sort_unstable();
    schemes.dedup();
    let via = if schemes.is_empty() {
        String::new()
    } else {
        format!(" ({})", schemes.join(", "))
    };
    let asks = plural(gated.len(), "endpoint asks", "endpoints ask");
    let basic_plain = gated.iter().any(|ep| !ep.tls && scheme_is(ep, "basic"));

    if !exposed.is_empty() {
        let list = paths(&exposed);
        let text = format!(
            "{asks} for credentials{via}, but these sensitive paths answer without: {list}."
        );
        (Posture::Insecure, text)
    } else if basic_plain {
        let text = format!(
            "{asks} for credentials{via}, but Basic over plain HTTP sends passwords in the clear."
        );
        (Posture::Insecure, text)
    } else {
        let text = format!("{asks} for credentials{via}, and every sensitive path found is gated.");
        (Posture::Configured, text)
    }
}

/// Bearer-token (JWT) challenges, and whether tokens travel encrypted.
fn jwt(eps: &[&Endpoint]) -> (Posture, String) {
    let bearer: Vec<&Endpoint> = eps
        .iter()
        .copied()
        .filter(|ep| scheme_is(ep, "bearer"))
        .collect();
    if bearer.is_empty() {
        let text = "No endpoint asks for a Bearer token.".to_string();
        return (Posture::Missing, text);
    }
    let list = paths(&bearer);
    if bearer.iter().any(|ep| !ep.tls) {
        let text = format!(
            "Bearer tokens required on {list}, but sent over plain HTTP, readable on the wire."
        );
        (Posture::Insecure, text)
    } else {
        let text = format!("Bearer tokens required on {list}, over HTTPS.");
        (Posture::Configured, text)
    }
}

/// Advertised or enforced limits, open API endpoints without one, and
/// limits that did not hold under the opt-in burst.
fn rate_limiting(eps: &[&Endpoint]) -> (Posture, String) {
    let limited: Vec<&Endpoint> = eps
        .iter()
        .copied()
        .filter(|ep| ep.rate_limit.any_signal())
        .collect();
    if limited.is_empty() {
        let text = "No endpoint advertises or enforces a rate limit.".to_string();
        return (Posture::Missing, text);
    }
    let unlimited: Vec<&Endpoint> = eps
        .iter()
        .copied()
        .filter(|ep| ep.auth == AuthState::Open && is_api_like(&ep.path))
        .filter(|ep| !ep.rate_limit.any_signal())
        .collect();
    let unenforced: Vec<&Endpoint> = eps
        .iter()
        .copied()
        .filter(|ep| matches!(ep.rate_limit.active, Some((_, false))))
        .collect();

    let mut text = format!("Limits on {}.", paths(&limited));
    if !unlimited.is_empty() {
        let list = paths(&unlimited);
        text.push_str(&format!(" Open API endpoints with none: {list}."));
    }
    if !unenforced.is_empty() {
        let list = paths(&unenforced);
        text.push_str(&format!(" Not throttled under a burst: {list}."));
    }
    if unlimited.is_empty() && unenforced.is_empty() {
        text.push_str(" Every open API endpoint has one.");
        (Posture::Configured, text)
    } else {
        (Posture::Insecure, text)
    }
}

/// Whether the HTTP services are served over TLS.
fn transport(services: &[ServiceReport]) -> (Posture, String) {
    let served: Vec<&ServiceReport> = services
        .iter()
        .filter(|s| s.reachable && !s.endpoints.is_empty())
        .collect();
    let plain: Vec<String> = served
        .iter()
        .filter(|s| s.scheme == "http")
        .map(|s| s.port.to_string())
        .collect();
    if plain.is_empty() {
        let text = "Every HTTP service is served over TLS.".to_string();
        return (Posture::Configured, text);
    }
    let ports = plain.join(", ");
    if plain.len() == served.len() {
        let text = format!(
            "Plain HTTP only on port {ports}. Passwords and tokens cross the wire unencrypted."
        );
        (Posture::Missing, text)
    } else {
        let text = format!("TLS on some ports, but plain HTTP on port {ports}.");
        (Posture::Insecure, text)
    }
}

/// Column a control's description starts at, past its verdict block.
const BODY: usize = 20;

/// Each security control with a highlighted verdict and what was seen.
fn security_section(paint: Paint, services: &[ServiceReport], out: &mut String) {
    heading(paint, "SECURITY", "", out);
    let eps: Vec<&Endpoint> = services
        .iter()
        .filter(|s| s.reachable)
        .flat_map(|s| s.endpoints.iter())
        .collect();
    if eps.is_empty() {
        let mut row = Row::new(paint);
        row.add("", "  ");
        row.add("1;30;47", " No HTTP endpoints found to assess. ");
        row.finish(out);
        return;
    }

    let controls = [
        ("Authentication", authentication(&eps)),
        ("JWT", jwt(&eps)),
        ("Rate limiting", rate_limiting(&eps)),
        ("HTTPS", transport(services)),
    ];
    for (i, (name, (posture, text))) in controls.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let mut row = Row::new(paint);
        row.add("", "  ");
        chip(&mut row, *posture);
        row.add("", "  ");
        row.add("1", name);
        row.finish(out);

        for line in wrap(text, WIDTH - BODY) {
            let mut row = Row::new(paint);
            row.pad_to(BODY);
            row.add("", &line);
            row.finish(out);
        }
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
    for svc in services {
        if svc.reachable && !svc.endpoints.is_empty() {
            endpoint_section(paint, svc, &mut out);
        }
    }
    security_section(paint, services, &mut out);

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
