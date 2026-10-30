//! Turn raw scan data into prioritized findings and render them.
//!
//! The tool reports *exposure and posture*, never intent - it cannot know
//! whether a given host is meant to be public. Severities reflect potential
//! impact so an engineer can triage quickly; the decision is theirs.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use endpoints::tls::{Cert, TlsReport};
use endpoints::{AuthState, Endpoint, ServiceReport};
use scanner::scan::OpenPort;
use serde::Serialize;

mod render;
mod tech;

pub use render::{render_human, Posture};
pub use tech::{technologies, Tech};

/// Impact tier for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
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
    /// For a range, each host that answered, with its open ports.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<HostView>,
    /// The software recognized on the open ports; see [`technologies`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub technologies: Vec<Tech>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostView {
    pub ip: String,
    pub open_ports: Vec<PortView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortView {
    pub port: u16,
    pub service: String,
    /// What the service said first on connect, such as its version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// For HTTPS, its certificate and any old TLS versions it accepts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<CertView>,
    pub legacy: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertView {
    pub subject: String,
    pub issuer: String,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    pub names: Vec<String>,
    pub self_signed: bool,
}

impl From<&TlsReport> for TlsView {
    fn from(t: &TlsReport) -> Self {
        TlsView {
            cert: t.cert.as_ref().map(|c: &Cert| CertView {
                subject: c.subject.clone(),
                issuer: c.issuer.clone(),
                not_before: c.not_before,
                not_after: c.not_after,
                names: c.names.clone(),
                self_signed: c.self_signed,
            }),
            legacy: t.legacy.iter().map(|v| v.to_string()).collect(),
        }
    }
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
    /// The verdict per security control, as the text report colors it.
    pub controls: Controls,
    /// The verdict per security header, the same way.
    pub headers: HeaderControls,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeaderControls {
    pub hsts: Posture,
    pub csp: Posture,
    pub frame: Posture,
    pub nosniff: Posture,
    pub cors: Posture,
    pub cookies: Posture,
}

#[derive(Debug, Clone, Serialize)]
pub struct Controls {
    pub auth: Posture,
    pub jwt: Posture,
    pub rate: Posture,
    pub https: Posture,
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

        if let Some(tls) = &svc.tls {
            findings.extend(tls_findings(svc.port, tls, now()));
        }
        findings.extend(header_findings(svc));

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

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// What an HTTPS service's TLS is worth flagging at `now`: a certificate
/// that has expired, expires within 30 days or signed itself, and old
/// protocol versions still accepted.
fn tls_findings(port: u16, tls: &TlsReport, now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    let loc = format!("port {port} (https)");
    if let Some(c) = &tls.cert {
        let days = (c.not_after - now) / 86_400;
        if c.not_after < now {
            out.push(Finding {
                severity: Severity::Medium,
                title: "Expired TLS certificate".to_string(),
                location: loc.clone(),
                detail: format!(
                    "The certificate for {} expired {} days ago, so clients refuse it. Renew it.",
                    c.subject, -days
                ),
            });
        } else if days < 30 {
            out.push(Finding {
                severity: Severity::Low,
                title: "TLS certificate expires soon".to_string(),
                location: loc.clone(),
                detail: format!(
                    "The certificate for {} expires in {days} days. Renew it before then.",
                    c.subject
                ),
            });
        }
        if c.self_signed {
            out.push(Finding {
                severity: Severity::Low,
                title: "Self-signed TLS certificate".to_string(),
                location: loc.clone(),
                detail: format!(
                    "{} issued its own certificate, so clients can't verify who they're talking to. Use one from a certificate authority, or a private CA your clients trust.",
                    c.subject
                ),
            });
        }
    }
    if !tls.legacy.is_empty() {
        out.push(Finding {
            severity: Severity::Medium,
            title: "Legacy TLS accepted".to_string(),
            location: loc,
            detail: format!(
                "Accepts {}, deprecated and open to downgrade attacks. Require TLS 1.2 or newer.",
                tls.legacy.join(" and ")
            ),
        });
    }
    out
}

/// What a service's headers are worth flagging, once per service rather
/// than per endpoint, from its openly reachable endpoints: no HSTS over
/// HTTPS, pages without CSP or framing protection, and cookies missing
/// their flags.
fn header_findings(svc: &ServiceReport) -> Vec<Finding> {
    let mut out = Vec::new();
    let open: Vec<&Endpoint> = svc
        .endpoints
        .iter()
        .filter(|e| e.auth == AuthState::Open)
        .collect();
    let loc = format!("port {} ({})", svc.port, svc.scheme);
    if open.iter().any(|e| render::hsts(e) == Posture::Missing) {
        out.push(Finding {
            severity: Severity::Low,
            title: "No HSTS on HTTPS service".to_string(),
            location: loc.clone(),
            detail: "Responses carry no Strict-Transport-Security header, so a browser can be steered to plain HTTP first. Send it with a long max-age.".to_string(),
        });
    }
    let unguarded = open
        .iter()
        .any(|e| render::csp(e) == Posture::Missing || render::frame(e) == Posture::Missing);
    if unguarded {
        out.push(Finding {
            severity: Severity::Low,
            title: "Pages served without CSP or framing protection".to_string(),
            location: loc.clone(),
            detail: "HTML responses lack a Content-Security-Policy or X-Frame-Options, which limit injected script and clickjacking. Add both.".to_string(),
        });
    }
    let mut loose: Vec<&str> = open
        .iter()
        .copied()
        .flat_map(|e| {
            e.headers
                .cookies
                .iter()
                .filter(move |c| !render::cookie_ok(c, e.tls))
                .map(|c| c.name.as_str())
        })
        .collect();
    loose.sort_unstable();
    loose.dedup();
    if !loose.is_empty() {
        out.push(Finding {
            severity: Severity::Low,
            title: "Cookies missing security flags".to_string(),
            location: loc,
            detail: format!(
                "{} set without all of HttpOnly, SameSite and, over HTTPS, Secure. Add them so scripts and other sites can't read or send the cookies.",
                loose.join(", ")
            ),
        });
    }
    out
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

    let any_origin = ep.headers.cors_origin.as_deref().map(str::trim) == Some("*");
    if any_origin && ep.headers.cors_credentials {
        out.push(Finding {
            severity: Severity::Medium,
            title: "CORS allows any origin with credentials".to_string(),
            location: loc.clone(),
            detail: "Access-Control-Allow-Origin is * alongside Access-Control-Allow-Credentials: true. Name the origins that may call it instead.".to_string(),
        });
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
            banner: None,
            tls: services
                .iter()
                .find(|s| s.port == o.port)
                .and_then(|s| s.tls.as_ref())
                .map(TlsView::from),
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
                controls: Controls {
                    auth: render::auth(ep),
                    jwt: render::jwt(ep),
                    rate: render::rate(ep),
                    https: render::https(ep),
                },
                headers: HeaderControls {
                    hsts: render::hsts(ep),
                    csp: render::csp(ep),
                    frame: render::frame(ep),
                    nosniff: render::nosniff(ep),
                    cors: render::cors(ep),
                    cookies: render::cookies(ep),
                },
            });
        }
    }

    Report {
        target: target.to_string(),
        resolved_ip: resolved_ip.to_string(),
        open_ports: open_ports_view,
        endpoints,
        findings,
        hosts: Vec::new(),
        technologies: Vec::new(),
    }
}

/// Assemble the report of a range: each host that answered with its open
/// ports, and the risky services among them, located by host and port.
pub fn assemble_range(target: &str, hosts: &[(IpAddr, Vec<OpenPort>)]) -> Report {
    let mut findings = Vec::new();
    let mut views = Vec::new();
    for (ip, open) in hosts {
        for f in build_findings(open, &[]) {
            findings.push(Finding {
                location: format!("{ip} ({})", f.location),
                ..f
            });
        }
        views.push(HostView {
            ip: ip.to_string(),
            open_ports: open
                .iter()
                .map(|o| PortView {
                    port: o.port,
                    service: o.service.to_string(),
                    banner: None,
                    tls: None,
                })
                .collect(),
        });
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    Report {
        target: target.to_string(),
        resolved_ip: target.to_string(),
        open_ports: Vec::new(),
        endpoints: Vec::new(),
        findings,
        hosts: views,
        technologies: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use endpoints::{Cookie, RateLimitInfo, SecurityHeaders};

    fn open_ep(path: &str, sensitive: bool, status: u16) -> Endpoint {
        Endpoint {
            url: format!("http://h{path}"),
            path: path.to_string(),
            status,
            auth: AuthState::Open,
            tls: false,
            sensitive,
            note: "n".to_string(),
            server: None,
            powered_by: None,
            content_type: None,
            www_authenticate: None,
            location: None,
            rate_limit: RateLimitInfo::default(),
            headers: SecurityHeaders::default(),
        }
    }

    #[test]
    fn header_findings_once_per_service() {
        let mut page = open_ep("/", false, 200);
        page.tls = true;
        page.content_type = Some("text/html".to_string());
        page.headers.cookies.push(Cookie {
            name: "sid".to_string(),
            secure: false,
            http_only: true,
            same_site: Some("Lax".to_string()),
        });
        let svc = ServiceReport {
            port: 443,
            scheme: "https".to_string(),
            reachable: true,
            endpoints: vec![page.clone(), page],
            tls: None,
        };
        let titles: Vec<String> = header_findings(&svc).into_iter().map(|f| f.title).collect();
        assert_eq!(
            titles,
            [
                "No HSTS on HTTPS service",
                "Pages served without CSP or framing protection",
                "Cookies missing security flags"
            ]
        );
    }

    #[test]
    fn sensitive_open_endpoint_is_high() {
        let svc = ServiceReport {
            port: 8080,
            scheme: "http".to_string(),
            reachable: true,
            endpoints: vec![open_ep("/actuator/env", true, 200)],
            tls: None,
        };
        let f = build_findings(&[], &[svc]);
        assert!(f.iter().any(|x| x.severity == Severity::High));
    }

    #[test]
    fn exposed_redis_is_high() {
        let op = OpenPort {
            port: 6379,
            service: "redis",
            http_tls: None,
        };
        let f = build_findings(&[op], &[]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn findings_sorted_high_first() {
        let svc = ServiceReport {
            port: 80,
            scheme: "http".to_string(),
            reachable: true,
            endpoints: vec![
                open_ep("/actuator/env", true, 200),
                open_ep("/api", false, 200),
            ],
            tls: None,
        };
        let f = build_findings(&[], &[svc]);
        assert!(f.windows(2).all(|w| w[0].severity >= w[1].severity));
    }

    #[test]
    fn range_findings_name_the_host() {
        let redis = OpenPort {
            port: 6379,
            service: "redis",
            http_tls: None,
        };
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let r = assemble_range("10.0.0.0/24", &[(ip, vec![redis])]);
        assert_eq!(r.hosts.len(), 1);
        assert_eq!(r.findings[0].location, "10.0.0.5 (port 6379)");
    }

    fn tls(not_after: i64, self_signed: bool, legacy: Vec<&'static str>) -> TlsReport {
        TlsReport {
            cert: Some(Cert {
                subject: "api.example".to_string(),
                issuer: "Example CA".to_string(),
                not_before: 0,
                not_after,
                names: Vec::new(),
                self_signed,
            }),
            legacy,
        }
    }

    #[test]
    fn tls_findings_by_state() {
        let now = 1_000_000_000;
        assert!(tls_findings(443, &tls(now + 90 * 86_400, false, vec![]), now).is_empty());
        let expired = tls_findings(443, &tls(now - 86_400, false, vec![]), now);
        assert_eq!(expired[0].title, "Expired TLS certificate");
        let soon = tls_findings(443, &tls(now + 5 * 86_400, false, vec![]), now);
        assert_eq!(soon[0].severity, Severity::Low);
        let weak = tls_findings(443, &tls(now + 90 * 86_400, true, vec!["TLS 1.0"]), now);
        assert_eq!(weak.len(), 2);
        assert!(weak.iter().all(|f| f.location == "port 443 (https)"));
    }
}
