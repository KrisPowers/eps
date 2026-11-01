//! What each open port runs, recognized from what the scan already saw:
//! `Server` and `X-Powered-By` headers, session cookie names, paths only a
//! given product answers, and service greetings. Nothing extra is sent.

use std::collections::BTreeMap;

use endpoints::{Endpoint, ServiceReport};
use serde::Serialize;

use crate::PortView;

/// One piece of software recognized on a port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tech {
    pub port: u16,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// What sort of thing it is: web server, language, framework, ...
    pub kind: &'static str,
    /// What gave it away.
    pub evidence: String,
}

/// Session cookies and the language or framework that names them so.
const COOKIES: &[(&str, &str)] = &[
    ("JSESSIONID", "Java"),
    ("PHPSESSID", "PHP"),
    ("ASP.NET_SessionId", "ASP.NET"),
    ("laravel_session", "Laravel"),
    ("connect.sid", "Express"),
    ("csrftoken", "Django"),
    ("ci_session", "CodeIgniter"),
];

/// Paths only one product answers, the content type it answers with, and
/// the product. The content type keeps a site that answers every path with
/// the same page from claiming them all.
const PATHS: &[(&str, &str, &str)] = &[
    ("/actuator", "json", "Spring Boot"),
    ("/nginx_status", "text/plain", "nginx"),
    ("/debug/vars", "json", "Go"),
    ("/_cluster/health", "json", "Elasticsearch"),
    ("/v1/sys/health", "json", "HashiCorp Vault"),
];

/// Products named in greetings, as they are written there.
const GREETED: &[&str] = &[
    "Postfix",
    "Exim",
    "Sendmail",
    "vsFTPd",
    "ProFTPD",
    "Pure-FTPd",
    "FileZilla Server",
    "Dovecot",
    "MariaDB",
];

/// Everything recognized on the open ports, by port then name.
pub fn technologies(ports: &[PortView], services: &[ServiceReport]) -> Vec<Tech> {
    let mut found: BTreeMap<(u16, String), Tech> = BTreeMap::new();
    let mut add = |port: u16, (name, version): (String, Option<String>), evidence: String| {
        let entry = found.entry((port, name.clone())).or_insert(Tech {
            port,
            kind: kind(&name),
            name,
            version: None,
            evidence,
        });
        if entry.version.is_none() {
            entry.version = version;
        }
    };

    for svc in services {
        for ep in &svc.endpoints {
            if let Some(p) = ep.server.as_deref().and_then(product) {
                add(svc.port, p, "Server header".to_string());
            }
            if let Some(p) = ep.powered_by.as_deref().and_then(product) {
                add(svc.port, p, "X-Powered-By header".to_string());
            }
            for c in &ep.headers.cookies {
                if let Some((cookie, name)) = COOKIES.iter().find(|(n, _)| c.name == *n) {
                    add(
                        svc.port,
                        (name.to_string(), None),
                        format!("{cookie} cookie"),
                    );
                }
            }
            if let Some(name) = by_path(ep) {
                add(
                    svc.port,
                    (name.to_string(), None),
                    format!("{} answers", ep.path),
                );
            }
        }
    }
    for p in ports {
        if let Some(found) = p.banner.as_deref().and_then(|b| greeting(b, &p.service)) {
            add(p.port, found, "greeting".to_string());
        }
    }
    found.into_values().collect()
}

fn by_path(ep: &Endpoint) -> Option<&'static str> {
    let ct = ep
        .content_type
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    PATHS
        .iter()
        .find(|(path, want, _)| ep.path == *path && ct.contains(*want))
        .map(|(_, _, name)| *name)
}

/// A `Server` or `X-Powered-By` value's product and version:
/// `nginx/1.25.3` or `Apache/2.4.57 (Debian)`.
pub fn product(header: &str) -> Option<(String, Option<String>)> {
    let token = header.split_whitespace().next()?;
    let (name, version) = match token.split_once('/') {
        Some((n, v)) => (n, Some(v.to_string()).filter(|v| !v.is_empty())),
        None => (token, None),
    };
    if name.is_empty() {
        return None;
    }
    Some((pretty(name), version))
}

/// The software a greeting names: `SSH-2.0-OpenSSH_9.6p1`, MySQL's version
/// line, or a mail or FTP server naming itself.
pub fn greeting(banner: &str, service: &str) -> Option<(String, Option<String>)> {
    if let Some(rest) = banner.strip_prefix("SSH-") {
        let software = rest.split_once('-')?.1.split_whitespace().next()?;
        return Some(match software.split_once('_') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (software.to_string(), None),
        });
    }
    if let Some(name) = GREETED.iter().find(|n| banner.contains(**n)) {
        let after = banner.split(*name).nth(1).unwrap_or("");
        let version = after
            .split_whitespace()
            .next()
            .map(|v| v.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.'))
            .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()));
        // MariaDB says `5.5.5-10.6.12-MariaDB`: its version comes before.
        let version = if *name == "MariaDB" {
            banner.split('-').nth(1).map(str::to_string)
        } else {
            version.map(str::to_string)
        };
        return Some((name.to_string(), version));
    }
    if service == "mysql" && banner.starts_with(|c: char| c.is_ascii_digit()) {
        return Some(("MySQL".to_string(), Some(banner.to_string())));
    }
    None
}

/// The name a product is known by.
fn pretty(name: &str) -> String {
    match name.to_ascii_lowercase().as_str() {
        "microsoft-iis" => "IIS".to_string(),
        "apache" => "Apache httpd".to_string(),
        "php" => "PHP".to_string(),
        "express" => "Express".to_string(),
        "asp.net" => "ASP.NET".to_string(),
        "next.js" => "Next.js".to_string(),
        _ => name.to_string(),
    }
}

fn kind(name: &str) -> &'static str {
    match name.to_ascii_lowercase().as_str() {
        "nginx" | "apache httpd" | "iis" | "caddy" | "openresty" | "lighttpd" | "envoy"
        | "traefik" | "jetty" | "kestrel" | "gunicorn" | "uvicorn" | "hypercorn" | "waitress"
        | "werkzeug" | "cowboy" | "apache-coyote" => "Web server",
        "cloudflare" | "amazons3" | "akamaighost" => "Edge",
        "php" | "asp.net" | "java" | "go" | "python" | "node.js" => "Language",
        "express" | "spring boot" | "django" | "laravel" | "next.js" | "flask" | "codeigniter" => {
            "Framework"
        }
        "mysql" | "mariadb" | "elasticsearch" => "Database",
        "openssh" | "dropbear" => "Remote access",
        "postfix" | "exim" | "sendmail" | "dovecot" => "Mail",
        "vsftpd" | "proftpd" | "pure-ftpd" | "filezilla server" => "File transfer",
        "hashicorp vault" => "Secrets",
        _ => "Software",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_headers() {
        assert_eq!(
            product("nginx/1.25.3"),
            Some(("nginx".to_string(), Some("1.25.3".to_string())))
        );
        assert_eq!(
            product("Apache/2.4.57 (Debian)"),
            Some(("Apache httpd".to_string(), Some("2.4.57".to_string())))
        );
        assert_eq!(product("uvicorn"), Some(("uvicorn".to_string(), None)));
        assert_eq!(product("  "), None);
    }

    #[test]
    fn greetings() {
        let ssh = greeting("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", "ssh");
        assert_eq!(
            ssh,
            Some(("OpenSSH".to_string(), Some("9.6p1".to_string())))
        );
        let ftp = greeting("220 (vsFTPd 3.0.5)", "ftp");
        assert_eq!(ftp, Some(("vsFTPd".to_string(), Some("3.0.5".to_string()))));
        let maria = greeting("5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1", "mysql");
        assert_eq!(
            maria,
            Some(("MariaDB".to_string(), Some("10.6.12".to_string())))
        );
        let mysql = greeting("8.0.36", "mysql");
        assert_eq!(
            mysql,
            Some(("MySQL".to_string(), Some("8.0.36".to_string())))
        );
        assert_eq!(greeting("+OK ready", "pop3"), None);
    }

    #[test]
    fn kinds() {
        assert_eq!(kind("nginx"), "Web server");
        assert_eq!(kind("Spring Boot"), "Framework");
        assert_eq!(kind("OpenSSH"), "Remote access");
        assert_eq!(kind("Something"), "Software");
    }
}
