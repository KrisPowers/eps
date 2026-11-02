//! Reading source a site serves (its scripts, any PHP it leaks, the original
//! code in its source maps) for what was left in it: credentials and keys,
//! the requests it makes and the request parameters its PHP reads.
//!
//! Nothing is run. Code that builds a key or an address as it runs can slip
//! past a reading.

/// A credential found in code: what it looks like, how bad, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    pub label: &'static str,
    /// `high` or `medium`.
    pub severity: &'static str,
    pub why: &'static str,
    /// Byte offset of the credential itself.
    pub at: usize,
    /// Its length in bytes.
    pub len: usize,
}

/// A request the code makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// `GET`, `POST`, ..., or `WS` for a WebSocket.
    pub method: String,
    /// The address as the code names it.
    pub url: String,
}

/// A credential with a format of its own: a prefix, then a body of `size`
/// characters (at least, unless `exact`) from `chars`.
struct Token {
    prefix: &'static str,
    size: usize,
    exact: bool,
    chars: fn(u8) -> bool,
    label: &'static str,
    severity: &'static str,
    why: &'static str,
}

fn alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
fn upper(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}
fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}
fn dotted(b: u8) -> bool {
    word(b) || b == b'.'
}
fn base64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"+/=".contains(&b)
}
fn slashed(b: u8) -> bool {
    alnum(b) || b == b'/'
}

const LIVE: &str = "A working credential in code anyone can download. Revoke it, issue a new one and keep it on the server.";

const TOKENS: &[Token] = &[
    Token { prefix: "AKIA", size: 16, exact: true, chars: upper, label: "AWS access key", severity: "high", why: LIVE },
    Token { prefix: "ASIA", size: 16, exact: true, chars: upper, label: "AWS access key", severity: "high", why: LIVE },
    Token { prefix: "AIza", size: 35, exact: true, chars: word, label: "Google API key", severity: "medium", why: "A Google API key in the page. Some are meant to be public, but unless it is restricted to this site and the APIs it needs, anyone can run up its bill." },
    Token { prefix: "sk_live_", size: 20, exact: false, chars: alnum, label: "Stripe secret key", severity: "high", why: LIVE },
    Token { prefix: "rk_live_", size: 20, exact: false, chars: alnum, label: "Stripe secret key", severity: "high", why: LIVE },
    Token { prefix: "sk_test_", size: 20, exact: false, chars: alnum, label: "Stripe test key", severity: "medium", why: "A Stripe test key left in the code: no money moves with it, but it opens the account's test data." },
    Token { prefix: "ghp_", size: 36, exact: true, chars: alnum, label: "GitHub token", severity: "high", why: LIVE },
    Token { prefix: "gho_", size: 36, exact: true, chars: alnum, label: "GitHub token", severity: "high", why: LIVE },
    Token { prefix: "ghu_", size: 36, exact: true, chars: alnum, label: "GitHub token", severity: "high", why: LIVE },
    Token { prefix: "ghs_", size: 36, exact: true, chars: alnum, label: "GitHub token", severity: "high", why: LIVE },
    Token { prefix: "github_pat_", size: 22, exact: false, chars: word, label: "GitHub token", severity: "high", why: LIVE },
    Token { prefix: "glpat-", size: 20, exact: false, chars: word, label: "GitLab token", severity: "high", why: LIVE },
    Token { prefix: "xoxb-", size: 10, exact: false, chars: word, label: "Slack token", severity: "high", why: LIVE },
    Token { prefix: "xoxp-", size: 10, exact: false, chars: word, label: "Slack token", severity: "high", why: LIVE },
    Token { prefix: "xoxa-", size: 10, exact: false, chars: word, label: "Slack token", severity: "high", why: LIVE },
    Token { prefix: "hooks.slack.com/services/", size: 20, exact: false, chars: slashed, label: "Slack webhook", severity: "medium", why: "Anyone with this address can post messages into the Slack channel it belongs to." },
    Token { prefix: "sk-ant-", size: 20, exact: false, chars: word, label: "Anthropic API key", severity: "high", why: LIVE },
    Token { prefix: "sk-proj-", size: 20, exact: false, chars: word, label: "OpenAI API key", severity: "high", why: LIVE },
    Token { prefix: "SG.", size: 60, exact: false, chars: dotted, label: "SendGrid API key", severity: "high", why: LIVE },
    Token { prefix: "npm_", size: 36, exact: true, chars: alnum, label: "npm token", severity: "high", why: LIVE },
    Token { prefix: "AccountKey=", size: 40, exact: false, chars: base64, label: "Azure storage key", severity: "high", why: LIVE },
    Token { prefix: "eyJ", size: 30, exact: false, chars: dotted, label: "JSON Web Token", severity: "medium", why: "A signed token in the code. If it is a real session or service token, anyone can use it until it expires." },
];

/// Names that hold a credential, compared with `_` and `-` removed and in
/// lowercase, as the end of a variable or key.
const CREDENTIAL_NAMES: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "apikey",
    "secretkey",
    "accesskey",
    "privatekey",
    "clientsecret",
    "authtoken",
    "accesstoken",
    "apitoken",
    "apisecret",
    "dbpassword",
    "dbpass",
];

/// Whether a variable, key or field name holds a credential: `DB_PASSWORD`,
/// `apiKey`, `client_secret`. Anti-forgery tokens aren't credentials.
pub fn credential_name(name: &str) -> bool {
    let n: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    let forgery = ["csrf", "xsrf", "nonce", "authenticity", "verification"];
    !n.is_empty()
        && !forgery.iter().any(|f| n.contains(f))
        && CREDENTIAL_NAMES.iter().any(|c| n.ends_with(c))
}

/// Whether a literal reads as a real credential rather than a label, a path,
/// a placeholder or a template.
pub fn credential_value(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    let first = v.bytes().next().unwrap_or(b' ');
    let symbols = v.bytes().any(|b| !b.is_ascii_alphabetic());
    (6..=200).contains(&v.len())
        && !v.bytes().any(|b| b.is_ascii_whitespace())
        && !b"/.#$%{<*".contains(&first)
        && (symbols || v.len() >= 16)
        && !v.bytes().all(|b| b == first)
        && ![
            "${",
            "{{",
            "xxxx",
            "****",
            "example",
            "placeholder",
            "your",
            "redacted",
            "process.env",
            "getenv",
        ]
        .iter()
        .any(|p| lower.contains(p))
}

/// The credentials in `code`, at most 20.
pub fn secrets(code: &str) -> Vec<Secret> {
    const MOST: usize = 20;
    let bytes = code.as_bytes();
    let mut out: Vec<Secret> = Vec::new();
    let add = |s: Secret, out: &mut Vec<Secret>| {
        if out.len() < MOST && !out.iter().any(|o| o.at <= s.at && s.at < o.at + o.len) {
            out.push(s);
        }
    };
    for t in TOKENS {
        let mut from = 0;
        while let Some(i) = code[from..].find(t.prefix).map(|i| i + from) {
            from = i + t.prefix.len();
            if i > 0 && alnum(bytes[i - 1]) {
                continue;
            }
            let body = bytes[from..].iter().take_while(|b| (t.chars)(**b)).count();
            if body < t.size || (t.exact && body != t.size) {
                continue;
            }
            // A JSON Web Token is three dotted parts, the second also JSON.
            if t.prefix == "eyJ" && !code[from..from + body].contains(".eyJ") {
                continue;
            }
            let len = if t.prefix.ends_with('/') || t.prefix.ends_with('=') {
                body
            } else {
                t.prefix.len() + body
            };
            let at = from + body - len;
            add(
                Secret {
                    label: t.label,
                    severity: t.severity,
                    why: t.why,
                    at,
                    len,
                },
                &mut out,
            );
        }
    }
    let mut from = 0;
    while let Some(i) = code[from..].find("PRIVATE KEY-----").map(|i| i + from) {
        from = i + 16;
        let start = code[..i].rfind("-----BEGIN").filter(|s| i - s < 40);
        if let Some(start) = start {
            add(
                Secret {
                    label: "Private key",
                    severity: "high",
                    why: "A private key in code anyone can download. Whatever it signs or decrypts is no longer private: replace it.",
                    at: start,
                    len: from - start,
                },
                &mut out,
            );
        }
    }
    for (at, len) in url_passwords(code) {
        add(
            Secret {
                label: "Password in an address",
                severity: "high",
                why: "An address with a user name and password in it, readable by anyone who downloads the code.",
                at,
                len,
            },
            &mut out,
        );
    }
    for (at, len) in assignments(code) {
        add(
            Secret {
                label: "Password or key in the code",
                severity: "medium",
                why: "A value assigned to a name that holds a password or key. If it's real, anyone who reads the code has it: move it to the server and change it.",
                at,
                len,
            },
            &mut out,
        );
    }
    out.sort_by_key(|s| s.at);
    out
}

/// Passwords in addresses such as `mysql://app:hunter2@db`: where each is,
/// and its length.
fn url_passwords(code: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = code[from..].find("://").map(|i| i + from + 3) {
        from = i;
        let rest = &code[i..];
        let end = rest
            .find(|c: char| c.is_whitespace() || "/\"'`?#<>()".contains(c))
            .unwrap_or(rest.len());
        let Some(at) = rest[..end].rfind('@') else {
            continue;
        };
        let Some(colon) = rest[..at].find(':') else {
            continue;
        };
        let password = &rest[colon + 1..at];
        let skip = ["${", "{", "%", "<", "*", "$"];
        if !password.is_empty()
            && rest[..colon]
                .bytes()
                .all(|b| word(b) || b == b'.' || b == b'%')
            && !skip.iter().any(|s| password.starts_with(s))
            && !password.eq_ignore_ascii_case("password")
        {
            out.push((i + colon + 1, password.len()));
        }
    }
    out
}

/// String literals assigned to a credential's name: `password: "s3cret!"`,
/// `$db_pass = 'x9!'`, `'DB_PASSWORD' => '...'` and PHP's
/// `define('DB_PASSWORD', '...')`. Where each value is, and its length.
fn assignments(code: &str) -> Vec<(usize, usize)> {
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') || (i > 0 && word(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && word(bytes[i]) {
            i += 1;
        }
        if i - start > 40 || !credential_name(&code[start..i]) {
            continue;
        }
        let quoted = start > 0 && b"\"'".contains(&bytes[start - 1]);
        let mut j = i;
        if quoted && j < bytes.len() && bytes[j] == bytes[start - 1] {
            j += 1;
        }
        while j < bytes.len() && bytes[j] == b' ' {
            j += 1;
        }
        let Some(&op) = bytes.get(j) else { break };
        let assigns = match op {
            b'=' => {
                j += 1;
                while j < bytes.len() && b"=>".contains(&bytes[j]) {
                    j += 1;
                }
                true
            }
            b':' => {
                j += 1;
                true
            }
            // define('NAME', 'value')
            b',' if quoted => {
                j += 1;
                true
            }
            _ => false,
        };
        if !assigns {
            continue;
        }
        while j < bytes.len() && bytes[j] == b' ' {
            j += 1;
        }
        let Some(&q) = bytes.get(j).filter(|b| b"\"'`".contains(b)) else {
            continue;
        };
        let at = j + 1;
        let Some(len) = code[at..].find(q as char) else {
            continue;
        };
        let value = &code[at..at + len];
        if !value.contains('\n') && credential_value(value) {
            out.push((at, len));
        }
        i = at + len;
    }
    out
}

/// `text` with the credential at `at` masked to its first few and last two
/// characters, so a report never carries the whole thing.
pub fn mask(text: &str, at: usize, len: usize) -> String {
    let secret = &text[at..at + len];
    let chars: Vec<char> = secret.chars().collect();
    let keep = if chars.len() > 12 { 4 } else { 1 };
    let shown: String = chars[..keep].iter().collect();
    let tail: String = if chars.len() > 12 {
        chars[chars.len() - 2..].iter().collect()
    } else {
        String::new()
    };
    let stars = "*".repeat((chars.len() - keep - tail.chars().count()).min(12));
    format!("{}{shown}{stars}{tail}{}", &text[..at], &text[at + len..])
}

/// About 120 characters around a credential, on one line, with the
/// credential masked.
pub fn evidence(code: &str, s: &Secret) -> String {
    let mut start = s.at.saturating_sub(50);
    while !code.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (s.at + s.len + 30).min(code.len());
    while !code.is_char_boundary(end) {
        end += 1;
    }
    mask(&code[start..end], s.at - start, s.len)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

const METHODS: &[&str] = &["get", "post", "put", "patch", "delete", "head", "options"];

/// The string literal starting at byte `at` (on its opening quote), if
/// there is one: up to its closing quote, on one line.
fn literal(code: &str, at: usize) -> Option<&str> {
    let q = *code.as_bytes().get(at)?;
    if !b"\"'`".contains(&q) {
        return None;
    }
    let len = code[at + 1..].find(q as char)?;
    let s = &code[at + 1..at + 1 + len];
    (!s.is_empty() && s.len() <= 300 && !s.contains(['\n', ' '])).then_some(s)
}

/// Skips spaces from byte `at`.
fn skip(code: &str, at: usize) -> usize {
    at + code[at..]
        .bytes()
        .take_while(|b| b.is_ascii_whitespace())
        .count()
}

/// A method named as `method: "POST"` or `type: 'post'` within `window`.
fn method_in(window: &str) -> Option<String> {
    for key in ["method", "type"] {
        let mut from = 0;
        while let Some(i) = window[from..].find(key).map(|i| i + from + key.len()) {
            from = i;
            let mut j = i;
            if window.as_bytes().get(j).is_some_and(|b| b"\"'".contains(b)) {
                j += 1;
            }
            j = skip(window, j);
            if window.as_bytes().get(j) != Some(&b':') {
                continue;
            }
            j = skip(window, j + 1);
            if let Some(m) = literal(window, j) {
                if METHODS.contains(&m.to_ascii_lowercase().as_str()) {
                    return Some(m.to_ascii_uppercase());
                }
            }
        }
    }
    None
}

/// Whether a literal reads as somewhere a request goes.
fn addressy(url: &str) -> bool {
    url.starts_with('/')
        || url.starts_with("http")
        || url.starts_with("ws")
        || url.starts_with("${")
}

/// The requests `code` makes, as far as reading it shows: `fetch`,
/// `XMLHttpRequest.open`, `axios`, jQuery and `$http`-style `.get(`,
/// `.post(`, ..., `$.ajax`, `sendBeacon` and `WebSocket`. At most 100.
pub fn requests(code: &str) -> Vec<Call> {
    const MOST: usize = 100;
    let mut out: Vec<Call> = Vec::new();
    let mut add = |method: String, url: &str| {
        if out.len() < MOST && !out.iter().any(|c| c.method == method && c.url == url) {
            out.push(Call {
                method,
                url: url.to_string(),
            });
        }
    };
    // The rest of the statement a call starts, up to 300 bytes.
    let window = |at: usize| {
        let mut end = (at + 300).min(code.len());
        while !code.is_char_boundary(end) {
            end += 1;
        }
        let w = &code[at..end];
        &w[..w.find(';').unwrap_or(w.len())]
    };
    let each = |needle: &str, f: &mut dyn FnMut(usize)| {
        let mut from = 0;
        while let Some(i) = code[from..].find(needle).map(|i| i + from + needle.len()) {
            from = i;
            f(i);
        }
    };
    let mut found: Vec<(String, String)> = Vec::new();
    each("fetch(", &mut |i| {
        if let Some(url) = literal(code, skip(code, i)) {
            let method = method_in(window(i)).unwrap_or_else(|| "GET".to_string());
            found.push((method, url.to_string()));
        }
    });
    each(".open(", &mut |i| {
        let j = skip(code, i);
        let Some(m) = literal(code, j) else { return };
        if !METHODS.contains(&m.to_ascii_lowercase().as_str()) {
            return;
        }
        let k = skip(code, j + m.len() + 2);
        if code.as_bytes().get(k) != Some(&b',') {
            return;
        }
        if let Some(url) = literal(code, skip(code, k + 1)) {
            found.push((m.to_ascii_uppercase(), url.to_string()));
        }
    });
    for m in METHODS {
        each(&format!(".{m}("), &mut |i| {
            if let Some(url) = literal(code, skip(code, i)).filter(|u| addressy(u)) {
                found.push((m.to_ascii_uppercase(), url.to_string()));
            }
        });
    }
    for call in ["ajax(", "axios("] {
        each(call, &mut |i| {
            let w = window(i);
            let Some(u) = w.find("url") else { return };
            let mut j = u + 3;
            if w.as_bytes().get(j).is_some_and(|b| b"\"'".contains(b)) {
                j += 1;
            }
            j = skip(w, j);
            if w.as_bytes().get(j) != Some(&b':') {
                return;
            }
            if let Some(url) = literal(w, skip(w, j + 1)).filter(|u| addressy(u)) {
                let method = method_in(w).unwrap_or_else(|| "GET".to_string());
                found.push((method, url.to_string()));
            }
        });
    }
    each("sendBeacon(", &mut |i| {
        if let Some(url) = literal(code, skip(code, i)) {
            found.push(("POST".to_string(), url.to_string()));
        }
    });
    each("WebSocket(", &mut |i| {
        if let Some(url) = literal(code, skip(code, i)) {
            found.push(("WS".to_string(), url.to_string()));
        }
    });
    for (method, url) in found {
        add(method, &url);
    }
    out
}

/// The request parameters PHP source reads, by how they arrive: `GET`,
/// `POST`, `ANY` (`$_REQUEST`), `COOKIE` or `FILE` (an upload).
pub fn php_inputs(code: &str) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    for (global, method) in [
        ("$_GET[", "GET"),
        ("$_POST[", "POST"),
        ("$_REQUEST[", "ANY"),
        ("$_COOKIE[", "COOKIE"),
        ("$_FILES[", "FILE"),
    ] {
        let mut from = 0;
        while let Some(i) = code[from..].find(global).map(|i| i + from + global.len()) {
            from = i;
            if let Some(name) = literal(code, skip(code, i)) {
                if out.len() < 100 && !out.iter().any(|(m, n)| *m == method && n == name) {
                    out.push((method, name.to_string()));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(code: &str) -> Vec<&'static str> {
        secrets(code).iter().map(|s| s.label).collect()
    }

    #[test]
    fn finds_tokens_by_their_format() {
        assert_eq!(labels(r#"k="AKIAIOSFODNN7EXAMPLE""#), ["AWS access key"]);
        assert!(labels(r#"k="AKIAIOSFODNN7EXAMPLE1""#).is_empty());
        // Put together here so the file itself carries no key-shaped string.
        let stripe = format!("s='{}{}'", "sk_live_", "x".repeat(24));
        assert_eq!(labels(&stripe), ["Stripe secret key"]);
        assert_eq!(
            labels("-----BEGIN RSA PRIVATE KEY-----\nMIIE"),
            ["Private key"]
        );
        assert_eq!(
            labels("a='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'"),
            ["JSON Web Token"]
        );
        assert!(labels("var data='eyJpbWFnZSI6dHJ1ZX0'").is_empty());
    }

    #[test]
    fn finds_assigned_passwords_not_labels() {
        assert_eq!(
            labels(r#"const config={password:"hunter2!"}"#),
            ["Password or key in the code"]
        );
        assert_eq!(
            labels("define('DB_PASSWORD', 'r00tPass');"),
            ["Password or key in the code"]
        );
        assert_eq!(
            labels("$db_pass = \"s3cr3t#1\";"),
            ["Password or key in the code"]
        );
        assert_eq!(
            labels("'api_key' => 'a8f5f167f44f4964e6c998dee827110c'"),
            ["Password or key in the code"]
        );
        assert!(labels(
            r#"{password:"Password",forgotPassword:"/forgot",passwordHint:"Enter your password"}"#
        )
        .is_empty());
        assert!(labels(r#"password: process.env.DB_PASSWORD"#).is_empty());
        assert!(labels(r#"x={csrf_token:"abc123def456"}"#).is_empty());
    }

    #[test]
    fn finds_passwords_in_addresses() {
        assert_eq!(
            labels(r#"db="mysql://app:hunter2@db.internal/shop""#),
            ["Password in an address"]
        );
        assert!(labels(r#"u="https://user@example.com/""#).is_empty());
        assert!(labels(r#"u="https://${u}:${p}@host/""#).is_empty());
    }

    #[test]
    fn masks_what_it_shows() {
        let code = r#"key = "AKIAIOSFODNN7EXAMPLE";"#;
        let s = &secrets(code)[0];
        let shown = evidence(code, s);
        assert!(shown.contains("AKIA"));
        assert!(!shown.contains("IOSFODNN7EXAMPLE"));
        assert!(shown.ends_with("LE\";"));
    }

    #[test]
    fn reads_requests() {
        let code = r#"fetch("/api/orders",{method:"POST",body:b});fetch('/api/me');
            x.open("DELETE", "/api/users/1");axios.put(`/api/cart`);$.post("/contact.php",d);
            $.ajax({url:"/admin/save",type:"post"});m.get("key");new WebSocket("wss://live.example/ws");"#;
        let got: Vec<(String, String)> = requests(code)
            .into_iter()
            .map(|c| (c.method, c.url))
            .collect();
        let has = |m: &str, u: &str| got.iter().any(|(a, b)| a == m && b == u);
        assert!(has("POST", "/api/orders"));
        assert!(has("GET", "/api/me"));
        assert!(has("DELETE", "/api/users/1"));
        assert!(has("PUT", "/api/cart"));
        assert!(has("POST", "/contact.php"));
        assert!(has("POST", "/admin/save"));
        assert!(has("WS", "wss://live.example/ws"));
        assert!(!got.iter().any(|(_, u)| u == "key"));
    }

    #[test]
    fn reads_php_inputs() {
        let php = r#"<?php $id = $_GET['id']; $n = $_POST["name"]; move_uploaded_file($_FILES['doc']['tmp_name'], $to);"#;
        assert_eq!(
            php_inputs(php),
            [
                ("GET", "id".to_string()),
                ("POST", "name".to_string()),
                ("FILE", "doc".to_string())
            ]
        );
    }
}
