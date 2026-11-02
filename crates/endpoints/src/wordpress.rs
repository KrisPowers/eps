//! What a WordPress site gives away: its users, XML-RPC, its login page and
//! version, a public debug log, an uploads folder anyone can list, and setup
//! left open. Each is one plain `GET`; nothing is posted or logged into.

use futures::future::join_all;
use reqwest::{Client, Url};

use crate::site::{Says, Signal};

/// Each path asked, in the order [`check`] reads the answers.
const PATHS: [&str; 8] = [
    "/wp-json/wp/v2/users",
    "/?author=1",
    "/xmlrpc.php",
    "/wp-login.php",
    "/feed/",
    "/wp-content/debug.log",
    "/wp-content/uploads/",
    "/wp-admin/setup-config.php",
];

/// The most of any one answer read.
const BIGGEST: usize = 512 * 1024;
/// The most of an answer kept to show.
const SHOWN: usize = 64 * 1024;

/// A path's status, `Location` and body.
async fn fetch(client: &Client, root: &Url, path: &str) -> Option<(u16, String, String)> {
    let resp = client.get(root.join(path).ok()?).send().await.ok()?;
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = crate::capped(resp, BIGGEST).await?;
    Some((
        status,
        location,
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

/// A concern, with the answer it was read from: the signal (its span in
/// that answer), the path asked, the answer, and the answer's language.
pub type Found = (Signal, String, String, &'static str);

/// A concern at `needle` in the answer to `path`.
fn found(
    label: &str,
    severity: &'static str,
    says: Says,
    evidence: String,
    path: &str,
    text: &str,
    needle: &str,
) -> Found {
    let mut end = text.len().min(SHOWN);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let shown = &text[..end];
    let span = shown.find(needle).map(|i| (i, i + needle.len()));
    let kind = match path {
        "/wp-json/wp/v2/users" => "json",
        "/xmlrpc.php" | "/feed/" => "xml",
        p if p.ends_with(".log") => "text",
        _ => "html",
    };
    let signal = Signal {
        category: "WordPress",
        label: label.to_string(),
        severity,
        why: says.why,
        impact: says.impact,
        evidence,
        page: path.to_string(),
        span,
        ..Signal::default()
    };
    (signal, path.to_string(), shown.to_string(), kind)
}

/// The user names a `/wp-json/wp/v2/users` answer lists.
fn users(body: &str) -> Vec<String> {
    let Ok(serde_json::Value::Array(list)) = serde_json::from_str(body) else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|u| u.get("slug").and_then(|s| s.as_str()))
        .map(str::to_string)
        .collect()
}

/// The WordPress version a feed's `<generator>` names.
fn version(feed: &str) -> Option<&str> {
    let at = feed.find("wordpress.org/?v=")? + 17;
    let len = feed[at..]
        .bytes()
        .take_while(|b| b.is_ascii_digit() || *b == b'.')
        .count();
    (len > 0).then(|| &feed[at..at + len])
}

const USERS: Says = Says {
    why: "The REST API names every author's login. Hide the users endpoint from visitors who aren't signed in.",
    impact: "A ready-made list of user names for password guessing against wp-login.php and xmlrpc.php: an attacker now only has to guess the password.",
};
const AUTHORS: Says = Says {
    why: "Asking for an author by number redirects to their page, which carries their login name. Counting up lists every user.",
    impact: USERS.impact,
};
const XMLRPC: Says = Says {
    why: "xmlrpc.php is on. Turn it off unless something uses it.",
    impact: "One request to it can try hundreds of passwords, getting around login rate limits, and its pingbacks can make your server send requests to other sites for an attacker.",
};
const LOGIN: Says = Says {
    why: "The login page is at the address every WordPress site uses.",
    impact: "Bots guess passwords against it around the clock; a weak or reused admin password falls quickly. Limit attempts and add two-factor sign-in, or restrict who can reach it.",
};
const VERSION: Says = Says {
    why: "The feed says exactly which WordPress runs here. Keep it up to date.",
    impact: "Anyone can match the version against published vulnerabilities and pick the ones that work on it.",
};
const DEBUG_LOG: Says = Says {
    why: "Anyone can read the PHP error log. Turn off WP_DEBUG_LOG on the live site and delete the file.",
    impact: "File paths, database errors, plugin names and sometimes visitors' emails and form data are readable, a map of the server for an attacker.",
};
const UPLOADS: Says = Says {
    why: "The uploads folder lists its contents. Turn off directory listing.",
    impact: "Every file ever uploaded, private documents never linked from the site included, can be found and downloaded.",
};
const SETUP: Says = Says {
    why: "WordPress isn't configured yet and its setup page is public.",
    impact: "Whoever finishes setup first points the site at their own database, makes themselves admin, and can then run code on the server.",
};

/// Checks the WordPress site at `root`.
pub async fn check(client: &Client, root: &Url) -> Vec<Found> {
    let got = join_all(PATHS.iter().map(|p| fetch(client, root, p))).await;
    let mut out = Vec::new();
    let answer = |i: usize| {
        got[i]
            .as_ref()
            .map(|(s, l, b)| (*s, l.as_str(), b.as_str()))
    };

    if let Some((200, _, body)) = answer(0) {
        let names = users(body);
        if let Some(first) = names.first() {
            out.push(found(
                "Lists its users",
                "medium",
                USERS,
                names
                    .iter()
                    .take(10)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                PATHS[0],
                body,
                &format!("\"slug\":\"{first}\""),
            ));
        }
    }
    if let Some((s, location, _)) = answer(1) {
        if (300..400).contains(&s) && location.contains("/author/") {
            let text = format!("HTTP {s}\nLocation: {location}\n");
            let (signal, path, text, _) = found(
                "Names its users by number",
                "low",
                AUTHORS,
                format!("{} to {location}", PATHS[1]),
                PATHS[1],
                &text,
                location,
            );
            out.push((signal, path, text, "http"));
        }
    }
    if let Some((s, _, body)) = answer(2) {
        let said = "XML-RPC server accepts POST requests only";
        if (s == 405 || s == 200) && body.contains(said) {
            out.push(found(
                "XML-RPC is on",
                "medium",
                XMLRPC,
                format!("{said}."),
                PATHS[2],
                body,
                said,
            ));
        }
    }
    if let Some((200, _, body)) = answer(3) {
        if body.contains("user_login") {
            out.push(found(
                "Login page at the default address",
                "low",
                LOGIN,
                format!("{}{}", root.as_str().trim_end_matches('/'), PATHS[3]),
                PATHS[3],
                body,
                "user_login",
            ));
        }
    }
    if let Some((200, _, body)) = answer(4) {
        if let Some(v) = version(body) {
            out.push(found(
                "Names its WordPress version",
                "low",
                VERSION,
                format!("WordPress {v}"),
                PATHS[4],
                body,
                &format!("wordpress.org/?v={v}"),
            ));
        }
    }
    if let Some((200, _, body)) = answer(5) {
        let log = [
            "PHP Warning",
            "PHP Fatal",
            "PHP Notice",
            "PHP Parse",
            "PHP Deprecated",
            "PHP Stack trace",
        ];
        if let Some(at) = log.iter().find_map(|l| body.find(l)) {
            let mut end = body[at..]
                .find('\n')
                .map_or(body.len(), |e| at + e)
                .min(at + 160);
            while !body.is_char_boundary(end) {
                end -= 1;
            }
            let line = &body[at..end];
            out.push(found(
                "Debug log is public",
                "high",
                DEBUG_LOG,
                line.to_string(),
                PATHS[5],
                body,
                line,
            ));
        }
    }
    if let Some((200, _, body)) = answer(6) {
        if body.contains("Index of") {
            out.push(found(
                "Lists its uploads folder",
                "medium",
                UPLOADS,
                "Index of /wp-content/uploads".to_string(),
                PATHS[6],
                body,
                "Index of",
            ));
        }
    }
    if let Some((200, _, body)) = answer(7) {
        let step = "setup-config.php?step=1";
        if body.contains(step) && !body.contains("already exists") {
            out.push(found(
                "Setup is open to anyone",
                "high",
                SETUP,
                format!("{}{}", root.as_str().trim_end_matches('/'), PATHS[7]),
                PATHS[7],
                body,
                step,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_users_and_version() {
        assert_eq!(
            users(r#"[{"id":1,"slug":"admin"},{"id":2,"slug":"editor"}]"#),
            ["admin", "editor"]
        );
        assert!(users(r#"{"code":"rest_no_route"}"#).is_empty());
        assert_eq!(
            version("<generator>https://wordpress.org/?v=6.4.2</generator>"),
            Some("6.4.2")
        );
        assert_eq!(version("<generator>Hugo</generator>"), None);
    }

    #[test]
    fn marks_what_it_found_in_the_answer() {
        let body = r#"[{"id":1,"slug":"admin"}]"#;
        let (signal, path, text, kind) = found(
            "Lists its users",
            "medium",
            USERS,
            String::new(),
            PATHS[0],
            body,
            "\"slug\":\"admin\"",
        );
        assert_eq!((path.as_str(), kind), ("/wp-json/wp/v2/users", "json"));
        let (s, e) = signal.span.unwrap();
        assert_eq!(&text[s..e], "\"slug\":\"admin\"");
    }
}
