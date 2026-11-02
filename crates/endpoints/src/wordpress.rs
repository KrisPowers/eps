//! What a WordPress site gives away: its users, XML-RPC, its login page and
//! version, a public debug log, an uploads folder anyone can list, and setup
//! left open. Each is one plain `GET`; nothing is posted or logged into.

use futures::future::join_all;
use reqwest::{Client, Url};

use crate::site::Signal;

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

fn signal(
    label: &str,
    severity: &'static str,
    why: &'static str,
    evidence: String,
    page: &str,
) -> Signal {
    Signal {
        category: "WordPress",
        label: label.to_string(),
        severity,
        why,
        evidence,
        page: page.to_string(),
        script: None,
    }
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

/// Checks the WordPress site at `root`.
pub async fn check(client: &Client, root: &Url) -> Vec<Signal> {
    let got = join_all(PATHS.iter().map(|p| fetch(client, root, p))).await;
    let mut out = Vec::new();
    let answer = |i: usize| {
        got[i]
            .as_ref()
            .map(|(s, l, b)| (*s, l.as_str(), b.as_str()))
    };

    if let Some((200, _, body)) = answer(0) {
        let names = users(body);
        if !names.is_empty() {
            out.push(signal(
                "Lists its users",
                "medium",
                "The REST API names every author's login, so anyone guessing passwords only has to guess the password. Hide the users endpoint from visitors who aren't signed in.",
                names.iter().take(10).cloned().collect::<Vec<_>>().join(", "),
                PATHS[0],
            ));
        }
    }
    if let Some((s, location, _)) = answer(1) {
        if (300..400).contains(&s) && location.contains("/author/") {
            out.push(signal(
                "Names its users by number",
                "low",
                "Asking for an author by number redirects to their page, which carries their login name. Counting up lists every user.",
                format!("{} to {location}", PATHS[1]),
                PATHS[1],
            ));
        }
    }
    if let Some((s, _, body)) = answer(2) {
        if (s == 405 || s == 200) && body.contains("XML-RPC server accepts POST requests only") {
            out.push(signal(
                "XML-RPC is on",
                "medium",
                "xmlrpc.php lets one request try hundreds of passwords, and can make this site send requests to others. Turn it off unless something uses it.",
                "XML-RPC server accepts POST requests only.".to_string(),
                PATHS[2],
            ));
        }
    }
    if let Some((200, _, body)) = answer(3) {
        if body.contains("user_login") {
            out.push(signal(
                "Login page at the default address",
                "low",
                "Automated password guessing goes straight to wp-login.php. Limit attempts and add two-factor sign-in, or restrict who can reach it.",
                format!("{}{}", root.as_str().trim_end_matches('/'), PATHS[3]),
                PATHS[3],
            ));
        }
    }
    if let Some((200, _, body)) = answer(4) {
        if let Some(v) = version(body) {
            out.push(signal(
                "Names its WordPress version",
                "low",
                "The feed says exactly which WordPress runs here, so anyone can look up what it is vulnerable to. Keep it up to date.",
                format!("WordPress {v}"),
                PATHS[4],
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
            out.push(signal(
                "Debug log is public",
                "high",
                "Anyone can read the PHP error log: file paths, queries and sometimes visitors' data. Turn off WP_DEBUG_LOG on the live site and delete the file.",
                body[at..end].to_string(),
                PATHS[5],
            ));
        }
    }
    if let Some((200, _, body)) = answer(6) {
        if body.contains("Index of") {
            out.push(signal(
                "Lists its uploads folder",
                "medium",
                "Anyone can browse every file ever uploaded, including ones never linked from the site. Turn off directory listing.",
                "Index of /wp-content/uploads".to_string(),
                PATHS[6],
            ));
        }
    }
    if let Some((200, _, body)) = answer(7) {
        if body.contains("setup-config.php?step=1") && !body.contains("already exists") {
            out.push(signal(
                "Setup is open to anyone",
                "high",
                "WordPress isn't configured yet and its setup page is public: whoever finishes it first owns the site and can run code on the server.",
                format!("{}{}", root.as_str().trim_end_matches('/'), PATHS[7]),
                PATHS[7],
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
}
