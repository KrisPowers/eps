//! A website on an HTTP service: its paths, mapped from `robots.txt`, its
//! sitemaps and its own links, and what its pages would do in a visitor's
//! browser, read from each page and every script it loads.
//!
//! Nothing is run. Pages and scripts are fetched with plain `GET`s inside the
//! scanner and their source is read for code that reaches into the browser:
//! location, the visitor's IP address, device fingerprinting, camera and
//! sensors, keystrokes, crypto mining, hidden frames, password forms that
//! post elsewhere, redirects, trackers and session recorders. Code that only
//! builds these calls as it runs can slip past a reading.

use std::collections::{HashSet, VecDeque};

use futures::future::join_all;
use reqwest::{Client, Url};
use serde::Serialize;

/// Pages fetched per site, at most.
const MOST_PAGES: usize = 100;
/// How many links deep from the start the crawl follows.
const DEEPEST: usize = 3;
/// Scripts read per site, at most.
const MOST_SCRIPTS: usize = 60;
/// Sitemap documents read per site, at most.
const MOST_SITEMAPS: usize = 5;
/// The most of any one body read.
const BIGGEST: usize = 3 * 1024 * 1024;
/// Requests in flight at once.
const AT_ONCE: usize = 8;

/// Paths not worth fetching as pages: images, styles, fonts, media, archives.
const ASSETS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".css", ".js", ".mjs", ".map",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".mp4", ".webm",
    ".mp3", ".wav", ".avi", ".mov", ".dmg", ".exe", ".iso",
];

/// One path on the site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Page {
    pub path: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// How it was found: `start`, `url`, `link`, `sitemap` or `robots`.
    pub found: &'static str,
}

/// A script a page loads from a URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Script {
    pub url: String,
    /// Served from another site than the one scanned.
    pub third_party: bool,
    /// Bytes read; 0 when it couldn't be fetched.
    pub bytes: usize,
}

/// Something a page would do in a visitor's browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Signal {
    /// Location, Network, Fingerprinting, ...
    pub category: &'static str,
    pub label: String,
    /// `high`, `medium` or `low`.
    pub severity: &'static str,
    /// What it means for someone who opens the page.
    pub why: &'static str,
    /// The code or markup that showed it.
    pub evidence: String,
    /// The page it was on.
    pub page: String,
    /// The script it was in; `None` for the page's own markup or inline code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
}

/// A site, mapped and read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Site {
    /// `scheme://host:port`.
    pub base: String,
    pub pages: Vec<Page>,
    pub scripts: Vec<Script>,
    pub signals: Vec<Signal>,
    /// Pages on other hosts the site links to, in its markup or its scripts:
    /// often its own subdomains.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<String>,
}

/// Links kept per site, at most.
const MOST_LINKS: usize = 300;

/// Keeps `url` among the site's links when it's on another host.
fn link_out(site: &mut Site, root: &Url, url: Url) {
    let web = matches!(url.scheme(), "http" | "https");
    if web && url.host_str() != root.host_str() && site.links.len() < MOST_LINKS {
        let mut url = url;
        url.set_fragment(None);
        let url = url.to_string();
        if !site.links.contains(&url) {
            site.links.push(url);
        }
    }
}

/// Absolute web addresses a script names as string literals.
fn addresses(code: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for scheme in ["\"https://", "'https://", "`https://", "\"http://", "'http://", "`http://"] {
        let quote = &scheme[..1];
        let mut from = 0;
        while let Some(i) = code[from..].find(scheme).map(|i| i + from + 1) {
            let Some(end) = code[i..].find(quote).map(|e| e + i) else { break };
            if end - i < 300 {
                out.push(&code[i..end]);
            }
            from = end + 1;
        }
    }
    out
}

/// Maps and reads the site at `base`, starting from `/` and `start` (such
/// as a URL's own path).
pub async fn explore(client: &Client, base: &str, start: &[String]) -> Site {
    let Ok(root) = Url::parse(base) else {
        return Site::default();
    };
    let mut site = Site {
        base: base.trim_end_matches('/').to_string(),
        ..Site::default()
    };
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    enqueue(&mut seen, &mut queue, "/".to_string(), 0, "start");
    for path in start {
        enqueue(&mut seen, &mut queue, path.clone(), 0, "url");
    }
    from_robots_and_sitemaps(client, &root, &mut seen, &mut queue).await;

    let mut scripts: Vec<String> = Vec::new();
    crawl(client, &root, &mut site, &mut seen, &mut queue, &mut scripts, true).await;

    // Every script the pages load, from this site or any other. The site's
    // own scripts also name its routes, which a single-page app never links
    // in its markup.
    scripts.truncate(MOST_SCRIPTS);
    for chunk in scripts.chunks(AT_ONCE) {
        let bodies = join_all(chunk.iter().map(|u| body(client, u))).await;
        for (url, code) in chunk.iter().zip(bodies) {
            let third_party = Url::parse(url).map_or(true, |u| !same_origin(&root, &u));
            site.scripts.push(Script {
                url: url.clone(),
                third_party,
                bytes: code.as_ref().map_or(0, String::len),
            });
            let page = first_page_with(&site, url);
            trackers(url, &page, Some(url), &mut site.signals);
            if let Some(code) = code {
                read_code(&code, &page, Some(url), &mut site.signals);
                if !third_party {
                    for route in routes(&code) {
                        enqueue(&mut seen, &mut queue, route, DEEPEST, "script");
                    }
                    for address in addresses(&code) {
                        if let Ok(u) = Url::parse(address) {
                            link_out(&mut site, &root, u);
                        }
                    }
                }
            }
        }
    }
    crawl(client, &root, &mut site, &mut seen, &mut queue, &mut scripts, false).await;
    dedupe(&mut site.signals);
    site
}

/// Fetches what's queued, recording each path. When `read`, each page's
/// markup is read too and its links followed, up to [`MOST_PAGES`];
/// otherwise the paths are only recorded, up to as many again.
async fn crawl(
    client: &Client,
    root: &Url,
    site: &mut Site,
    seen: &mut HashSet<String>,
    queue: &mut VecDeque<(String, usize, &'static str)>,
    scripts: &mut Vec<String>,
    read: bool,
) {
    let most = if read { MOST_PAGES } else { MOST_PAGES * 2 };
    while !queue.is_empty() && site.pages.len() < most {
        let n = queue.len().min(AT_ONCE).min(most - site.pages.len());
        let batch: Vec<(String, usize, &'static str)> = queue.drain(..n).collect();
        let fetched = join_all(batch.iter().map(|(path, _, _)| get(client, root, path))).await;
        for ((path, depth, found), got) in batch.into_iter().zip(fetched) {
            let Some(got) = got else { continue };
            site.pages.push(Page {
                path: path.clone(),
                status: got.status,
                title: got.html.as_deref().and_then(title),
                content_type: got.content_type.clone(),
                found,
            });
            if let Some(to) = got.location.as_deref().and_then(|l| got.url.join(l).ok()) {
                if !same_site(root, &to) && (300..400).contains(&got.status) {
                    site.signals.push(Signal {
                        category: "Redirects and frames",
                        label: format!("Redirects to {}", to.host_str().unwrap_or("another site")),
                        severity: "medium",
                        why: "Opening this path sends you on to a different site.",
                        evidence: format!("{} to {to}", got.status),
                        page: path.clone(),
                        script: None,
                    });
                }
            }
            let Some(html) = got.html.filter(|_| read) else { continue };
            read_page(site, root, &got.url, &path, &html, scripts);
            for link in values(&html, "a", "href") {
                match local_path(root, &got.url, link) {
                    Some(next) if depth < DEEPEST => enqueue(seen, queue, next, depth + 1, "link"),
                    Some(_) => {}
                    None => {
                        if let Ok(u) = got.url.join(link.trim()) {
                            link_out(site, root, u);
                        }
                    }
                }
            }
        }
    }
}

/// Paths a script names as string literals, `"/docs/install"`: the routes a
/// single-page app knows but never links in its markup.
fn routes(code: &str) -> Vec<String> {
    const MOST: usize = 200;
    let bytes = code.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i + 2 < bytes.len() && out.len() < MOST {
        let quote = bytes[i];
        if matches!(quote, b'"' | b'\'' | b'`') && bytes[i + 1] == b'/' {
            let start = i + 1;
            let mut j = start + 1;
            while j < bytes.len() && j - start < 100 && (bytes[j].is_ascii_alphanumeric() || b"/-_.".contains(&bytes[j])) {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == quote {
                let path = &code[start..j];
                if route_like(path) && !out.iter().any(|p| p == path) {
                    out.push(path.to_string());
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Whether a string reads as a site's route: a letter after the slash, no
/// `//` or `..`, and not a file such as a script or image.
fn route_like(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    path.len() > 1
        && path.as_bytes()[1].is_ascii_alphabetic()
        && !path.contains("//")
        && !path.contains("..")
        && !ASSETS.iter().any(|ext| lower.ends_with(ext))
}

fn enqueue(
    seen: &mut HashSet<String>,
    queue: &mut VecDeque<(String, usize, &'static str)>,
    path: String,
    depth: usize,
    found: &'static str,
) {
    let lower = path.to_ascii_lowercase();
    if ASSETS.iter().any(|ext| lower.ends_with(ext)) {
        return;
    }
    if seen.insert(path.clone()) {
        queue.push_back((path, depth, found));
    }
}

/// Paths `robots.txt` names (disallowed ones too: they are often what a site
/// would rather not list) and the pages in the site's sitemaps.
async fn from_robots_and_sitemaps(
    client: &Client,
    root: &Url,
    seen: &mut HashSet<String>,
    queue: &mut VecDeque<(String, usize, &'static str)>,
) {
    let mut sitemaps: Vec<Url> = root.join("/sitemap.xml").into_iter().collect();
    if let Some(robots) = root.join("/robots.txt").ok().map(|u| u.to_string()) {
        if let Some(text) = body(client, &robots).await {
            for line in text.lines() {
                let Some((key, value)) = line.split_once(':') else { continue };
                let value = value.trim();
                match key.trim().to_ascii_lowercase().as_str() {
                    "disallow" | "allow" if value.starts_with('/') && !value.contains('*') => {
                        let path = value.trim_end_matches('$').to_string();
                        enqueue(seen, queue, path, DEEPEST, "robots");
                    }
                    "sitemap" => {
                        if let Ok(u) = Url::parse(value) {
                            if same_origin(root, &u) && !sitemaps.contains(&u) {
                                sitemaps.push(u);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let mut read = 0;
    while let Some(map) = sitemaps.pop() {
        if read == MOST_SITEMAPS {
            break;
        }
        read += 1;
        let Some(xml) = body(client, map.as_str()).await else { continue };
        let index = xml.contains("<sitemapindex");
        for loc in between(&xml, "<loc>", "</loc>") {
            let Ok(u) = Url::parse(loc.trim()) else { continue };
            if !same_origin(root, &u) {
                continue;
            }
            if index {
                sitemaps.push(u);
            } else {
                enqueue(seen, queue, u.path().to_string(), DEEPEST, "sitemap");
            }
        }
    }
}

/// A fetched path.
struct Got {
    url: Url,
    status: u16,
    content_type: Option<String>,
    location: Option<String>,
    /// The body, when it's a page.
    html: Option<String>,
}

async fn get(client: &Client, root: &Url, path: &str) -> Option<Got> {
    let url = root.join(path).ok()?;
    let resp = client.get(url.clone()).send().await.ok()?;
    let header = |name: &str| resp.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    let content_type = header("content-type");
    let location = header("location");
    let status = resp.status().as_u16();
    let page = resp.status().is_success() && content_type.as_deref().is_some_and(|t| t.contains("html"));
    let html = if page { read(resp).await } else { None };
    Some(Got {
        url,
        status,
        content_type,
        location,
        html,
    })
}

/// The body at `url`, when it answers with success.
async fn body(client: &Client, url: &str) -> Option<String> {
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    read(resp).await
}

async fn read(resp: reqwest::Response) -> Option<String> {
    let bytes = resp.bytes().await.ok()?;
    Some(String::from_utf8_lossy(&bytes[..bytes.len().min(BIGGEST)]).into_owned())
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Whether two URLs are on the same site by name, whatever their scheme or
/// port, `www.` aside: moving from HTTP to HTTPS, or to `www.`, isn't
/// leaving the site.
fn same_site(a: &Url, b: &Url) -> bool {
    let name = |u: &Url| u.host_str().map(|h| h.trim_start_matches("www.").to_ascii_lowercase());
    name(a) == name(b)
}

/// A link's path on this site, or `None` for one elsewhere or not a page.
fn local_path(root: &Url, page: &Url, link: &str) -> Option<String> {
    let link = link.trim();
    let lower = link.to_ascii_lowercase();
    if link.is_empty() || link.starts_with('#') || ["mailto:", "tel:", "javascript:", "data:"].iter().any(|s| lower.starts_with(*s)) {
        return None;
    }
    let u = page.join(link).ok()?;
    same_origin(root, &u).then(|| u.path().to_string())
}

/// The page that first loaded the script at `url`, by its signals' record
/// of where scripts came from, else the site's root.
fn first_page_with(site: &Site, url: &str) -> String {
    site.signals
        .iter()
        .find(|s| s.category == "Scripts" && s.evidence == url)
        .map_or_else(|| "/".to_string(), |s| s.page.clone())
}

/// Reads one page's markup: the scripts it loads, its inline code, hidden
/// frames, password forms and redirects.
fn read_page(site: &mut Site, root: &Url, url: &Url, path: &str, html: &str, scripts: &mut Vec<String>) {
    let lower = html.to_ascii_lowercase();
    for (tag, inner) in elements(html, &lower, "script") {
        match value(tag, "src") {
            Some(src) => {
                if let Ok(u) = url.join(src.trim()) {
                    let u = u.to_string();
                    if !scripts.contains(&u) {
                        // Remembered so the script's findings name this page.
                        site.signals.push(Signal {
                            category: "Scripts",
                            label: String::new(),
                            severity: "",
                            why: "",
                            evidence: u.clone(),
                            page: path.to_string(),
                            script: None,
                        });
                        scripts.push(u);
                    }
                }
            }
            None => {
                trackers(inner, path, None, &mut site.signals);
                read_code(inner, path, None, &mut site.signals);
            }
        }
    }
    for (tag, _) in elements(html, &lower, "iframe") {
        let t = tag.to_ascii_lowercase().replace(' ', "");
        let hidden = ["display:none", "visibility:hidden", "width=\"0\"", "height=\"0\"", "width=0", "height=0", "width=\"1\"", "height=\"1\""]
            .iter()
            .any(|h| t.contains(*h));
        if hidden {
            site.signals.push(Signal {
                category: "Redirects and frames",
                label: "Loads a hidden frame".to_string(),
                severity: "medium",
                why: "An invisible frame loads another page in the background, a common way to run code or track you out of sight.",
                evidence: snippet(tag),
                page: path.to_string(),
                script: None,
            });
        }
    }
    let password = ["type=\"password\"", "type='password'", "type=password"].iter().any(|p| lower.contains(*p));
    if password {
        for (tag, _) in elements(html, &lower, "form") {
            let Some(to) = value(tag, "action").and_then(|a| url.join(a.trim()).ok()) else { continue };
            if !same_site(root, &to) {
                site.signals.push(Signal {
                    category: "Forms",
                    label: format!("Sends a password to {}", to.host_str().unwrap_or("another site")),
                    severity: "high",
                    why: "The page asks for a password and sends it to a different site than the one you'd be on, the shape of a phishing page.",
                    evidence: snippet(tag),
                    page: path.to_string(),
                    script: None,
                });
            }
        }
        if root.scheme() == "http" {
            site.signals.push(Signal {
                category: "Forms",
                label: "Asks for a password over plain HTTP".to_string(),
                severity: "medium",
                why: "Anything typed into this page travels unencrypted and can be read on the way.",
                evidence: "<input type=\"password\">".to_string(),
                page: path.to_string(),
                script: None,
            });
        }
    }
    for (tag, _) in elements(html, &lower, "meta") {
        let refresh = value(tag, "http-equiv").is_some_and(|v| v.eq_ignore_ascii_case("refresh"));
        let Some(content) = value(tag, "content").filter(|_| refresh) else { continue };
        let target = content.to_ascii_lowercase().find("url=").map(|i| content[i + 4..].trim_matches(['\'', '"', ' ']));
        let Some(to) = target.and_then(|t| url.join(t).ok()) else { continue };
        if !same_site(root, &to) {
            site.signals.push(Signal {
                category: "Redirects and frames",
                label: format!("Redirects to {}", to.host_str().unwrap_or("another site")),
                severity: "medium",
                why: "The page sends you on to a different site as soon as it loads.",
                evidence: snippet(tag),
                page: path.to_string(),
                script: None,
            });
        }
    }
}

/// What to look for in code: every group must match one of its alternatives.
struct Rule {
    category: &'static str,
    label: &'static str,
    severity: &'static str,
    all: &'static [&'static [&'static str]],
    why: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        category: "Location",
        label: "Asks for your location",
        severity: "medium",
        all: &[&["getCurrentPosition", "watchPosition"]],
        why: "Your browser would ask to share your precise location with the site.",
    },
    Rule {
        category: "Location",
        label: "Looks up where your IP address is",
        severity: "medium",
        all: &[&["ipapi.co", "ipinfo.io", "ip-api.com", "ipgeolocation", "freegeoip", "geoip-db", "api.ipify.org", "extreme-ip-lookup", "geolocation-db"]],
        why: "The page asks a third party for your public IP address or the place it's registered to.",
    },
    Rule {
        category: "Network",
        label: "Can reveal your local IP address",
        severity: "medium",
        all: &[&["RTCPeerConnection", "webkitRTCPeerConnection"], &["onicecandidate", "createDataChannel"]],
        why: "WebRTC used this way can expose your device's address on its local network, even behind a VPN.",
    },
    Rule {
        category: "Fingerprinting",
        label: "Uses a fingerprinting library",
        severity: "medium",
        all: &[&["fingerprintjs", "FingerprintJS", "fpjs.io", "ClientJS", "evercookie", "fingerprint2", "Fingerprint2"]],
        why: "A library built to identify your browser across visits without cookies.",
    },
    Rule {
        category: "Fingerprinting",
        label: "Draws a hidden canvas to fingerprint your browser",
        severity: "low",
        all: &[&["toDataURL", "getImageData"], &["fillText"]],
        why: "Text drawn on an unseen canvas renders slightly differently on every machine, which identifies yours.",
    },
    Rule {
        category: "Fingerprinting",
        label: "Reads your graphics card",
        severity: "low",
        all: &[&["UNMASKED_RENDERER_WEBGL", "UNMASKED_VENDOR_WEBGL", "WEBGL_debug_renderer_info"]],
        why: "The exact graphics hardware is one of the strongest fingerprinting signals.",
    },
    Rule {
        category: "Fingerprinting",
        label: "Fingerprints your audio stack",
        severity: "low",
        all: &[&["createOscillator"], &["createDynamicsCompressor", "OfflineAudioContext"]],
        why: "A silent sound processed by your browser comes out slightly differently on every machine.",
    },
    Rule {
        category: "Fingerprinting",
        label: "Reads your battery",
        severity: "low",
        all: &[&["getBattery("]],
        why: "Battery level and charging state can tie your visits together.",
    },
    Rule {
        category: "Fingerprinting",
        label: "Collects details about your device",
        severity: "low",
        all: &[&["hardwareConcurrency"], &["deviceMemory", "navigator.plugins", "getHighEntropyValues", "colorDepth"]],
        why: "Processor count, memory, plugins and screen details together narrow down who you are.",
    },
    Rule {
        category: "Camera and sensors",
        label: "Asks for your camera or microphone",
        severity: "medium",
        all: &[&["getUserMedia("]],
        why: "Your browser would ask to turn on your camera or microphone for the site.",
    },
    Rule {
        category: "Camera and sensors",
        label: "Lists your cameras and microphones",
        severity: "low",
        all: &[&["enumerateDevices("]],
        why: "The devices attached to your machine help identify it.",
    },
    Rule {
        category: "Camera and sensors",
        label: "Reads motion sensors",
        severity: "low",
        all: &[&["DeviceMotionEvent", "DeviceOrientationEvent", "devicemotion", "deviceorientation"]],
        why: "On phones, motion sensors can reveal how you hold the device and even what you tap.",
    },
    Rule {
        category: "Camera and sensors",
        label: "Reads your clipboard",
        severity: "medium",
        all: &[&["clipboard.readText", "clipboard.read("]],
        why: "Whatever you last copied, such as a password, could be read by the page.",
    },
    Rule {
        category: "Typing",
        label: "May send what you type as you type it",
        severity: "medium",
        all: &[
            &["\"keydown\"", "'keydown'", "\"keypress\"", "'keypress'", "\"keyup\"", "'keyup'", "onkeypress", "onkeydown"],
            &["sendBeacon", "new Image().src", "new WebSocket("],
        ],
        why: "Key presses are watched by code that can quietly send data away, before you ever submit anything.",
    },
    Rule {
        category: "Mining",
        label: "Mines cryptocurrency in your browser",
        severity: "high",
        all: &[&["coinhive", "CoinHive", "cryptonight", "CryptoNight", "coinimp", "webminer", "minero.cc", "crypto-loot", "deepMiner", "webmine.pro"]],
        why: "The page would use your processor to mine for someone else, slowing and heating your machine.",
    },
    Rule {
        category: "Hidden code",
        label: "Runs packed, hidden code",
        severity: "low",
        all: &[&["eval(atob(", "eval(function(p,a,c,k,e", "eval(unescape(", "document.write(unescape("]],
        why: "Code wrapped so it can't be read until it runs, often to hide what it does.",
    },
    Rule {
        category: "Persistence",
        label: "Installs a service worker",
        severity: "low",
        all: &[&["serviceWorker.register"]],
        why: "A service worker keeps code for the site in your browser after you leave the page.",
    },
    Rule {
        category: "Persistence",
        label: "Asks to send you notifications",
        severity: "low",
        all: &[&["Notification.requestPermission", "pushManager.subscribe"]],
        why: "Allowing it lets the site push messages to you whenever it likes.",
    },
];

/// Reads one script's code against the rules.
fn read_code(code: &str, page: &str, script: Option<&str>, out: &mut Vec<Signal>) {
    for rule in RULES {
        let mut first = None;
        let matched = rule.all.iter().all(|group| match group.iter().find_map(|n| code.find(*n)) {
            Some(i) => {
                first.get_or_insert(i);
                true
            }
            None => false,
        });
        if let (true, Some(at)) = (matched, first) {
            out.push(Signal {
                category: rule.category,
                label: rule.label.to_string(),
                severity: rule.severity,
                why: rule.why,
                evidence: around(code, at),
                page: page.to_string(),
                script: script.map(str::to_string),
            });
        }
    }
}

/// Analytics and ad trackers, and session recorders, by where they load from.
const TRACKERS: &[(&str, &str, bool)] = &[
    ("google-analytics.com", "Google Analytics", false),
    ("googletagmanager.com", "Google Tag Manager", false),
    ("connect.facebook.net", "Meta Pixel", false),
    ("doubleclick.net", "Google Ads", false),
    ("analytics.tiktok.com", "TikTok Pixel", false),
    ("snap.licdn.com", "LinkedIn Insight", false),
    ("bat.bing.com", "Microsoft Ads", false),
    ("cdn.segment.com", "Segment", false),
    ("cdn.mxpnl.com", "Mixpanel", false),
    ("hotjar.com", "Hotjar", true),
    ("clarity.ms", "Microsoft Clarity", true),
    ("fullstory.com", "FullStory", true),
    ("mouseflow.com", "Mouseflow", true),
    ("smartlook.com", "Smartlook", true),
    ("cdn.logrocket", "LogRocket", true),
    ("crazyegg.com", "Crazy Egg", true),
];

/// The trackers `text` (a script's URL or inline code) loads.
fn trackers(text: &str, page: &str, script: Option<&str>, out: &mut Vec<Signal>) {
    for (host, name, replay) in TRACKERS {
        let Some(at) = text.find(*host) else { continue };
        out.push(if *replay {
            Signal {
                category: "Session recording",
                label: format!("Records your session with {name}"),
                severity: "medium",
                why: "Session recorders capture your clicks, scrolling and often what you type, and replay it for the site's owners.",
                evidence: around(text, at),
                page: page.to_string(),
                script: script.map(str::to_string),
            }
        } else {
            Signal {
                category: "Trackers",
                label: format!("Tracks you with {name}"),
                severity: "low",
                why: "An analytics or advertising tracker that follows your visit and often your browsing elsewhere.",
                evidence: around(text, at),
                page: page.to_string(),
                script: script.map(str::to_string),
            }
        });
    }
}

/// Drops repeats of the same thing on the same page, and the notes of which
/// page loaded which script.
fn dedupe(signals: &mut Vec<Signal>) {
    let mut seen = HashSet::new();
    signals.retain(|s| s.category != "Scripts" && seen.insert((s.label.clone(), s.page.clone(), s.script.clone())));
}

/// About 120 characters of `text` around byte `at`, on one line.
fn around(text: &str, at: usize) -> String {
    let mut start = at.saturating_sub(50);
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (at + 70).min(text.len());
    while !text.is_char_boundary(end) {
        end += 1;
    }
    text[start..end].split_whitespace().collect::<Vec<_>>().join(" ")
}

fn snippet(tag: &str) -> String {
    around(tag, 0)
}

/// A page's `<title>`.
fn title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let open = lower.find("<title")?;
    let start = open + lower[open..].find('>')? + 1;
    let end = start + lower[start..].find("</title")?;
    let t = html[start..end].split_whitespace().collect::<Vec<_>>().join(" ");
    (!t.is_empty()).then_some(t)
}

/// Each `<name ...>` element: its opening tag, and for `script`, what's
/// between it and `</script>`.
fn elements<'a>(html: &'a str, lower: &str, name: &str) -> Vec<(&'a str, &'a str)> {
    let mut out = Vec::new();
    let open = format!("<{name}");
    let close = format!("</{name}");
    let mut from = 0;
    while let Some(i) = lower[from..].find(&open).map(|i| i + from) {
        let after = i + open.len();
        let next = lower.as_bytes().get(after).copied().unwrap_or(b'>');
        if !(next == b'>' || next.is_ascii_whitespace() || next == b'/') {
            from = after;
            continue;
        }
        let Some(end) = lower[after..].find('>').map(|e| e + after) else { break };
        let tag = &html[i..=end];
        let inner = if name == "script" {
            let stop = lower[end + 1..].find(&close).map_or(html.len(), |c| c + end + 1);
            &html[end + 1..stop]
        } else {
            ""
        };
        out.push((tag, inner));
        from = end + 1;
    }
    out
}

/// Every value of attribute `attr` on `<name>` elements.
fn values<'a>(html: &'a str, name: &str, attr: &str) -> Vec<&'a str> {
    let lower = html.to_ascii_lowercase();
    elements(html, &lower, name).into_iter().filter_map(|(tag, _)| value(tag, attr)).collect()
}

/// An attribute's value in an opening tag, quoted or not.
fn value<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find(attr).map(|i| i + from) {
        let before = lower.as_bytes().get(i.wrapping_sub(1)).copied().unwrap_or(b' ');
        let rest = lower[i + attr.len()..].trim_start();
        if before.is_ascii_whitespace() && rest.starts_with('=') {
            let eq = i + attr.len() + (lower[i + attr.len()..].len() - rest.len());
            let v = tag[eq + 1..].trim_start();
            return Some(match v.chars().next() {
                Some(q @ ('"' | '\'')) => v[1..].split(q).next().unwrap_or(""),
                _ => v.split(|c: char| c.is_whitespace() || c == '>').next().unwrap_or(""),
            });
        }
        from = i + attr.len();
    }
    None
}

/// Every piece of `text` between `open` and `close`.
fn between<'a>(text: &'a str, open: &str, close: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = text[from..].find(open).map(|i| i + from + open.len()) {
        let Some(j) = text[i..].find(close).map(|j| j + i) else { break };
        out.push(&text[i..j]);
        from = j + close.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_attributes() {
        assert_eq!(value(r#"<a class="x" href="/about">"#, "href"), Some("/about"));
        assert_eq!(value("<a href=/plain target=_blank>", "href"), Some("/plain"));
        assert_eq!(value(r#"<a data-href="/no">"#, "href"), None);
        assert_eq!(values(r#"<p><a href='/a'>A</a> <A HREF="/b">B</A></p>"#, "a", "href"), ["/a", "/b"]);
    }

    #[test]
    fn reads_scripts_and_titles() {
        let html = r#"<title> Shop </title><script src="/app.js"></script><script>var x = 1;</script>"#;
        let lower = html.to_ascii_lowercase();
        let found = elements(html, &lower, "script");
        assert_eq!(found.len(), 2);
        assert_eq!(value(found[0].0, "src"), Some("/app.js"));
        assert_eq!(found[1].1, "var x = 1;");
        assert_eq!(title(html).as_deref(), Some("Shop"));
    }

    #[test]
    fn keeps_links_on_the_site() {
        let root = Url::parse("https://shop.example").unwrap();
        let page = root.join("/a/b").unwrap();
        assert_eq!(local_path(&root, &page, "c?x=1#y").as_deref(), Some("/a/c"));
        assert_eq!(local_path(&root, &page, "https://other.example/"), None);
        assert_eq!(local_path(&root, &page, "mailto:x@y"), None);
    }

    #[test]
    fn rules_need_every_group() {
        let mut out = Vec::new();
        read_code("pc = new RTCPeerConnection(); pc.onicecandidate = f;", "/", None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].category, "Network");
        let mut out = Vec::new();
        read_code("new RTCPeerConnection()", "/", None, &mut out);
        assert!(out.is_empty());
        let mut out = Vec::new();
        read_code("navigator.geolocation.getCurrentPosition(ok)", "/", Some("https://cdn.example/a.js"), &mut out);
        assert_eq!(out[0].label, "Asks for your location");
        assert_eq!(out[0].script.as_deref(), Some("https://cdn.example/a.js"));
    }

    #[test]
    fn flags_password_forms_posting_elsewhere() {
        let root = Url::parse("http://shop.example").unwrap();
        let mut site = Site::default();
        let mut scripts = Vec::new();
        let html = r#"<form action="https://collect.evil/login"><input type="password"></form><iframe src="/x" style="display: none"></iframe>"#;
        read_page(&mut site, &root, &root, "/", html, &mut scripts);
        let labels: Vec<&str> = site.signals.iter().map(|s| s.label.as_str()).collect();
        assert!(labels.contains(&"Loads a hidden frame"));
        assert!(labels.contains(&"Sends a password to collect.evil"));
        assert!(labels.contains(&"Asks for a password over plain HTTP"));
    }

    #[test]
    fn reads_routes_from_scripts() {
        let code = r#"const r=[{path:"/docs"},{path:'/docs/install'}];go(`/blog/`);x="/assets/a.png";y="//cdn";z="/2";w="a/b""#;
        assert_eq!(routes(code), ["/docs", "/docs/install", "/blog/"]);
    }

    #[test]
    fn keeps_links_to_other_hosts() {
        let root = Url::parse("https://shop.example").unwrap();
        let mut site = Site::default();
        let code = r#"a="https://docs.shop.example/start";b='https://shop.example/x';c=`https://cdn.example/a.js`"#;
        for address in addresses(code) {
            link_out(&mut site, &root, Url::parse(address).unwrap());
        }
        assert_eq!(site.links, ["https://docs.shop.example/start", "https://cdn.example/a.js"]);
    }

    #[test]
    fn upgrading_to_https_is_not_leaving() {
        let http = Url::parse("http://shop.example").unwrap();
        assert!(same_site(&http, &Url::parse("https://shop.example/").unwrap()));
        assert!(same_site(&http, &Url::parse("https://www.shop.example/").unwrap()));
        assert!(!same_site(&http, &Url::parse("https://other.example/").unwrap()));
    }

    #[test]
    fn finds_trackers_and_sitemap_locs() {
        let mut out = Vec::new();
        trackers("https://static.hotjar.com/c/hotjar-1.js", "/", None, &mut out);
        assert_eq!(out[0].category, "Session recording");
        assert_eq!(between("<url><loc>a</loc></url><url><loc>b</loc></url>", "<loc>", "</loc>"), ["a", "b"]);
    }
}
