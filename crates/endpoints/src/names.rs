//! Names a domain's certificates have been issued for, from the public
//! certificate transparency logs: subdomains a site never links to and its
//! sitemap never lists. Every certificate a public authority issues is
//! logged, so a subdomain that ever had one shows up. Two log searches are
//! asked at once, Cert Spotter and crt.sh, since either can be slow or down.

use std::time::Duration;

use reqwest::Client;
use serde_json::Value;

/// Names kept, at most.
const MOST: usize = 500;

/// Every name under `domain` that a logged certificate covers, wildcards
/// as their domain; empty when neither log answers.
pub async fn from_certificates(domain: &str) -> Vec<String> {
    let Ok(client) = Client::builder()
        .user_agent(concat!("portscan/", env!("CARGO_PKG_VERSION"), " (read-only recon)"))
        .build()
    else {
        return Vec::new();
    };
    let spotter = format!("https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names");
    let crtsh = format!("https://crt.sh/?q=%25.{domain}&output=json");
    let (a, b) = futures::join!(
        rows(&client, &spotter, Duration::from_secs(20)),
        rows(&client, &crtsh, Duration::from_secs(45)),
    );
    let mut all = a;
    all.extend(b);
    names(&all, domain)
}

/// A log search's rows, none when it fails or times out.
async fn rows(client: &Client, url: &str, wait: Duration) -> Vec<Value> {
    let Ok(resp) = client.get(url).timeout(wait).send().await else {
        return Vec::new();
    };
    let Ok(text) = resp.text().await else {
        return Vec::new();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

/// The names in the rows that sit under `domain`, each once: crt.sh lists
/// them in `name_value`, a line each; Cert Spotter in `dns_names`.
fn names(rows: &[Value], domain: &str) -> Vec<String> {
    let under = format!(".{domain}");
    let mut out: Vec<String> = rows
        .iter()
        .flat_map(|r| {
            let mut found: Vec<&str> = r["name_value"].as_str().map(|v| v.split('\n').collect()).unwrap_or_default();
            found.extend(r["dns_names"].as_array().into_iter().flatten().filter_map(Value::as_str));
            found
        })
        .map(|n| n.trim().trim_start_matches("*.").to_ascii_lowercase())
        .filter(|n| n.as_str() == domain || n.ends_with(&under))
        .collect();
    out.sort();
    out.dedup();
    out.truncate(MOST);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_under_the_domain_once() {
        let rows: Vec<Value> = serde_json::from_str(
            r#"[{"name_value":"api.shop.example\n*.shop.example"},{"name_value":"API.shop.example"},{"name_value":"shop.example.evil"},{"dns_names":["docs.shop.example","*.shop.example"]}]"#,
        )
        .unwrap();
        assert_eq!(names(&rows, "shop.example"), ["api.shop.example", "docs.shop.example", "shop.example"]);
    }
}
