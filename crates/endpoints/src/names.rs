//! Names a domain's certificates have been issued for, from the public
//! certificate transparency logs, through crt.sh: subdomains a site never
//! links to and its sitemap never lists. Every certificate a public authority
//! issues is logged, so a subdomain that ever had one shows up here.

use std::time::Duration;

use reqwest::Client;
use serde_json::Value;

/// Names kept, at most.
const MOST: usize = 500;

/// Every name under `domain` that a logged certificate covers, wildcards
/// as their domain; empty when the logs can't be reached.
pub async fn from_certificates(domain: &str) -> Vec<String> {
    let Ok(client) = Client::builder()
        .timeout(Duration::from_secs(25))
        .user_agent(concat!("portscan/", env!("CARGO_PKG_VERSION"), " (read-only recon)"))
        .build()
    else {
        return Vec::new();
    };
    let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
    let Ok(resp) = client.get(url).send().await else {
        return Vec::new();
    };
    let Ok(text) = resp.text().await else {
        return Vec::new();
    };
    match serde_json::from_str::<Vec<Value>>(&text) {
        Ok(rows) => names(&rows, domain),
        Err(_) => Vec::new(),
    }
}

/// The names in crt.sh's rows that sit under `domain`, each once.
fn names(rows: &[Value], domain: &str) -> Vec<String> {
    let under = format!(".{domain}");
    let mut out: Vec<String> = rows
        .iter()
        .filter_map(|r| r["name_value"].as_str())
        .flat_map(|v| v.split('\n'))
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
            r#"[{"name_value":"api.shop.example\n*.shop.example"},{"name_value":"API.shop.example"},{"name_value":"shop.example.evil"}]"#,
        )
        .unwrap();
        assert_eq!(names(&rows, "shop.example"), ["api.shop.example", "shop.example"]);
    }
}
