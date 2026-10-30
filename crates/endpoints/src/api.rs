//! API descriptions a service publishes: an OpenAPI or Swagger document at
//! one of the conventional paths, read with the same plain `GET` as every
//! other path, for the operations it lists and how they are secured.

use serde::Serialize;
use serde_json::Value;

/// Paths an OpenAPI or Swagger document is conventionally served at.
pub const SPEC_PATHS: &[&str] = &[
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
];

/// Operations listed per document, at most.
const MOST: usize = 500;

const METHODS: &[&str] = &["get", "put", "post", "delete", "patch", "options", "head"];

/// An API document and what it lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiSpec {
    pub url: String,
    /// `OpenAPI 3.0.1`, `Swagger 2.0`.
    pub spec: String,
    pub title: String,
    pub version: String,
    /// The security schemes it defines: `bearerAuth`, `api_key`, ...
    pub schemes: Vec<String>,
    pub operations: Vec<Operation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Operation {
    pub method: String,
    pub path: String,
    pub summary: String,
    /// Whether it, or the document as a whole, requires a security scheme.
    pub secured: bool,
}

impl Operation {
    /// Whether it changes data rather than reading it.
    pub fn writes(&self) -> bool {
        matches!(self.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
    }
}

/// Reads an OpenAPI 3 or Swagger 2 JSON document. `None` when `body` isn't
/// one, such as a site's page served at every path.
pub fn parse(url: &str, body: &str) -> Option<ApiSpec> {
    let doc: Value = serde_json::from_str(body).ok()?;
    let spec = if let Some(v) = doc["openapi"].as_str() {
        format!("OpenAPI {v}")
    } else if let Some(v) = doc["swagger"].as_str() {
        format!("Swagger {v}")
    } else {
        return None;
    };
    let required = |v: Option<&Value>| v.and_then(Value::as_array).map(|a| !a.is_empty());
    let global = required(doc.get("security")).unwrap_or(false);

    let mut operations = Vec::new();
    for (path, item) in doc["paths"].as_object().into_iter().flatten() {
        for method in METHODS {
            let Some(op) = item.get(*method) else {
                continue;
            };
            let summary = op["summary"].as_str().or(op["operationId"].as_str());
            operations.push(Operation {
                method: method.to_ascii_uppercase(),
                path: path.clone(),
                summary: summary.unwrap_or("").to_string(),
                secured: required(op.get("security")).unwrap_or(global),
            });
        }
    }
    operations.truncate(MOST);

    let schemes = doc["components"]["securitySchemes"]
        .as_object()
        .or(doc["securityDefinitions"].as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    Some(ApiSpec {
        url: url.to_string(),
        spec,
        title: doc["info"]["title"].as_str().unwrap_or("").to_string(),
        version: doc["info"]["version"].as_str().unwrap_or("").to_string(),
        schemes,
        operations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{
        "openapi": "3.0.1",
        "info": { "title": "Shop", "version": "2.1" },
        "security": [{ "bearerAuth": [] }],
        "components": { "securitySchemes": { "bearerAuth": { "type": "http" } } },
        "paths": {
            "/orders": {
                "get": { "summary": "List orders" },
                "post": { "operationId": "createOrder", "security": [] }
            }
        }
    }"#;

    #[test]
    fn reads_openapi() {
        let s = parse("http://h/openapi.json", DOC).unwrap();
        assert_eq!(s.spec, "OpenAPI 3.0.1");
        assert_eq!(s.title, "Shop");
        assert_eq!(s.schemes, ["bearerAuth"]);
        assert_eq!(s.operations.len(), 2);
        let post = s.operations.iter().find(|o| o.method == "POST").unwrap();
        assert_eq!(post.summary, "createOrder");
        assert!(!post.secured && post.writes());
        assert!(s.operations.iter().find(|o| o.method == "GET").unwrap().secured);
    }

    #[test]
    fn rejects_other_documents() {
        assert_eq!(parse("u", "<html></html>"), None);
        assert_eq!(parse("u", r#"{"status":"UP"}"#), None);
    }
}
