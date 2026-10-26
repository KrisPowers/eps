//! Catalog of conventional, framework-published endpoint paths.
//!
//! These are well-known paths that application runtimes and frameworks expose
//! by default (health probes, metrics, API docs, management consoles). Probing
//! them is a conventional discovery step, not brute force. Paths flagged
//! `sensitive` are ones that frequently leak configuration, internals, or
//! control surfaces when left unauthenticated.

/// A conventional endpoint path and whether exposure without auth is notable.
pub struct KnownPath {
    pub path: &'static str,
    /// True when an unauthenticated 2xx here is a meaningful finding.
    pub sensitive: bool,
    /// Short note on what the path usually is.
    pub note: &'static str,
}

const fn kp(path: &'static str, sensitive: bool, note: &'static str) -> KnownPath {
    KnownPath {
        path,
        sensitive,
        note,
    }
}

/// Default discovery list. Kept deliberately focused on conventional,
/// default-published paths across common stacks.
pub const DEFAULT: &[KnownPath] = &[
    // Liveness / readiness / status.
    kp("/", false, "root"),
    kp("/health", false, "health probe"),
    kp("/healthz", false, "k8s-style health probe"),
    kp("/livez", false, "liveness probe"),
    kp("/readyz", false, "readiness probe"),
    kp("/status", false, "status page"),
    kp("/ping", false, "ping"),
    kp("/up", false, "uptime probe"),
    kp("/version", false, "version info"),
    kp("/info", true, "build/app info"),
    // Metrics / observability.
    kp("/metrics", true, "Prometheus metrics"),
    kp("/prometheus", true, "Prometheus metrics"),
    kp("/stats", true, "runtime stats"),
    kp("/server-status", true, "Apache server-status"),
    kp("/nginx_status", true, "nginx stub_status"),
    // API surfaces.
    kp("/api", false, "API root"),
    kp("/api/v1", false, "API v1"),
    kp("/api/v2", false, "API v2"),
    kp("/v1", false, "API v1"),
    kp("/v2", false, "API v2"),
    kp("/graphql", false, "GraphQL endpoint"),
    kp("/graphiql", true, "GraphQL IDE"),
    kp("/rest", false, "REST root"),
    // API documentation (often reveals full surface + schemas).
    kp("/swagger", true, "Swagger UI"),
    kp("/swagger-ui", true, "Swagger UI"),
    kp("/swagger-ui.html", true, "Swagger UI"),
    kp("/swagger.json", true, "Swagger spec"),
    kp("/openapi.json", true, "OpenAPI spec"),
    kp("/api-docs", true, "API docs"),
    kp("/v2/api-docs", true, "Springfox API docs"),
    kp("/v3/api-docs", true, "springdoc OpenAPI"),
    kp("/docs", false, "docs"),
    kp("/redoc", true, "ReDoc API docs"),
    // Spring Boot Actuator (classic over-exposure source).
    kp("/actuator", true, "Spring Actuator index"),
    kp("/actuator/health", false, "Actuator health"),
    kp("/actuator/info", true, "Actuator info"),
    kp("/actuator/env", true, "Actuator environment (secrets risk)"),
    kp("/actuator/configprops", true, "Actuator config props"),
    kp("/actuator/metrics", true, "Actuator metrics"),
    kp("/actuator/mappings", true, "Actuator route map"),
    kp("/actuator/beans", true, "Actuator beans"),
    kp("/actuator/httptrace", true, "Actuator HTTP trace"),
    kp(
        "/actuator/heapdump",
        true,
        "Actuator heap dump (memory disclosure)",
    ),
    kp("/actuator/threaddump", true, "Actuator thread dump"),
    kp("/actuator/loggers", true, "Actuator loggers"),
    // Management / admin consoles.
    kp("/admin", true, "admin console"),
    kp("/console", true, "console"),
    kp("/management", true, "management endpoint"),
    kp("/manager/html", true, "Tomcat manager"),
    kp("/env", true, "environment dump"),
    kp("/config", true, "configuration"),
    kp("/debug", true, "debug endpoint"),
    kp("/debug/pprof", true, "Go pprof profiler"),
    kp("/debug/vars", true, "Go expvar"),
    kp("/dump", true, "state dump"),
    kp("/trace", true, "trace endpoint"),
    // Datastore / cluster HTTP surfaces.
    kp("/_cluster/health", true, "Elasticsearch cluster health"),
    kp("/_cat/indices", true, "Elasticsearch indices"),
    kp("/ui/", true, "Consul/Vault UI"),
    kp("/v1/sys/health", false, "Vault health"),
    // Accidentally served source/config files.
    kp("/.env", true, "leaked .env file"),
    kp("/.git/HEAD", true, "exposed .git repo"),
    kp("/.well-known/security.txt", false, "security.txt"),
    kp("/robots.txt", false, "robots.txt"),
];
