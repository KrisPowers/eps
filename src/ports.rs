//! Curated catalog of common service ports and HTTP-likely hints.
//!
//! The default scan covers this list rather than all 65,535 ports so a bare
//! `at @host` stays fast and polite. Use `--full` for an exhaustive sweep or
//! `--ports` to supply your own set.

/// A well-known port with its usual service label and whether it typically
/// speaks HTTP (and if so, over TLS).
pub struct KnownPort {
    pub port: u16,
    pub service: &'static str,
    /// `Some(true)` = HTTPS, `Some(false)` = plaintext HTTP, `None` = not HTTP.
    pub http_tls: Option<bool>,
}

const fn p(port: u16, service: &'static str, http_tls: Option<bool>) -> KnownPort {
    KnownPort {
        port,
        service,
        http_tls,
    }
}

/// Top ~120 commonly exposed ports, biased toward services an application
/// engineer is likely to stand up or leave open by accident.
pub const COMMON: &[KnownPort] = &[
    p(21, "ftp", None),
    p(22, "ssh", None),
    p(23, "telnet", None),
    p(25, "smtp", None),
    p(53, "dns", None),
    p(80, "http", Some(false)),
    p(81, "http-alt", Some(false)),
    p(110, "pop3", None),
    p(111, "rpcbind", None),
    p(135, "msrpc", None),
    p(139, "netbios-ssn", None),
    p(143, "imap", None),
    p(389, "ldap", None),
    p(443, "https", Some(true)),
    p(445, "smb", None),
    p(465, "smtps", None),
    p(514, "syslog", None),
    p(587, "submission", None),
    p(631, "ipp", None),
    p(636, "ldaps", None),
    p(873, "rsync", None),
    p(990, "ftps", None),
    p(993, "imaps", None),
    p(995, "pop3s", None),
    p(1080, "socks", None),
    p(1433, "mssql", None),
    p(1521, "oracle", None),
    p(1723, "pptp", None),
    p(2049, "nfs", None),
    p(2082, "cpanel", Some(false)),
    p(2083, "cpanel-ssl", Some(true)),
    p(2375, "docker", Some(false)),
    p(2376, "docker-tls", Some(true)),
    p(2379, "etcd", Some(false)),
    p(2380, "etcd-peer", Some(false)),
    p(3000, "dev-http", Some(false)),
    p(3001, "dev-http", Some(false)),
    p(3306, "mysql", None),
    p(3389, "rdp", None),
    p(4000, "dev-http", Some(false)),
    p(4040, "spark-ui", Some(false)),
    p(4200, "angular-dev", Some(false)),
    p(4443, "https-alt", Some(true)),
    p(5000, "http-dev", Some(false)),
    p(5001, "http-dev", Some(false)),
    p(5432, "postgresql", None),
    p(5601, "kibana", Some(false)),
    p(5672, "amqp", None),
    p(5900, "vnc", None),
    p(5984, "couchdb", Some(false)),
    p(6000, "x11", None),
    p(6379, "redis", None),
    p(6443, "kube-apiserver", Some(true)),
    p(7000, "cassandra", None),
    p(7001, "weblogic", Some(false)),
    p(7077, "spark", None),
    p(7474, "neo4j", Some(false)),
    p(8000, "http-dev", Some(false)),
    p(8008, "http-alt", Some(false)),
    p(8009, "ajp", None),
    p(8010, "http-alt", Some(false)),
    p(8080, "http-proxy", Some(false)),
    p(8081, "http-alt", Some(false)),
    p(8083, "http-alt", Some(false)),
    p(8086, "influxdb", Some(false)),
    p(8088, "http-alt", Some(false)),
    p(8090, "http-alt", Some(false)),
    p(8125, "statsd", None),
    p(8161, "activemq", Some(false)),
    p(8181, "http-alt", Some(false)),
    p(8200, "vault", Some(false)),
    p(8443, "https-alt", Some(true)),
    p(8500, "consul", Some(false)),
    p(8529, "arangodb", Some(false)),
    p(8686, "jmx", None),
    p(8787, "rstudio", Some(false)),
    p(8888, "http-alt", Some(false)),
    p(9000, "http-alt", Some(false)),
    p(9042, "cassandra-cql", None),
    p(9090, "prometheus", Some(false)),
    p(9091, "prometheus-push", Some(false)),
    p(9092, "kafka", None),
    p(9100, "node-exporter", Some(false)),
    p(9200, "elasticsearch", Some(false)),
    p(9300, "elasticsearch-nodes", None),
    p(9418, "git", None),
    p(9443, "https-alt", Some(true)),
    p(9600, "logstash", Some(false)),
    p(9990, "wildfly-mgmt", Some(false)),
    p(10000, "webmin", Some(false)),
    p(10250, "kubelet", Some(true)),
    p(11211, "memcached", None),
    p(15672, "rabbitmq-mgmt", Some(false)),
    p(16686, "jaeger-ui", Some(false)),
    p(27017, "mongodb", None),
    p(27018, "mongodb-shard", None),
    p(28017, "mongodb-http", Some(false)),
    p(50070, "hadoop-namenode", Some(false)),
];

/// Ports in [`COMMON`] that typically speak HTTP, with their TLS flag.
pub fn http_hint(port: u16) -> Option<bool> {
    COMMON
        .iter()
        .find(|k| k.port == port)
        .and_then(|k| k.http_tls)
}

/// Human service label for a port, or `"unknown"`.
