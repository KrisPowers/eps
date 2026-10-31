// The shapes `portscan --serve` answers with; see crates/cli/src/serve.rs
// and the report crate.

export type Status = "queued" | "running" | "done" | "failed";
export type Phase = "queued" | "resolving" | "ports" | "endpoints" | "done";
export type Severity = "high" | "medium" | "low" | "info";
export type Posture = "configured" | "insecure" | "missing" | "unknown";

export interface Port {
  port: number;
  service: string;
  // What the service said first on connect, such as its version.
  banner?: string | null;
  // For HTTPS, its certificate and any old TLS versions it accepts.
  tls?: Tls | null;
  // While a scan runs: what the port exposes, once it is done.
  found?: Found | null;
}

export interface Tls {
  cert?: Cert;
  legacy: string[];
}

export interface Cert {
  subject: string;
  issuer: string;
  // Unix seconds.
  not_before: number;
  not_after: number;
  names: string[];
  self_signed: boolean;
}

export interface Found {
  endpoints: Endpoint[];
  findings: Finding[];
  // Missing from scans made before these were found as each port finished.
  tls?: Tls | null;
  apis?: Api[];
  technologies?: Tech[];
  site?: Site | null;
}

export interface Progress {
  phase: Phase;
  ip: string;
  ports_total: number;
  ports_done: number;
  // The highest port whose probe has finished.
  port: number;
  open: Port[];
  services_total: number;
  services_done: number;
  // The ports whose HTTP services are being inspected; several run at once.
  inspecting: number[];
  // The DNS records and their findings, once the lookup is done.
  dns?: { records: DnsRecord[]; findings: Finding[] } | null;
  // The subdomains found, once the logs and guesses are in.
  subdomains?: Subdomain[] | null;
}

export interface ScanRow {
  id: string;
  target: string;
  // The line it was started with, as typed in a terminal.
  command: string;
  status: Status;
  created: number;
  finished: number | null;
  error: string | null;
  resolved_ip: string | null;
  open_ports: number;
  endpoints: number;
  // For a range, the hosts that answered.
  hosts?: number;
  findings: Record<Severity, number>;
  progress?: Progress;
}

export interface Endpoint {
  url: string;
  status: number;
  note: string;
  sensitive: boolean;
  controls: Record<"auth" | "jwt" | "rate" | "https", Posture>;
  // Missing from reports made before headers were checked.
  headers?: Record<"hsts" | "csp" | "frame" | "nosniff" | "cors" | "cookies", Posture>;
}

export interface Finding {
  severity: Severity;
  title: string;
  location: string;
  detail: string;
}

export interface Report {
  target: string;
  resolved_ip: string;
  open_ports: Port[];
  endpoints: Endpoint[];
  findings: Finding[];
  // For a range, each host that answered.
  hosts?: Host[];
  // The software recognized on the open ports.
  technologies?: Tech[];
  // The API documents served without auth.
  apis?: Api[];
  // The target's DNS records.
  dns?: DnsRecord[];
  // Every address a name resolved to, when there were several.
  addresses?: string[];
  // Each website found, mapped and read.
  sites?: Site[];
  // Other names under the target's domain.
  subdomains?: Subdomain[];
}

export interface Subdomain {
  name: string;
  // Its IPv4 addresses now; empty when it no longer resolves.
  addresses: string[];
  // "certificate", "guess", or both.
  found: string[];
}

// A website on one port: its paths, the scripts its pages load, and what
// those pages would do in a visitor's browser.
export interface Site {
  port: number;
  // `scheme://host:port`.
  base: string;
  pages: SitePage[];
  scripts: Script[];
  signals: Signal[];
  // Pages on other hosts the site links to, often its own subdomains.
  links?: string[];
}

export interface SitePage {
  path: string;
  status: number;
  title?: string;
  content_type?: string;
  // How it was found: start, url, link, sitemap or robots.
  found: string;
}

export interface Script {
  url: string;
  third_party: boolean;
  // Bytes read; 0 when it couldn't be fetched.
  bytes: number;
}

export interface Signal {
  category: string;
  label: string;
  severity: "high" | "medium" | "low";
  // What it means for someone who opens the page.
  why: string;
  evidence: string;
  page: string;
  script?: string;
}

export interface DnsRecord {
  name: string;
  // `A`, `MX`, `TXT`, ...
  kind: string;
  value: string;
  ttl: number;
}

export interface Api {
  port: number;
  url: string;
  // `OpenAPI 3.0.1`, `Swagger 2.0`.
  spec: string;
  title: string;
  version: string;
  schemes: string[];
  operations: Operation[];
}

export interface Operation {
  method: string;
  path: string;
  summary: string;
  secured: boolean;
}

export interface Tech {
  port: number;
  name: string;
  version?: string;
  // Web server, language, framework, ...
  kind: string;
  // What gave it away.
  evidence: string;
}

export interface Host {
  ip: string;
  open_ports: Port[];
}

export interface ScanDetail extends ScanRow {
  report: Report | null;
}
