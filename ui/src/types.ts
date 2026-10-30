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
