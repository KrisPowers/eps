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
  inspecting: number | null;
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
}

export interface ScanDetail extends ScanRow {
  report: Report | null;
}
