// The shapes `portscan --serve` answers with; see crates/cli/src/serve.rs
// and the report crate.

export type Status = "queued" | "running" | "done" | "failed";
export type Phase = "queued" | "resolving" | "ports" | "endpoints" | "done";
export type Severity = "high" | "medium" | "low" | "info";
export type Posture = "configured" | "insecure" | "missing" | "unknown";

export interface Port {
  port: number;
  service: string;
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
  endpoints: number;
}

export interface ScanRow {
  id: string;
  target: string;
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
