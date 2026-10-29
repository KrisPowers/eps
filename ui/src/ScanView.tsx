import type { ReactNode } from "react";
import { Icon } from "./Icon";
import type { Endpoint, Phase, Port, Posture, Progress, Report, ScanRow, Severity } from "./types";

// ScanView is one scan: where it is while it runs, then what it found.
export function ScanView({ scan, report, onAgain, onDelete }: {
  scan: ScanRow;
  report?: Report;
  onAgain: () => void;
  onDelete: () => void;
}) {
  const going = scan.status === "queued" || scan.status === "running";
  const ip = report?.resolved_ip ?? scan.progress?.ip ?? scan.resolved_ip;
  return (
    <>
      <div className="page-header">
        <h1>{scan.target}</h1>
        {ip && ip !== scan.target && <span className="muted mono">{ip}</span>}
        <StatusChip scan={scan} />
        <div className="page-actions">
          <button type="button" className="btn secondary" disabled={going} onClick={onAgain}>
            <Icon name="refresh" size={18} /><span>Scan again</span>
          </button>
          <button type="button" className="icon-btn danger" aria-label="Delete scan" title="Delete scan" disabled={going} onClick={onDelete}>
            <Icon name="delete" />
          </button>
        </div>
      </div>
      {scan.status === "failed" && (
        <div className="callout bad"><Icon name="error" /><span>{scan.error ?? "The scan failed."}</span></div>
      )}
      {going && <Live scan={scan} progress={scan.progress} />}
      {scan.status === "done" && (report ? <Results report={report} /> : <SkeletonRows rows={6} />)}
    </>
  );
}

function StatusChip({ scan }: { scan: ScanRow }) {
  if (scan.status === "failed") return <span className="chip bad">Failed</span>;
  if (scan.status !== "done") return <span className="chip plain">{scan.status === "queued" ? "Queued" : "Scanning"}</span>;
  const { high, medium } = scan.findings;
  if (high) return <span className="chip bad">{high} high</span>;
  if (medium) return <span className="chip warn">{medium} medium</span>;
  return <span className="chip ok">Nothing serious</span>;
}

const PHASES: [Phase, string][] = [["resolving", "Resolve"], ["ports", "Ports"], ["endpoints", "Endpoints"]];
const ORDER: Phase[] = ["queued", "resolving", "ports", "endpoints", "done"];

// Live draws a running scan: the phase, the port it has reached, and the
// open ports and endpoints as they turn up, with skeleton rows for what's
// still coming.
function Live({ scan, progress: p }: { scan: ScanRow; progress?: Progress }) {
  const phase = p?.phase ?? "queued";
  const at = ORDER.indexOf(phase);
  const portsDone = at > ORDER.indexOf("ports");
  const pct = portsDone ? 100 : p && p.ports_total ? Math.floor((p.ports_done / p.ports_total) * 100) : 0;

  let text: ReactNode = "Waiting for a free slot";
  if (phase === "resolving") text = <>Resolving <b>{scan.target}</b></>;
  if (phase === "ports" && p) {
    text = p.ports_total === 1
      ? <>Checking port <b className="mono">{p.port || "…"}</b></>
      : <>Port <b className="mono">{p.port.toLocaleString()}</b> of {p.ports_total.toLocaleString()}</>;
  }
  if (phase === "endpoints" && p) {
    text = p.inspecting
      ? <>Inspecting HTTP on port <b className="mono">{p.inspecting}</b>, service {Math.min(p.services_done + 1, p.services_total)} of {p.services_total}</>
      : "Inspecting HTTP services";
  }

  return (
    <>
      <ol className="stepper-nav">
        {PHASES.map(([key, label], i) => {
          const me = ORDER.indexOf(key);
          return (
            <li key={key} className={at > me ? "done" : at === me ? "current" : ""}>
              <span className="num">{at > me ? <Icon name="check" size={16} /> : i + 1}</span>
              <span>{label}</span>
            </li>
          );
        })}
      </ol>

      <div className="scan-progress">
        <div className="scan-progress-head">
          <span>{text}</span>
          {phase === "ports" && <span className="mono">{pct}%</span>}
        </div>
        <div className={"bar" + (phase === "ports" ? "" : " indeterminate")}>
          <div style={{ width: (phase === "ports" ? pct : 100) + "%" }} />
        </div>
      </div>

      <div className="metrics">
        <Metric label="Open ports" value={p?.open.length ?? 0} />
        <Metric label="Endpoints" value={p?.endpoints ?? 0} />
      </div>

      <section className="section">
        <div className="section-head"><h2>Open ports</h2></div>
        <PortsTable ports={p?.open ?? []} pending={!portsDone} />
      </section>

      {phase === "endpoints" && (
        <section className="section">
          <div className="section-head"><h2>Endpoints</h2></div>
          <SkeletonRows rows={3} />
        </section>
      )}
    </>
  );
}

function Results({ report }: { report: Report }) {
  const count = (s: Severity) => report.findings.filter((f) => f.severity === s).length;
  return (
    <>
      <div className="metrics">
        <Metric label="Open ports" value={report.open_ports.length} />
        <Metric label="Endpoints" value={report.endpoints.length} />
        <Metric label="High" value={count("high")} tone={count("high") ? "bad" : undefined} />
        <Metric label="Medium" value={count("medium")} tone={count("medium") ? "warn" : undefined} />
        <Metric label="Low" value={count("low")} />
      </div>

      {report.findings.length > 0 && (
        <section className="section">
          <div className="section-head"><h2>Findings</h2></div>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Severity</th><th className="grow">Finding</th><th>Where</th></tr></thead>
              <tbody>
                {report.findings.map((f, i) => (
                  <tr key={i}>
                    <td><span className={"chip " + SEVERITY[f.severity]}>{f.severity}</span></td>
                    <td className="wrap"><div>{f.title}</div><div className="fix">{f.detail}</div></td>
                    <td className="mono">{f.location}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section className="section">
        <div className="section-head"><h2>Open ports</h2></div>
        <PortsTable ports={report.open_ports} />
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Endpoints</h2>
          <div className="section-actions legend">
            {(["configured", "insecure", "missing", "unknown"] as Posture[]).map((p) => (
              <span key={p} className="legend-item"><span className={"swatch " + p} />{POSTURE[p]}</span>
            ))}
          </div>
        </div>
        <EndpointsTable endpoints={report.endpoints} />
      </section>
    </>
  );
}

const SEVERITY: Record<Severity, string> = { high: "bad", medium: "warn", low: "plain", info: "ok" };
const POSTURE: Record<Posture, string> = {
  configured: "Configured",
  insecure: "Bypassable",
  missing: "Not configured",
  unknown: "Not shown",
};
const CONTROLS = [["auth", "AUTH"], ["jwt", "JWT"], ["rate", "RATE"], ["https", "HTTPS"]] as const;

function Metric({ label, value, tone }: { label: string; value: number; tone?: "bad" | "warn" }) {
  return (
    <div className="metric">
      <div className="metric-label">{label}</div>
      <div className={"metric-value" + (tone ? " " + tone : "")}>{value}</div>
    </div>
  );
}

function PortsTable({ ports, pending }: { ports: Port[]; pending?: boolean }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Port</th><th className="grow">Service</th></tr></thead>
        <tbody>
          {ports.map((p) => (
            <tr key={p.port}><td className="mono">{p.port}/tcp</td><td>{p.service}</td></tr>
          ))}
          {pending && [0, 1, 2].map((i) => (
            <tr key={"s" + i} className="skeleton-row"><td><span className="bone short" /></td><td><span className="bone" /></td></tr>
          ))}
          {!pending && ports.length === 0 && <Empty cols={2}>No open ports found</Empty>}
        </tbody>
      </table>
    </div>
  );
}

// EndpointsTable groups endpoints under the service they were found on.
function EndpointsTable({ endpoints }: { endpoints: Endpoint[] }) {
  const groups = new Map<string, Endpoint[]>();
  for (const e of endpoints) {
    const u = new URL(e.url);
    groups.set(u.origin, [...(groups.get(u.origin) ?? []), e]);
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Status</th><th>Controls</th><th>Path</th><th className="grow">Note</th></tr></thead>
        <tbody>
          {[...groups].map(([origin, list]) => [
            <tr key={origin} className="child-row"><td colSpan={4} className="mono">{origin}</td></tr>,
            ...list.map((e) => (
              <tr key={e.url}>
                <td className={"mono status-" + Math.floor(e.status / 100)}>{e.status}</td>
                <td>
                  <span className="controls">
                    {CONTROLS.map(([key, label]) => (
                      <span key={key} className={"control " + e.controls[key]} title={label + ": " + POSTURE[e.controls[key]]}>{label}</span>
                    ))}
                  </span>
                </td>
                <td className="mono">{new URL(e.url).pathname}</td>
                <td className="muted">{e.note}</td>
              </tr>
            )),
          ])}
          {endpoints.length === 0 && <Empty cols={4}>No HTTP endpoints found</Empty>}
        </tbody>
      </table>
    </div>
  );
}

function Empty({ cols, children }: { cols: number; children: ReactNode }) {
  return <tr className="empty-row"><td colSpan={cols}><div className="empty">{children}</div></td></tr>;
}

function SkeletonRows({ rows }: { rows: number }) {
  return (
    <div className="skeleton" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => <span key={i} className="bone" />)}
    </div>
  );
}
