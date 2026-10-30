import { useEffect, useRef, useState, type CSSProperties } from "react";
import { Icon } from "./Icon";
import type { Endpoint, Finding, Found, Port, Posture, Progress, Report, ScanRow, Severity } from "./types";

// A port as the page draws it: waiting its turn, being checked, or done with
// what it turned out to expose.
type Item = Port & { state: "waiting" | "checking" | "done" };

// ScanView is one scan: the port it has reached while it sweeps, then each
// open port, filled in as soon as that port is done.
export function ScanView({ scan, report, onAgain, onDelete }: {
  scan: ScanRow;
  report?: Report;
  onAgain: () => void;
  onDelete: () => void;
}) {
  const going = scan.status === "queued" || scan.status === "running";
  // The last progress seen keeps the ports on screen between the scan
  // finishing and its report arriving.
  const last = useRef(scan.progress);
  if (scan.progress) last.current = scan.progress;
  const p = scan.progress ?? last.current;
  const swept = p?.phase === "endpoints" || p?.phase === "done";
  const items = report ? fromReport(report) : p && swept ? fromProgress(p) : null;
  const ip = report?.resolved_ip ?? p?.ip ?? scan.resolved_ip;

  return (
    <>
      <div className="summary">
        <div className="summary-main">
          <div className="summary-title">
            <h1>{scan.target}</h1>
            {ip && ip !== scan.target && <span className="muted mono">{ip}</span>}
            {/ --?[a-z]/.test(scan.command) && <code className="command-line">{scan.command}</code>}
          </div>
          <Facts scan={scan} items={items} progress={going ? p : undefined} />
        </div>
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
      {items ? <PortList items={items} /> : going ? <Stage scan={scan} progress={p} /> : scan.status === "done" && <Loading />}
    </>
  );
}

function Facts({ scan, items, progress: p }: { scan: ScanRow; items: Item[] | null; progress?: Progress }) {
  const found = items?.flatMap((i) => (i.found ? [i.found] : [])) ?? [];
  const endpoints = found.reduce((n, f) => n + f.endpoints.length, 0);
  const count = (s: Severity) => found.reduce((n, f) => n + f.findings.filter((x) => x.severity === s).length, 0);
  const serious = count("high") + count("medium") > 0;
  return (
    <div className="facts">
      {scan.status === "failed" && <span className="chip bad">Failed</span>}
      {scan.status === "queued" && <span className="chip plain">Queued</span>}
      {scan.status === "running" && <span className="chip plain"><span className="spinner tiny" />Scanning</span>}
      {scan.status === "done" && items && !serious && <span className="chip ok">Nothing serious</span>}
      {p?.phase === "endpoints" && p.inspecting && (
        <span>Checking port <b className="mono">{p.inspecting}</b>, {Math.min(p.services_done + 1, p.services_total)} of {p.services_total}</span>
      )}
      {items && (
        <>
          <span><b>{items.length}</b> open {items.length === 1 ? "port" : "ports"}</span>
          <span><b>{endpoints}</b> {endpoints === 1 ? "endpoint" : "endpoints"}</span>
        </>
      )}
      {(["high", "medium", "low"] as const).map((s) => count(s) > 0 && (
        <span key={s} className={"chip " + SEVERITY[s]}>{count(s)} {s}</span>
      ))}
    </div>
  );
}

// Stage is the sweep: skeleton rows standing in for the ports to come, and
// the port the scan has reached in the middle of them.
function Stage({ scan, progress: p }: { scan: ScanRow; progress?: Progress }) {
  const sweep = p?.phase === "ports" ? p : undefined;
  const single = sweep?.ports_total === 1;
  const port = useTween(sweep?.port ?? 0, 700);
  const pct = sweep?.ports_total ? Math.floor((sweep.ports_done / sweep.ports_total) * 100) : 0;
  return (
    <section className="stage" aria-busy="true">
      <div className="stage-bones" aria-hidden="true">
        {Array.from({ length: 7 }, (_, i) => (
          <div key={i} className="ghost"><span className="bone short" /><span className="bone" /></div>
        ))}
      </div>
      <div className="stage-center">
        {sweep ? (
          <>
            <div className="stage-label">{single ? "Checking port" : "Scanning ports"}</div>
            <div className="stage-port">{single ? sweep.port || "…" : port.toLocaleString()}</div>
            {!single && <div className="stage-sub">of {sweep.ports_total.toLocaleString()}, {pct}%</div>}
            <div className="bar"><div style={{ width: pct + "%" }} /></div>
            {sweep.open.length > 0 && (
              <div className="stage-found" aria-label="Open so far">
                {sweep.open.map((o) => <span key={o.port} className="chip plain mono">{o.port}</span>)}
              </div>
            )}
          </>
        ) : (
          <div className="stage-label">{p?.phase === "resolving" ? <>Resolving <b>{scan.target}</b></> : "Waiting for a free slot"}</div>
        )}
      </div>
    </section>
  );
}

function PortList({ items }: { items: Item[] }) {
  if (items.length === 0) return <div className="empty">No open ports found</div>;
  const endpoints = items.some((i) => i.found?.endpoints.length);
  return (
    <section>
      <div className="ports-head">
        <h2>Open ports</h2>
        {endpoints && (
          <div className="legend">
            {(["configured", "insecure", "missing", "unknown"] as Posture[]).map((p) => (
              <span key={p} className="legend-item"><span className={"swatch " + p} />{POSTURE[p]}</span>
            ))}
          </div>
        )}
      </div>
      <div className="ports">
        {items.map((item, i) => <PortCard key={item.port} item={item} index={i} />)}
      </div>
    </section>
  );
}

// PortCard opens by itself once its port has something to show, until it is
// opened or closed by hand.
function PortCard({ item, index }: { item: Item; index: number }) {
  const { port, service, state, found } = item;
  const [open, setOpen] = useState<boolean | null>(null);
  const has = !!found && (found.endpoints.length > 0 || found.findings.length > 0);
  const expanded = has && (open ?? true);
  return (
    <article className={"port " + state} style={{ "--i": index } as CSSProperties}>
      <button type="button" className="port-head" disabled={!has} aria-expanded={has ? expanded : undefined} onClick={() => setOpen(!expanded)}>
        <span className="port-num">{port}<small>/tcp</small></span>
        <span className="port-service">{service}</span>
        <span className="port-state">
          {state === "waiting" && "Waiting"}
          {state === "checking" && <><span className="spinner small" />Checking endpoints</>}
          {found && <Counts found={found} />}
        </span>
        {has && <Icon name="expand_more" className="chev" />}
      </button>
      {state === "checking" && <div className="port-body"><SkeletonRows rows={3} /></div>}
      {expanded && found && (
        <div className="port-body reveal">
          {found.findings.length > 0 && (
            <ul className="findings">
              {found.findings.map((f, i) => <FindingRow key={i} finding={f} />)}
            </ul>
          )}
          {found.endpoints.length > 0 && <EndpointsTable endpoints={found.endpoints} />}
        </div>
      )}
    </article>
  );
}

function Counts({ found }: { found: Found }) {
  const worst = found.findings.find((f) => f.severity !== "info");
  const n = found.endpoints.length;
  if (!worst && !n) return <span className="muted">Nothing found</span>;
  return (
    <>
      {worst && <span className={"chip " + SEVERITY[worst.severity]}>{worst.severity}</span>}
      {n > 0 && <span>{n} {n === 1 ? "endpoint" : "endpoints"}</span>}
    </>
  );
}

function FindingRow({ finding: f }: { finding: Finding }) {
  const where = path(f.location);
  return (
    <li className="finding">
      <span className={"chip " + SEVERITY[f.severity]}>{f.severity}</span>
      <div>
        <div className="finding-title">{f.title}</div>
        <div className="fix">{f.detail}</div>
      </div>
      {where && <code className="finding-where">{where}</code>}
    </li>
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

function EndpointsTable({ endpoints }: { endpoints: Endpoint[] }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Status</th><th>Path</th><th>Controls</th><th className="grow">Note</th></tr></thead>
        <tbody>
          {endpoints.map((e) => (
            <tr key={e.url}>
              <td className={"mono status-" + Math.floor(e.status / 100)}>{e.status}</td>
              <td className="mono">{new URL(e.url).pathname}</td>
              <td>
                <span className="controls">
                  {CONTROLS.map(([key, label]) => (
                    <span key={key} className={"control " + e.controls[key]} title={label + ": " + POSTURE[e.controls[key]]}>{label}</span>
                  ))}
                </span>
              </td>
              <td className="muted">{e.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Loading() {
  return (
    <div className="ports" aria-label="Loading">
      {[0, 1, 2].map((i) => <div key={i} className="ghost"><span className="bone short" /><span className="bone" /></div>)}
    </div>
  );
}

function SkeletonRows({ rows }: { rows: number }) {
  return (
    <div className="skeleton" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => <span key={i} className="bone" />)}
    </div>
  );
}

function fromProgress(p: Progress): Item[] {
  return p.open.map((o): Item => ({
    ...o,
    state: o.found ? "done" : o.port === p.inspecting ? "checking" : "waiting",
  }));
}

// fromReport splits a finished report back into its ports, the same shape
// the scan showed while it ran.
function fromReport(r: Report): Item[] {
  return r.open_ports.map((o): Item => ({
    ...o,
    state: "done",
    found: {
      endpoints: r.endpoints.filter((e) => portOf(e.url) === o.port),
      findings: r.findings.filter((f) => Number(/(?:^|\()port (\d+)/.exec(f.location)?.[1]) === o.port),
    },
  }));
}

function portOf(url: string) {
  const u = new URL(url);
  return Number(u.port || (u.protocol === "https:" ? 443 : 80));
}

// path is the part of a finding's location worth showing inside its port:
// the path of an endpoint, nothing for the port itself.
function path(location: string) {
  const url = location.split(" (port ")[0];
  return url.startsWith("http") ? new URL(url).pathname : "";
}

// useTween eases a number to each new value over `ms`, so a figure that
// arrives in steps reads as one that moves.
function useTween(to: number, ms: number) {
  const [shown, setShown] = useState(to);
  const from = useRef(to);
  useEffect(() => {
    const start = performance.now();
    const a = from.current;
    let raf = 0;
    const tick = (t: number) => {
      const k = Math.min(1, (t - start) / ms);
      from.current = Math.round(a + (to - a) * k);
      setShown(from.current);
      if (k < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [to, ms]);
  return shown;
}
