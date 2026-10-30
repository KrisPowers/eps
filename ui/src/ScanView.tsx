import { useRef, useState } from "react";
import { Icon } from "./Icon";
import type { Endpoint, Finding, Port, Posture, Progress, Report, ScanRow, Severity } from "./types";

// A port as the page draws it: waiting its turn, being checked, or done with
// what it turned out to expose.
type Item = Port & { state: "waiting" | "checking" | "done" };

// ScanView is one scan: the sweep while it runs, then a catalog of the open
// ports, each opening a page of its own. A port can be opened as soon as it
// is done, while the rest are still being checked.
export function ScanView({ scan, report, port, onPort, onAgain, onDelete }: {
  scan: ScanRow;
  report?: Report;
  port: number | null;
  onPort: (port: number | null) => void;
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
  const open = items?.find((i) => i.port === port);
  const ip = report?.resolved_ip ?? p?.ip ?? scan.resolved_ip;

  let body = null;
  if (open && items) body = <PortPage key={open.port} item={open} items={items} onPort={onPort} />;
  else if (items) body = <Catalog items={items} onPort={onPort} />;
  else if (going) body = <Stage scan={scan} progress={p} />;
  else if (scan.status === "done") body = <Loading />;

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
      {body}
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

// Stage is the sweep: skeleton rows for the ports to come and, in the middle
// of them, the port being scanned in a pill above the loading bar.
function Stage({ scan, progress: p }: { scan: ScanRow; progress?: Progress }) {
  const sweep = p?.phase === "ports" ? p : undefined;
  const pct = sweep?.ports_total ? (sweep.ports_done / sweep.ports_total) * 100 : 0;
  return (
    <section className="stage" aria-busy="true">
      <div className="stage-bones" aria-hidden="true">
        {Array.from({ length: 7 }, (_, i) => (
          <div key={i} className="ghost"><span className="bone short" /><span className="bone" /></div>
        ))}
      </div>
      <div className="stage-center">
        {sweep ? (
          <div className="sweep" role="progressbar" aria-label="Ports scanned" aria-valuenow={Math.floor(pct)} aria-valuemin={0} aria-valuemax={100}>
            <span className="sweep-pill"><Ticker value={String(sweep.port || "…")} /></span>
            <div className="bar"><div style={{ width: pct + "%" }} /></div>
          </div>
        ) : (
          <div className="stage-label">{p?.phase === "resolving" ? <>Resolving <b>{scan.target}</b></> : "Waiting for a free slot"}</div>
        )}
      </div>
    </section>
  );
}

// Catalog is every open port as a tile: what it is, the worst thing on it,
// and how much it holds. A tile opens the port's page.
function Catalog({ items, onPort }: { items: Item[]; onPort: (port: number) => void }) {
  if (items.length === 0) return <div className="empty">No open ports found</div>;
  return (
    <div className="catalog">
      {items.map((item) => {
        const f = item.found;
        const worst = f?.findings.find((x) => x.severity !== "info");
        return (
          <button key={item.port} type="button" className={"tile " + item.state} onClick={() => onPort(item.port)}>
            <span className="tile-top">
              <span className="port-num">{item.port}<small>/tcp</small></span>
              {item.state === "checking" && <span className="spinner small" aria-label="Checking" />}
              {worst && <span className={"chip " + SEVERITY[worst.severity]}>{worst.severity}</span>}
            </span>
            <span className="tile-service">{item.service}</span>
            <span className="tile-meta">
              {item.state === "waiting" && "Waiting"}
              {item.state === "checking" && "Checking endpoints"}
              {f && <>{plural(f.findings.length, "finding")} · {plural(f.endpoints.length, "endpoint")}</>}
            </span>
          </button>
        );
      })}
    </div>
  );
}

// PortPage is one port: back to the catalog, a step to the ports either
// side, and what it holds, findings and endpoints each on a tab.
function PortPage({ item, items, onPort }: { item: Item; items: Item[]; onPort: (port: number | null) => void }) {
  const i = items.indexOf(item);
  const prev = items[i - 1];
  const next = items[i + 1];
  const f = item.found;
  const [tab, setTab] = useState<"findings" | "endpoints">(f?.findings.length || !f?.endpoints.length ? "findings" : "endpoints");
  return (
    <section className="port-page">
      <div className="port-page-head">
        <button type="button" className="btn back" onClick={() => onPort(null)}>
          <Icon name="arrow_back" size={18} /><span>All ports</span>
        </button>
        <h2 className="port-title">
          <span className="port-num">{item.port}<small>/tcp</small></span>
          <span className="muted">{item.service}</span>
        </h2>
        <div className="pager">
          <button type="button" className="icon-btn" aria-label="Previous port" disabled={!prev} onClick={() => prev && onPort(prev.port)}>
            <Icon name="chevron_left" />
          </button>
          <span className="pager-pos">{i + 1} of {items.length}</span>
          <button type="button" className="icon-btn" aria-label="Next port" disabled={!next} onClick={() => next && onPort(next.port)}>
            <Icon name="chevron_right" />
          </button>
        </div>
      </div>

      {!f && (
        <div className="panel">
          <div className="panel-note">{item.state === "checking" ? "Checking endpoints" : "Waiting its turn"}</div>
          <SkeletonRows rows={4} />
        </div>
      )}
      {f && (
        <>
          <div className="tabs" role="tablist">
            {([["findings", "Findings", f.findings.length], ["endpoints", "Endpoints", f.endpoints.length]] as const).map(([key, label, n]) => (
              <button key={key} type="button" role="tab" aria-selected={tab === key} className="tab" onClick={() => setTab(key)}>
                {label}<span className="tab-count">{n}</span>
              </button>
            ))}
          </div>
          <div className="panel" role="tabpanel">
            {tab === "findings" && (f.findings.length
              ? <ul className="findings">{f.findings.map((x, k) => <FindingRow key={k} finding={x} />)}</ul>
              : <div className="empty">No findings on this port</div>)}
            {tab === "endpoints" && (f.endpoints.length
              ? <EndpointsTable endpoints={f.endpoints} />
              : <div className="empty">No HTTP endpoints on this port</div>)}
          </div>
        </>
      )}
    </section>
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
    <>
      <div className="legend">
        {(["configured", "insecure", "missing", "unknown"] as Posture[]).map((p) => (
          <span key={p} className="legend-item"><span className={"swatch " + p} />{POSTURE[p]}</span>
        ))}
      </div>
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
    </>
  );
}

function Loading() {
  return (
    <div className="catalog" aria-label="Loading">
      {[0, 1, 2, 3].map((i) => <div key={i} className="tile ghost-tile"><span className="bone short" /><span className="bone" /></div>)}
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

function plural(n: number, word: string) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
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

// Ticker shows a value that, when it changes, rises and fades out while the
// new one rises in from below.
function Ticker({ value }: { value: string }) {
  const [shown, setShown] = useState({ now: value, was: "" });
  if (shown.now !== value) setShown({ now: value, was: shown.now });
  return (
    <span className="ticker">
      {shown.was && <span key={"was" + shown.was} className="ticker-was" aria-hidden="true">{shown.was}</span>}
      <span key={shown.now} className="ticker-now">{shown.now}</span>
    </span>
  );
}
