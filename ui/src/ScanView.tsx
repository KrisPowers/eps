import { useState } from "react";
import { Icon } from "./Icon";
import { href, type Page } from "./route";
import type { Endpoint, Finding, Port, Posture, Progress, Report, ScanRow, Severity } from "./types";

// A port as the page draws it: waiting its turn, being checked, or done with
// what it turned out to expose.
export type Item = Port & { state: "waiting" | "checking" | "done" };

// results is a scan's open ports: from its report once it has one, from its
// progress once the sweep is over, none before.
export function results(scan: ScanRow, report: Report | undefined, p: Progress | undefined): Item[] | null {
  if (report) return fromReport(report);
  if (p && (p.phase === "endpoints" || p.phase === "done")) return fromProgress(p);
  return null;
}

// ScanView is one page of a scan: the sweep while it runs, then the open
// ports as a catalog, each with a page of its own, or every endpoint or
// finding on one page. A port can be opened as soon as it is done, while the
// rest are still being checked.
export function ScanView({ scan, items, progress: p, page, port, onAgain, onDelete }: {
  scan: ScanRow;
  items: Item[] | null;
  progress?: Progress;
  page: Page;
  port: number | null;
  onAgain: () => void;
  onDelete: () => void;
}) {
  const going = scan.status === "queued" || scan.status === "running";
  const ip = scan.resolved_ip ?? p?.ip;
  const open = items?.find((i) => i.port === port);
  const found = items?.flatMap((i) => (i.found ? [i.found] : [])) ?? [];

  let body = null;
  if (!items) body = going ? <Stage scan={scan} progress={p} /> : scan.status === "done" ? <Loading /> : null;
  else if (page === "ports") body = open ? <PortPage key={open.port} id={scan.id} item={open} items={items} /> : <Catalog id={scan.id} items={items} />;
  else if (page === "endpoints") {
    const all = found.flatMap((f) => f.endpoints);
    body = all.length ? <div className="panel"><EndpointsTable id={scan.id} endpoints={all} /></div> : <Nothing going={going} what="No HTTP endpoints found" />;
  } else {
    const all = found.flatMap((f) => f.findings).sort((a, b) => RANK[a.severity] - RANK[b.severity]);
    body = all.length ? <div className="panel"><ul className="findings">{all.map((x, k) => <FindingRow key={k} id={scan.id} finding={x} />)}</ul></div> : <Nothing going={going} what="No findings" />;
  }

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
          <button type="button" className="btn" disabled={going} onClick={onAgain}>
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
// of them, the port being scanned in a pill that shines with them.
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
function Catalog({ id, items }: { id: string; items: Item[] }) {
  if (items.length === 0) return <div className="panel"><div className="empty">No open ports found</div></div>;
  return (
    <div className="catalog">
      {items.map((item) => {
        const f = item.found;
        const worst = f?.findings.find((x) => x.severity !== "info");
        return (
          <a key={item.port} className={"tile " + item.state} href={href(id, "ports", item.port)}>
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
          </a>
        );
      })}
    </div>
  );
}

// PortPage is one port: back to the catalog, a step to the ports either
// side, and what it holds, findings and endpoints each on a tab.
function PortPage({ id, item, items }: { id: string; item: Item; items: Item[] }) {
  const i = items.indexOf(item);
  const prev = items[i - 1];
  const next = items[i + 1];
  const f = item.found;
  const [tab, setTab] = useState<"findings" | "endpoints">(f?.findings.length || !f?.endpoints.length ? "findings" : "endpoints");
  return (
    <section className="port-page">
      <div className="port-page-head">
        <a className="btn back" href={href(id)}>
          <Icon name="arrow_back" size={18} /><span>All ports</span>
        </a>
        <h2 className="port-title">
          <span className="port-num">{item.port}<small>/tcp</small></span>
          <span className="muted">{item.service}</span>
        </h2>
        <div className="pager">
          <Step id={id} to={prev} label="Previous port" icon="chevron_left" />
          <span className="pager-pos">{i + 1} of {items.length}</span>
          <Step id={id} to={next} label="Next port" icon="chevron_right" />
        </div>
      </div>

      {!f && (
        <div className="panel">
          <div className="panel-note">{item.state === "checking" ? "Checking endpoints" : "Waiting its turn"}</div>
          <SkeletonRows rows={4} />
        </div>
      )}
      {f && (
        <div className="panel">
          <div className="tabs" role="tablist">
            {([["findings", "Findings", f.findings.length], ["endpoints", "Endpoints", f.endpoints.length]] as const).map(([key, label, n]) => (
              <button key={key} type="button" role="tab" aria-selected={tab === key} className="tab" onClick={() => setTab(key)}>
                {label}<span className="tab-count">{n}</span>
              </button>
            ))}
          </div>
          <div role="tabpanel">
            {tab === "findings" && (f.findings.length
              ? <ul className="findings">{f.findings.map((x, k) => <FindingRow key={k} finding={x} />)}</ul>
              : <div className="empty">No findings on this port</div>)}
            {tab === "endpoints" && (f.endpoints.length
              ? <EndpointsTable endpoints={f.endpoints} />
              : <div className="empty">No HTTP endpoints on this port</div>)}
          </div>
        </div>
      )}
    </section>
  );
}

function Step({ id, to, label, icon }: { id: string; to?: Item; label: string; icon: "chevron_left" | "chevron_right" }) {
  if (!to) return <span className="icon-btn" aria-disabled="true"><Icon name={icon} /></span>;
  return <a className="icon-btn" href={href(id, "ports", to.port)} aria-label={label} title={label}><Icon name={icon} /></a>;
}

// FindingRow is one finding. Given the scan's id, it is on a page of every
// finding and links the port it was found on.
function FindingRow({ id, finding: f }: { id?: string; finding: Finding }) {
  const where = path(f.location);
  const port = portIn(f.location);
  return (
    <li className="finding">
      <span className={"chip " + SEVERITY[f.severity]}>{f.severity}</span>
      <div>
        <div className="finding-title">{f.title}</div>
        <div className="fix">{f.detail}</div>
      </div>
      <span className="finding-where">
        {id && port > 0 && <a className="port-link mono" href={href(id, "ports", port)}>{port}</a>}
        {where && <code>{where}</code>}
      </span>
    </li>
  );
}

export const SEVERITY: Record<Severity, string> = { high: "bad", medium: "warn", low: "plain", info: "ok" };
const RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };
const POSTURE: Record<Posture, string> = {
  configured: "Configured",
  insecure: "Bypassable",
  missing: "Not configured",
  unknown: "Not shown",
};
const CONTROLS = [["auth", "AUTH"], ["jwt", "JWT"], ["rate", "RATE"], ["https", "HTTPS"]] as const;

// EndpointsTable lists endpoints with a block per control. Given the scan's
// id, it holds endpoints from every port and links each one's port.
function EndpointsTable({ id, endpoints }: { id?: string; endpoints: Endpoint[] }) {
  return (
    <>
      <div className="legend">
        {(["configured", "insecure", "missing", "unknown"] as Posture[]).map((p) => (
          <span key={p} className="legend-item"><span className={"swatch " + p} />{POSTURE[p]}</span>
        ))}
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Status</th>{id && <th>Port</th>}<th>Path</th><th>Controls</th><th className="grow">Note</th></tr></thead>
          <tbody>
            {endpoints.map((e) => (
              <tr key={e.url}>
                <td className={"mono status-" + Math.floor(e.status / 100)}>{e.status}</td>
                {id && <td><a className="port-link mono" href={href(id, "ports", portOf(e.url))}>{portOf(e.url)}</a></td>}
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

// Nothing is an empty page: still filling while the scan runs, else empty.
function Nothing({ going, what }: { going: boolean; what: string }) {
  return (
    <div className="panel">
      {going ? <><div className="panel-note">Checking endpoints</div><SkeletonRows rows={4} /></> : <div className="empty">{what}</div>}
    </div>
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
      findings: r.findings.filter((f) => portIn(f.location) === o.port),
    },
  }));
}

function portOf(url: string) {
  const u = new URL(url);
  return Number(u.port || (u.protocol === "https:" ? 443 : 80));
}

// portIn is the port a finding's location names, `port 22` or
// `<url> (port 8080)`, 0 for none.
function portIn(location: string) {
  return Number(/(?:^|\()port (\d+)/.exec(location)?.[1] ?? 0);
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
