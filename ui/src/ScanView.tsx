import { useCallback, useRef, useState, type ReactNode } from "react";
import { useDismiss } from "./dismiss";
import { download, FORMATS } from "./export";
import { Icon } from "./Icon";
import { href, type Page } from "./route";
import type { Endpoint, Finding, Host, Port, Posture, Progress, Report, ScanRow, Severity, Tls } from "./types";

// A port as the page draws it: waiting its turn, being checked, or done with
// what it turned out to expose.
export type Item = Port & { state: "waiting" | "checking" | "done" };

// results is a scan's open ports: from its report once it has one, from its
// progress once the sweep is over, none before.
export function results(report: Report | undefined, p: Progress | undefined): Item[] | null {
  if (report) return fromReport(report);
  if (p && (p.phase === "endpoints" || p.phase === "done")) return fromProgress(p);
  return null;
}

// The last finished scan of the same target before this one, to compare with.
export interface Previous {
  scan: ScanRow;
  report?: Report;
}

// ScanView is a scan: its findings, one result per open port, worst first,
// or, with a port picked, that port's own page, or what changed since the
// scan before it.
export function ScanView({ scan, report, items, progress: p, page, port, previous, history, onAgain, onScan, onDelete }: {
  scan: ScanRow;
  report?: Report;
  items: Item[] | null;
  progress?: Progress;
  page: Page;
  port: number | null;
  previous?: Previous;
  // Every kept scan of the same target, newest first.
  history: ScanRow[];
  onAgain: () => void;
  onScan: (command: string) => void;
  onDelete: () => void;
}) {
  const range = isRange(scan);
  const open = items?.find((i) => i.port === port);
  if (open && items) return <Detail key={open.port} id={scan.id} item={open} items={sorted(items)} />;

  const going = scan.status === "queued" || scan.status === "running";
  const ip = scan.resolved_ip ?? p?.ip;
  return (
    <>
      <div className="page-head">
        <div className="page-head-main">
          <h1>{scan.target}</h1>
          <div className="page-sub">
            {ip && ip !== scan.target && <span className="mono">{ip}</span>}
            {/ --?[a-z]/.test(scan.command) && <code className="command-line">{scan.command}</code>}
            <Status scan={scan} progress={going ? p : undefined} />
          </div>
        </div>
        <div className="page-actions">
          <Export report={report} when={scan.finished ?? scan.created} />
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
      {page === "changes"
        ? <Changes scan={scan} report={report} previous={previous} />
        : page === "history" ? <History scan={scan} history={history} />
        : page === "tech" ? <Later scan={scan} ready={report}>{(r) => <Technologies id={scan.id} report={r} />}</Later>
        : page === "api" ? <Later scan={scan} ready={report}>{(r) => <Apis report={r} />}</Later>
        : range && report ? <Hosts report={report} onScan={onScan} />
        : !range && items ? <Results id={scan.id} items={items} />
        : going ? <Stage scan={scan} progress={p} /> : scan.status === "done" ? <Loading /> : null}
    </>
  );
}

function Status({ scan, progress: p }: { scan: ScanRow; progress?: Progress }) {
  if (scan.status === "queued") return <span className="chip plain">Queued</span>;
  if (scan.status === "failed") return <span className="chip bad">Failed</span>;
  if (scan.status === "done") return <span>Finished {new Date(scan.finished ?? scan.created).toLocaleString()}</span>;
  return (
    <>
      <span className="chip plain"><span className="spinner tiny" />Scanning</span>
      {p?.phase === "endpoints" && p.inspecting && (
        <span>Checking port <b className="mono">{p.inspecting}</b>, {Math.min(p.services_done + 1, p.services_total)} of {p.services_total}</span>
      )}
    </>
  );
}

// Results is the scan's findings: how many of each severity, then every open
// port, worst first, each opening its own page.
function Results({ id, items }: { id: string; items: Item[] }) {
  if (items.length === 0) return <div className="card empty">No open ports found</div>;
  const findings = items.flatMap((i) => i.found?.findings ?? []);
  const endpoints = items.reduce((n, i) => n + (i.found?.endpoints.length ?? 0), 0);
  return (
    <>
      <div className="tally">
        {LEVELS.map((s) => (
          <div key={s} className={"tally-item " + SEVERITY[s]}>
            <b>{findings.filter((f) => f.severity === s).length}</b><span>{s}</span>
          </div>
        ))}
        <div className="tally-item"><b>{items.length}</b><span>Open ports</span></div>
        <div className="tally-item"><b>{endpoints}</b><span>Endpoints</span></div>
      </div>
      <ul className="card results">
        {sorted(items).map((item) => (
          <li key={item.port}>
            <a className={"result " + item.state} href={href(id, item.port)}>
              <span className="port-num">{item.port}<small>/tcp</small></span>
              <span className="result-service">{item.service}{item.banner && <small className="mono">{item.banner}</small>}</span>
              <span className="result-what">
                {item.state === "waiting" && "Waiting"}
                {item.state === "checking" && <><span className="spinner small" />Checking endpoints</>}
                {item.found && <Counts findings={item.found.findings} />}
              </span>
              <span className="result-meta">{item.found && plural(item.found.endpoints.length, "endpoint")}</span>
              <Icon name="chevron_right" className="result-go" />
            </a>
          </li>
        ))}
      </ul>
    </>
  );
}

// Export downloads the finished report as JSON, Markdown or SARIF.
function Export({ report, when }: { report?: Report; when: number }) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(open, close, box);
  return (
    <div className="menu-wrap" ref={box}>
      <button type="button" className="btn" disabled={!report} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <Icon name="download" size={18} /><span>Export</span>
      </button>
      {open && report && (
        <div className="menu" role="menu" aria-label="Export as">
          {FORMATS.map(([format, label]) => (
            <button key={format} type="button" role="menuitem" className="menu-item"
              onClick={() => {
                download(report, when, format);
                setOpen(false);
              }}>
              {label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// Changes is what differs from the last finished scan of the same target:
// ports that opened or closed, findings that are new or gone.
function Changes({ scan, report, previous }: { scan: ScanRow; report?: Report; previous?: Previous }) {
  if (scan.status !== "done") return <div className="card empty">Changes show once the scan finishes</div>;
  if (!previous) return <div className="card empty">No earlier scan of {scan.target} to compare with</div>;
  if (!report || !previous.report) return <Loading />;
  const before = previous.report;
  const ports = (r: Report) => new Set(r.open_ports.map((o) => o.port));
  const key = (f: Finding) => f.severity + "|" + f.title + "|" + f.location;
  const keys = (r: Report) => new Set(r.findings.map(key));
  const opened = report.open_ports.filter((o) => !ports(before).has(o.port));
  const closed = before.open_ports.filter((o) => !ports(report).has(o.port));
  const ips = (r: Report) => new Set((r.hosts ?? []).map((h) => h.ip));
  const up = (report.hosts ?? []).filter((h) => !ips(before).has(h.ip));
  const down = (before.hosts ?? []).filter((h) => !ips(report).has(h.ip));
  const range = isRange(scan);
  const added = report.findings.filter((f) => !keys(before).has(key(f)));
  const gone = before.findings.filter((f) => !keys(report).has(key(f)));
  const portList = (id: string, list: Port[]) => (
    <ul className="results">
      {list.map((o) => (
        <li key={o.port}>
          <a className="result" href={href(id, o.port)}>
            <span className="port-num">{o.port}<small>/tcp</small></span>
            <span className="result-service">{o.service}</span>
            <span /><span />
            <Icon name="chevron_right" className="result-go" />
          </a>
        </li>
      ))}
    </ul>
  );
  const findingList = (list: Finding[]) => (
    <ul className="findings">{list.map((f, k) => <FindingRow key={k} finding={f} at />)}</ul>
  );
  return (
    <>
      <p className="lede">Compared with <a href={href(previous.scan.id)}>the scan from {new Date(previous.scan.created).toLocaleString()}</a></p>
      <div className="tally four">
        {range ? (
          <>
            <div className="tally-item bad"><b>{up.length}</b><span>New hosts</span></div>
            <div className="tally-item ok"><b>{down.length}</b><span>Hosts gone</span></div>
          </>
        ) : (
          <>
            <div className="tally-item bad"><b>{opened.length}</b><span>Ports opened</span></div>
            <div className="tally-item ok"><b>{closed.length}</b><span>Ports closed</span></div>
          </>
        )}
        <div className="tally-item warn"><b>{added.length}</b><span>New findings</span></div>
        <div className="tally-item ok"><b>{gone.length}</b><span>Resolved findings</span></div>
      </div>
      {opened.length + closed.length + up.length + down.length + added.length + gone.length === 0 ? (
        <div className="card empty">Nothing changed</div>
      ) : (
        <div className="stack">
          {up.length > 0 && <Card title="New hosts" sub={plural(up.length, "host")}><HostList hosts={up} /></Card>}
          {down.length > 0 && <Card title="Hosts gone" sub={plural(down.length, "host")}><HostList hosts={down} /></Card>}
          {opened.length > 0 && <Card title="Ports opened" sub={plural(opened.length, "port")}>{portList(scan.id, opened)}</Card>}
          {closed.length > 0 && <Card title="Ports closed" sub={plural(closed.length, "port")}>{portList(previous.scan.id, closed)}</Card>}
          {added.length > 0 && <Card title="New findings" sub={plural(added.length, "finding")}>{findingList(added)}</Card>}
          {gone.length > 0 && <Card title="Resolved findings" sub={plural(gone.length, "finding")}>{findingList(gone)}</Card>}
        </div>
      )}
    </>
  );
}

// isRange is whether a scan covers a range of addresses, `10.0.0.0/24`,
// rather than one host.
export function isRange(scan: ScanRow) {
  return scan.target.includes("/");
}

// Hosts is a range scan's result: each host that answered with its open
// ports, any one of which can be scanned in full, then the risky services
// found among them.
function Hosts({ report, onScan }: { report: Report; onScan: (command: string) => void }) {
  const hosts = report.hosts ?? [];
  const count = (s: Severity) => report.findings.filter((f) => f.severity === s).length;
  return (
    <>
      <div className="tally four">
        <div className="tally-item"><b>{hosts.length}</b><span>Hosts up</span></div>
        <div className="tally-item"><b>{hosts.reduce((n, h) => n + h.open_ports.length, 0)}</b><span>Open ports</span></div>
        <div className="tally-item bad"><b>{count("high")}</b><span>high</span></div>
        <div className="tally-item warn"><b>{count("medium")}</b><span>medium</span></div>
      </div>
      <div className="stack">
        {hosts.length === 0 ? <div className="card empty">No host in the range answered on a common port</div> : <HostList hosts={hosts} onScan={onScan} />}
        {report.findings.length > 0 && (
          <Card title="Findings" sub={plural(report.findings.length, "finding")}>
            <ul className="findings">{report.findings.map((f, k) => <FindingRow key={k} finding={f} at />)}</ul>
          </Card>
        )}
      </div>
    </>
  );
}

function HostList({ hosts, onScan }: { hosts: Host[]; onScan?: (command: string) => void }) {
  return (
    <ul className="card results">
      {hosts.map((h) => (
        <li key={h.ip}>
          <div className="result host">
            <span className="mono">{h.ip}</span>
            <span className="port-chips">{h.open_ports.map((o) => <span key={o.port} className="port-chip" title={o.service}>{o.port} {o.service}</span>)}</span>
            {onScan && <button type="button" className="btn" onClick={() => onScan("@ " + h.ip)}>Scan host</button>}
          </div>
        </li>
      ))}
    </ul>
  );
}

// Later holds a page that needs the finished report: the sweep while the
// scan runs, then the page.
function Later({ scan, ready, children }: { scan: ScanRow; ready?: Report; children: (report: Report) => ReactNode }) {
  if (ready) return <>{children(ready)}</>;
  if (scan.status === "failed") return null;
  if (scan.status === "done") return <Loading />;
  return <div className="card empty">Shows once the scan finishes</div>;
}

// Technologies is the software recognized on the open ports, a card per
// sort of thing: web servers, languages, frameworks, databases, ...
function Technologies({ id, report }: { id: string; report: Report }) {
  const all = report.technologies ?? [];
  if (!all.length) return <div className="card empty">Nothing recognized. Servers that don't name themselves show nothing here.</div>;
  const kinds = [...new Set(all.map((t) => t.kind))];
  return (
    <div className="stack">
      {kinds.map((kind) => {
        const these = all.filter((t) => t.kind === kind);
        return (
          <Card key={kind} title={kind} sub={`${these.length} found`}>
            <ul className="results">
              {these.map((t) => (
                <li key={t.port + t.name}>
                  <a className="result tech-row" href={href(id, t.port)}>
                    <span className="tech-name">{t.name}{t.version && <span className="port-chip">{t.version}</span>}</span>
                    <span className="port-num">{t.port}<small>/tcp</small></span>
                    <span className="result-meta">{t.evidence}</span>
                    <Icon name="chevron_right" className="result-go" />
                  </a>
                </li>
              ))}
            </ul>
          </Card>
        );
      })}
    </div>
  );
}

// Apis is every API document the scan found served without auth: what it
// is and the security it defines, then each operation it lists, with the
// ones that change data and declare no security marked.
function Apis({ report }: { report: Report }) {
  const all = report.apis ?? [];
  if (!all.length) return <div className="card empty">No OpenAPI or Swagger document found served without auth</div>;
  return (
    <div className="stack">
      {all.map((a) => {
        const open = a.operations.filter((o) => !o.secured && ["POST", "PUT", "PATCH", "DELETE"].includes(o.method));
        return (
          <Card key={a.url} title={`${a.title || "Untitled API"} ${a.version}`}
            sub={<>{a.spec} at <code>{a.url}</code></>}
            action={open.length > 0 && <span className="chip warn">{open.length} write {open.length === 1 ? "operation" : "operations"} without auth</span>}>
            <dl className="facts-list">
              <dt>Security</dt>
              <dd>{a.schemes.length ? a.schemes.map((s) => <span key={s} className="port-chip">{s}</span>) : <span className="chip warn">None defined</span>}</dd>
            </dl>
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Method</th><th>Path</th><th>Auth</th><th className="grow">Summary</th></tr></thead>
                <tbody>
                  {a.operations.map((o) => (
                    <tr key={o.method + o.path}>
                      <td><span className={"method " + o.method.toLowerCase()}>{o.method}</span></td>
                      <td className="mono">{o.path}</td>
                      <td>{o.secured ? <span className="chip ok">Required</span> : <span className={"chip " + (open.includes(o) ? "warn" : "plain")}>None</span>}</td>
                      <td className="muted">{o.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        );
      })}
    </div>
  );
}

// History is every kept scan of the same target: a bar per finished scan of
// what it found, oldest to newest, then a row per scan, newest first, each
// opening that scan.
function History({ scan, history }: { scan: ScanRow; history: ScanRow[] }) {
  const done = history.filter((s) => s.status === "done");
  const serious = (s: ScanRow) => s.findings.high + s.findings.medium + s.findings.low;
  const most = Math.max(1, ...done.map(serious));
  const when = (s: ScanRow) => new Date(s.created).toLocaleString();
  return (
    <div className="stack">
      {done.length > 1 && (
        <Card title="Findings over time" sub={`High, medium and low, across ${done.length} finished scans`}>
          <div className="trend">
            {[...done].reverse().map((s) => (
              <a key={s.id} className={"trend-bar" + (s.id === scan.id ? " on" : "")} href={href(s.id, "history")}
                title={`${when(s)}: ${s.findings.high} high, ${s.findings.medium} medium, ${s.findings.low} low`}>
                <span className="trend-stack" style={{ height: `${(serious(s) / most) * 100}%` }}>
                  {LEVELS.slice(0, 3).map((l) => s.findings[l] > 0 && <span key={l} className={SEVERITY[l]} style={{ flexGrow: s.findings[l] }} />)}
                </span>
                <span className="trend-label">{new Date(s.created).toLocaleDateString(undefined, { month: "short", day: "numeric" })}</span>
              </a>
            ))}
          </div>
        </Card>
      )}
      <Card title="Scans" sub={`${history.length} kept of ${scan.target}`}>
        <ul className="results">
          {history.map((s) => (
            <li key={s.id}>
              <a className={"result history-row" + (s.id === scan.id ? " on" : "")} href={href(s.id)}>
                <span>{when(s)}</span>
                {s.status === "done" ? (
                  <>
                    <span className="result-meta">{plural(s.open_ports, "open port")}</span>
                    <span className="result-meta">{plural(s.endpoints, "endpoint")}</span>
                    <span className="chips">
                      {LEVELS.slice(0, 3).some((l) => s.findings[l] > 0)
                        ? LEVELS.slice(0, 3).map((l) => s.findings[l] > 0 && <span key={l} className={"chip " + SEVERITY[l]}>{s.findings[l]} {l}</span>)
                        : <span className="muted">Nothing serious</span>}
                    </span>
                  </>
                ) : (
                  <span className="muted history-status">{s.status === "failed" ? "Failed" : s.status === "queued" ? "Queued" : "Scanning"}</span>
                )}
                <Icon name="chevron_right" className="result-go" />
              </a>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}

// Counts is a chip per severity found, worst first, or a quiet all clear.
function Counts({ findings }: { findings: Finding[] }) {
  const shown = LEVELS.filter((s) => s !== "info" && findings.some((f) => f.severity === s));
  if (!shown.length) return <span className="muted">Nothing serious</span>;
  return (
    <span className="chips">
      {shown.map((s) => <span key={s} className={"chip " + SEVERITY[s]}>{findings.filter((f) => f.severity === s).length} {s}</span>)}
    </span>
  );
}

// Detail is one port's page: back to the findings, a step to the ports either
// side, then the findings on it and the endpoints it serves.
function Detail({ id, item, items }: { id: string; item: Item; items: Item[] }) {
  const i = items.indexOf(item);
  const prev = items[i - 1];
  const next = items[i + 1];
  const f = item.found;
  return (
    <>
      <div className="page-head">
        <a className="icon-btn" href={href(id)} aria-label="Back to findings" title="Back to findings"><Icon name="arrow_back" /></a>
        <div className="page-head-main">
          <h1 className="port-num">{item.port}<small>/tcp</small></h1>
          <div className="page-sub">
            <span>{item.service}</span>
            {item.banner && <code className="command-line">{item.banner}</code>}
            {f && <Counts findings={f.findings} />}
          </div>
        </div>
        <div className="pager">
          <Step id={id} to={prev} label="Previous port" icon="chevron_left" />
          <span className="pager-pos">{i + 1} of {items.length}</span>
          <Step id={id} to={next} label="Next port" icon="chevron_right" />
        </div>
      </div>

      {!f && (
        <Card title={item.state === "checking" ? "Checking endpoints" : "Waiting its turn"}>
          <div className="skeleton" aria-label="Loading">{[0, 1, 2, 3].map((k) => <span key={k} className="bone" />)}</div>
        </Card>
      )}
      {f && (
        <div className="stack">
          <Card title="Findings" sub={plural(f.findings.length, "finding")}>
            {f.findings.length
              ? <ul className="findings">{[...f.findings].sort((a, b) => LEVELS.indexOf(a.severity) - LEVELS.indexOf(b.severity)).map((x, k) => <FindingRow key={k} finding={x} />)}</ul>
              : <div className="empty">No findings on this port</div>}
          </Card>
          {item.tls && <TlsCard tls={item.tls} />}
          <Card title="Endpoints" sub={plural(f.endpoints.length, "endpoint")} action={f.endpoints.length > 0 && <Legend />}>
            {f.endpoints.length
              ? <EndpointsTable endpoints={f.endpoints} />
              : <div className="empty">No HTTP endpoints on this port</div>}
          </Card>
        </div>
      )}
    </>
  );
}

// TlsCard is an HTTPS port's certificate: who it names and who issued it,
// how long it is good for, the names it covers, and any old TLS versions
// the port still accepts.
function TlsCard({ tls }: { tls: Tls }) {
  const c = tls.cert;
  const left = c ? Math.floor((c.not_after * 1000 - Date.now()) / 86_400_000) : 0;
  const day = (s: number) => new Date(s * 1000).toLocaleDateString();
  return (
    <Card title="TLS" sub={c ? c.subject : "Certificate not readable"}>
      <dl className="facts-list">
        {c && (
          <>
            <dt>Issued by</dt>
            <dd>{c.issuer}{c.self_signed && <span className="chip warn">Self-signed</span>}</dd>
            <dt>Valid</dt>
            <dd>
              {day(c.not_before)} to {day(c.not_after)}
              <span className={"chip " + (left < 0 ? "bad" : left < 30 ? "warn" : "ok")}>{left < 0 ? `Expired ${-left} days ago` : `${left} days left`}</span>
            </dd>
            {c.names.length > 0 && (
              <>
                <dt>Covers</dt>
                <dd className="chips">{c.names.map((n) => <code key={n} className="command-line">{n}</code>)}</dd>
              </>
            )}
          </>
        )}
        <dt>Protocols</dt>
        <dd>
          {tls.legacy.length
            ? tls.legacy.map((v) => <span key={v} className="chip bad">{v} accepted</span>)
            : <span className="chip ok">No TLS 1.0 or 1.1</span>}
        </dd>
      </dl>
    </Card>
  );
}

// Card is a titled section: a heading, a line under it, an action on the
// right, and what it holds.
export function Card({ title, sub, action, children }: { title: ReactNode; sub?: ReactNode; action?: ReactNode; children?: ReactNode }) {
  return (
    <section className="card">
      <div className="card-head">
        <div className="card-titles">
          <h2>{title}</h2>
          {sub && <p>{sub}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function Step({ id, to, label, icon }: { id: string; to?: Item; label: string; icon: "chevron_left" | "chevron_right" }) {
  if (!to) return <span className="icon-btn" aria-disabled="true"><Icon name={icon} /></span>;
  return <a className="icon-btn" href={href(id, to.port)} aria-label={label} title={label}><Icon name={icon} /></a>;
}

// FindingRow is one finding; `at` names the port it is on as well as the
// path, for a list that mixes ports.
function FindingRow({ finding: f, at }: { finding: Finding; at?: boolean }) {
  const port = /(?:^|\()port (\d+)/.exec(f.location)?.[1];
  // A range's findings name their host before the port.
  const head = f.location.split(" (port ")[0];
  const host = at && !head.startsWith("http") && !head.startsWith("port") ? head : "";
  const where = [host, at && port ? "port " + port : "", path(f.location)].filter(Boolean).join(" ");
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

function Loading() {
  return (
    <div className="card results" aria-label="Loading">
      {[0, 1, 2, 3].map((i) => <div key={i} className="result"><span className="bone short" /><span className="bone" /></div>)}
    </div>
  );
}

export const SEVERITY: Record<Severity, string> = { high: "bad", medium: "warn", low: "plain", info: "ok" };
const LEVELS: Severity[] = ["high", "medium", "low", "info"];
const POSTURE: Record<Posture, string> = {
  configured: "Configured",
  insecure: "Bypassable",
  missing: "Not configured",
  unknown: "Not shown",
};
const CONTROLS = [["auth", "AUTH"], ["jwt", "JWT"], ["rate", "RATE"], ["https", "HTTPS"]] as const;
const HEADERS = [["hsts", "HSTS"], ["csp", "CSP"], ["frame", "FRAME"], ["nosniff", "SNIFF"], ["cors", "CORS"], ["cookies", "COOKIE"]] as const;

function Legend() {
  return (
    <div className="legend">
      {(["configured", "insecure", "missing", "unknown"] as Posture[]).map((p) => (
        <span key={p} className="legend-item"><span className={"swatch " + p} />{POSTURE[p]}</span>
      ))}
    </div>
  );
}

function EndpointsTable({ endpoints }: { endpoints: Endpoint[] }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Status</th><th>Path</th><th>Controls</th><th>Headers</th><th className="grow">Note</th></tr></thead>
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
              <td>
                {e.headers && (
                  <span className="controls">
                    {HEADERS.map(([key, label]) => (
                      <span key={key} className={"control " + e.headers![key]} title={label + ": " + POSTURE[e.headers![key]]}>{label}</span>
                    ))}
                  </span>
                )}
              </td>
              <td className="muted">{e.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// sorted puts the ports in the order the findings list them: worst finding
// first, then by number.
function sorted(items: Item[]) {
  const rank = (i: Item) => Math.min(LEVELS.length, ...(i.found?.findings ?? []).map((f) => LEVELS.indexOf(f.severity)));
  return [...items].sort((a, b) => rank(a) - rank(b) || a.port - b.port);
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
