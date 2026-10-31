import { useCallback, useRef, useState, type ReactNode } from "react";
import { ApiDetail, Apis, Badge, BoneRows, Dns, FindingFold, History, live, Software, SoftwareDetail, Tabs } from "./Pages";
import { Fold, usePaged } from "./paged";
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
export function ScanView({ scan, report, items, progress: p, page, port, item, previous, history, onAgain, onScan, onDelete }: {
  scan: ScanRow;
  report?: Report;
  items: Item[] | null;
  progress?: Progress;
  page: Page;
  port: number | null;
  // One thing on the page, such as a technology.
  item: string | null;
  previous?: Previous;
  // Every kept scan of the same target, newest first.
  history: ScanRow[];
  onAgain: () => void;
  onScan: (command: string) => void;
  onDelete: () => void;
}) {
  const range = isRange(scan);
  const open = items?.find((i) => i.port === port);
  const going = scan.status === "queued" || scan.status === "running";
  const ip = scan.resolved_ip ?? p?.ip;
  const found = live(scan, report, p);
  const host = scan.target.split(":")[0];
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
      {/* The heading above stays put; only what's under it changes from page to page. */}
      <div className="page-body" key={page + "/" + (port ?? "") + "/" + (item ?? "")}>
      {open && items ? <Detail id={scan.id} item={open} items={sorted(items)} />
        : page === "history" ? <History scan={scan} live={found} history={history} previous={previous} />
        : page === "software" ? (item ? <SoftwareDetail id={scan.id} live={found} name={item} /> : <Software id={scan.id} live={found} />)
        : page === "api" ? (item ? <ApiDetail id={scan.id} live={found} index={item} /> : <Apis id={scan.id} live={found} />)
        : page === "dns" ? <Dns host={host} live={found} />
        : range && report ? <Hosts report={report} onScan={onScan} />
        : !range && items ? <Results id={scan.id} items={items} />
        : going ? <Stage scan={scan} progress={p} /> : scan.status === "done" ? <Loading /> : null}
      </div>
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
      {p && p.services_total > 0 && (
        <span>Checked <b>{p.services_done}</b> of <b>{p.services_total}</b> HTTP services</span>
      )}
    </>
  );
}

// quiet is whether a port is open and nothing more: checked, no endpoints to
// send anything to, and nothing found worse than info.
function quiet(item: Item) {
  return item.state === "done" && !item.found?.endpoints.length && !item.found?.findings.some((f) => f.severity !== "info");
}

// Results is the scan's findings, the way Software shows software: a tile
// per open port, worst first, filtered by its worst severity, a page at a
// time, each opening its own page. Ports that are only open hide behind a
// count under the tiles until it's clicked.
function Results({ id, items }: { id: string; items: Item[] }) {
  const [reveal, setReveal] = useState(false);
  const [level, setLevel] = useState("");
  const hidden = items.filter(quiet);
  const visible = sorted(reveal ? items : items.filter((i) => !quiet(i)));
  const levels = ["High", "Medium", "Low"].filter((l) => visible.some((i) => worstOf(i) === l.toLowerCase()));
  const { shown, pager } = usePaged(level ? visible.filter((i) => worstOf(i) === level.toLowerCase()) : visible, 12);
  if (items.length === 0) return <div className="card empty">No open ports found</div>;
  return (
    <>
      <Tabs all={levels} value={level} onChange={setLevel}
        counts={(l) => (l ? visible.filter((i) => worstOf(i) === l.toLowerCase()).length : visible.length)} />
      <div className="tiles">
        {shown.map((item) => {
          const serious = item.found?.findings.filter((f) => f.severity !== "info") ?? [];
          const worst = worstOf(item);
          const software = item.found?.technologies?.[0];
          return (
            <a key={item.port} className="tile-card" href={href(id, item.port)}>
              {software
                ? <Badge name={software.name} kind={software.kind} />
                : <span className={"badge sev " + (worst ? SEVERITY[worst] : "ok")} aria-hidden="true"><Icon name="shield" /></span>}
              <span className="tile-title">{item.port}<small>/tcp</small></span>
              <span className="tile-sub">{software ? software.name : item.service}</span>
              <span className="tile-foot">
                {item.state !== "done"
                  ? <span className="checking"><span className="spinner tiny" />{item.state === "checking" ? "Checking" : "Waiting"}</span>
                  : worst ? <span className={"chip " + SEVERITY[worst]}>{plural(serious.length, "finding")}</span>
                  : <span>Nothing serious</span>}
                {item.found && <span>{plural(item.found.endpoints.length, "endpoint")}</span>}
              </span>
            </a>
          );
        })}
      </div>
      {pager}
      {hidden.length > 0 && (
        <button type="button" className="hidden-note" aria-expanded={reveal} onClick={() => setReveal((r) => !r)}>
          {reveal
            ? `Hide the ${hidden.length} ${hidden.length === 1 ? "port" : "ports"} that are only open`
            : `${hidden.length} hidden ${hidden.length === 1 ? "result" : "results"}: open, with no endpoints or findings`}
        </button>
      )}
    </>
  );
}

// worstOf is the worst severity found on a port, info aside, or "".
function worstOf(item: Item): Severity | "" {
  return LEVELS.find((l) => l !== "info" && item.found?.findings.some((f) => f.severity === l)) ?? "";
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

// isRange is whether a scan covers a range of addresses, `10.0.0.0/24`,
// rather than one host.
export function isRange(scan: ScanRow) {
  return scan.target.includes("/");
}

// Hosts is a range scan's result: one line of what it found, each host that
// answered with its open ports, a page at a time, any one of which can be
// scanned in full, then the risky services among them, folded.
function Hosts({ report, onScan }: { report: Report; onScan: (command: string) => void }) {
  const hosts = report.hosts ?? [];
  const { shown, pager } = usePaged(hosts, 10);
  return (
    <>
      <p className="summary-line">
        <span><b>{hosts.length}</b> {hosts.length === 1 ? "host" : "hosts"} up</span>
        <span><b>{hosts.reduce((n, h) => n + h.open_ports.length, 0)}</b> open ports</span>
        <Counts findings={report.findings} />
      </p>
      {hosts.length === 0 ? <div className="card empty">No host in the range answered on a common port</div> : (
        <div className="card">
          <HostList hosts={shown} onScan={onScan} />
          {pager}
        </div>
      )}
      {report.findings.length > 0 && (
        <div className="card folds gap-top">{report.findings.map((f, k) => <FindingFold key={k} finding={f} />)}</div>
      )}
    </>
  );
}

export function HostList({ hosts, onScan }: { hosts: Host[]; onScan?: (command: string) => void }) {
  return (
    <ul className="results">
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
// side, then its findings, its certificate and its endpoints, each a line
// until it's opened, a page at a time.
function Detail({ id, item, items }: { id: string; item: Item; items: Item[] }) {
  const i = items.indexOf(item);
  const prev = items[i - 1];
  const next = items[i + 1];
  const f = item.found;
  const findings = [...(f?.findings ?? [])].sort((a, b) => LEVELS.indexOf(a.severity) - LEVELS.indexOf(b.severity));
  const fp = usePaged(findings, 8);
  const ep = usePaged(f?.endpoints ?? [], 10);
  return (
    <>
      <div className="sub-head">
        <a className="icon-btn" href={href(id)} aria-label="Back to findings" title="Back to findings"><Icon name="arrow_back" /></a>
        <div className="page-head-main">
          <h2 className="port-num">{item.port}<small>/tcp</small></h2>
          <div className="page-sub">
            <span>{item.service}</span>
            {item.banner && <code className="command-line">{item.banner}</code>}
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
          <BoneRows n={4} />
        </Card>
      )}
      {f && (
        <div className="stack">
          <Card title="Findings" sub={plural(findings.length, "finding")}>
            {findings.length ? fp.shown.map((x, k) => <FindingFold key={k} finding={x} />) : <div className="empty">No findings on this port</div>}
            {fp.pager}
          </Card>
          {item.tls && <TlsCard tls={item.tls} />}
          <Card title="Endpoints" sub={plural(f.endpoints.length, "endpoint")}>
            {f.endpoints.length ? ep.shown.map((e) => <EndpointFold key={e.url} endpoint={e} />) : <div className="empty">No HTTP endpoints on this port</div>}
            {ep.pager}
          </Card>
        </div>
      )}
    </>
  );
}

// TlsCard is an HTTPS port's certificate: who it names, how long it has left
// and whether old TLS versions still work at a glance, the rest folded.
function TlsCard({ tls }: { tls: Tls }) {
  const c = tls.cert;
  const left = c ? Math.floor((c.not_after * 1000 - Date.now()) / 86_400_000) : 0;
  const day = (s: number) => new Date(s * 1000).toLocaleDateString();
  return (
    <Card title="TLS" sub={c ? c.subject : "Certificate not readable"}
      action={
        <span className="chips">
          {c && <span className={"chip " + (left < 0 ? "bad" : left < 30 ? "warn" : "ok")}>{left < 0 ? `Expired ${-left} days ago` : `${left} days left`}</span>}
          {c?.self_signed && <span className="chip warn">Self-signed</span>}
          {tls.legacy.map((v) => <span key={v} className="chip bad">{v}</span>)}
        </span>
      }>
      {c && (
        <Fold head={<span className="fold-title">Certificate details</span>}>
          <dl className="facts-list">
            <dt>Issued by</dt><dd>{c.issuer}</dd>
            <dt>Valid</dt><dd>{day(c.not_before)} to {day(c.not_after)}</dd>
            {c.names.length > 0 && <><dt>Covers</dt><dd className="chips">{c.names.map((n) => <code key={n} className="command-line">{n}</code>)}</dd></>}
            <dt>Old protocols</dt><dd>{tls.legacy.length ? tls.legacy.join(" and ") + " accepted" : "TLS 1.0 and 1.1 refused"}</dd>
          </dl>
        </Fold>
      )}
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

// EndpointFold is an endpoint as one line, its status, path, note and how
// many of its controls and headers fall short; its blocks fold under it.
function EndpointFold({ endpoint: e }: { endpoint: Endpoint }) {
  const blocks = (list: readonly (readonly [string, string])[], verdicts: Record<string, Posture> | undefined) =>
    verdicts && (
      <span className="controls">
        {list.map(([key, label]) => <span key={key} className={"control " + verdicts[key]} title={label + ": " + POSTURE[verdicts[key]]}>{label}</span>)}
      </span>
    );
  const verdicts = [...Object.values(e.controls), ...Object.values(e.headers ?? {})];
  const short = verdicts.filter((v) => v === "missing" || v === "insecure").length;
  return (
    <Fold head={
      <>
        <span className={"mono status-" + Math.floor(e.status / 100)}>{e.status}</span>
        <span className="mono fold-title">{new URL(e.url).pathname}</span>
        <span className="muted fold-note-inline">{e.note}</span>
        {short > 0 ? <span className="chip warn">{short} short</span> : <span className="chip ok">All set</span>}
      </>
    }>
      <div className="blocks">
        <span className="muted">Controls</span>{blocks(CONTROLS, e.controls)}
        {e.headers && <><span className="muted">Headers</span>{blocks(HEADERS, e.headers)}</>}
      </div>
      <Legend />
    </Fold>
  );
}

// sorted puts the ports in the order the findings list them: worst finding
// first, then by number.
function sorted(items: Item[]) {
  const rank = (i: Item) => Math.min(LEVELS.length, ...(i.found?.findings ?? []).map((f) => LEVELS.indexOf(f.severity)));
  return [...items].sort((a, b) => rank(a) - rank(b) || a.port - b.port);
}

export function plural(n: number, word: string) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

export function fromProgress(p: Progress): Item[] {
  return p.open.map((o): Item => ({
    ...o,
    tls: o.tls ?? o.found?.tls,
    state: o.found ? "done" : p.inspecting.includes(o.port) ? "checking" : "waiting",
  }));
}

// fromReport splits a finished report back into its ports, the same shape
// the scan showed while it ran.
export function fromReport(r: Report): Item[] {
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
