import { useState, type ReactNode } from "react";
import { Icon } from "./Icon";
import { href } from "./route";
import { Card, FindingRow, fromProgress, fromReport, HostList, isRange, plural, SEVERITY, type Item, type Previous } from "./ScanView";
import type { Api, DnsRecord, Finding, Host, Operation, Progress, Report, ScanRow, Severity, Tech } from "./types";

// The pages of a scan beyond Findings: Technologies, API and DNS, each with
// a page per thing on it, and History and Changes. Each draws what has been
// found so far while the scan runs, with skeletons where more is coming.

// Live is what a scan has found so far: everything in its report once it
// has one, else what its progress carries.
export interface Live {
  // More may still come: the scan runs, or its report hasn't arrived.
  going: boolean;
  items: Item[];
  technologies: Tech[];
  apis: Api[];
  // null until the lookup is in.
  dns: DnsRecord[] | null;
  findings: Finding[];
  // The highest port the sweep has passed; every port, once it's over.
  reached: number;
  // For a range, the hosts that answered.
  hosts: Host[];
}

const ALL_PORTS = 65535;

export function live(scan: ScanRow, report: Report | undefined, p: Progress | undefined): Live {
  if (report) {
    return {
      going: false,
      items: fromReport(report),
      technologies: report.technologies ?? [],
      apis: report.apis ?? [],
      dns: report.dns ?? [],
      findings: report.findings,
      reached: ALL_PORTS,
      hosts: report.hosts ?? [],
    };
  }
  const items = p ? fromProgress(p) : [];
  return {
    going: scan.status !== "failed",
    items,
    technologies: items.flatMap((i) => i.found?.technologies ?? []),
    apis: items.flatMap((i) => i.found?.apis ?? []),
    dns: p?.dns ? p.dns.records : null,
    findings: [...items.flatMap((i) => i.found?.findings ?? []), ...(p?.dns?.findings ?? [])],
    reached: !p || p.phase === "queued" || p.phase === "resolving" ? 0 : p.phase === "ports" ? p.port : ALL_PORTS,
    hosts: [],
  };
}

const LEVELS: Severity[] = ["high", "medium", "low", "info"];

// ---- shared pieces ----

// Back is a page within a page's heading: back to the page, then what this is.
function Back({ to, label, children }: { to: string; label: string; children: ReactNode }) {
  return (
    <div className="sub-head">
      <a className="icon-btn" href={to} aria-label={"Back to " + label} title={"Back to " + label}><Icon name="arrow_back" /></a>
      <div className="page-head-main">{children}</div>
    </div>
  );
}

// Bones are skeleton tiles standing in for what is still being found.
function Bones({ n, label }: { n: number; label: string }) {
  return (
    <>
      {Array.from({ length: n }, (_, i) => (
        <div key={i} className="tile-card bones" aria-label={i === 0 ? label : undefined} aria-busy="true">
          <span className="bone badge-bone" />
          <span className="bone" />
          <span className="bone short" />
        </div>
      ))}
    </>
  );
}

function Empty({ icon, title, children }: { icon: "dns" | "lock" | "language" | "history" | "difference"; title: string; children: ReactNode }) {
  return (
    <div className="card welcome">
      <Icon name={icon} size={36} />
      <h2>{title}</h2>
      <p className="muted">{children}</p>
    </div>
  );
}

// Still is the line under a page while more is coming.
function Still({ live: l, what }: { live: Live; what: string }) {
  if (!l.going) return null;
  const pending = l.items.filter((i) => !i.found).length;
  return (
    <p className="still">
      <span className="spinner small" />
      {l.reached < ALL_PORTS ? `Sweeping, past port ${l.reached}` : "Sweep done"}
      {pending > 0 && `, ${plural(pending, "port")} still being checked`}; {what} show as they're found
    </p>
  );
}

// ---- technologies ----

const KINDS: Record<string, string> = {
  "Web server": "web",
  Edge: "edge",
  Language: "lang",
  Framework: "framework",
  Database: "db",
  "Remote access": "remote",
  Mail: "mail",
  "File transfer": "files",
  Secrets: "secrets",
};

const ABOUT: Record<string, string> = {
  "Web server": "Software that answers HTTP. Its name and version, when it gives them, tell an attacker which known weaknesses to try.",
  Edge: "A CDN or proxy in front of the service. What's behind it may differ from what answers.",
  Language: "The language the application runs on, given away by a header or a session cookie's name.",
  Framework: "The framework the application is built with, from its cookies or the paths only it answers.",
  Database: "A database answering on the network. Most should only be reachable by the applications that use them.",
  "Remote access": "A way to log in to the machine. Keep it patched, and reachable only from where it's needed.",
  Mail: "A mail server, named in its greeting.",
  "File transfer": "A file transfer server, named in its greeting.",
  Secrets: "A secrets store. Its API should never be open to the network at large.",
};

// A technology as the page draws it: one name, wherever it was seen.
interface Seen {
  name: string;
  kind: string;
  versions: string[];
  at: Tech[];
}

function gather(all: Tech[]): Seen[] {
  const by = new Map<string, Seen>();
  for (const t of all) {
    const s = by.get(t.name) ?? { name: t.name, kind: t.kind, versions: [], at: [] };
    if (t.version && !s.versions.includes(t.version)) s.versions.push(t.version);
    s.at.push(t);
    by.set(t.name, s);
  }
  return [...by.values()].sort((a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name));
}

function Badge({ name, kind, big }: { name: string; kind: string; big?: boolean }) {
  return <span className={"badge k-" + (KINDS[kind] ?? "other") + (big ? " big" : "")} aria-hidden="true">{name.slice(0, 1).toUpperCase()}</span>;
}

// Technologies is the software recognized on the open ports, a tile each,
// filtered by kind; a tile opens where it was seen.
export function Technologies({ id, live: l }: { id: string; live: Live }) {
  const [kind, setKind] = useState("");
  const all = gather(l.technologies);
  const kinds = [...new Set(all.map((s) => s.kind))];
  const shown = kind ? all.filter((s) => s.kind === kind) : all;
  if (!all.length && !l.going) {
    return <Empty icon="dns" title="Nothing recognized">Servers that don't name themselves in headers, cookies or greetings show nothing here.</Empty>;
  }
  return (
    <>
      {kinds.length > 1 && (
        <div className="filters" role="tablist" aria-label="Kinds">
          <button type="button" role="tab" aria-selected={!kind} className="filter" onClick={() => setKind("")}>All<span>{all.length}</span></button>
          {kinds.map((k) => (
            <button key={k} type="button" role="tab" aria-selected={kind === k} className="filter" onClick={() => setKind(k)}>
              {k}<span>{all.filter((s) => s.kind === k).length}</span>
            </button>
          ))}
        </div>
      )}
      <div className="tiles">
        {shown.map((s) => (
          <a key={s.name} className="tile-card" href={href(id, "tech", s.name)}>
            <Badge name={s.name} kind={s.kind} />
            <span className="tile-title">{s.name}</span>
            <span className="tile-sub mono">{s.versions.join(", ") || "Version not shown"}</span>
            <span className="tile-foot">
              <span className={"kind k-" + (KINDS[s.kind] ?? "other")}>{s.kind}</span>
              <span>{s.at.length === 1 ? `Port ${s.at[0].port}` : plural(s.at.length, "port")}</span>
            </span>
          </a>
        ))}
        {l.going && <Bones n={shown.length ? 2 : 4} label="Finding technologies" />}
      </div>
      <Still live={l} what="technologies" />
    </>
  );
}

// TechDetail is one technology: what sort of thing it is, every port it was
// seen on with the version and what gave it away, and the findings there.
export function TechDetail({ id, live: l, name }: { id: string; live: Live; name: string }) {
  const s = gather(l.technologies).find((t) => t.name === name);
  if (!s) {
    return (
      <>
        <Back to={href(id, "tech")} label="Technologies"><h2>{name}</h2></Back>
        {l.going ? <div className="tiles"><Bones n={2} label="Looking" /></div> : <div className="card empty">Not seen in this scan</div>}
      </>
    );
  }
  const ports = new Set(s.at.map((t) => t.port));
  const findings = l.items.filter((i) => ports.has(i.port)).flatMap((i) => i.found?.findings ?? []);
  return (
    <>
      <Back to={href(id, "tech")} label="Technologies">
        <div className="title-row">
          <Badge name={s.name} kind={s.kind} big />
          <div>
            <h2>{s.name}</h2>
            <div className="page-sub">
              <span className={"kind k-" + (KINDS[s.kind] ?? "other")}>{s.kind}</span>
              {s.versions.map((v) => <span key={v} className="port-chip">{v}</span>)}
            </div>
          </div>
        </div>
      </Back>
      <div className="stack">
        {ABOUT[s.kind] && <p className="lede">{ABOUT[s.kind]}</p>}
        <Card title="Seen on" sub={plural(s.at.length, "port")}>
          <ul className="results">
            {s.at.map((t) => (
              <li key={t.port}>
                <a className="result seen-row" href={href(id, t.port)}>
                  <span className="port-num">{t.port}<small>/tcp</small></span>
                  <span className="mono">{t.version ?? "No version shown"}</span>
                  <span className="result-meta">{t.evidence}</span>
                  <Icon name="chevron_right" className="result-go" />
                </a>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Findings on these ports" sub={plural(findings.length, "finding")}>
          {findings.length
            ? <ul className="findings">{findings.map((f, k) => <FindingRow key={k} finding={f} at />)}</ul>
            : <div className="empty">Nothing found on these ports</div>}
        </Card>
      </div>
    </>
  );
}

// ---- API documents ----

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const writes = (o: Operation) => ["POST", "PUT", "PATCH", "DELETE"].includes(o.method);

// MethodBar is how an API's operations split by method, a segment each.
function MethodBar({ ops }: { ops: Operation[] }) {
  const counts = [...METHODS, "OTHER"].map((m) => [m, ops.filter((o) => (m === "OTHER" ? !METHODS.includes(o.method) : o.method === m)).length] as const).filter(([, n]) => n > 0);
  return (
    <span className="method-bar" role="img" aria-label={counts.map(([m, n]) => `${n} ${m}`).join(", ")}>
      {counts.map(([m, n]) => <span key={m} className={"seg " + m.toLowerCase()} style={{ flexGrow: n }} title={`${n} ${m}`} />)}
    </span>
  );
}

// Apis is every API document the scan found served without auth, a tile
// each: what it is, how its operations split by method, and how many change
// data without auth. A tile opens its operations.
export function Apis({ id, live: l }: { id: string; live: Live }) {
  if (!l.apis.length && !l.going) {
    return <Empty icon="lock" title="No API documents">No OpenAPI or Swagger document was served without auth at a conventional path, such as /openapi.json or /v3/api-docs.</Empty>;
  }
  return (
    <>
      <div className="tiles wide">
        {l.apis.map((a, i) => {
          const open = a.operations.filter((o) => writes(o) && !o.secured).length;
          return (
            <a key={a.url} className="tile-card" href={href(id, "api", String(i))}>
              <span className="api-top">
                <span className="spec">{a.spec}</span>
                <span className="port-chip">port {a.port}</span>
              </span>
              <span className="tile-title">{a.title || "Untitled API"} <small>{a.version}</small></span>
              <span className="tile-sub mono">{a.url}</span>
              <MethodBar ops={a.operations} />
              <span className="tile-foot">
                <span>{plural(a.operations.length, "operation")}</span>
                {open ? <span className="chip warn">{open} writes without auth</span> : <span className="chip ok">Writes secured</span>}
              </span>
            </a>
          );
        })}
        {l.going && <Bones n={l.apis.length ? 1 : 2} label="Looking for API documents" />}
      </div>
      <Still live={l} what="API documents" />
    </>
  );
}

// ApiDetail is one API document: where it is and how it's secured, then its
// operations grouped by their first path segment, filtered by method or to
// the writes without auth.
export function ApiDetail({ id, live: l, index }: { id: string; live: Live; index: string }) {
  const [method, setMethod] = useState("");
  const [openOnly, setOpenOnly] = useState(false);
  const a = l.apis[Number(index)];
  if (!a) {
    return (
      <>
        <Back to={href(id, "api")} label="API"><h2>API document</h2></Back>
        {l.going ? <div className="tiles"><Bones n={1} label="Looking" /></div> : <div className="card empty">Not found in this scan</div>}
      </>
    );
  }
  const open = a.operations.filter((o) => writes(o) && !o.secured);
  const shown = a.operations.filter((o) => (!method || o.method === method) && (!openOnly || (writes(o) && !o.secured)));
  const groups = new Map<string, Operation[]>();
  for (const o of shown) {
    const head = "/" + (o.path.split("/").filter(Boolean)[0] ?? "");
    groups.set(head, [...(groups.get(head) ?? []), o]);
  }
  const methods = METHODS.filter((m) => a.operations.some((o) => o.method === m));
  return (
    <>
      <Back to={href(id, "api")} label="API">
        <h2>{a.title || "Untitled API"} <small className="muted">{a.version}</small></h2>
        <div className="page-sub"><span className="spec">{a.spec}</span><code className="command-line">{a.url}</code></div>
      </Back>
      <div className="stack">
        <div className="tally four">
          <div className="tally-item"><b>{a.operations.length}</b><span>Operations</span></div>
          <div className="tally-item"><b>{a.operations.filter(writes).length}</b><span>Change data</span></div>
          <div className={"tally-item " + (open.length ? "warn" : "ok")}><b>{open.length}</b><span>Writes without auth</span></div>
          <div className="tally-item"><b>{a.schemes.length}</b><span>Security schemes</span></div>
        </div>
        <Card title="Security" sub="The schemes the document defines">
          <div className="pad-chips">
            {a.schemes.length ? a.schemes.map((s) => <span key={s} className="port-chip">{s}</span>) : <span className="chip warn">None defined</span>}
            <a className="btn" href={href(id, a.port)}>Port {a.port}<Icon name="chevron_right" size={18} /></a>
          </div>
        </Card>
        <Card title="Operations" sub={`${shown.length} of ${a.operations.length}`}
          action={
            <div className="filters inline">
              <button type="button" className="filter" aria-selected={!method} onClick={() => setMethod("")}>All</button>
              {methods.map((m) => <button key={m} type="button" className="filter" aria-selected={method === m} onClick={() => setMethod(m)}>{m}</button>)}
              <button type="button" className="filter" aria-selected={openOnly} onClick={() => setOpenOnly((v) => !v)}>Without auth</button>
            </div>
          }>
          {[...groups].map(([head, ops]) => (
            <div key={head} className="op-group">
              <div className="op-group-head mono">{head}<span>{ops.length}</span></div>
              {ops.map((o) => (
                <div key={o.method + o.path} className="op">
                  <span className={"method " + o.method.toLowerCase()}>{o.method}</span>
                  <span className="mono op-path">{o.path}</span>
                  <span className="muted op-summary">{o.summary}</span>
                  {o.secured ? <span className="chip ok">Auth</span> : <span className={"chip " + (writes(o) ? "warn" : "plain")}>No auth</span>}
                </div>
              ))}
            </div>
          ))}
          {!shown.length && <div className="empty">No operations match</div>}
        </Card>
      </div>
    </>
  );
}

// ---- DNS ----

// The record types the page groups by, what each is called, and what it's for.
const KINDS_DNS: [string, string, string][] = [
  ["A", "IPv4 addresses", "Where the name points over IPv4."],
  ["AAAA", "IPv6 addresses", "Where the name points over IPv6."],
  ["CNAME", "Aliases", "Another name this one stands in for."],
  ["MX", "Mail servers", "Where mail for the domain goes, lowest preference first."],
  ["NS", "Name servers", "The servers that answer for the domain."],
  ["TXT", "Text", "Free-form records: SPF, site verifications, policies."],
  ["CAA", "Certificate authorities", "Which authorities may issue certificates for the name."],
  ["PTR", "Reverse name", "The name the scanned address points back to."],
];

const ttl = (s: number) => (s < 120 ? `${s} s` : s < 7200 ? `${Math.round(s / 60)} min` : s < 172800 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} days`);

// Policy is SPF or DMARC at a glance: published, weak, or missing.
function Policy({ name, value, weak, what }: { name: string; value?: string; weak: boolean; what: string }) {
  const state = !value ? "missing" : weak ? "weak" : "ok";
  return (
    <div className={"policy " + state}>
      <div className="policy-head">
        <b>{name}</b>
        <span className={"chip " + (state === "ok" ? "ok" : state === "weak" ? "warn" : "bad")}>{state === "ok" ? "Published" : state === "weak" ? "Weak" : "Missing"}</span>
      </div>
      <p className="muted">{what}</p>
      {value && <code>{value}</code>}
    </div>
  );
}

// Dns is the target's DNS: its mail protection, a tile per record type
// opening its records, and the findings, which name no port.
export function Dns({ id, host, live: l }: { id: string; host: string; live: Live }) {
  const all = l.dns;
  const notes = l.findings.filter((f) => f.location.startsWith("dns "));
  if (all === null) {
    return (
      <>
        <div className="tiles"><Bones n={4} label="Looking up DNS" /></div>
        <Still live={l} what="records" />
      </>
    );
  }
  if (!all.length) {
    return <Empty icon="language" title="No DNS records">An address gets only its reverse name, and only when the dashboard has a resolver to ask.</Empty>;
  }
  const txt = (name: string, prefix: string) => all.find((r) => r.kind === "TXT" && r.name.toLowerCase() === name.toLowerCase() && r.value.startsWith(prefix))?.value;
  const mail = all.some((r) => r.kind === "MX");
  const spf = txt(host, "v=spf1");
  const dmarc = txt("_dmarc." + host, "v=DMARC1");
  return (
    <div className="stack">
      {mail && (
        <div className="policies">
          <Policy name="SPF" value={spf} weak={!!spf && /(^|\s)\+?all(\s|$)/.test(spf)} what="Which servers may send mail as this domain" />
          <Policy name="DMARC" value={dmarc} weak={!!dmarc && /p\s*=\s*none/.test(dmarc)} what="What receivers do with mail that fails SPF and DKIM" />
        </div>
      )}
      <div className="tiles">
        {KINDS_DNS.filter(([k]) => all.some((r) => r.kind === k)).map(([k, label]) => {
          const these = all.filter((r) => r.kind === k);
          return (
            <a key={k} className="tile-card" href={href(id, "dns", k)}>
              <span className="tile-top-row"><span className="method">{k}</span><b>{these.length}</b></span>
              <span className="tile-title">{label}</span>
              <span className="dns-preview mono">
                {these.slice(0, 2).map((r, i) => <span key={i}>{r.value}</span>)}
                {these.length > 2 && <span className="muted">and {these.length - 2} more</span>}
              </span>
            </a>
          );
        })}
      </div>
      {notes.length > 0 && (
        <Card title="Findings" sub={plural(notes.length, "finding")}>
          <ul className="findings">{notes.map((f, k) => <FindingRow key={k} finding={f} />)}</ul>
        </Card>
      )}
    </div>
  );
}

// DnsDetail is one record type: what it's for, then each record.
export function DnsDetail({ id, live: l, kind }: { id: string; live: Live; kind: string }) {
  const [, label, what] = KINDS_DNS.find(([k]) => k === kind) ?? [kind, kind, ""];
  const these = (l.dns ?? []).filter((r) => r.kind === kind);
  return (
    <>
      <Back to={href(id, "dns")} label="DNS">
        <h2>{label}</h2>
        <div className="page-sub"><span className="method">{kind}</span><span>{what}</span></div>
      </Back>
      {l.dns === null ? (
        <div className="tiles"><Bones n={2} label="Looking up DNS" /></div>
      ) : (
        <Card title="Records" sub={plural(these.length, "record")}>
          {these.length ? (
            <ul className="records">
              {these.map((r, i) => (
                <li key={i} className="record">
                  <span className="mono record-value">{r.value}</span>
                  <span className="muted mono">{r.name}</span>
                  <span className="port-chip" title="How long resolvers may keep it">{ttl(r.ttl)}</span>
                </li>
              ))}
            </ul>
          ) : <div className="empty">None</div>}
        </Card>
      )}
    </>
  );
}

// ---- history ----

const serious = (f: Record<Severity, number>) => f.high + f.medium + f.low;

// History is every kept scan of the same target: how it's trending, a bar
// per scan of what it found, the one running drawn as it fills, then each
// scan with how it differs from the one before.
export function History({ scan, live: l, history }: { scan: ScanRow; live: Live; history: ScanRow[] }) {
  const counts = (s: ScanRow): Record<Severity, number> => {
    if (s.id !== scan.id || !l.going) return s.findings;
    const c = { high: 0, medium: 0, low: 0, info: 0 };
    for (const f of l.findings) c[f.severity]++;
    return c;
  };
  const shown = history.filter((s) => s.status === "done" || (s.id === scan.id && l.going));
  const oldest = [...shown].reverse();
  const most = Math.max(1, ...shown.map((s) => serious(counts(s))));
  const done = history.filter((s) => s.status === "done");
  const first = done[done.length - 1];
  const latest = done[0];
  const delta = first && latest ? serious(latest.findings) - serious(first.findings) : 0;
  const day = (ms: number) => new Date(ms).toLocaleDateString(undefined, { month: "short", day: "numeric" });

  if (!history.length) return <Empty icon="history" title="No history">Scans of this target show here as they're run.</Empty>;
  return (
    <div className="stack">
      <div className="tally four">
        <div className="tally-item"><b>{history.length}</b><span>Scans kept</span></div>
        <div className="tally-item"><b>{done.length}</b><span>Finished</span></div>
        <div className="tally-item bad"><b>{latest ? latest.findings.high : 0}</b><span>High, latest</span></div>
        <div className={"tally-item " + (delta > 0 ? "bad" : delta < 0 ? "ok" : "")}>
          <b>{delta > 0 ? "+" + delta : delta}</b><span>Since the first</span>
        </div>
      </div>
      {shown.length > 0 && (
        <Card title="Findings over time" sub="High, medium and low, oldest to newest">
          <div className="trend">
            {oldest.map((s) => {
              const c = counts(s);
              const filling = s.id === scan.id && l.going;
              return (
                <a key={s.id} className={"trend-bar" + (s.id === scan.id ? " on" : "") + (filling ? " filling" : "")} href={href(s.id, "history")}
                  title={`${new Date(s.created).toLocaleString()}: ${c.high} high, ${c.medium} medium, ${c.low} low`}>
                  <span className="trend-num">{serious(c)}</span>
                  <span className="trend-stack" style={{ height: `${Math.max(4, (serious(c) / most) * 100)}%` }}>
                    {LEVELS.slice(0, 3).map((v) => c[v] > 0 && <span key={v} className={SEVERITY[v]} style={{ flexGrow: c[v] }} />)}
                  </span>
                  <span className="trend-label">{filling ? "Now" : day(s.created)}</span>
                </a>
              );
            })}
          </div>
        </Card>
      )}
      <Card title="Scans" sub={`${history.length} kept of ${scan.target}`}>
        <ul className="timeline">
          {history.map((s, i) => {
            const c = counts(s);
            const prior = history.slice(i + 1).find((x) => x.status === "done");
            const change = s.status === "done" && prior ? serious(c) - serious(prior.findings) : null;
            const running = s.status === "queued" || s.status === "running";
            return (
              <li key={s.id}>
                <a className={"moment" + (s.id === scan.id ? " on" : "")} href={href(s.id)}>
                  <span className={"moment-dot " + (s.status === "failed" ? "bad" : running ? "plain" : c.high ? "bad" : c.medium ? "warn" : "ok")} />
                  <span className="moment-when">
                    <b>{new Date(s.created).toLocaleString()}</b>
                    <small className="mono">{s.command}</small>
                  </span>
                  <span className="moment-what">
                    {running ? <span className="chip plain"><span className="spinner tiny" />Scanning</span>
                      : s.status === "failed" ? <span className="chip bad">Failed</span>
                      : <>
                          <span className="muted">{plural(s.open_ports, "port")} · {plural(s.endpoints, "endpoint")}</span>
                          {LEVELS.slice(0, 3).map((v) => c[v] > 0 && <span key={v} className={"chip " + SEVERITY[v]}>{c[v]} {v}</span>)}
                        </>}
                  </span>
                  {change !== null && change !== 0 && <span className={"delta " + (change > 0 ? "up" : "down")}>{change > 0 ? "+" + change : change}</span>}
                  <Icon name="chevron_right" className="result-go" />
                </a>
              </li>
            );
          })}
        </ul>
      </Card>
    </div>
  );
}

// ---- changes ----

// Changes is what differs from the last finished scan of the same target:
// the two side by side, then ports that opened or closed and findings that
// are new or resolved. While the scan runs, ports count once the sweep has
// passed them; resolved findings wait for it to finish.
export function Changes({ scan, live: l, previous }: { scan: ScanRow; live: Live; previous?: Previous }) {
  if (!previous) return <Empty icon="difference" title="Nothing to compare with">There is no earlier finished scan of {scan.target}. Scan it again later to see what changes.</Empty>;
  const before = previous.report;
  if (!before) return <div className="tiles"><Bones n={2} label="Loading the scan before" /></div>;

  const key = (f: Finding) => f.severity + "|" + f.title + "|" + f.location;
  const nowPorts = new Set(l.items.map((i) => i.port));
  const wasPorts = new Set(before.open_ports.map((o) => o.port));
  const opened = l.items.filter((i) => !wasPorts.has(i.port));
  const closed = before.open_ports.filter((o) => o.port <= l.reached && !nowPorts.has(o.port));
  const was = new Set(before.findings.map(key));
  const added = l.findings.filter((f) => !was.has(key(f)));
  const now = new Set(l.findings.map(key));
  const gone = l.going ? [] : before.findings.filter((f) => !now.has(key(f)));
  const range = isRange(scan);

  const count = (f: Finding[], s: Severity) => f.filter((x) => x.severity === s).length;
  const side = (title: string, sub: ReactNode, ports: number, findings: Finding[], link?: string) => (
    <div className="side">
      <div className="side-head"><b>{title}</b>{link ? <a href={link}>{sub}</a> : <span className="muted">{sub}</span>}</div>
      <div className="side-nums">
        <span><b>{ports}</b>open ports</span>
        <span className="bad"><b>{count(findings, "high")}</b>high</span>
        <span className="warn"><b>{count(findings, "medium")}</b>medium</span>
        <span><b>{count(findings, "low")}</b>low</span>
      </div>
    </div>
  );
  const portRows = (id: string, list: { port: number; service: string }[]) => (
    <ul className="results">
      {list.map((o) => (
        <li key={o.port}>
          <a className="result seen-row" href={href(id, o.port)}>
            <span className="port-num">{o.port}<small>/tcp</small></span>
            <span className="result-service">{o.service}</span>
            <span />
            <Icon name="chevron_right" className="result-go" />
          </a>
        </li>
      ))}
    </ul>
  );
  const wereUp = new Set((before.hosts ?? []).map((h) => h.ip));
  const hostsMoved = range && (l.hosts.some((h) => !wereUp.has(h.ip)) || (before.hosts ?? []).length !== l.hosts.length);
  const nothing = opened.length + closed.length + added.length + gone.length === 0 && !hostsMoved;
  return (
    <div className="stack">
      <div className="compare">
        {side("Before", new Date(previous.scan.created).toLocaleString(), before.open_ports.length, before.findings, href(previous.scan.id))}
        <Icon name="chevron_right" size={28} className="compare-arrow" />
        {side("This scan", l.going ? "Still running" : new Date(scan.created).toLocaleString(), l.items.length, l.findings)}
      </div>
      <div className="tally four">
        <div className="tally-item bad"><b>{opened.length}</b><span>Ports opened</span></div>
        <div className="tally-item ok"><b>{closed.length}</b><span>Ports closed</span></div>
        <div className="tally-item warn"><b>{added.length}</b><span>New findings</span></div>
        <div className="tally-item ok"><b>{l.going ? "…" : gone.length}</b><span>Resolved findings</span></div>
      </div>
      {range && !l.going && <HostChanges before={before.hosts ?? []} now={l.hosts} />}
      {opened.length > 0 && <Card title="Ports opened" sub={plural(opened.length, "port")}>{portRows(scan.id, opened)}</Card>}
      {closed.length > 0 && <Card title="Ports closed" sub={plural(closed.length, "port")}>{portRows(previous.scan.id, closed)}</Card>}
      {added.length > 0 && (
        <Card title="New findings" sub={plural(added.length, "finding")}>
          <ul className="findings">{added.map((f, k) => <FindingRow key={k} finding={f} at />)}</ul>
        </Card>
      )}
      {gone.length > 0 && (
        <Card title="Resolved findings" sub={plural(gone.length, "finding")}>
          <ul className="findings">{gone.map((f, k) => <FindingRow key={k} finding={f} at />)}</ul>
        </Card>
      )}
      {l.going && <Still live={l} what="changes" />}
      {!l.going && nothing && <div className="card empty">Nothing changed</div>}
    </div>
  );
}

function HostChanges({ before, now }: { before: Host[]; now: Host[] }) {
  const was = new Set(before.map((h) => h.ip));
  const is = new Set(now.map((h) => h.ip));
  const up = now.filter((h) => !was.has(h.ip));
  const down = before.filter((h) => !is.has(h.ip));
  return (
    <>
      {up.length > 0 && <Card title="New hosts" sub={plural(up.length, "host")}><HostList hosts={up} /></Card>}
      {down.length > 0 && <Card title="Hosts gone" sub={plural(down.length, "host")}><HostList hosts={down} /></Card>}
    </>
  );
}
