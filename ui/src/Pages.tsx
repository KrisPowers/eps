import { useEffect, useState, type CSSProperties, type ReactNode } from "react";
import { api } from "./api";
import { Icon } from "./Icon";
import { logo } from "./logos";
import { Fold, usePaged } from "./paged";
import { href } from "./route";
import { Card, fromProgress, fromReport, plural, SEVERITY, type Item, type Previous } from "./ScanView";
import type { Api, DnsRecord, Finding, Host, Operation, Progress, Report, ScanRow, Severity, Signal, Site, Subdomain, Tech } from "./types";

// The pages of a scan beyond Findings: Software and API, each with a page per
// thing on it, DNS, and History. Each draws what has been found so far while
// the scan runs, with skeletons where more is coming, a page of a list at a
// time, and detail folded away until it's asked for.

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
  // Each website, mapped and read.
  sites: Site[];
  // Other names under the target's domain; null until they're in.
  subdomains: Subdomain[] | null;
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
      sites: report.sites ?? [],
      subdomains: report.subdomains ?? [],
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
    sites: items.flatMap((i) => (i.found?.site ? [i.found.site] : [])),
    subdomains: p?.subdomains ?? null,
  };
}

const SERIOUS: Severity[] = ["high", "medium", "low"];

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

// BoneRows are skeleton rows in a list still filling.
export function BoneRows({ n }: { n: number }) {
  return <div className="skeleton" aria-busy="true">{Array.from({ length: n }, (_, i) => <span key={i} className="bone" />)}</div>;
}

function Empty({ icon, title, children }: { icon: "dns" | "lock" | "language" | "history"; title: string; children: ReactNode }) {
  return (
    <div className="card welcome">
      <Icon name={icon} size={36} />
      <h2>{title}</h2>
      <p className="muted">{children}</p>
    </div>
  );
}

// Still is the line under a page while more is coming.
function Still({ live: l }: { live: Live }) {
  if (!l.going) return null;
  return (
    <p className="still">
      <span className="spinner small" />
      {l.reached < ALL_PORTS ? `Still scanning, past port ${l.reached}` : "Finishing the last checks"}
    </p>
  );
}

// Tabs filter a list by one of its kinds, with how many of each.
export function Tabs({ all, value, onChange, counts }: { all: string[]; value: string; onChange: (v: string) => void; counts: (v: string) => number }) {
  if (all.length < 2) return null;
  return (
    <div className="filters" role="tablist">
      <button type="button" role="tab" aria-selected={!value} className="filter" onClick={() => onChange("")}>All<span>{counts("")}</span></button>
      {all.map((k) => (
        <button key={k} type="button" role="tab" aria-selected={value === k} className="filter" onClick={() => onChange(k)}>{k}<span>{counts(k)}</span></button>
      ))}
    </div>
  );
}

// FindingFold is a finding as one line, its advice folded until opened.
export function FindingFold({ finding: f }: { finding: Finding }) {
  return (
    <Fold head={<><span className={"chip " + SEVERITY[f.severity]}>{f.severity}</span><span className="fold-title">{f.title}</span></>}>
      <p>{f.detail}</p>
      <code className="command-line">{f.location}</code>
    </Fold>
  );
}

// ---- software ----

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

// A piece of software as the page draws it: one name, wherever it was seen.
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

// Badge is a piece of software's mark: its logo in its brand's colour when
// it has a well-known one, else its initial in its kind's colour.
export function Badge({ name, kind, big }: { name: string; kind: string; big?: boolean }) {
  const mark = logo(name);
  if (mark) {
    return (
      <span className={"badge logo" + (big ? " big" : "")} style={{ "--brand": mark.color } as CSSProperties} aria-hidden="true">
        <svg viewBox="0 0 24 24"><path d={mark.path} /></svg>
      </span>
    );
  }
  return <span className={"badge k-" + (KINDS[kind] ?? "other") + (big ? " big" : "")} aria-hidden="true">{name.slice(0, 1).toUpperCase()}</span>;
}

// Software is what runs on the open ports, a tile each, filtered by kind; a
// tile opens where it was seen.
export function Software({ id, live: l }: { id: string; live: Live }) {
  const [kind, setKind] = useState("");
  const all = gather(l.technologies);
  const kinds = [...new Set(all.map((s) => s.kind))];
  const { shown, pager } = usePaged(kind ? all.filter((s) => s.kind === kind) : all, 12);
  if (!all.length && !l.going) {
    return <Empty icon="dns" title="Nothing recognized">Servers that don't name themselves in headers, cookies or greetings show nothing here.</Empty>;
  }
  return (
    <>
      <Tabs all={kinds} value={kind} onChange={setKind} counts={(k) => (k ? all.filter((s) => s.kind === k).length : all.length)} />
      <div className="tiles">
        {shown.map((s) => (
          <a key={s.name} className="tile-card" href={href(id, "software", s.name)}>
            <Badge name={s.name} kind={s.kind} />
            <span className="tile-title">{s.name}</span>
            <span className="tile-sub mono">{s.versions.join(", ") || "Version not shown"}</span>
            <span className="tile-foot">
              <span className={"kind k-" + (KINDS[s.kind] ?? "other")}>{s.kind}</span>
              <span>{s.at.length === 1 ? `Port ${s.at[0].port}` : plural(s.at.length, "port")}</span>
            </span>
          </a>
        ))}
        {l.going && <Bones n={shown.length ? 1 : 4} label="Finding software" />}
      </div>
      {pager}
      <Still live={l} />
    </>
  );
}

// SoftwareDetail is one piece of software: what sort of thing it is, every
// port it was seen on with the version and what gave it away, and the
// findings there, each folded until opened.
export function SoftwareDetail({ id, live: l, name }: { id: string; live: Live; name: string }) {
  const s = gather(l.technologies).find((t) => t.name === name);
  const ports = new Set(s?.at.map((t) => t.port));
  const findings = l.items.filter((i) => ports.has(i.port)).flatMap((i) => i.found?.findings ?? []);
  const seen = usePaged(s?.at ?? [], 8);
  const found = usePaged(findings, 8);
  if (!s) {
    return (
      <>
        <Back to={href(id, "software")} label="Software"><h2>{name}</h2></Back>
        {l.going ? <div className="tiles"><Bones n={2} label="Looking" /></div> : <div className="card empty">Not seen in this scan</div>}
      </>
    );
  }
  return (
    <>
      <Back to={href(id, "software")} label="Software">
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
            {seen.shown.map((t) => (
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
          {seen.pager}
        </Card>
        <Card title="Findings on these ports" sub={plural(findings.length, "finding")}>
          {findings.length ? found.shown.map((f, k) => <FindingFold key={k} finding={f} />) : <div className="empty">Nothing found on these ports</div>}
          {found.pager}
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
// each; a tile opens its operations.
export function Apis({ id, live: l }: { id: string; live: Live }) {
  const { shown, pager } = usePaged(l.apis.map((a, i) => [a, i] as const), 9);
  if (!l.apis.length && !l.going) {
    return <Empty icon="lock" title="No API documents">No OpenAPI or Swagger document was served without auth at a conventional path, such as /openapi.json or /v3/api-docs.</Empty>;
  }
  return (
    <>
      <div className="tiles wide">
        {shown.map(([a, i]) => {
          const open = a.operations.filter((o) => writes(o) && !o.secured).length;
          return (
            <a key={a.url} className="tile-card" href={href(id, "api", String(i))}>
              <span className="api-top">
                <span className="spec">{a.spec}</span>
                <span className="port-chip">port {a.port}</span>
              </span>
              <span className="tile-title">{a.title || "Untitled API"} <small>{a.version}</small></span>
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
      {pager}
      <Still live={l} />
    </>
  );
}

// ApiDetail is one API document's operations, a page at a time, filtered by
// method or to the writes without auth; a summary shows on hover.
export function ApiDetail({ id, live: l, index }: { id: string; live: Live; index: string }) {
  const [method, setMethod] = useState("");
  const a = l.apis[Number(index)];
  const ops = a?.operations ?? [];
  const OPEN = "Without auth";
  const list = ops.filter((o) => (method === OPEN ? writes(o) && !o.secured : !method || o.method === method));
  const { shown, pager } = usePaged(list, 15);
  if (!a) {
    return (
      <>
        <Back to={href(id, "api")} label="API"><h2>API document</h2></Back>
        {l.going ? <div className="tiles"><Bones n={1} label="Looking" /></div> : <div className="card empty">Not found in this scan</div>}
      </>
    );
  }
  const open = ops.filter((o) => writes(o) && !o.secured).length;
  const kinds = [...METHODS.filter((m) => ops.some((o) => o.method === m)), ...(open ? [OPEN] : [])];
  return (
    <>
      <Back to={href(id, "api")} label="API">
        <h2>{a.title || "Untitled API"} <small className="muted">{a.version}</small></h2>
        <div className="page-sub">
          <span className="spec">{a.spec}</span>
          <a href={href(id, a.port)}>Port {a.port}</a>
          {a.schemes.length ? a.schemes.map((s) => <span key={s} className="port-chip">{s}</span>) : <span className="chip warn">No security defined</span>}
        </div>
      </Back>
      <Tabs all={kinds} value={method} onChange={setMethod}
        counts={(k) => (!k ? ops.length : k === OPEN ? open : ops.filter((o) => o.method === k).length)} />
      <div className="card">
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Method</th><th className="grow">Path</th><th>Auth</th></tr></thead>
            <tbody>
              {shown.map((o) => (
                <tr key={o.method + o.path} title={o.summary || undefined}>
                  <td><span className={"method " + o.method.toLowerCase()}>{o.method}</span></td>
                  <td className="mono wrap">{o.path}</td>
                  <td>{o.secured ? <span className="chip ok">Required</span> : <span className={"chip " + (writes(o) ? "warn" : "plain")}>None</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!list.length && <div className="empty">No operations match</div>}
        {pager}
      </div>
    </>
  );
}

// ---- DNS ----

const ttl = (s: number) => (s < 120 ? `${s} s` : s < 7200 ? `${Math.round(s / 60)} min` : s < 172800 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} d`);

// The order record types are listed in.
const ORDER = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "PTR"];

// Dns is the target's records as a table, filtered by type, a page at a
// time. A domain that takes mail gets its SPF and DMARC state on one line,
// and the findings, which name no port, fold under the table.
export function Dns({ host, live: l }: { host: string; live: Live }) {
  const [kind, setKind] = useState("");
  const all = [...(l.dns ?? [])].sort((a, b) => ORDER.indexOf(a.kind) - ORDER.indexOf(b.kind));
  const { shown, pager } = usePaged(kind ? all.filter((r) => r.kind === kind) : all, 15);
  const notes = l.findings.filter((f) => f.location.startsWith("dns "));
  if (l.dns === null) return <div className="card"><BoneRows n={6} /></div>;
  if (!all.length) {
    return <Empty icon="language" title="No DNS records">An address gets only its reverse name, and only when the dashboard has a resolver to ask.</Empty>;
  }
  const txt = (name: string, prefix: string) => all.find((r) => r.kind === "TXT" && r.name.toLowerCase() === name.toLowerCase() && r.value.startsWith(prefix))?.value;
  const spf = txt(host, "v=spf1");
  const dmarc = txt("_dmarc." + host, "v=DMARC1");
  const state = (v: string | undefined, weak: boolean) => (!v ? <span className="chip bad">Missing</span> : weak ? <span className="chip warn">Weak</span> : <span className="chip ok">Published</span>);
  const kinds = ORDER.filter((k) => all.some((r) => r.kind === k));
  return (
    <>
      {all.some((r) => r.kind === "MX") && (
        <p className="summary-line">
          <span>SPF {state(spf, !!spf && /(^|\s)\+?all(\s|$)/.test(spf))}</span>
          <span>DMARC {state(dmarc, !!dmarc && /p\s*=\s*none/.test(dmarc))}</span>
        </p>
      )}
      <Tabs all={kinds} value={kind} onChange={setKind} counts={(k) => (k ? all.filter((r) => r.kind === k).length : all.length)} />
      <div className="card">
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Type</th><th>Name</th><th className="grow">Value</th><th>TTL</th></tr></thead>
            <tbody>
              {shown.map((r, i) => (
                <tr key={i}>
                  <td className="mono"><b>{r.kind}</b></td>
                  <td className="mono">{r.name}</td>
                  <td className="mono wrap">{r.value}</td>
                  <td className="muted">{ttl(r.ttl)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {pager}
      </div>
      {notes.length > 0 && (
        <div className="card folds gap-top">
          {notes.map((f, k) => <FindingFold key={k} finding={f} />)}
        </div>
      )}
    </>
  );
}

// ---- subdomains ----

const HOW: Record<string, string> = { certificate: "Certificate log", guess: "Common name", link: "Site link" };

// Copy is a value shown as plain text, underlined with dots and followed by
// a small copy mark, that copies itself to the clipboard when clicked.
function Copy({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1200);
    return () => clearTimeout(t);
  }, [done]);
  return (
    <button type="button" className={"copy" + (done ? " done" : "")} title={done ? "Copied" : "Copy"}
      onClick={() => navigator.clipboard?.writeText(text).then(() => setDone(true), () => {})}>
      <span className="copy-text">{text}</span>
      <Icon name="content_copy" size={14} className="copy-icon" />
    </button>
  );
}

// Subdomains is the other names under the target's domain: from the public
// certificate logs, where every certificate issued is recorded, and common
// names that resolve. Live ones first, a page at a time; each name and
// address copies when clicked.
export function Subdomains({ live: l }: { live: Live }) {
  const [show, setShow] = useState("");
  const all = [...(l.subdomains ?? [])].sort((a, b) => Number(!a.addresses.length) - Number(!b.addresses.length) || a.name.localeCompare(b.name));
  const LIVE = "Resolving";
  const GONE = "Not resolving";
  const list = all.filter((s) => !show || (show === LIVE ? s.addresses.length > 0 : s.addresses.length === 0));
  const { shown, pager } = usePaged(list, 15);
  if (l.subdomains === null) return l.going ? <div className="card"><BoneRows n={6} /></div> : <div className="card empty">Only a domain name has subdomains</div>;
  if (!all.length) {
    return <Empty icon="language" title="No other names found">Neither the certificate logs nor common names turned up anything under this domain.</Empty>;
  }
  const up = all.filter((s) => s.addresses.length).length;
  return (
    <>
      <Tabs all={[LIVE, GONE]} value={show} onChange={setShow}
        counts={(v) => (!v ? all.length : v === LIVE ? up : all.length - up)} />
      <div className="card">
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th className="grow">Name</th><th>Addresses</th><th>Found in</th></tr></thead>
            <tbody>
              {shown.map((s) => (
                <tr key={s.name}>
                  <td className="mono"><Copy text={s.name} /></td>
                  <td className="mono muted">
                    {s.addresses.length
                      ? s.addresses.map((a, i) => <span key={a}>{i > 0 && ", "}<Copy text={a} /></span>)
                      : "Not resolving"}
                  </td>
                  <td className="muted">{s.found.map((f) => HOW[f] ?? f).join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {pager}
      </div>
    </>
  );
}

// ---- sitemap ----

const FOUND: Record<string, string> = { start: "Start", url: "Your URL", link: "Link", sitemap: "Sitemap", robots: "robots.txt", script: "Script", linked: "Linked from the site" };

// apexOf is the domain a host belongs to: `docs.shop.co.uk` is `shop.co.uk`.
function apexOf(host: string) {
  const l = host.toLowerCase().split(".");
  const three = l.length >= 3 && l[l.length - 1].length === 2 && ["co", "com", "org", "net", "gov", "ac", "edu"].includes(l[l.length - 2]);
  return l.slice(three ? -3 : -2).join(".");
}

// linkedSites is the pages the scanned sites link to on other names under
// `host`'s domain, as sites of their own: listed, not fetched.
function linkedSites(sites: Site[], host: string): Site[] {
  const apex = apexOf(host);
  const by = new Map<string, Site>();
  for (const url of sites.flatMap((s) => s.links ?? [])) {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      continue;
    }
    const name = u.hostname.toLowerCase();
    if (name !== apex && !name.endsWith("." + apex)) continue;
    const site = by.get(u.origin) ?? { port: 0, base: u.origin, pages: [], scripts: [], signals: [] };
    if (!site.pages.some((p) => p.path === u.pathname)) site.pages.push({ path: u.pathname, status: 0, found: "linked" });
    by.set(u.origin, site);
  }
  return [...by.values()];
}

// Sitemap is every path mapped on the site: from its start and your URL,
// its robots.txt and sitemaps, and its own links, a page at a time,
// filtered by how each was found, and by site when there are several.
export function Sitemap({ live: l, host }: { live: Live; host: string }) {
  const [base, setBase] = useState("");
  const [found, setFound] = useState("");
  const every = [...l.sites, ...linkedSites(l.sites, host)];
  const sites = every.filter((s) => !base || s.base === base);
  const all = sites.flatMap((s) => s.pages.map((p) => ({ ...p, base: s.base })));
  const ways = Object.keys(FOUND).filter((k) => all.some((p) => p.found === k));
  const { shown, pager } = usePaged(found ? all.filter((p) => p.found === found) : all, 15);
  if (!l.sites.length) {
    return l.going ? <div className="card"><BoneRows n={6} /></div>
      : <Empty icon="language" title="No website">No web service answered, so there was no site to map.</Empty>;
  }
  return (
    <>
      {every.length > 1 && (
        <Tabs all={every.map((s) => s.base)} value={base} onChange={setBase}
          counts={(b) => (b ? every.find((s) => s.base === b)?.pages.length ?? 0 : every.reduce((n, s) => n + s.pages.length, 0))} />
      )}
      <Tabs all={ways.map((k) => FOUND[k])} value={found ? FOUND[found] : ""}
        onChange={(v) => setFound(ways.find((k) => FOUND[k] === v) ?? "")}
        counts={(v) => (v ? all.filter((p) => FOUND[p.found] === v).length : all.length)} />
      <div className="card">
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Path</th><th>Status</th><th className="grow">Title</th><th>Found by</th></tr></thead>
            <tbody>
              {shown.map((p) => (
                <tr key={p.base + p.path} title={p.base + p.path}>
                  <td className="mono wrap">{p.path}</td>
                  <td className={"mono status-" + Math.floor(p.status / 100)}>{p.status || ""}</td>
                  <td className="muted wrap">{p.title ?? ""}</td>
                  <td className="muted">{FOUND[p.found] ?? p.found}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {pager}
      </div>
      <Still live={l} />
    </>
  );
}

// ---- client-side ----

const SEVERITIES: Severity[] = ["high", "medium", "low"];
const worst = (list: Signal[]) => SEVERITIES.find((s) => list.some((x) => x.severity === s));

// Client is what the site's pages would do in a visitor's browser, read
// inside the scanner so you never open them: one line of the verdict, then
// a tile per kind of concern, and one for the scripts read; each opens.
export function Client({ id, live: l }: { id: string; live: Live }) {
  const signals = l.sites.flatMap((s) => s.signals);
  const scripts = l.sites.flatMap((s) => s.scripts);
  const pages = l.sites.reduce((n, s) => n + s.pages.length, 0);
  const kinds = [...new Set(signals.map((s) => s.category))].sort((a, b) =>
    SEVERITIES.indexOf(worst(signals.filter((s) => s.category === a))!) - SEVERITIES.indexOf(worst(signals.filter((s) => s.category === b))!));
  if (!l.sites.length) {
    return l.going ? <div className="tiles"><Bones n={4} label="Reading the site" /></div>
      : <Empty icon="language" title="No website">No web service answered, so there were no pages to read.</Empty>;
  }
  const w = worst(signals);
  return (
    <>
      <p className="summary-line">
        {w ? <span className={"chip " + SEVERITY[w]}>{plural(signals.length, "concern")}</span> : <span className="chip ok">Nothing reaches into your browser</span>}
        <span><b>{pages}</b> {pages === 1 ? "page" : "pages"} read</span>
        <span><b>{scripts.length}</b> {scripts.length === 1 ? "script" : "scripts"}, {scripts.filter((s) => s.third_party).length} from other sites</span>
      </p>
      <div className="tiles">
        {kinds.map((k) => {
          const these = signals.filter((s) => s.category === k);
          const sev = worst(these)!;
          return (
            <a key={k} className="tile-card" href={href(id, "client", k)}>
              <span className={"badge sev " + SEVERITY[sev]} aria-hidden="true">{k.slice(0, 1)}</span>
              <span className="tile-title">{k}</span>
              <span className="tile-sub">{these[0].label}{these.length > 1 && `, and ${these.length - 1} more`}</span>
              <span className="tile-foot">
                <span className={"chip " + SEVERITY[sev]}>{sev}</span>
                <span>{plural(new Set(these.map((s) => s.page)).size, "page")}</span>
              </span>
            </a>
          );
        })}
        {scripts.length > 0 && (
          <a className="tile-card" href={href(id, "client", "Scripts")}>
            <span className="badge sev plain" aria-hidden="true">S</span>
            <span className="tile-title">Scripts</span>
            <span className="tile-sub">Every script the pages load</span>
            <span className="tile-foot">
              <span>{plural(scripts.length, "script")}</span>
              <span>{scripts.filter((s) => s.third_party).length} from other sites</span>
            </span>
          </a>
        )}
        {l.going && <Bones n={1} label="Reading more pages" />}
      </div>
      <Still live={l} />
    </>
  );
}

// ClientDetail is one kind of concern, each a line naming the page until
// opened for what it means, the code that showed it and the script it's
// in; or the scripts the pages load.
export function ClientDetail({ id, live: l, category }: { id: string; live: Live; category: string }) {
  const signals = l.sites.flatMap((s) => s.signals).filter((s) => s.category === category);
  const scripts = l.sites.flatMap((s) => s.scripts);
  const list = usePaged(signals, 10);
  const js = usePaged(scripts, 15);
  const kb = (n: number) => (n ? (n < 1024 ? `${n} B` : `${Math.round(n / 1024)} KB`) : "Not read");
  return (
    <>
      <Back to={href(id, "client")} label="Client-side">
        <h2>{category}</h2>
        <div className="page-sub">{category === "Scripts" ? plural(scripts.length, "script") : plural(signals.length, "concern")}</div>
      </Back>
      {category === "Scripts" ? (
        <div className="card">
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th className="grow">Script</th><th>From</th><th>Size</th></tr></thead>
              <tbody>
                {js.shown.map((s) => (
                  <tr key={s.url}>
                    <td className="mono wrap">{s.url}</td>
                    <td className="muted">{s.third_party ? "Another site" : "This site"}</td>
                    <td className="muted">{kb(s.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {js.pager}
        </div>
      ) : signals.length ? (
        <div className="card folds">
          {list.shown.map((s, k) => (
            <Fold key={k} head={<><span className={"chip " + SEVERITY[s.severity]}>{s.severity}</span><span className="fold-title">{s.label}</span><span className="muted mono fold-note-inline">{s.page}</span></>}>
              <p>{s.why}</p>
              <code className="command-line evidence">{s.evidence}</code>
              <span className="muted">{s.script ? <>In <span className="mono">{s.script}</span></> : "In the page itself"}</span>
            </Fold>
          ))}
          {list.pager}
        </div>
      ) : (
        <div className="card empty">Nothing of this kind</div>
      )}
    </>
  );
}

// ---- history ----

const serious = (f: Record<Severity, number>) => f.high + f.medium + f.low;

// What changed between a scan and the one before it.
interface Diff {
  opened: number[];
  closed: number[];
  added: Finding[];
  gone: Finding[];
  // Resolved findings wait for the scan to finish.
  partial: boolean;
}

function diff(ports: number[], findings: Finding[], before: Report, reached: number, partial: boolean): Diff {
  const key = (f: Finding) => f.severity + "|" + f.title + "|" + f.location;
  const now = new Set(ports);
  const was = new Set(before.open_ports.map((o) => o.port));
  const had = new Set(before.findings.map(key));
  const has = new Set(findings.map(key));
  return {
    opened: ports.filter((p) => !was.has(p)),
    closed: before.open_ports.filter((o) => o.port <= reached && !now.has(o.port)).map((o) => o.port),
    added: findings.filter((f) => !had.has(key(f))),
    gone: partial ? [] : before.findings.filter((f) => !has.has(key(f))),
    partial,
  };
}

// History is every kept scan of the same target, newest first, a page at a
// time: when, and what it found. Opening a scan shows what changed from the
// one before it; the scan open here counts what it has found so far while
// it runs.
export function History({ scan, live: l, history, previous }: { scan: ScanRow; live: Live; history: ScanRow[]; previous?: Previous }) {
  const { shown, pager } = usePaged(history, 10);
  if (!history.length) return <Empty icon="history" title="No history">Scans of this target show here as they're run.</Empty>;
  return (
    <>
      <div className="card folds">
        {shown.map((s) => {
          const i = history.indexOf(s);
          const before = history.slice(i + 1).find((x) => x.status === "done");
          const mine = s.id === scan.id;
          return <Moment key={s.id} scan={s} on={mine} before={before} live={mine ? l : undefined} prior={mine ? previous?.report : undefined} />;
        })}
      </div>
      {pager}
    </>
  );
}

// Moment is one scan in the history, what changed in it folded until opened.
function Moment({ scan: s, on, before, live: l, prior }: { scan: ScanRow; on: boolean; before?: ScanRow; live?: Live; prior?: Report }) {
  const running = s.status === "queued" || s.status === "running";
  let c = s.findings;
  if (l?.going) {
    c = { high: 0, medium: 0, low: 0, info: 0 };
    for (const f of l.findings) c[f.severity]++;
  }
  const change = s.status === "done" && before ? serious(c) - serious(before.findings) : null;
  const head = (
    <>
      <span className={"moment-dot " + (s.status === "failed" ? "bad" : running ? "plain" : c.high ? "bad" : c.medium ? "warn" : "ok")} />
      <span className="moment-when">{new Date(s.created).toLocaleString()}{on && <span className="chip plain">This scan</span>}</span>
      <span className="moment-what">
        {running ? <span className="muted"><span className="spinner tiny" /> Scanning</span>
          : s.status === "failed" ? <span className="chip bad">Failed</span>
          : SERIOUS.some((v) => c[v] > 0) ? SERIOUS.map((v) => c[v] > 0 && <span key={v} className={"chip " + SEVERITY[v]}>{c[v]} {v}</span>)
          : <span className="muted">Nothing serious</span>}
      </span>
      {change ? <span className={"delta " + (change > 0 ? "up" : "down")}>{change > 0 ? "+" + change : change}</span> : <span />}
    </>
  );
  return (
    <Fold head={head}>
      <Changes scan={s} before={before} live={l} prior={prior} />
    </Fold>
  );
}

// Changes is what changed in a scan from the one before it, loaded when
// opened: ports that opened or closed, findings new or resolved.
function Changes({ scan: s, before, live: l, prior }: { scan: ScanRow; before?: ScanRow; live?: Live; prior?: Report }) {
  const [reports, setReports] = useState<Record<string, Report>>({});
  const want = [!l && s.status === "done" ? s.id : "", before && !prior ? before.id : ""].filter(Boolean).join(",");
  useEffect(() => {
    for (const id of want.split(",").filter(Boolean)) {
      if (reports[id]) continue;
      api.scan(id).then((d) => d.report && setReports((r) => ({ ...r, [id]: d.report! }))).catch(() => {});
    }
  }, [want, reports]);

  if (s.status === "failed") return <p className="muted fold-note">The scan failed.</p>;
  if (!before) return <p className="muted fold-note">The first finished scan of this target, so nothing to compare with.</p>;
  const was = prior ?? reports[before.id];
  const mine = l ?? (reports[s.id] && live(s, reports[s.id], undefined));
  if (!was || !mine) return <BoneRows n={3} />;
  const d = diff(mine.items.map((i) => i.port), mine.findings, was, mine.reached, mine.going);
  const none = !d.opened.length && !d.closed.length && !d.added.length && !d.gone.length;
  return (
    <div className="changes">
      <p className="muted fold-note">Against <a href={href(before.id)}>the scan from {new Date(before.created).toLocaleString()}</a>{d.partial && ", so far"}</p>
      {none && <p className="fold-note">{d.partial ? "Nothing yet." : "Nothing changed."}</p>}
      {d.opened.length > 0 && <Line label="Ports opened" tone="bad">{d.opened.map((p) => <a key={p} className="port-chip" href={href(s.id, p)}>{p}</a>)}</Line>}
      {d.closed.length > 0 && <Line label="Ports closed" tone="ok">{d.closed.map((p) => <span key={p} className="port-chip">{p}</span>)}</Line>}
      {d.added.length > 0 && <Line label="New findings" tone="warn"><FindingList list={d.added} /></Line>}
      {d.gone.length > 0 && <Line label="Resolved" tone="ok"><FindingList list={d.gone} /></Line>}
    </div>
  );
}

function Line({ label, tone, children }: { label: string; tone: string; children: ReactNode }) {
  return (
    <div className="change-line">
      <span className={"change-label " + tone}>{label}</span>
      <div className="change-items">{children}</div>
    </div>
  );
}

// FindingList is findings as short lines, a page at a time.
function FindingList({ list }: { list: Finding[] }) {
  const { shown, pager } = usePaged(list, 5);
  return (
    <div className="mini-list">
      {shown.map((f, k) => <span key={k}><span className={"chip " + SEVERITY[f.severity]}>{f.severity}</span>{f.title}</span>)}
      {pager}
    </div>
  );
}
