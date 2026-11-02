import { Fragment, useEffect, type ReactNode } from "react";
import { Icon } from "./Icon";
import { usePaged } from "./paged";
import { Bones, Empty, Still, type Live } from "./Pages";
import { href } from "./route";
import { plural, SEVERITY } from "./ScanView";
import type { Issue, Mark, Section, Severity, Signal, SourceFile } from "./types";

// Code is the site's code read the way an editor shows it: what its pages
// would do in a visitor's browser and what the site gives away, together.
// A file explorer on the left lists each file something was found in; the
// file opens on the right, re-printed with what caused each concern
// highlighted and a note under it saying what it is and what could happen.
// Forms are one concern each, naming where they submit, with every problem
// they have.

const RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };
const worst = (list: { severity: Severity }[]) =>
  list.reduce<Severity | null>((w, s) => (w === null || RANK[s.severity] < RANK[w] ? s.severity : w), null);
const serious = (s: Signal) => s.severity !== "info";

// A file with the site it's on, and a signal with its place in the page's list.
type File = SourceFile & { base: string };
type Found = Signal & { key: string };

const KIND: Record<string, string> = { html: "HTML", js: "JavaScript", css: "CSS", php: "PHP", json: "JSON", xml: "XML", http: "HTTP answer", text: "Text" };

export function Code({ id, live: l, item }: { id: string; live: Live; item: string | null }) {
  const files: File[] = l.sites.flatMap((s) => (s.files ?? []).map((f) => ({ ...f, base: s.base })));
  const signals: Found[] = l.sites.flatMap((s, si) => s.signals.map((x, i) => ({ ...x, key: `c${si}-${i}` })));
  const requests = l.sites.flatMap((s) => s.requests ?? []);
  const scripts = l.sites.flatMap((s) => s.scripts);
  if (!l.sites.length) {
    return l.going ? <div className="tiles"><Bones n={4} label="Reading the site" /></div>
      : <Empty icon="language" title="No website">No web service answered, so there was no code to read.</Empty>;
  }
  const inFile = (f: File) => signals.filter((s) => s.file === f.url);
  const loose = signals.filter((s) => !s.file || !files.some((f) => f.url === s.file));
  // The file picked, else the one with the worst concern.
  const ranked = [...files].sort((a, b) => RANK[worst(inFile(a)) ?? "info"] - RANK[worst(inFile(b)) ?? "info"]);
  const picked = item ?? ranked[0]?.url ?? (requests.length ? "@requests" : "@scripts");
  const file = files.find((f) => f.url === picked);
  const concerns = signals.filter(serious);
  const w = worst(concerns);
  const forms = signals.filter((s) => s.category === "Forms" && s.label.startsWith("Form: ")).length;
  const writes = requests.filter((r) => !["GET", "HEAD", "OPTIONS"].includes(r.method)).length;
  return (
    <>
      <p className="summary-line">
        {w ? <span className={"chip " + SEVERITY[w]}>{plural(concerns.length, "concern")}</span> : <span className="chip ok">Nothing found</span>}
        <span><b>{files.length}</b> {files.length === 1 ? "file" : "files"} with something in them</span>
        <span><b>{forms}</b> {forms === 1 ? "form" : "forms"}</span>
        <span><b>{scripts.length}</b> {scripts.length === 1 ? "script" : "scripts"}, {scripts.filter((s) => s.third_party).length} from other sites</span>
        <span><b>{requests.length}</b> {requests.length === 1 ? "request" : "requests"}, {writes} that send data</span>
      </p>
      <div className="ide">
        <nav className="ide-tree" aria-label="Files">
          <Tree id={id} files={files} signals={signals} picked={picked} />
          <div className="ide-tree-rule" />
          <TreeRow id={id} to="@requests" icon="lan" name="Every request" count={requests.length} picked={picked} depth={0} />
          <TreeRow id={id} to="@scripts" icon="code" name="Every script" count={scripts.length} picked={picked} depth={0} />
          {loose.length > 0 && (
            <TreeRow id={id} to="@other" icon="info" name="Not in a file" count={loose.length} picked={picked} depth={0} sev={worst(loose)} />
          )}
        </nav>
        <section className="ide-main">
          {file ? <FileView file={file} signals={inFile(file)} />
            : picked === "@requests" ? <Requests list={requests} />
            : picked === "@other" ? <Notes list={loose} />
            : <Scripts list={scripts} />}
        </section>
      </div>
      <Still live={l} />
    </>
  );
}

// ---- the explorer ----

interface Folder {
  name: string;
  folders: Map<string, Folder>;
  files: File[];
}

// Where a file sits in the explorer: under its site's host for the site's
// own, else under the host or folder its name starts with.
function segments(f: File): string[] {
  if (f.name.startsWith("/")) {
    let host = f.base;
    try {
      host = new URL(f.base).host;
    } catch {
      // keep the base as it is
    }
    return [host, ...f.name.slice(1).split("/")];
  }
  return f.name.split("/");
}

function Tree({ id, files, signals, picked }: { id: string; files: File[]; signals: Found[]; picked: string }) {
  const root: Folder = { name: "", folders: new Map(), files: [] };
  for (const f of files) {
    const parts = segments(f);
    let at = root;
    for (const p of parts.slice(0, -1)) {
      const next = at.folders.get(p) ?? { name: p, folders: new Map(), files: [] };
      at.folders.set(p, next);
      at = next;
    }
    at.files.push(f);
  }
  const draw = (folder: Folder, depth: number): ReactNode => (
    <>
      {[...folder.folders.values()].sort((a, b) => a.name.localeCompare(b.name)).map((sub) => (
        <Fragment key={sub.name}>
          <div className="ide-row folder" style={{ paddingLeft: 8 + depth * 14 }}>
            <Icon name="folder" size={18} /><span className="ide-row-name">{sub.name}</span>
          </div>
          {draw(sub, depth + 1)}
        </Fragment>
      ))}
      {[...folder.files].sort((a, b) => a.name.localeCompare(b.name)).map((f) => {
        const these = signals.filter((s) => s.file === f.url);
        const bad = these.filter(serious);
        const last = segments(f).at(-1) ?? f.name;
        return (
          <TreeRow key={f.url} id={id} to={f.url} icon="description" name={last} title={f.url}
            count={bad.length || these.length} sev={worst(bad.length ? bad : these)} picked={picked} depth={depth} />
        );
      })}
    </>
  );
  return <>{draw(root, 0)}</>;
}

function TreeRow({ id, to, icon, name, title, count, sev, picked, depth }: {
  id: string; to: string; icon: "description" | "lan" | "code" | "info"; name: string; title?: string;
  count: number; sev?: Severity | null; picked: string; depth: number;
}) {
  return (
    <a className={"ide-row" + (picked === to ? " on" : "")} href={href(id, "code", to)} title={title ?? name}
      aria-current={picked === to ? "page" : undefined} style={{ paddingLeft: 8 + depth * 14 }}>
      <Icon name={icon} size={18} />
      <span className="ide-row-name">{name}</span>
      {count > 0 && <span className={"ide-count " + (sev ? SEVERITY[sev] : "")}>{count}</span>}
    </a>
  );
}

// ---- a file ----

// FileView is one file: its address, the concerns in it to jump to, then
// its code with each concern marked and explained where it is.
function FileView({ file, signals }: { file: File; signals: Found[] }) {
  const sorted = [...signals].sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  // Back to the top of the code when another file opens.
  useEffect(() => {
    document.querySelector(".ide-code")?.scrollTo({ top: 0 });
  }, [file.url]);
  const jump = (key: string) => document.getElementById(key)?.scrollIntoView({ block: "center", behavior: "smooth" });
  const lineOf = (m?: Mark) => {
    if (!m) return null;
    const sec = file.sections[m.section];
    return sec ? sec.line + countLines(sec.text.slice(0, m.at)) : null;
  };
  return (
    <>
      <div className="ide-head">
        <span className="ide-kind">{KIND[file.kind] ?? file.kind}</span>
        <span className="mono ide-path" title={file.url}>{file.url}</span>
      </div>
      {sorted.length > 0 && (
        <div className="ide-problems">
          {sorted.map((s) => (
            <button key={s.key} type="button" className="ide-problem" onClick={() => jump(s.key)}>
              <span className={"chip " + SEVERITY[s.severity]}>{s.severity}</span>
              <span className="ide-problem-label">{s.label}</span>
              {(s.issues?.length ?? 0) > 0 && <span className="muted">{plural(s.issues!.length, "issue")}</span>}
              {lineOf(s.mark) !== null && <span className="muted mono">Ln {lineOf(s.mark)}</span>}
            </button>
          ))}
        </div>
      )}
      <div className="ide-code">
        {signals.filter((s) => !s.mark).map((s) => <Note key={s.key} signal={s} />)}
        {file.sections.map((sec, i) => (
          <Fragment key={i}>
            {i > 0 && <div className="ide-gap" aria-hidden="true">⋯</div>}
            <Lines file={file} index={i} section={sec} signals={signals} />
          </Fragment>
        ))}
      </div>
    </>
  );
}

const countLines = (s: string) => s.split("\n").length - 1;

// A highlighted run of a section, from its signal or one of a form's issues.
interface Hit { at: number; len: number; severity: Severity; key: string; title: string }

// Lines is one section of a file, line by line: the line number, the code
// coloured by its syntax, what was found marked, and the note for each
// concern under the line it starts on.
function Lines({ file, index, section, signals }: { file: File; index: number; section: Section; signals: Found[] }) {
  const text = section.text;
  const syntax = lex(file.kind, text);
  const hits: Hit[] = [];
  const notes = new Map<number, Found[]>();
  for (const s of signals) {
    const marks: [Mark | undefined, Severity, string, string][] = [
      [s.mark, s.severity, s.key, s.label],
      ...(s.issues ?? []).map((iss: Issue, n): [Mark | undefined, Severity, string, string] => [iss.mark, iss.severity, `${s.key}-${n}`, iss.label]),
    ];
    for (const [m, severity, key, title] of marks) {
      if (m && m.section === index) hits.push({ at: m.at, len: m.len, severity, key, title });
    }
    if (s.mark?.section === index) {
      const line = countLines(text.slice(0, s.mark.at));
      notes.set(line, [...(notes.get(line) ?? []), s]);
    }
  }
  // Worse ones drawn last, so they win where marks overlap.
  hits.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
  const owner = new Int32Array(text.length).fill(-1);
  hits.forEach((h, n) => owner.fill(n, h.at, Math.min(text.length, h.at + h.len)));
  const starts = new Map<number, string[]>();
  for (const h of hits) starts.set(h.at, [...(starts.get(h.at) ?? []), h.key]);

  const rows: ReactNode[] = [];
  let from = 0;
  text.split("\n").forEach((line, n) => {
    const to = from + line.length;
    const runs: ReactNode[] = [];
    let k = from;
    while (k < to) {
      let e = k + 1;
      while (e < to && syntax[e] === syntax[k] && owner[e] === owner[k] && !starts.has(e)) e++;
      const piece = text.slice(k, e).replace(/\r/g, "");
      const anchors = (starts.get(k) ?? []).map((key) => <span key={key} id={key} className="ide-anchor" />);
      const h = owner[k] >= 0 ? hits[owner[k]] : null;
      runs.push(
        <Fragment key={k}>
          {anchors}
          <span className={"tk" + syntax[k] + (h ? " ide-hit " + SEVERITY[h.severity] : "")} title={h?.title}>{piece}</span>
        </Fragment>,
      );
      k = e;
    }
    rows.push(
      <div key={n} className={"ide-line" + (notes.has(n) ? " flagged" : "")}>
        <span className="ide-num">{section.line + n}</span>
        <code className="ide-text">{n === 0 && section.col > 0 && <span className="ide-cut">…</span>}{runs}</code>
      </div>,
    );
    for (const s of notes.get(n) ?? []) rows.push(<Note key={s.key} signal={s} />);
    from = to + 1;
  });
  return <>{rows}</>;
}

// Note is a concern under the code that caused it: what it is, what could
// happen, and for a form, each of its problems.
function Note({ signal: s }: { signal: Found }) {
  const issues = s.issues ?? [];
  return (
    <div className={"ide-note " + SEVERITY[s.severity]}>
      <div className="ide-note-head">
        <span className={"chip " + SEVERITY[s.severity]}>{s.severity}</span>
        <b>{s.label}</b>
        <span className="muted">{s.category}</span>
      </div>
      <p>{s.why}</p>
      {s.impact && <p className="ide-impact"><b>What could happen</b>{s.impact}</p>}
      {issues.length > 0 && (
        <ul className="ide-issues">
          {issues.map((i, n) => (
            <li key={n}>
              <div className="ide-note-head"><span className={"chip " + SEVERITY[i.severity]}>{i.severity}</span><b>{i.label}</b></div>
              <p>{i.why}</p>
              <p className="ide-impact"><b>What could happen</b>{i.impact}</p>
            </li>
          ))}
        </ul>
      )}
      <span className="muted ide-where">On <span className="mono">{s.page}</span>{s.script && s.script !== s.file && <>, in <span className="mono">{s.script}</span></>}</span>
    </div>
  );
}

// ---- the lists ----

function Notes({ list }: { list: Found[] }) {
  return (
    <>
      <div className="ide-head"><span className="ide-kind">Not in a file</span></div>
      <div className="ide-code">{list.map((s) => <Note key={s.key} signal={s} />)}</div>
    </>
  );
}

function Requests({ list }: { list: { method: string; url: string; params?: string[]; page: string; script?: string }[] }) {
  const { shown, pager } = usePaged(list, 20);
  return (
    <>
      <div className="ide-head"><span className="ide-kind">Every request</span><span className="muted">{plural(list.length, "request")} its forms and code make</span></div>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Method</th><th className="grow">Address</th><th>Sends</th><th>Found in</th></tr></thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.method + r.url + r.page}>
                <td><span className={"method " + r.method.toLowerCase()}>{r.method}</span></td>
                <td className="mono wrap">{r.url}</td>
                <td className="muted mono wrap">{r.params?.join(", ") ?? ""}</td>
                <td className="muted mono wrap">{r.script ?? r.page}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {pager}
    </>
  );
}

function Scripts({ list }: { list: { url: string; third_party: boolean; bytes: number }[] }) {
  const { shown, pager } = usePaged(list, 20);
  const kb = (n: number) => (n ? (n < 1024 ? `${n} B` : `${Math.round(n / 1024)} KB`) : "Not read");
  return (
    <>
      <div className="ide-head"><span className="ide-kind">Every script</span><span className="muted">{plural(list.length, "script")} the pages load</span></div>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th className="grow">Script</th><th>From</th><th>Size</th></tr></thead>
          <tbody>
            {shown.map((s) => (
              <tr key={s.url}>
                <td className="mono wrap">{s.url}</td>
                <td className="muted">{s.third_party ? "Another site" : "This site"}</td>
                <td className="muted">{kb(s.bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {pager}
    </>
  );
}

// ---- syntax ----

// Token kinds, each drawn by its class tk1 to tk6; plain code is tk0.
const COMMENT = 1, STRING = 2, KEYWORD = 3, NUMBER = 4, TAG = 5, ATTR = 6;

const KEYWORDS = new Set([
  "async", "await", "break", "case", "catch", "class", "const", "continue", "default", "delete", "do", "else", "export", "extends",
  "false", "finally", "for", "from", "function", "if", "import", "in", "instanceof", "let", "new", "null", "return", "static",
  "super", "switch", "this", "throw", "true", "try", "typeof", "undefined", "var", "void", "while", "yield",
  "array", "as", "echo", "elseif", "endif", "foreach", "global", "include", "include_once", "isset", "namespace", "private",
  "protected", "public", "require", "require_once", "unset", "use", "define",
]);

// lex gives each character of `text` its token kind, for a language.
function lex(kind: string, text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  if (kind === "html" || kind === "xml") lexMarkup(text, out);
  else if (kind === "http") lexHeaders(text, out);
  else if (kind !== "text") lexCode(text, 0, text.length, out, kind);
  return out;
}

function lexHeaders(t: string, out: Uint8Array) {
  let from = 0;
  for (const line of t.split("\n")) {
    const colon = line.indexOf(":");
    if (from === 0) out.fill(KEYWORD, 0, line.length);
    else if (colon > 0) out.fill(ATTR, from, from + colon);
    from += line.length + 1;
  }
}

function lexMarkup(t: string, out: Uint8Array) {
  const lower = t.toLowerCase();
  let i = 0;
  while (i < t.length) {
    if (t.startsWith("<!--", i)) {
      const e = t.indexOf("-->", i);
      const end = e < 0 ? t.length : e + 3;
      out.fill(COMMENT, i, end);
      i = end;
      continue;
    }
    if (t[i] === "<" && /[a-zA-Z/!?]/.test(t[i + 1] ?? "")) {
      let j = i + 1;
      while (j < t.length && !/[\s>]/.test(t[j])) j++;
      out.fill(TAG, i, j);
      const name = lower.slice(i + 1, j);
      while (j < t.length && t[j] !== ">") {
        const c = t[j];
        if (c === '"' || c === "'") {
          const e = t.indexOf(c, j + 1);
          const end = e < 0 ? t.length : e + 1;
          out.fill(STRING, j, end);
          j = end;
        } else if (/[\w:@-]/.test(c)) {
          let k = j;
          while (k < t.length && /[\w:@.-]/.test(t[k])) k++;
          out.fill(ATTR, j, k);
          j = k;
        } else j++;
      }
      if (j < t.length) out[j++] = TAG;
      if (name === "script" || name === "style") {
        const close = lower.indexOf("</" + name, j);
        const end = close < 0 ? t.length : close;
        lexCode(t, j, end, out, name === "script" ? "js" : "css");
        i = end;
        continue;
      }
      i = j;
      continue;
    }
    i++;
  }
}

function lexCode(t: string, from: number, to: number, out: Uint8Array, kind: string) {
  let i = from;
  while (i < to) {
    const c = t[i];
    const next = t[i + 1];
    if ((c === "/" && next === "/" && kind !== "css" && kind !== "json") || (c === "#" && kind === "php")) {
      const e = t.indexOf("\n", i);
      const end = e < 0 || e > to ? to : e;
      out.fill(COMMENT, i, end);
      i = end;
    } else if (c === "/" && next === "*") {
      const e = t.indexOf("*/", i + 2);
      const end = e < 0 || e > to ? to : e + 2;
      out.fill(COMMENT, i, end);
      i = end;
    } else if (c === '"' || c === "'" || c === "`") {
      let j = i + 1;
      while (j < to && t[j] !== c && !(c !== "`" && t[j] === "\n")) j += t[j] === "\\" ? 2 : 1;
      const end = Math.min(to, j + 1);
      out.fill(STRING, i, end);
      i = end;
    } else if (kind === "php" && c === "<" && t.startsWith("<?php", i)) {
      out.fill(TAG, i, i + 5);
      i += 5;
    } else if (/[0-9]/.test(c) && !/[\w$]/.test(t[i - 1] ?? "")) {
      let j = i;
      while (j < to && /[\w.]/.test(t[j])) j++;
      out.fill(NUMBER, i, j);
      i = j;
    } else if (/[A-Za-z_$]/.test(c)) {
      let j = i + 1;
      while (j < to && /[\w$]/.test(t[j])) j++;
      const word = t.slice(i, j);
      if (kind === "php" && c === "$") out.fill(ATTR, i, j);
      else if (KEYWORDS.has(word)) out.fill(KEYWORD, i, j);
      i = j;
    } else i++;
  }
}
