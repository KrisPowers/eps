import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent, type ReactNode } from "react";
import { Icon } from "./Icon";
import { usePaged } from "./paged";
import { Bones, Empty, Still, type Live } from "./Pages";
import { href } from "./route";
import { plural, SEVERITY } from "./ScanView";
import type { Script, Severity, Signal, SiteRequest, SourceFile } from "./types";

// Code is the site's code in an editor: a file explorer of every file
// something was found in, folders folding, and the picked file printed in
// full with line numbers, its syntax coloured and the code behind each
// concern underlined. A minimap down the right shows the whole file with
// where each concern is; a click on it, on the code or on a line's dot opens
// the concern in a panel under the code, with what it is and what could
// happen, stepping to the next and previous ones as an editor's problems do.

const RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };
const worst = (list: { severity: Severity }[]) =>
  list.reduce<Severity | null>((w, s) => (w === null || RANK[s.severity] < RANK[w] ? s.severity : w), null);
const serious = (s: { severity: Severity }) => s.severity !== "info";

type File = SourceFile & { base: string };
type Concern = Signal & { key: string };

const KIND: Record<string, string> = { html: "HTML", js: "JavaScript", css: "CSS", php: "PHP", json: "JSON", xml: "XML", http: "HTTP", text: "Text" };

export function Code({ id, live: l, item }: { id: string; live: Live; item: string | null }) {
  const files: File[] = l.sites.flatMap((s) => (s.files ?? []).map((f) => ({ ...f, base: s.base })));
  const concerns: Concern[] = l.sites.flatMap((s, si) => s.signals.map((x, i) => ({ ...x, key: `c${si}-${i}` })));
  const requests = l.sites.flatMap((s) => s.requests ?? []);
  const scripts = l.sites.flatMap((s) => s.scripts);
  if (!l.sites.length) {
    return l.going ? <div className="tiles"><Bones n={4} label="Reading the site" /></div>
      : <Empty icon="language" title="No website">No web service answered, so there was no code to read.</Empty>;
  }
  const inFile = (f: File) => concerns.filter((c) => c.file === f.url);
  const loose = concerns.filter((c) => !c.file || !files.some((f) => f.url === c.file));
  const ranked = [...files].sort((a, b) => RANK[worst(inFile(a)) ?? "info"] - RANK[worst(inFile(b)) ?? "info"]);
  const picked = item ?? ranked[0]?.url ?? (loose.length ? "@other" : "@requests");
  const file = files.find((f) => f.url === picked);
  const bad = concerns.filter(serious);
  const w = worst(bad);
  const forms = concerns.filter((c) => c.label.startsWith("Form: ")).length;
  const writes = requests.filter((r) => !["GET", "HEAD", "OPTIONS"].includes(r.method)).length;
  return (
    <>
      <p className="summary-line">
        {w ? <span className={"chip " + SEVERITY[w]}>{plural(bad.length, "concern")}</span> : <span className="chip ok">Nothing found</span>}
        <span><b>{files.length}</b> {files.length === 1 ? "file" : "files"}</span>
        <span><b>{forms}</b> {forms === 1 ? "form" : "forms"}</span>
        <span><b>{scripts.length}</b> {scripts.length === 1 ? "script" : "scripts"}, {scripts.filter((s) => s.third_party).length} from other sites</span>
        <span><b>{requests.length}</b> {requests.length === 1 ? "request" : "requests"}, {writes} that send data</span>
      </p>
      <div className="ide">
        <Explorer id={id} files={files} concerns={concerns} picked={picked} going={l.going}
          extras={[
            { to: "@requests", icon: "lan", name: "Every request", count: requests.length },
            { to: "@scripts", icon: "code", name: "Every script", count: scripts.length },
            ...(loose.length ? [{ to: "@other", icon: "info" as const, name: "Not in a file", count: loose.length, sev: worst(loose) }] : []),
          ]} />
        <section className="ide-main">
          {file ? <Editor key={file.url} file={file} concerns={inFile(file)} />
            : picked === "@requests" ? <Requests list={requests} />
            : picked === "@scripts" ? <Scripts list={scripts} />
            : <Loose list={loose} />}
        </section>
      </div>
      <Still live={l} />
    </>
  );
}

// ---- explorer ----

interface Folder {
  name: string;
  path: string;
  folders: Map<string, Folder>;
  files: File[];
}

// A file's place in the explorer: under its site's host for the site's own,
// else under the host or folder its name starts with.
function segments(f: File): string[] {
  if (!f.name.startsWith("/")) return f.name.split("/");
  let host = f.base;
  try {
    host = new URL(f.base).host;
  } catch {
    // keep the base as it is
  }
  return [host, ...f.name.slice(1).split("/")];
}

interface Extra { to: string; icon: "lan" | "code" | "info"; name: string; count: number; sev?: Severity | null }

function Explorer({ id, files, concerns, picked, going, extras }: {
  id: string; files: File[]; concerns: Concern[]; picked: string; going: boolean; extras: Extra[];
}) {
  const [closed, setClosed] = useState<Set<string>>(() => new Set());
  const toggle = (path: string) => setClosed((c) => {
    const next = new Set(c);
    if (!next.delete(path)) next.add(path);
    return next;
  });
  const root: Folder = { name: "", path: "", folders: new Map(), files: [] };
  for (const f of files) {
    let at = root;
    for (const p of segments(f).slice(0, -1)) {
      const path = at.path + "/" + p;
      const next = at.folders.get(p) ?? { name: p, path, folders: new Map(), files: [] };
      at.folders.set(p, next);
      at = next;
    }
    at.files.push(f);
  }
  const within = (folder: Folder): File[] => [...folder.files, ...[...folder.folders.values()].flatMap(within)];
  const counted = (list: File[]) => {
    const these = concerns.filter((c) => list.some((f) => f.url === c.file));
    const bad = these.filter(serious);
    return { count: bad.length || these.length, sev: worst(bad.length ? bad : these) };
  };
  const pad = (depth: number) => ({ paddingLeft: 8 + depth * 12 });
  const draw = (folder: Folder, depth: number): ReactNode[] => [
    ...[...folder.folders.values()].sort((a, b) => a.name.localeCompare(b.name)).flatMap((sub) => {
      const open = !closed.has(sub.path);
      const { count, sev } = counted(within(sub));
      return [
        <button key={sub.path} type="button" className="ide-row" style={pad(depth)} aria-expanded={open} onClick={() => toggle(sub.path)}>
          <Icon name="chevron_right" size={16} className={"ide-caret" + (open ? " open" : "")} />
          <Icon name="folder" size={18} />
          <span className="ide-row-name">{sub.name}</span>
          {!open && count > 0 && <span className={"ide-count " + (sev ? SEVERITY[sev] : "")}>{count}</span>}
        </button>,
        ...(open ? draw(sub, depth + 1) : []),
      ];
    }),
    ...[...folder.files].sort((a, b) => a.name.localeCompare(b.name)).map((f) => {
      const { count, sev } = counted([f]);
      return (
        <a key={f.url} className={"ide-row" + (picked === f.url ? " on" : "")} style={pad(depth)} href={href(id, "code", f.url)}
          title={f.url} aria-current={picked === f.url ? "page" : undefined}>
          <span className="ide-caret-space" />
          <Icon name="description" size={18} />
          <span className="ide-row-name">{segments(f).at(-1)}</span>
          {count > 0 && <span className={"ide-count " + (sev ? SEVERITY[sev] : "")}>{count}</span>}
        </a>
      );
    }),
  ];
  return (
    <nav className="ide-tree" aria-label="Files">
      <div className="ide-tree-title">Explorer</div>
      {files.length ? draw(root, 0) : <p className="ide-tree-note">{going ? "Files open here when the scan finishes." : "No file had anything in it."}</p>}
      <div className="ide-tree-rule" />
      {extras.map((x) => (
        <a key={x.to} className={"ide-row" + (picked === x.to ? " on" : "")} style={pad(0)} href={href(id, "code", x.to)}
          aria-current={picked === x.to ? "page" : undefined}>
          <Icon name={x.icon} size={18} />
          <span className="ide-row-name">{x.name}</span>
          {x.count > 0 && <span className={"ide-count " + (x.sev ? SEVERITY[x.sev] : "")}>{x.count}</span>}
        </a>
      ))}
    </nav>
  );
}

// ---- editor ----

// Every line is this tall, so only the lines in view are drawn.
const LINE = 20;
// The line numbers' column.
const GUTTER = 72;
// Lines longer than this draw only the part in view.
const LONG = 2000;

interface Line { sec: number; from: number; to: number; num: number; cut: boolean; gap: boolean }
// A run of a file that's marked: a concern's own, or one of a form's issues.
interface Hit { key: string; owner: string; sec: number; from: number; to: number; severity: Severity; title: string }

// The file as lines, its syntax per section, and its widest line.
function layout(file: File) {
  const lines: Line[] = [];
  const syntax = file.sections.map((s) => lex(file.kind, s.text));
  let widest = 0;
  file.sections.forEach((sec, si) => {
    if (si > 0) lines.push({ sec: si, from: 0, to: 0, num: 0, cut: false, gap: true });
    let from = 0;
    for (let n = 0; ; n++) {
      const nl = sec.text.indexOf("\n", from);
      const to = nl < 0 ? sec.text.length : nl;
      lines.push({ sec: si, from, to, num: sec.line + n, cut: n === 0 && sec.col > 0, gap: false });
      widest = Math.max(widest, to - from);
      if (nl < 0) break;
      from = nl + 1;
    }
  });
  return { lines, syntax, widest };
}

// The index of the line holding offset `at` of section `sec`.
function lineOf(lines: Line[], sec: number, at: number) {
  let lo = 0;
  let hi = lines.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    const l = lines[mid];
    if (l.sec < sec || (l.sec === sec && l.from <= at)) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

function Editor({ file, concerns }: { file: File; concerns: Concern[] }) {
  // Laid out and coloured once per file, not on every poll of the scan.
  const { lines, syntax, widest } = useMemo(() => layout(file), [file.url, file.sections]);
  const hits = useMemo(() => {
    const out: Hit[] = [];
    for (const c of concerns) {
      if (c.mark) out.push({ key: c.key, owner: c.key, sec: c.mark.section, from: c.mark.at, to: c.mark.at + c.mark.len, severity: c.severity, title: c.label });
      (c.issues ?? []).forEach((i, n) => {
        if (i.mark) out.push({ key: `${c.key}-${n}`, owner: c.key, sec: i.mark.section, from: i.mark.at, to: i.mark.at + i.mark.len, severity: i.severity, title: i.label });
      });
    }
    // Worse ones last, so they win where marks overlap.
    return out.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
  }, [concerns]);
  // Each concern in the order it comes in the file.
  const order = useMemo(() => {
    const at = (c: Concern) => (c.mark ? lineOf(lines, c.mark.section, c.mark.at) * 1e7 + c.mark.at : -1);
    return [...concerns].sort((a, b) => at(a) - at(b));
  }, [concerns, lines]);
  const byLine = useMemo(() => {
    const m = new Map<number, Hit[]>();
    for (const h of hits) {
      const first = lineOf(lines, h.sec, h.from);
      const last = lineOf(lines, h.sec, Math.max(h.from, h.to - 1));
      for (let i = first; i <= last; i++) m.set(i, [...(m.get(i) ?? []), h]);
    }
    return m;
  }, [hits, lines]);

  const scroller = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ top: 0, left: 0, width: 800, height: 600 });
  const [ch, setCh] = useState(7.8);
  const [sel, setSel] = useState<string | null>(order[0]?.key ?? null);
  const [focus, setFocus] = useState<string | null>(null);

  const measure = useCallback(() => {
    const el = scroller.current;
    if (el) setView({ top: el.scrollTop, left: el.scrollLeft, width: el.clientWidth, height: el.clientHeight });
  }, []);
  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const probe = document.createElement("span");
    probe.className = "ide-text";
    probe.style.position = "absolute";
    probe.style.visibility = "hidden";
    probe.style.padding = "0";
    probe.textContent = "0".repeat(100);
    el.appendChild(probe);
    setCh(probe.getBoundingClientRect().width / 100 || 7.8);
    el.removeChild(probe);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [measure]);

  // Scrolls a mark into view: its line a third of the way down, and on a
  // long line, across to it.
  const reveal = useCallback((key: string) => {
    const el = scroller.current;
    const h = hits.find((x) => x.key === key);
    if (!el || !h) return;
    const i = lineOf(lines, h.sec, h.from);
    const col = h.from - lines[i].from;
    const x = col * ch;
    el.scrollTo({ top: Math.max(0, i * LINE - el.clientHeight / 3), left: x > el.clientWidth - GUTTER - 120 ? x - 160 : 0 });
  }, [hits, lines, ch]);

  const pick = useCallback((owner: string, hit?: string) => {
    setSel(owner);
    setFocus(hit ?? null);
    reveal(hit ?? owner);
  }, [reveal]);

  // Opens on the first concern in the file, once.
  const opened = useRef(false);
  useEffect(() => {
    if (opened.current || !order[0]) return;
    opened.current = true;
    requestAnimationFrame(() => reveal(order[0].key));
  }, [order, reveal]);

  const cur = order.findIndex((c) => c.key === sel);
  const step = (by: number) => {
    if (!order.length) return;
    const next = order[(Math.max(cur, 0) + by + order.length) % order.length];
    pick(next.key);
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "F8") {
      e.preventDefault();
      step(e.shiftKey ? -1 : 1);
    } else if (e.key === "Escape") setSel(null);
  };

  const first = Math.max(0, Math.floor(view.top / LINE) - 20);
  const last = Math.min(lines.length, Math.ceil((view.top + view.height) / LINE) + 20);
  const rows: ReactNode[] = [];
  for (let i = first; i < last; i++) {
    const line = lines[i];
    const top = i * LINE;
    if (line.gap) {
      rows.push(<div key={i} className="ide-line gap" style={{ top }}><span className="ide-num">⋯</span></div>);
      continue;
    }
    const these = byLine.get(i) ?? [];
    const lineWorst = worst(these);
    const mine = these.some((h) => h.owner === sel);
    rows.push(
      <div key={i} className={"ide-line" + (lineWorst ? " hit " + SEVERITY[lineWorst] : "") + (mine ? " current" : "")} style={{ top }}>
        <span className="ide-num">
          {lineWorst && (
            <button type="button" className={"ide-dot " + SEVERITY[lineWorst]} aria-label={"Open " + these[these.length - 1].title}
              onClick={() => pick(these[these.length - 1].owner)} />
          )}
          {line.num}
        </span>
        <code className="ide-text">{runs(line, file.sections[line.sec].text, syntax[line.sec], these, sel, focus, view.left, view.width, ch, pick)}</code>
      </div>,
    );
  }

  const selected = cur >= 0 ? order[cur] : null;
  return (
    <>
      <div className="ide-tabbar">
        <span className="ide-tab"><Icon name="description" size={16} />{segments(file).at(-1)}</span>
        <span className="ide-crumbs mono" title={file.url}>{file.url}</span>
        <span className="ide-kind">{KIND[file.kind] ?? file.kind}</span>
      </div>
      <div className="ide-editor">
        <div className="ide-scroll" ref={scroller} onScroll={measure} onKeyDown={onKey} tabIndex={0} aria-label={"Code of " + file.url}>
          <div className="ide-canvas" style={{ height: lines.length * LINE + 2 * LINE, width: GUTTER + widest * ch + 64 }}>{rows}</div>
        </div>
        <Minimap lines={lines} byLine={byLine} sel={sel} view={view} onJump={(i) => {
          const el = scroller.current;
          if (el) el.scrollTo({ top: Math.max(0, i * LINE - el.clientHeight / 2) });
        }} />
      </div>
      {selected && (
        <Peek concern={selected} index={cur} total={order.length} lineNo={selected.mark ? lines[lineOf(lines, selected.mark.section, selected.mark.at)].num : null}
          focus={focus} onStep={step} onClose={() => setSel(null)} onIssue={(n) => pick(selected.key, `${selected.key}-${n}`)}
          issueLine={(n) => {
            const m = selected.issues?.[n]?.mark;
            return m ? lines[lineOf(lines, m.section, m.at)].num : null;
          }} />
      )}
    </>
  );
}

// The spans of one line: coloured by syntax, marked where a concern is, and
// on a very long line, only the part in view.
function runs(line: Line, text: string, syntax: Uint8Array, hits: Hit[], sel: string | null, focus: string | null,
  left: number, width: number, ch: number, pick: (owner: string, hit?: string) => void): ReactNode[] {
  const len = line.to - line.from;
  let c0 = 0;
  let c1 = len;
  if (len > LONG) {
    c0 = Math.max(0, Math.floor((left - GUTTER) / ch) - 400);
    c1 = Math.min(len, c0 + Math.ceil(width / ch) + 800);
  }
  const from = line.from + c0;
  const to = line.from + c1;
  const owner = new Int16Array(to - from).fill(-1);
  hits.forEach((h, n) => {
    const a = Math.max(h.from, from);
    const b = Math.min(h.to, to);
    if (a < b) owner.fill(n, a - from, b - from);
  });
  const out: ReactNode[] = [];
  if (line.cut) out.push(<span key="cut" className="ide-cut">…</span>);
  if (c0 > 0) out.push(<span key="pad" style={{ display: "inline-block", width: c0 * ch }} />);
  let k = from;
  while (k < to) {
    let e = k + 1;
    while (e < to && syntax[e] === syntax[k] && owner[e - from] === owner[k - from]) e++;
    const piece = text.slice(k, e).replace(/\r/g, "");
    const h = owner[k - from] >= 0 ? hits[owner[k - from]] : null;
    out.push(h ? (
      <span key={k} className={"tk" + syntax[k] + " ide-hit " + SEVERITY[h.severity] + (h.owner === sel ? " on" : "") + (h.key === focus ? " focus" : "")}
        title={h.title} onClick={() => pick(h.owner, h.key === h.owner ? undefined : h.key)}>{piece}</span>
    ) : <span key={k} className={"tk" + syntax[k]}>{piece}</span>);
    k = e;
  }
  return out;
}

// ---- minimap ----

// Minimap is the whole file down the editor's right edge: each line as a
// sliver as long as its code, each concern's lines in its colour across the
// width, and the part on screen shaded. Click or drag to go there.
function Minimap({ lines, byLine, sel, view, onJump }: {
  lines: Line[]; byLine: Map<number, Hit[]>; sel: string | null; view: { top: number; height: number }; onJump: (line: number) => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return;
    const fit = () => setSize({ w: el.clientWidth, h: el.clientHeight });
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const scale = Math.min(2, size.h / Math.max(1, lines.length));
  useEffect(() => {
    const c = canvas.current;
    const el = box.current;
    if (!c || !el || !size.h) return;
    const dpr = devicePixelRatio || 1;
    c.width = size.w * dpr;
    c.height = size.h * dpr;
    const g = c.getContext("2d");
    if (!g) return;
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, size.w, size.h);
    const color = (css: string) => {
      const probe = document.createElement("span");
      probe.style.color = css;
      el.appendChild(probe);
      const out = getComputedStyle(probe).color;
      el.removeChild(probe);
      return out;
    };
    const tone: Record<string, string> = {
      bad: color("var(--bad)"), warn: color("var(--warn)"), plain: color("var(--accent)"), ok: color("var(--accent)"),
    };
    g.fillStyle = color("var(--text-3)");
    g.globalAlpha = 0.45;
    const bar = Math.max(0.5, scale * 0.7);
    lines.forEach((l, i) => {
      const len = l.to - l.from;
      if (!len) return;
      g.fillRect(6, i * scale, Math.min(size.w - 12, 4 + len * 0.35), bar);
    });
    g.globalAlpha = 1;
    for (const [i, hs] of byLine) {
      const w = worst(hs);
      if (!w) continue;
      const mine = hs.some((h) => h.owner === sel);
      g.fillStyle = tone[SEVERITY[w]];
      g.globalAlpha = mine ? 1 : 0.8;
      g.fillRect(0, i * scale - 1, size.w, Math.max(3, scale));
    }
    g.globalAlpha = 0.14;
    g.fillStyle = color("var(--text)");
    g.fillRect(0, (view.top / LINE) * scale, size.w, Math.max(8, (view.height / LINE) * scale));
    g.globalAlpha = 1;
  }, [lines, byLine, sel, view.top, view.height, size, scale]);
  const jump = (e: PointerEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    onJump(Math.floor((e.clientY - r.top) / Math.max(scale, 1e-6)));
  };
  return (
    <div ref={box} className="ide-minimap" aria-hidden="true"
      onPointerDown={(e) => {
        e.currentTarget.setPointerCapture(e.pointerId);
        jump(e);
      }}
      onPointerMove={(e) => {
        if (e.buttons & 1) jump(e);
      }}>
      <canvas ref={canvas} style={{ width: size.w, height: size.h }} />
    </div>
  );
}

// ---- the open concern ----

// Peek is the concern picked, docked under the code as an editor's problem
// view is: what it is, what could happen, for a form each of its problems,
// and stepping to the next and previous concern in the file.
function Peek({ concern: c, index, total, lineNo, focus, onStep, onClose, onIssue, issueLine }: {
  concern: Concern; index: number; total: number; lineNo: number | null; focus: string | null;
  onStep: (by: number) => void; onClose: () => void; onIssue: (n: number) => void; issueLine: (n: number) => number | null;
}) {
  return (
    <div className={"ide-peek " + SEVERITY[c.severity]}>
      <div className="ide-peek-bar">
        <span className={"chip " + SEVERITY[c.severity]}>{c.severity}</span>
        <b className="ide-peek-title">{c.label}</b>
        <span className="muted">{c.category}{lineNo !== null && <>, line {lineNo}</>}</span>
        <span className="ide-peek-nav">
          <button type="button" className="icon-btn" aria-label="Previous concern (Shift+F8)" title="Previous (Shift+F8)" onClick={() => onStep(-1)}><Icon name="chevron_left" /></button>
          <span className="muted">{index + 1} of {total}</span>
          <button type="button" className="icon-btn" aria-label="Next concern (F8)" title="Next (F8)" onClick={() => onStep(1)}><Icon name="chevron_right" /></button>
          <button type="button" className="icon-btn" aria-label="Close" title="Close (Esc)" onClick={onClose}><Icon name="close" /></button>
        </span>
      </div>
      <Detail concern={c} focus={focus} onIssue={onIssue} issueLine={issueLine} />
    </div>
  );
}

// Detail is what a concern says.
function Detail({ concern: c, focus, onIssue, issueLine }: {
  concern: Concern; focus?: string | null; onIssue?: (n: number) => void; issueLine?: (n: number) => number | null;
}) {
  const issues = c.issues ?? [];
  return (
    <div className="ide-detail">
      <p>{c.why}</p>
      {c.impact && <div className="ide-impact"><b>What could happen</b><p>{c.impact}</p></div>}
      {issues.length > 0 && (
        <ol className="ide-issues">
          {issues.map((i, n) => {
            const at = issueLine?.(n) ?? null;
            return (
              <li key={n} className={focus === `${c.key}-${n}` ? "on" : ""}>
                <button type="button" className="ide-issue" onClick={() => onIssue?.(n)} disabled={!onIssue}>
                  <span className={"chip " + SEVERITY[i.severity]}>{i.severity}</span>
                  <b>{i.label}</b>
                  {at !== null && <span className="muted mono">line {at}</span>}
                </button>
                <p>{i.why}</p>
                <div className="ide-impact"><b>What could happen</b><p>{i.impact}</p></div>
              </li>
            );
          })}
        </ol>
      )}
      <span className="muted ide-where">On <span className="mono">{c.page}</span>{c.script && c.script !== c.file && <>, in <span className="mono">{c.script}</span></>}</span>
    </div>
  );
}

// ---- the lists ----

function Loose({ list }: { list: Concern[] }) {
  return (
    <>
      <div className="ide-tabbar"><span className="ide-tab"><Icon name="info" size={16} />Not in a file</span></div>
      <div className="ide-list">
        {list.map((c) => (
          <div key={c.key} className={"ide-peek " + SEVERITY[c.severity]}>
            <div className="ide-peek-bar">
              <span className={"chip " + SEVERITY[c.severity]}>{c.severity}</span>
              <b className="ide-peek-title">{c.label}</b>
              <span className="muted">{c.category}</span>
            </div>
            <Detail concern={c} />
          </div>
        ))}
      </div>
    </>
  );
}

function Requests({ list }: { list: SiteRequest[] }) {
  const { shown, pager } = usePaged(list, 25);
  return (
    <>
      <div className="ide-tabbar"><span className="ide-tab"><Icon name="lan" size={16} />Every request</span><span className="ide-crumbs">{plural(list.length, "request")} its forms and code make</span></div>
      <div className="ide-list">
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
      </div>
    </>
  );
}

function Scripts({ list }: { list: Script[] }) {
  const { shown, pager } = usePaged(list, 25);
  const kb = (n: number) => (n ? (n < 1024 ? `${n} B` : `${Math.round(n / 1024)} KB`) : "Not read");
  return (
    <>
      <div className="ide-tabbar"><span className="ide-tab"><Icon name="code" size={16} />Every script</span><span className="ide-crumbs">{plural(list.length, "script")} the pages load</span></div>
      <div className="ide-list">
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
      </div>
    </>
  );
}

// ---- syntax ----

// Token kinds, drawn by classes tk1 to tk6; plain code is tk0.
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
  if (kind === "html" || kind === "xml") markup(text, out);
  else if (kind === "http") headers(text, out);
  else if (kind !== "text") code(text, 0, text.length, out, kind);
  return out;
}

function headers(t: string, out: Uint8Array) {
  let from = 0;
  for (const line of t.split("\n")) {
    const colon = line.indexOf(":");
    if (from === 0) out.fill(KEYWORD, 0, line.length);
    else if (colon > 0) out.fill(ATTR, from, from + colon);
    from += line.length + 1;
  }
}

function markup(t: string, out: Uint8Array) {
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
        code(t, j, end, out, name === "script" ? "js" : "css");
        i = end;
        continue;
      }
      i = j;
      continue;
    }
    i++;
  }
}

function code(t: string, from: number, to: number, out: Uint8Array, kind: string) {
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
      if (kind === "php" && c === "$") out.fill(ATTR, i, j);
      else if (KEYWORDS.has(t.slice(i, j))) out.fill(KEYWORD, i, j);
      i = j;
    } else i++;
  }
}
