import { useCallback, useEffect, useRef, useState, type KeyboardEvent as KeyEvent } from "react";
import { api } from "./api";
import { DOCS, Docs } from "./Docs";
import { withDefaults } from "./prefs";
import { usePaged } from "./paged";
import { SETTINGS, Settings } from "./Settings";
import { Icon, type IconName } from "./Icon";
import { go, href, readHash } from "./route";
import { results, ScanView, SEVERITY } from "./ScanView";
import type { Progress, Report, ScanRow, Severity } from "./types";

// App is the frame every page sits in: a header with the search bar, help
// and settings, a sidebar of pages, and the page itself.
export function App() {
  const [scans, setScans] = useState<ScanRow[] | null>(null);
  const [reports, setReports] = useState<Record<string, Report>>({});
  const [route, setRoute] = useState(readHash);
  const { id, view, page, port, item, section } = route;
  const [problem, setProblem] = useState("");
  const [toast, setToast] = useState("");
  const [drawer, setDrawer] = useState(false);
  // The last progress seen of each scan keeps its ports on screen between
  // it finishing and its report arriving.
  const last = useRef<Record<string, Progress>>({});

  const load = useCallback(async () => {
    try {
      setScans(await api.scans());
      setProblem("");
    } catch (e) {
      setProblem((e as Error).message);
    }
  }, []);

  // Poll quickly while a scan is going, so its progress moves.
  const going = scans?.some((s) => s.status === "queued" || s.status === "running") ?? false;
  useEffect(() => {
    load();
    const t = setInterval(load, going ? 700 : 10000);
    return () => clearInterval(t);
  }, [load, going]);

  useEffect(() => {
    const onHash = () => {
      setRoute(readHash());
      setDrawer(false);
    };
    addEventListener("hashchange", onHash);
    return () => removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(""), 5000);
    return () => clearTimeout(t);
  }, [toast]);

  const selected = id ? scans?.find((s) => s.id === id) : undefined;
  useEffect(() => {
    if (scans && id && !selected) go("");
  }, [scans, id, selected]);

  // The last finished scan of the same target before this one, which the
  // Changes page compares with, even while this one runs. The scans are
  // newest first.
  const before = selected && scans?.find((s) => s.target === selected.target && s.status === "done" && s.created < selected.created);

  // A finished scan's report, and the one before it, are fetched once and kept.
  const doneId = selected?.status === "done" ? selected.id : "";
  const beforeId = before?.id ?? "";
  useEffect(() => {
    for (const want of [doneId, beforeId]) {
      if (!want || reports[want]) continue;
      api.scan(want)
        .then((d) => d.report && setReports((r) => ({ ...r, [want]: d.report! })))
        .catch((e) => setToast((e as Error).message));
    }
  }, [doneId, beforeId, reports]);

  if (selected?.progress) last.current[selected.id] = selected.progress;
  const progress = selected && (selected.progress ?? last.current[selected.id]);
  const items = selected ? results(reports[selected.id], progress) : null;

  // A new scan takes the options set in Settings; a scan run again keeps the
  // line it was first run with.
  const start = async (command: string, again = false) => {
    try {
      const row = await api.start(again ? command : withDefaults(command));
      await load();
      go(row.id);
    } catch (e) {
      setToast((e as Error).message);
    }
  };

  const remove = async (scan: ScanRow) => {
    try {
      await api.remove(scan.id);
      await load();
      go("");
    } catch (e) {
      setToast((e as Error).message);
    }
  };

  return (
    <div className="app">
      <header className="header">
        {(view === "docs" || view === "settings") && (
          <button type="button" className="icon-btn menu-btn" aria-label="Menu" aria-expanded={drawer} onClick={() => setDrawer((d) => !d)}>
            <Icon name="menu" />
          </button>
        )}
        <ScanBar scans={scans} onScan={start} />
        <div className="header-actions">
          <a className={"icon-btn" + (view === "docs" ? " on" : "")} href="#/docs" aria-label="Help" title="Help"><Icon name="help" /></a>
          <a className={"icon-btn" + (view === "settings" ? " on" : "")} href="#/settings" aria-label="Settings" title="Settings"><Icon name="settings" /></a>
        </div>
      </header>

      <div className="shell">
        <nav className={"sidebar" + (drawer ? " open" : "")} aria-label="Pages">
          {/* A scan's pages are a bar across the top of the scan, not here. */}
          {view === "docs" || view === "settings" ? (
            <>
              <a className="nav-back" href="#/"><Icon name="arrow_back" /><span>All scans</span></a>
              <hr className="nav-rule" />
              {(view === "docs" ? DOCS : SETTINGS).map(([key, label, icon], i) => (
                <NavItem key={key} to={`#/${view}/${key}`} icon={icon} label={label} on={section === key || (!section && i === 0)} quiet />
              ))}
            </>
          ) : null}
        </nav>
        {drawer && <div className="scrim" onClick={() => setDrawer(false)} />}

        <main className={"page" + (view === "docs" ? " wide" : "")} key={view + id}>
          {view === "docs" && <Docs section={section} />}
          {view === "settings" && <Settings section={section} scans={scans} onChanged={load} />}
          {view === "scan" && selected && (
            <ScanView scan={selected} report={reports[selected.id]} items={items} progress={progress} page={page} port={port} item={item}
              previous={before && { scan: before, report: reports[before.id] }}
              history={(scans ?? []).filter((s) => s.target === selected.target)}
              onAgain={() => start(selected.command || selected.target, true)} onScan={start} onDelete={() => remove(selected)} />
          )}
          {view === "scans" && <Home scans={scans} problem={problem} onScan={start} />}
        </main>
      </div>

      {toast && (
        <div className="toast bad" role="alert"><Icon name="error" /><span>{toast}</span></div>
      )}
    </div>
  );
}

// NavItem is a page in the sidebar. A section of the docs or settings is
// `quiet`: plain text, marked by colour and a bar beside it, not a pill.
function NavItem({ to, icon, label, on, quiet }: { to: string; icon: IconName; label: string; on: boolean; quiet?: boolean }) {
  return (
    <a className={"nav-item" + (quiet ? " quiet" : "") + (on ? " on" : "")} href={to} aria-current={on ? "page" : undefined}>
      <Icon name={icon} />
      <span className="nav-label">{label}</span>
    </a>
  );
}

// Home is the scans kept, newest first, a row each with the worst of what it
// found, a page at a time, each opening the scan.
function Home({ scans, problem, onScan }: { scans: ScanRow[] | null; problem: string; onScan: (command: string) => Promise<void> }) {
  const { shown, pager } = usePaged(scans ?? [], 12);
  return (
    <>
      <div className="page-head">
        <div className="page-head-main">
          <h1>Scans</h1>
          <div className="page-sub">Scan only hosts you own or are allowed to test.</div>
        </div>
      </div>
      {problem && !scans && (
        <div className="callout bad"><Icon name="error" /><span>Can't reach portscan: {problem}</span></div>
      )}
      {scans && scans.length === 0 && (
        <div className="card welcome">
          <Icon name="lan" size={40} />
          <h2>No scans yet</h2>
          <p className="muted">Type a host into the search bar, such as <code>192.168.1.10</code> or <code>api.internal:8080</code>, and press Enter.</p>
          <button type="button" className="btn primary" onClick={() => onScan("@")}>Scan this computer</button>
        </div>
      )}
      {scans && scans.length > 0 && (
        <div className="card">
          <ul className="results">
            {shown.map((s) => (
              <li key={s.id}>
                <a className="result scan-row" href={href(s.id)}>
                  <Mark scan={s} />
                  <span className="scan-target">{s.command.replace(/^@\s*/, "") || s.target}</span>
                  <span className="result-what">
                    {s.status === "done" ? <Severities counts={s.findings} /> : <span className="muted">{s.status === "failed" ? "Failed" : s.status === "queued" ? "Queued" : "Scanning"}</span>}
                  </span>
                  <span className="result-meta">{ago(s.created)}</span>
                  <Icon name="chevron_right" className="result-go" />
                </a>
              </li>
            ))}
          </ul>
          {pager}
        </div>
      )}
    </>
  );
}

function Severities({ counts }: { counts: Record<Severity, number> }) {
  const shown = (["high", "medium", "low"] as const).filter((s) => counts[s] > 0);
  if (!shown.length) return <span className="muted">Nothing serious</span>;
  return (
    <span className="chips">
      {shown.map((s) => <span key={s} className={"chip " + SEVERITY[s]}>{counts[s]} {s}</span>)}
    </span>
  );
}

// ScanBar is the `@` command line: type a host, a host and port, or any of
// the CLI's options, press Enter, it scans. Focused, it lists the recent
// scans, narrowed to what's typed; with nothing typed, the first row scans
// this computer, as an empty Enter does.
function ScanBar({ scans, onScan }: { scans: ScanRow[] | null; onScan: (command: string) => Promise<void> }) {
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        input.current?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const needle = q.trim().toLowerCase();
  const recent = (scans ?? []).filter((s) => !needle || s.command.toLowerCase().includes(needle) || s.target.toLowerCase().includes(needle)).slice(0, 6);
  const items: (ScanRow | null)[] = needle ? recent : [null, ...recent];
  const listed = open && items.length > 0;

  const close = () => {
    setOpen(false);
    setActive(-1);
  };

  const scan = async (line: string) => {
    if (busy) return;
    close();
    setBusy(true);
    await onScan(line.startsWith("@") ? line : "@ " + line);
    setBusy(false);
    setQ("");
    input.current?.blur();
  };

  const choose = (s: ScanRow | null) => {
    if (!s) return scan("");
    close();
    setQ("");
    input.current?.blur();
    go(s.id);
  };

  const onKeyDown = (e: KeyEvent) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      setOpen(true);
      const step = e.key === "ArrowDown" ? 1 : -1;
      setActive((a) => Math.max(-1, Math.min(items.length - 1, a + step)));
    } else if (e.key === "Enter" && listed && active >= 0) {
      e.preventDefault();
      choose(items[active]);
    } else if (e.key === "Escape") {
      if (listed) close();
      else input.current?.blur();
    }
  };

  return (
    <form className="search" role="search" autoComplete="off" onSubmit={(e) => {
      e.preventDefault();
      scan(q.trim());
    }}>
      <Icon name="search" className="search-icon" />
      <input ref={input} type="text" name="scan-command" aria-label="Scan a host" placeholder="Search"
        role="combobox" aria-expanded={listed} aria-controls="recent" aria-autocomplete="list"
        aria-activedescendant={listed && active >= 0 ? "recent-" + active : undefined}
        autoComplete="off" autoCorrect="off" autoCapitalize="off" spellCheck={false} data-1p-ignore data-lpignore="true"
        value={q} onFocus={() => setOpen(true)} onBlur={close} onKeyDown={onKeyDown}
        onChange={(e) => {
          setQ(e.target.value);
          setOpen(true);
          setActive(-1);
        }} />
      {busy ? <span className="spinner" aria-label="Starting" /> : <kbd>Ctrl+K</kbd>}
      {listed && (
        <div className="recent">
          <ul id="recent" role="listbox" aria-label="Recent scans">
            {items.map((s, i) => (
              <li key={s?.id ?? "local"} id={"recent-" + i} role="option" aria-selected={i === active}
                className={"recent-item" + (i === active ? " active" : "")}
                onMouseDown={(e) => e.preventDefault()} onMouseEnter={() => setActive(i)} onClick={() => choose(s)}>
                {s ? (
                  <>
                    <Mark scan={s} />
                    <span className="recent-target">{s.command.replace(/^@\s*/, "") || s.target}</span>
                    <span className="recent-when">{ago(s.created)}</span>
                  </>
                ) : (
                  <>
                    <Icon name="lan" size={18} />
                    <span className="recent-target">Scan this computer</span>
                  </>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </form>
  );
}

// Mark is a scan's status in the list: a spinner while it runs, then a dot
// coloured by the worst thing it found.
function Mark({ scan }: { scan: ScanRow }) {
  if (scan.status === "queued" || scan.status === "running") {
    return <span className="spinner small" aria-label="Running" />;
  }
  const health = scan.status === "failed" || scan.findings.high ? "bad" : scan.findings.medium ? "warn" : "ok";
  const label = scan.status === "failed" ? "Failed" : scan.findings.high ? "High findings" : scan.findings.medium ? "Medium findings" : "Nothing serious";
  return <span className={"dot " + health} role="img" aria-label={label} title={label} />;
}

function ago(ms: number) {
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(ms).toLocaleDateString();
}
