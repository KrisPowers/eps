import { useCallback, useEffect, useRef, useState, type KeyboardEvent as KeyEvent } from "react";
import { flushSync } from "react-dom";
import { api } from "./api";
import { Icon } from "./Icon";
import { ScanView } from "./ScanView";
import type { Report, ScanRow } from "./types";

// The scan shown is the one named in the URL hash, `#/<id>`; with none, the
// page is just the search bar.
function readHash() {
  return decodeURIComponent(location.hash.replace(/^#\/?/, ""));
}

function go(id: string) {
  location.hash = id ? "/" + encodeURIComponent(id) : "";
}

export function App() {
  const [scans, setScans] = useState<ScanRow[] | null>(null);
  const [reports, setReports] = useState<Record<string, Report>>({});
  const [id, setId] = useState(readHash);
  const [problem, setProblem] = useState("");
  const [toast, setToast] = useState("");
  const shown = useRef(id);
  shown.current = id;

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

  // Between the empty page and a scan, the search bar glides from the
  // middle of the page into the header.
  useEffect(() => {
    const onHash = () => {
      const next = readHash();
      const swap = () => flushSync(() => setId(next));
      const glide = !next !== !shown.current && "startViewTransition" in document && !matchMedia("(prefers-reduced-motion: reduce)").matches;
      if (glide) document.startViewTransition(swap);
      else swap();
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

  // A finished scan's report is fetched once and kept.
  const doneId = selected?.status === "done" ? selected.id : "";
  useEffect(() => {
    if (!doneId || reports[doneId]) return;
    api.scan(doneId)
      .then((d) => d.report && setReports((r) => ({ ...r, [doneId]: d.report! })))
      .catch((e) => setToast((e as Error).message));
  }, [doneId, reports]);

  const start = async (command: string) => {
    try {
      const row = await api.start(command);
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

  const bar = <ScanBar scans={scans} onScan={start} />;
  return (
    <div className="app">
      {id ? (
        <>
          <header className="header">
            <a className="brand" href="#/"><Icon name="lan" size={22} /><span>portscan</span></a>
            {bar}
          </header>
          <main className="page" key={id}>
            {selected && (
              <ScanView scan={selected} report={reports[selected.id]} onAgain={() => start(selected.command || selected.target)} onDelete={() => remove(selected)} />
            )}
          </main>
        </>
      ) : (
        <main className="home">
          <h1 className="wordmark"><Icon name="lan" size={30} /><span>portscan</span></h1>
          {bar}
          {problem && !scans && (
            <div className="callout bad"><Icon name="error" /><span>Can't reach portscan: {problem}</span></div>
          )}
          <p className="home-note">Scan only hosts you own or are allowed to test.</p>
        </main>
      )}

      {toast && (
        <div className="toast bad" role="alert"><Icon name="error" /><span>{toast}</span></div>
      )}
    </div>
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
