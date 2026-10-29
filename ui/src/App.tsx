import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import { Icon } from "./Icon";
import { ScanView } from "./ScanView";
import type { Report, ScanRow } from "./types";

// The scan shown is the one named in the URL hash, `#/<id>`.
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
  const [navOpen, setNavOpen] = useState(false);

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
      setId(readHash());
      setNavOpen(false);
    };
    addEventListener("hashchange", onHash);
    return () => removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(""), 5000);
    return () => clearTimeout(t);
  }, [toast]);

  const selected = id ? scans?.find((s) => s.id === id) : scans?.[0];

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

  return (
    <div className={"app" + (navOpen ? " nav-open" : "")}>
      <header className="header">
        <button type="button" className="icon-btn nav-toggle" aria-label="Scans" onClick={() => setNavOpen(!navOpen)}>
          <Icon name="left_panel_open" />
        </button>
        <a className="brand" href="#/">
          <Icon name="lan" size={26} />
          <span>portscan</span>
        </a>
        <ScanBar onScan={start} />
      </header>

      <nav className="sidebar" aria-label="Scans">
        <h2 className="sidebar-title">Scans</h2>
        {scans?.map((s) => (
          <a key={s.id} href={"#/" + encodeURIComponent(s.id)} className={"nav-item scan-item" + (s.id === selected?.id ? " active" : "")}>
            <Mark scan={s} />
            <span className="scan-item-text">
              <span className="scan-item-target">{s.target}</span>
              <span className="scan-item-when">{ago(s.created)}</span>
            </span>
          </a>
        ))}
        {scans?.length === 0 && <p className="sidebar-empty">No scans yet</p>}
      </nav>

      <main className="main">
        <div className="page" key={selected?.id ?? ""}>
          {problem && !scans && (
            <div className="callout bad"><Icon name="error" /><span>Can't reach portscan: {problem}</span></div>
          )}
          {selected ? (
            <ScanView scan={selected} report={reports[selected.id]} onAgain={() => start(selected.command || selected.target)} onDelete={() => remove(selected)} />
          ) : (
            scans && <Home onScan={start} />
          )}
        </div>
      </main>

      {toast && (
        <div className="toast bad" role="alert"><Icon name="error" /><span>{toast}</span></div>
      )}
    </div>
  );
}

// ScanBar is the header's command line: the `@` is already there, type a
// target and any of the CLI's options, press Enter, it scans.
function ScanBar({ onScan }: { onScan: (command: string) => Promise<void> }) {
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
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

  return (
    <form className="command" role="search" autoComplete="off" onSubmit={async (e) => {
      e.preventDefault();
      const line = q.trim();
      if (busy) return;
      setBusy(true);
      await onScan(line.startsWith("@") ? line : "@ " + line);
      setBusy(false);
      setQ("");
      input.current?.blur();
    }}>
      <span className="at" aria-hidden="true">@</span>
      <input ref={input} type="text" name="scan-command" aria-label="Scan command" placeholder="host[:port] [options]"
        autoComplete="off" autoCorrect="off" autoCapitalize="off" spellCheck={false} data-1p-ignore data-lpignore="true"
        value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Escape" && input.current?.blur()} />
      {busy ? <span className="spinner" aria-label="Starting" /> : <kbd>Ctrl+K</kbd>}
    </form>
  );
}

function Home({ onScan }: { onScan: (command: string) => Promise<void> }) {
  return (
    <div className="home">
      <Icon name="lan" size={48} />
      <h1>Scan a host to see what it exposes</h1>
      <button type="button" className="btn primary" onClick={() => onScan("@")}>
        <Icon name="search" size={18} /><span>Scan this computer</span>
      </button>
      <p className="muted small">Scan only hosts you own or are allowed to test.</p>
    </div>
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
