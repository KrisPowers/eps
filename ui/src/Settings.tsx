import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "./api";
import { useDismiss } from "./dismiss";
import { save } from "./export";
import { Icon } from "./Icon";
import { BASE, loadDefaults, saveDefaults, type Defaults } from "./prefs";
import { Card } from "./ScanView";
import type { ScanRow } from "./types";

type Theme = "system" | "light" | "dark";
const THEMES: [Theme, string][] = [["system", "System"], ["light", "Light"], ["dark", "Dark"]];
const TIMEOUTS: [number, string][] = [[400, "400 ms"], [800, "800 ms"], [1500, "1.5 s"], [3000, "3 s"]];
const CONCURRENCY: [number, string][] = [[64, "64"], [256, "256"], [512, "512"], [1024, "1024"]];

// Settings is the dashboard's preferences: the theme and the options every
// scan starts with, kept in this browser, and the scans the dashboard keeps.
export function Settings({ scans, onChanged }: { scans: ScanRow[] | null; onChanged: () => Promise<void> }) {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const t = localStorage.getItem("theme");
      return t === "light" || t === "dark" ? t : "system";
    } catch {
      return "system";
    }
  });
  const [d, setD] = useState<Defaults>(loadDefaults);
  const [version, setVersion] = useState("");
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState("");

  // index.html applies the theme kept here before the page draws.
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") delete root.dataset.theme;
    else root.dataset.theme = theme;
    try {
      if (theme === "system") localStorage.removeItem("theme");
      else localStorage.setItem("theme", theme);
    } catch {
      // Not kept, still applied.
    }
  }, [theme]);

  useEffect(() => {
    api.health().then((h) => setVersion(h.version ?? "")).catch(() => setVersion(""));
  }, []);

  // Clearing asks twice: the first press arms it for a few seconds.
  useEffect(() => {
    if (!confirm) return;
    const t = setTimeout(() => setConfirm(false), 4000);
    return () => clearTimeout(t);
  }, [confirm]);

  const set = (change: Partial<Defaults>) => {
    const next = { ...d, ...change };
    setD(next);
    saveDefaults(next);
  };

  const done = (scans ?? []).filter((s) => s.status === "done");
  const finished = (scans ?? []).filter((s) => s.status === "done" || s.status === "failed");

  const exportAll = async () => {
    setBusy("export");
    try {
      const all = await Promise.all(done.map((s) => api.scan(s.id)));
      const body = all.map((s) => ({ target: s.target, command: s.command, created: new Date(s.created).toISOString(), report: s.report }));
      save(`scans-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(body, null, 2), "application/json");
    } finally {
      setBusy("");
    }
  };

  const clear = async () => {
    if (!confirm) return setConfirm(true);
    setConfirm(false);
    setBusy("clear");
    try {
      await api.clear();
      await onChanged();
    } finally {
      setBusy("");
    }
  };

  return (
    <>
      <div className="page-head">
        <div className="page-head-main">
          <h1>Settings</h1>
          <div className="page-sub">Kept in this browser, apart from the scans, which the dashboard keeps</div>
        </div>
      </div>
      <div className="stack">
        <Card title="Appearance">
          <Row title="Theme" sub="Light, dark, or whatever this computer is set to">
            <Dropdown label="Theme" value={theme} options={THEMES} onChange={setTheme} />
          </Row>
        </Card>

        <Card title="Scanning" sub="Added to every scan started from the search bar, unless the line sets it itself">
          <Row title="Skip HTTP discovery" sub="Report open ports only, as --no-discovery">
            <Switch label="Skip HTTP discovery" on={d.noDiscovery} onChange={(v) => set({ noDiscovery: v })} />
          </Row>
          <Row title="Probe rate limiting" sub="Send a short burst to each open endpoint to see whether it throttles, as --probe-rate-limit">
            <Switch label="Probe rate limiting" on={d.probeRateLimit} onChange={(v) => set({ probeRateLimit: v })} />
          </Row>
          <Row title="Strict TLS" sub="Refuse invalid and self-signed certificates instead of inspecting them, as --strict-tls">
            <Switch label="Strict TLS" on={d.strictTls} onChange={(v) => set({ strictTls: v })} />
          </Row>
          <Row title="Connect timeout" sub={`How long each port gets to answer; ${BASE.connectTimeout} ms unless set`}>
            <Dropdown label="Connect timeout" value={d.connectTimeout} options={TIMEOUTS} onChange={(v) => set({ connectTimeout: v })} />
          </Row>
          <Row title="Concurrency" sub={`Ports probed at once; ${BASE.concurrency} unless set`}>
            <Dropdown label="Concurrency" value={d.concurrency} options={CONCURRENCY} onChange={(v) => set({ concurrency: v })} />
          </Row>
        </Card>

        <Card title="Scan data" sub={`${scans?.length ?? 0} scans kept; the dashboard keeps the last 100`}>
          <Row title="Export every scan" sub="Each finished scan's report, in one JSON file">
            <button type="button" className="btn" disabled={!done.length || busy !== ""} onClick={exportAll}>
              {busy === "export" ? <span className="spinner small" /> : <Icon name="download" size={18} />}<span>Export</span>
            </button>
          </Row>
          <Row title="Clear finished scans" sub="Forget every finished or failed scan. Scans still running are kept.">
            <button type="button" className={"btn danger" + (confirm ? " armed" : "")} disabled={!finished.length || busy !== ""} onClick={clear}>
              {busy === "clear" ? <span className="spinner small" /> : <Icon name="delete" size={18} />}
              <span>{confirm ? `Clear ${finished.length} ${finished.length === 1 ? "scan" : "scans"}` : "Clear"}</span>
            </button>
          </Row>
        </Card>

        <Card title="About">
          <Row title="Version"><span className="mono">{version || "Unknown"}</span></Row>
          <Row title="Help" sub="How to start a scan and read what comes back"><a className="btn" href="#/docs">Open</a></Row>
        </Card>
      </div>
    </>
  );
}

function Row({ title, sub, children }: { title: string; sub?: string; children: ReactNode }) {
  return (
    <div className="setting">
      <div className="setting-text">
        <div className="setting-title">{title}</div>
        {sub && <div className="setting-sub">{sub}</div>}
      </div>
      {children}
    </div>
  );
}

function Switch({ label, on, onChange }: { label: string; on: boolean; onChange: (on: boolean) => void }) {
  return <button type="button" role="switch" aria-checked={on} aria-label={label} className="switch" onClick={() => onChange(!on)}><span /></button>;
}

// Dropdown picks one of `options`, drawn as a field that opens a list.
function Dropdown<T extends string | number>({ label, value, options, onChange }: {
  label: string;
  value: T;
  options: [T, string][];
  onChange: (value: T) => void;
}) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(open, close, box);
  const shown = options.find(([v]) => v === value)?.[1] ?? String(value);
  return (
    <div className="menu-wrap" ref={box}>
      <button type="button" className="select" aria-haspopup="listbox" aria-expanded={open} aria-label={label} onClick={() => setOpen((o) => !o)}>
        <span>{shown}</span>
        <Icon name="chevron_right" size={18} className="select-caret" />
      </button>
      {open && (
        <ul className="menu" role="listbox" aria-label={label}>
          {options.map(([v, text]) => (
            <li key={String(v)} role="option" aria-selected={v === value} className="menu-item"
              onClick={() => {
                onChange(v);
                setOpen(false);
              }}>
              <span>{text}</span>
              {v === value && <Icon name="check" size={18} className="menu-check" />}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
