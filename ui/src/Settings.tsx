import { useEffect, useState, type ReactNode } from "react";
import { api } from "./api";
import { Dropdown, type Option } from "./Dropdown";
import { save } from "./export";
import { Icon, type IconName } from "./Icon";
import { BASE, loadDefaults, loadLook, saveDefaults, saveLook, withDefaults, type Defaults, type Look } from "./prefs";
import { Card } from "./ScanView";
import type { ScanRow } from "./types";

// The sections, in the order the sidebar lists them.
export const SETTINGS: [string, string, IconName][] = [
  ["appearance", "Appearance", "brightness_auto"],
  ["scanning", "Scanning", "search"],
  ["data", "Scan data", "download"],
  ["about", "About", "info"],
];

// Settings is the dashboard's preferences, a section per page in the
// sidebar: how it looks and the options new scans start with, kept in this
// browser, and the scans the dashboard keeps.
export function Settings({ section, scans, onChanged }: { section: string; scans: ScanRow[] | null; onChanged: () => Promise<void> }) {
  const [key, title] = SETTINGS.find(([k]) => k === section) ?? SETTINGS[0];
  return (
    <>
      <div className="page-head">
        <div className="page-head-main">
          <h1>Settings</h1>
          <div className="page-sub">Kept in this browser, apart from the scans, which the dashboard keeps</div>
        </div>
      </div>
      <div className="page-body stack flow" key={key}>
        <h2 className="doc-title">{title}</h2>
        {key === "appearance" && <Appearance />}
        {key === "scanning" && <Scanning />}
        {key === "data" && <Data scans={scans} onChanged={onChanged} />}
        {key === "about" && <About />}
      </div>
    </>
  );
}

const THEMES: Option<string>[] = [
  { value: "system", label: "System", hint: "Follow this computer", icon: "brightness_auto" },
  { value: "light", label: "Light", icon: "light_mode" },
  { value: "dark", label: "Dark", icon: "dark_mode" },
];
const MOTION: Option<string>[] = [
  { value: "system", label: "System", hint: "Follow this computer's setting" },
  { value: "reduce", label: "Reduced", hint: "No sliding, fading or rolling numbers" },
];
const DENSITY: Option<string>[] = [
  { value: "system", label: "Comfortable", hint: "Roomy rows" },
  { value: "compact", label: "Compact", hint: "More rows on screen" },
];

function Appearance() {
  const [look, setLook] = useState(() => ({ theme: loadLook("theme"), motion: loadLook("motion"), density: loadLook("density") }));
  const set = (key: Look) => (value: string) => {
    saveLook(key, value);
    setLook((l) => ({ ...l, [key]: value }));
  };
  return (
    <Card title="Look and feel">
      <Row title="Theme" sub="Light, dark, or whatever this computer is set to">
        <Dropdown label="Theme" value={look.theme} options={THEMES} onChange={set("theme")} />
      </Row>
      <Row title="Motion" sub="Animations as pages and results change">
        <Dropdown label="Motion" value={look.motion} options={MOTION} onChange={set("motion")} />
      </Row>
      <Row title="Density" sub="How tightly lists and tables are packed">
        <Dropdown label="Density" value={look.density} options={DENSITY} onChange={set("density")} />
      </Row>
    </Card>
  );
}

const ms = (values: number[]) => values.map((v): Option<number> => ({ value: v, label: v < 1000 ? `${v} ms` : `${v / 1000} s`, hint: v === BASE.connectTimeout ? "Default" : undefined }));
const counts = (values: number[], base: number) => values.map((v): Option<number> => ({ value: v, label: String(v), hint: v === base ? "Default" : undefined }));
const secs = (values: number[]) => values.map((v): Option<number> => ({ value: v, label: `${v} s`, hint: v === BASE.httpTimeout ? "Default" : undefined }));

function Scanning() {
  const [d, setD] = useState<Defaults>(loadDefaults);
  const set = (change: Partial<Defaults>) => {
    const next = { ...d, ...change };
    setD(next);
    saveDefaults(next);
  };
  const added = withDefaults("@ host").slice("@ host".length).trim();
  return (
    <>
      <Card title="Discovery">
        <Row title="Skip HTTP discovery" sub="Report open ports only, as --no-discovery">
          <Switch label="Skip HTTP discovery" on={d.noDiscovery} onChange={(v) => set({ noDiscovery: v })} />
        </Row>
        <Row title="Strict TLS" sub="Refuse invalid and self-signed certificates instead of inspecting them, as --strict-tls">
          <Switch label="Strict TLS" on={d.strictTls} onChange={(v) => set({ strictTls: v })} />
        </Row>
      </Card>
      <Card title="Rate limiting">
        <Row title="Probe rate limiting" sub="Send a short burst to each open endpoint to see whether it throttles, as --probe-rate-limit">
          <Switch label="Probe rate limiting" on={d.probeRateLimit} onChange={(v) => set({ probeRateLimit: v })} />
        </Row>
        <Row title="Burst size" sub="Requests per burst, as --burst">
          <Dropdown label="Burst size" value={d.burst} options={counts([5, 15, 30, 60], BASE.burst)} onChange={(v) => set({ burst: v })} />
        </Row>
      </Card>
      <Card title="Timing">
        <Row title="Connect timeout" sub="How long each port gets to answer">
          <Dropdown label="Connect timeout" value={d.connectTimeout} options={ms([400, 800, 1500, 3000])} onChange={(v) => set({ connectTimeout: v })} />
        </Row>
        <Row title="HTTP timeout" sub="How long each request gets">
          <Dropdown label="HTTP timeout" value={d.httpTimeout} options={secs([3, 6, 10, 20])} onChange={(v) => set({ httpTimeout: v })} />
        </Row>
        <Row title="Concurrency" sub="Ports probed at once">
          <Dropdown label="Concurrency" value={d.concurrency} options={counts([64, 256, 512, 1024], BASE.concurrency)} onChange={(v) => set({ concurrency: v })} />
        </Row>
      </Card>
      <Card title="Every new scan gets" sub="Added after what you type, unless the line sets it itself">
        <div className="preview"><code>{added || "Nothing; the CLI's defaults"}</code></div>
      </Card>
    </>
  );
}

function Data({ scans, onChanged }: { scans: ScanRow[] | null; onChanged: () => Promise<void> }) {
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState("");
  const all = scans ?? [];
  const done = all.filter((s) => s.status === "done");
  const failed = all.filter((s) => s.status === "failed");
  const running = all.length - done.length - failed.length;
  const finished = [...done, ...failed];

  // Clearing asks twice: the first press arms it for a few seconds.
  useEffect(() => {
    if (!confirm) return;
    const t = setTimeout(() => setConfirm(false), 4000);
    return () => clearTimeout(t);
  }, [confirm]);

  const exportAll = async () => {
    setBusy("export");
    try {
      const reports = await Promise.all(done.map((s) => api.scan(s.id)));
      const body = reports.map((s) => ({ target: s.target, command: s.command, created: new Date(s.created).toISOString(), report: s.report }));
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
      <div className="tally four">
        <div className="tally-item"><b>{all.length}</b><span>Kept</span></div>
        <div className="tally-item ok"><b>{done.length}</b><span>Finished</span></div>
        <div className="tally-item bad"><b>{failed.length}</b><span>Failed</span></div>
        <div className="tally-item plain"><b>{running}</b><span>Running</span></div>
      </div>
      <Card title="Keeping" sub="The dashboard keeps the last 100 scans, in its data folder, across restarts">
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
    </>
  );
}

function About() {
  const [version, setVersion] = useState("");
  useEffect(() => {
    api.health().then((h) => setVersion(h.version ?? "")).catch(() => setVersion(""));
  }, []);
  return (
    <>
      <Card title="EPS" sub="Read-only reconnaissance: open ports, endpoints and their posture">
        <Row title="Version"><span className="mono">{version || "Unknown"}</span></Row>
        <Row title="Source" sub="Issues, releases and the CLI"><a className="btn" href="https://github.com/KrisPowers/eps" target="_blank" rel="noreferrer">GitHub</a></Row>
        <Row title="License"><span>Apache 2.0</span></Row>
      </Card>
      <Card title="This dashboard">
        <Row title="Address" sub="It answers only requests addressed to this computer"><span className="mono">{location.host}</span></Row>
        <Row title="Scans at once" sub="Others wait their turn"><span>2</span></Row>
        <Row title="Help" sub="How to start a scan and read what comes back"><a className="btn" href="#/docs">Open</a></Row>
      </Card>
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
