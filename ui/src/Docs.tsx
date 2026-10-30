// Docs is the help page the header's ? opens: how to start a scan, the
// options the bar takes, and how to read what comes back.

const OPTIONS: [string, string][] = [
  ["--no-discovery", "Report open ports only; skip HTTP discovery."],
  ["--connect-timeout <MS>", "Per-port TCP connect timeout, default 800 ms."],
  ["--http-timeout <SECS>", "Per-request HTTP timeout, default 6 s."],
  ["--concurrency <N>", "Max concurrent port probes, default 256."],
  ["--probe-rate-limit", "Send a small burst to each open endpoint to see whether throttling kicks in. Passive header checks always run."],
  ["--burst <N>", "Requests per burst with --probe-rate-limit, default 15."],
  ["--strict-tls", "Reject invalid or self-signed certificates instead of inspecting them anyway."],
];

const CONTROLS: [string, string][] = [
  ["AUTH", "A credential gate: a 401 or 403, or a redirect to a login page. Basic auth over plain HTTP is bypassable."],
  ["JWT", "A bearer-token challenge. Bypassable when the token would travel over plain HTTP."],
  ["RATE", "Rate limiting, advertised in headers or enforced with a 429. Bypassable when advertised but not holding under a burst."],
  ["HTTPS", "Served over TLS."],
];

const SEVERITIES: [string, string, string][] = [
  ["high", "bad", "A sensitive endpoint open without auth, such as /actuator/env, /.env or /.git/HEAD, or a high-risk service exposed: Redis, MongoDB, a database, the Docker API, etcd, kubelet."],
  ["medium", "warn", "Exposed services like RDP, VNC, SMB, FTP or message brokers."],
  ["low", "plain", "Cleartext HTTP carrying open endpoints, open APIs with no rate-limit headers, no throttling under a burst."],
  ["info", "ok", "Good signs, such as a sensitive path correctly behind auth."],
];

export function Docs() {
  return (
    <article className="docs">
      <h1 className="page-title">Help</h1>

      <section className="panel doc">
        <h2>Starting a scan</h2>
        <p>The search bar is the <code>@</code> command line. Type what you'd type after <code>@</code> in a terminal and press Enter:</p>
        <ul className="examples">
          <li><code>192.168.1.10</code><span>every TCP port, then the HTTP services on them</span></li>
          <li><code>192.168.1.10:8080</code><span>one port only</span></li>
          <li><code>[2001:db8::1]:443</code><span>IPv6, bracketed when a port is attached</span></li>
          <li><code>api.internal --no-discovery</code><span>with any of the options below</span></li>
        </ul>
        <p>An empty line scans this computer. Focused, the bar lists your recent scans, narrowed to what you type; <kbd>Ctrl+K</kbd> focuses it from anywhere.</p>
      </section>

      <section className="panel doc">
        <h2>Options</h2>
        <div className="table-wrap">
          <table className="table">
            <tbody>
              {OPTIONS.map(([flag, what]) => (
                <tr key={flag}><td className="mono">{flag}</td><td className="wrap">{what}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted"><code>--paths</code> and <code>--serve</code> only work in a terminal.</p>
      </section>

      <section className="panel doc">
        <h2>Reading a scan</h2>
        <p>Once a scan starts, the sidebar holds its pages:</p>
        <ul className="examples">
          <li><b>Ports</b><span>every open port as a tile; each opens a page with that port's findings and endpoints</span></li>
          <li><b>Endpoints</b><span>every HTTP endpoint found, on any port</span></li>
          <li><b>Findings</b><span>everything worth a look, worst first</span></li>
        </ul>
        <p>A port's results show as soon as it is done, while the rest are still being checked.</p>
      </section>

      <section className="panel doc">
        <h2>Controls</h2>
        <p>Each endpoint has a block per security control, coloured by its verdict:</p>
        <div className="legend inline">
          <span className="legend-item"><span className="swatch configured" />Configured</span>
          <span className="legend-item"><span className="swatch insecure" />Configured but bypassable</span>
          <span className="legend-item"><span className="swatch missing" />Not configured</span>
          <span className="legend-item"><span className="swatch unknown" />The response doesn't show</span>
        </div>
        <ul className="examples">
          {CONTROLS.map(([name, what]) => <li key={name}><span className="control unknown">{name}</span><span>{what}</span></li>)}
        </ul>
      </section>

      <section className="panel doc">
        <h2>Severities</h2>
        <ul className="examples">
          {SEVERITIES.map(([name, tone, what]) => <li key={name}><span className={"chip " + tone}>{name}</span><span>{what}</span></li>)}
        </ul>
        <p className="muted">portscan reports exposure, never intent: it can't know whether a host is meant to be public. The call is yours.</p>
      </section>

      <section className="panel doc">
        <h2>Authorized use only</h2>
        <p>portscan is read-only: ordinary TCP connections and HTTP <code>GET</code> requests, nothing written, submitted or logged in to. Scan only hosts you own or are allowed to test; probing systems you don't control may be unlawful.</p>
      </section>
    </article>
  );
}
