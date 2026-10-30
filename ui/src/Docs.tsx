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

const HEADERS: [string, string][] = [
  ["HSTS", "Strict-Transport-Security over HTTPS. Bypassable with max-age=0."],
  ["CSP", "A Content-Security-Policy on pages. Bypassable when it allows unsafe-inline or unsafe-eval."],
  ["FRAME", "X-Frame-Options or CSP frame-ancestors on pages, against clickjacking."],
  ["SNIFF", "X-Content-Type-Options: nosniff."],
  ["CORS", "Access-Control-Allow-Origin. Bypassable when it allows any origin."],
  ["COOKIE", "Every cookie set is HttpOnly, has a SameSite, and is Secure over HTTPS."],
];

const SEVERITIES: [string, string, string][] = [
  ["high", "bad", "A sensitive endpoint open without auth, such as /actuator/env, /.env or /.git/HEAD, or a high-risk service exposed: Redis, MongoDB, a database, the Docker API, etcd, kubelet."],
  ["medium", "warn", "Exposed services like RDP, VNC, SMB, FTP or message brokers; an expired TLS certificate; TLS 1.0 or 1.1 still accepted; CORS allowing any origin with credentials."],
  ["low", "plain", "Cleartext HTTP carrying open endpoints, open APIs with no rate-limit headers, no throttling under a burst, a self-signed certificate or one expiring within 30 days, HTTPS without HSTS, pages without CSP or framing protection, cookies missing their flags."],
  ["info", "ok", "Good signs, such as a sensitive path correctly behind auth."],
];

export function Docs() {
  return (
    <article className="docs">
      <div className="page-head"><div className="page-head-main"><h1>Help</h1></div></div>

      <section className="card doc">
        <h2>Starting a scan</h2>
        <p>The search bar is the <code>@</code> command line. Type what you'd type after <code>@</code> in a terminal and press Enter:</p>
        <ul className="examples">
          <li><code>192.168.1.10</code><span>every TCP port, then the HTTP services on them</span></li>
          <li><code>192.168.1.10:8080</code><span>one port only</span></li>
          <li><code>[2001:db8::1]:443</code><span>IPv6, bracketed when a port is attached</span></li>
          <li><code>api.internal --no-discovery</code><span>with any of the options below</span></li>
          <li><code>192.168.1.0/24</code><span>a range, up to a /20: the common ports on every address, to find the hosts that are up</span></li>
        </ul>
        <p>An empty line scans this computer. Focused, the bar lists your recent scans, narrowed to what you type; <kbd>Ctrl+K</kbd> focuses it from anywhere.</p>
      </section>

      <section className="card doc">
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

      <section className="card doc">
        <h2>Reading a scan</h2>
        <p>A scan opens on its <b>Findings</b>: how many of each severity it found, then every open port, worst first. Open a port for its own page, with the findings on it and the endpoints it serves.</p>
        <p>A port's results show as soon as it is done, while the rest are still being checked. Services that speak first on connect, such as SSH, FTP, SMTP and MySQL, show what they said under their name, often their version.</p>
        <p>An HTTPS port's page shows its certificate: who it names, who issued it, the dates it is good for and the names it covers, and whether the port still accepts TLS 1.0 or 1.1.</p>
        <p>A range opens on its <b>Hosts</b>: each host that answered, with its open ports. <b>Scan host</b> scans one of them in full.</p>
        <p><b>Technologies</b> lists the software recognized on each port, from what the scan already saw: <code>Server</code> and <code>X-Powered-By</code> headers, session cookie names, paths only one product answers, and service greetings.</p>
        <p><b>API</b> reads any OpenAPI or Swagger document a port serves without auth at a conventional path, and lists its operations, marking those that change data with no security requirement declared.</p>
        <p><b>History</b> lists every kept scan of the same target, with a bar per finished scan of what it found, so a trend shows at a glance.</p>
        <p><b>Changes</b> compares a finished scan with the last finished scan of the same target: ports that opened or closed, findings that are new or resolved.</p>
        <p><b>Export</b> downloads a finished scan as JSON, the same report <code>--json</code> prints; Markdown, to paste into a ticket; or SARIF, for code-scanning tools such as GitHub's.</p>
      </section>

      <section className="card doc">
        <h2>Controls</h2>
        <p>Each endpoint has a block per security control, coloured by its verdict:</p>
        <div className="legend">
          <span className="legend-item"><span className="swatch configured" />Configured</span>
          <span className="legend-item"><span className="swatch insecure" />Configured but bypassable</span>
          <span className="legend-item"><span className="swatch missing" />Not configured</span>
          <span className="legend-item"><span className="swatch unknown" />The response doesn't show</span>
        </div>
        <ul className="examples">
          {CONTROLS.map(([name, what]) => <li key={name}><span className="control unknown">{name}</span><span>{what}</span></li>)}
        </ul>
        <p>And a block per security header, coloured the same way. Headers that only matter on pages, such as CSP, don't show for other responses.</p>
        <ul className="examples">
          {HEADERS.map(([name, what]) => <li key={name}><span className="control unknown">{name}</span><span>{what}</span></li>)}
        </ul>
      </section>

      <section className="card doc">
        <h2>Severities</h2>
        <ul className="examples">
          {SEVERITIES.map(([name, tone, what]) => <li key={name}><span className={"chip " + tone}>{name}</span><span>{what}</span></li>)}
        </ul>
        <p className="muted">portscan reports exposure, never intent: it can't know whether a host is meant to be public. The call is yours.</p>
      </section>

      <section className="card doc">
        <h2>Authorized use only</h2>
        <p>portscan is read-only: ordinary TCP connections and HTTP <code>GET</code> requests, nothing written, submitted or logged in to. Scan only hosts you own or are allowed to test; probing systems you don't control may be unlawful.</p>
      </section>
    </article>
  );
}
