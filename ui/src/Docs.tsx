import type { ReactNode } from "react";
import type { IconName } from "./Icon";

// Docs is the help the header's ? opens, a section per page in the sidebar:
// starting a scan, the options, reading each page of a scan, the blocks and
// severities, exporting, the terminal, and using it lawfully.

const OPTIONS: [string, string, string][] = [
  ["--no-discovery", "off", "Report open ports only; skip the HTTP phase, so no endpoints, headers, TLS or API documents."],
  ["--connect-timeout <MS>", "800", "How long each port gets to accept a connection. Raise it for slow or distant networks."],
  ["--http-timeout <SECS>", "6", "How long each HTTP request gets."],
  ["--concurrency <N>", "256", "Ports probed at once. Lower it if a firewall or the network starts dropping probes."],
  ["--probe-rate-limit", "off", "Send a short burst to each open endpoint to see whether it throttles. Passive header checks always run."],
  ["--burst <N>", "15", "Requests per burst with --probe-rate-limit."],
  ["--strict-tls", "off", "Refuse invalid or self-signed certificates instead of inspecting them anyway."],
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

const SEVERITIES: [string, string, string[]][] = [
  ["high", "bad", [
    "A sensitive endpoint open without auth, such as /actuator/env, /.env or /.git/HEAD",
    "A high-risk service exposed: Redis, MongoDB, a database, the Docker API, etcd, kubelet, Telnet",
  ]],
  ["medium", "warn", [
    "Exposed services like RDP, VNC, SMB, FTP or message brokers",
    "An expired TLS certificate, or TLS 1.0 or 1.1 still accepted",
    "CORS allowing any origin with credentials",
    "An API document listing write operations without auth",
    "SPF that lets any server send",
  ]],
  ["low", "plain", [
    "Cleartext HTTP carrying open endpoints",
    "Open APIs with no rate-limit headers, or no throttling under a burst",
    "A self-signed certificate, or one expiring within 30 days",
    "HTTPS without HSTS, pages without CSP or framing protection, cookies missing their flags",
    "No SPF or DMARC for a domain that takes mail, or DMARC that only monitors",
  ]],
  ["info", "ok", ["Good signs, such as a sensitive path correctly behind auth"]],
];

// The sections, in the order the sidebar lists them.
export const DOCS: [string, string, IconName][] = [
  ["start", "Starting a scan", "search"],
  ["options", "Options", "settings"],
  ["findings", "Findings and ports", "shield"],
  ["pages", "Other pages", "dns"],
  ["ranges", "Network ranges", "devices"],
  ["blocks", "Controls and headers", "lock"],
  ["severities", "Severities", "warning"],
  ["export", "Exporting", "download"],
  ["cli", "The terminal", "menu"],
  ["use", "Authorized use", "info"],
];

export function Docs({ section }: { section: string }) {
  const [key, title] = DOCS.find(([k]) => k === section) ?? DOCS[0];
  return (
    <>
      <div className="page-head">
        <div className="page-head-main">
          <h1>Help</h1>
          <div className="page-sub">How to scan, and how to read what comes back</div>
        </div>
      </div>
      <article className="page-body docs flow" key={key}>
        <h2 className="doc-title">{title}</h2>
        {SECTIONS[key]}
      </article>
    </>
  );
}

function Doc({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="card doc">
      {title && <h3>{title}</h3>}
      {children}
    </section>
  );
}

const SECTIONS: Record<string, ReactNode> = {
  start: (
    <>
      <Doc title="The search bar">
        <p>The search bar is the <code>@</code> command line. Type what you'd type after <code>@</code> in a terminal and press Enter.</p>
        <ul className="examples">
          <li><code>192.168.1.10</code><span>every TCP port, then the HTTP services on them</span></li>
          <li><code>192.168.1.10:8080</code><span>one port only</span></li>
          <li><code>api.internal</code><span>a name, resolved by the system resolver</span></li>
          <li><code>https://shop.example/login</code><span>a URL: its host is scanned in full, and its path checked with the usual endpoints</span></li>
          <li><code>[2001:db8::1]:443</code><span>IPv6, bracketed when a port is attached</span></li>
          <li><code>api.internal --no-discovery</code><span>with any of the options</span></li>
          <li><code>192.168.1.0/24</code><span>a range: which hosts are up</span></li>
        </ul>
      </Doc>
      <Doc title="Shortcuts">
        <ul className="examples">
          <li><kbd>Ctrl+K</kbd><span>focus the search bar from anywhere</span></li>
          <li><kbd>Enter</kbd><span>on an empty bar, scan this computer</span></li>
          <li><kbd>Arrow keys</kbd><span>move through the recent scans listed under the bar; Enter opens one</span></li>
        </ul>
      </Doc>
      <Doc title="Defaults">
        <p>Settings can add options to every new scan, such as a longer timeout or rate-limit probing. A line that sets an option itself keeps its own, and <b>Scan again</b> reruns the line exactly as first typed.</p>
      </Doc>
      <Doc title="While it runs">
        <p>A full scan tries all 65,535 ports, two scans at a time; others wait their turn. The port being reached rolls past in the middle of the page, and each open port's results show as soon as it is done.</p>
      </Doc>
    </>
  ),
  options: (
    <>
      <Doc>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Option</th><th>Default</th><th className="grow">What it does</th></tr></thead>
            <tbody>
              {OPTIONS.map(([flag, base, what]) => (
                <tr key={flag}><td className="mono">{flag}</td><td className="mono muted">{base}</td><td className="wrap">{what}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </Doc>
      <Doc title="Only in a terminal">
        <p><code>--paths &lt;FILE&gt;</code> replaces the endpoint list with your own, one path per line, <code>!</code> marking a sensitive one. <code>--json</code> prints the report as JSON and <code>--fail-on-high</code> exits with 2 on a high finding. <code>--serve</code> runs this dashboard.</p>
      </Doc>
    </>
  ),
  findings: (
    <>
      <Doc title="Findings">
        <p>A scan opens on its <b>Findings</b>: a tile per open port, worst first, with the software on it, its worst severity and how many endpoints it serves, filtered by severity. Ports that are only open, with no endpoints or findings, hide behind a count under the tiles; click it to show them.</p>
      </Doc>
      <Doc title="A port's page">
        <p>Open a port for its own page: its findings, worst first; its TLS certificate when it serves HTTPS; and every endpoint found on it, with a block per security control and header.</p>
        <p>The arrows step to the ports either side, in the same order as Findings.</p>
      </Doc>
      <Doc title="Greetings">
        <p>Services that speak first on connect, such as SSH, FTP, SMTP and MySQL, show what they said under their name, often their version. portscan only listens for it; nothing is sent.</p>
      </Doc>
      <Doc title="TLS">
        <p>An HTTPS port's certificate: who it names, who issued it, the dates it is good for, the names it covers, and whether it signed itself. The port is also tried with TLS 1.0 and 1.1, each offered alone, to see whether it still accepts them.</p>
      </Doc>
    </>
  ),
  pages: (
    <>
      <Doc title="Software">
        <p>The software recognized on each port, from what the scan already saw: <code>Server</code> and <code>X-Powered-By</code> headers, session cookie names, paths only one product answers, and service greetings. Versions show where the software names them. Each opens a page of the ports it was seen on.</p>
      </Doc>
      <Doc title="API">
        <p>Any OpenAPI or Swagger document a port serves without auth at a conventional path, such as <code>/openapi.json</code> or <code>/v3/api-docs</code>, read for every operation it lists. Operations that change data with no security requirement declared are marked.</p>
      </Doc>
      <Doc title="DNS">
        <p>The target's records in a table you can filter by type, asked of the resolver the dashboard uses: addresses, aliases, mail and name servers, TXT and CAA, its DMARC policy, and the reverse name of the address scanned. A domain that takes mail gets its SPF and DMARC state on one line under the table.</p>
      </Doc>
      <Doc title="Subdomains">
        <p>Other names under the target's domain: from the public certificate transparency logs (Cert Spotter and crt.sh, asked at once), where every certificate a public authority issues is recorded, so any subdomain that ever had one shows up; from about sixty common names (www, api, admin, staging, ...) that resolve; and from the site's own links. Guesses are skipped for a domain that answers for any name. Each says whether it still resolves, and any that does can be scanned.</p>
      </Doc>
      <Doc title="Sitemap">
        <p>Every path on each website the scan finds: from <code>/</code> and the path in your URL, the site's <code>robots.txt</code> (paths it disallows too) and its sitemaps, its own links up to three deep, and the routes its own scripts name, which a single-page app never links in its markup. Each with its status and title. Pages it links to on its other subdomains are listed too, under their own name, without being fetched.</p>
      </Doc>
      <Doc title="Client-side">
        <p>What the site's pages would do in your browser, checked so you never have to open them. The scanner fetches each page and every script it loads, from the site or anywhere else, and reads them without running anything, for code that asks for your location or looks up your IP address, can reveal your local IP over WebRTC, fingerprints your device or browser, asks for your camera, microphone, sensors or clipboard, watches your keystrokes, mines cryptocurrency or hides itself; and for hidden frames, password forms that post to another site, redirects, trackers and session recorders. Serious ones show on Findings too.</p>
        <p>Code that only builds these calls as it runs can slip past a reading, so a clean result means nothing was found, not that nothing is there.</p>
      </Doc>
      <Doc title="History">
        <p>Every kept scan of the same target, newest first, with what it found. Open a scan to see what changed from the one before it: ports that opened or closed, findings that are new or resolved. The scan running counts what it has found so far.</p>
      </Doc>
    </>
  ),
  ranges: (
    <>
      <Doc title="Scanning a range">
        <p>An IPv4 range, such as <code>192.168.1.0/24</code>, up to a <code>/20</code> (4,096 addresses), probes the common ports on every address in it. The network and broadcast addresses are left out.</p>
      </Doc>
      <Doc title="Hosts">
        <p>A range opens on its <b>Hosts</b>: each host that answered, with its open ports, then any risky services among them. <b>Scan host</b> starts a full scan of one. Ranges skip the HTTP phase.</p>
      </Doc>
    </>
  ),
  blocks: (
    <>
      <Doc title="Verdicts">
        <p>Each block is coloured by its verdict:</p>
        <div className="legend">
          <span className="legend-item"><span className="swatch configured" />Configured</span>
          <span className="legend-item"><span className="swatch insecure" />Configured but bypassable</span>
          <span className="legend-item"><span className="swatch missing" />Not configured</span>
          <span className="legend-item"><span className="swatch unknown" />The response doesn't show</span>
        </div>
      </Doc>
      <Doc title="Controls">
        <ul className="examples">
          {CONTROLS.map(([name, what]) => <li key={name}><span className="control unknown">{name}</span><span>{what}</span></li>)}
        </ul>
      </Doc>
      <Doc title="Headers">
        <p>Headers that only matter on pages, such as CSP, don't show for other responses.</p>
        <ul className="examples">
          {HEADERS.map(([name, what]) => <li key={name}><span className="control unknown">{name}</span><span>{what}</span></li>)}
        </ul>
      </Doc>
    </>
  ),
  severities: (
    <>
      {SEVERITIES.map(([name, tone, what]) => (
        <Doc key={name}>
          <span className={"chip " + tone}>{name}</span>
          <ul className="bullets">{what.map((w) => <li key={w}>{w}</li>)}</ul>
        </Doc>
      ))}
      <Doc>
        <p className="muted">portscan reports exposure, never intent: it can't know whether a host is meant to be public. Severities help you triage; the call is yours.</p>
      </Doc>
    </>
  ),
  export: (
    <>
      <Doc title="One scan">
        <p><b>Export</b>, on a finished scan, downloads it as:</p>
        <ul className="examples">
          <li><b>JSON</b><span>the same report <code>--json</code> prints</span></li>
          <li><b>Markdown</b><span>a summary, the ports, findings and endpoints, to paste into a ticket</span></li>
          <li><b>SARIF</b><span>for code-scanning tools such as GitHub's</span></li>
        </ul>
      </Doc>
      <Doc title="Every scan">
        <p>Settings, under Scan data, exports every finished scan's report in one JSON file.</p>
      </Doc>
    </>
  ),
  cli: (
    <>
      <Doc title="The same scans in a terminal">
        <p>The CLI is the same scanner, installed as <code>@</code>:</p>
        <ul className="examples">
          <li><code>@</code><span>scan this machine</span></li>
          <li><code>@ 192.168.1.10</code><span>every port, then the HTTP services</span></li>
          <li><code>@ api.internal --json</code><span>machine-readable, for pipelines</span></li>
          <li><code>@ 10.0.0.5 --fail-on-high</code><span>exit 2 on a high finding, for CI gates</span></li>
        </ul>
      </Doc>
      <Doc title="Exit codes">
        <ul className="examples">
          <li><code>0</code><span>ran successfully</span></li>
          <li><code>1</code><span>an error, such as a bad target or a name that doesn't resolve</span></li>
          <li><code>2</code><span>ran, and a high finding was reported, with <code>--fail-on-high</code></span></li>
        </ul>
      </Doc>
    </>
  ),
  use: (
    <>
      <Doc title="Read-only">
        <p>portscan makes ordinary TCP connections and HTTP <code>GET</code> requests. It never writes, submits, logs in, changes or exploits anything; it reports exposure and you decide what to do about it.</p>
      </Doc>
      <Doc title="Authorized use only">
        <p>Scan only hosts you own or are explicitly allowed to test. Probing systems you don't control may be unlawful and against provider terms, even read-only. You are responsible for how you use it.</p>
      </Doc>
      <Doc title="This dashboard">
        <p>The dashboard has no sign-in, so it only answers requests addressed to this computer. To reach it by another name, list the name in <code>PORTSCAN_HOSTS</code> and put your own sign-in in front of it.</p>
      </Doc>
    </>
  ),
};
