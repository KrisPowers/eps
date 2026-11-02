# How it works

EPS is a read-only reconnaissance tool for network and software engineers. Give
it a host or IP address, with or without a port, and one scan reports what is
exposed on it and how well each exposed thing is protected.

It makes ordinary TCP connections and HTTP `GET` requests. It never writes,
submits, logs in, changes or exploits anything. It reports exposure; you decide
what to do about it.

## What a scan reads

- **Open ports:** a TCP connect scan (no raw sockets, no root) across all 65,535
  ports.
- **Greetings:** what each service says first on connect, such as SSH's or
  MySQL's version line. EPS only listens; nothing is sent.
- **Endpoints:** for HTTP(S) services, conventional, framework-published paths
  (health probes, metrics, API docs, management consoles, and classic
  over-exposure sources like `/actuator/env` or `/.git/HEAD`).
- **Posture:** for each endpoint, whether it is reachable without
  authentication, served over TLS, and whether rate limiting is advertised or,
  with `--probe-rate-limit`, enforced.
- **TLS:** for each HTTPS service, its certificate (subject, issuer, validity,
  the names it covers, self-signed or not) and whether it still accepts TLS 1.0
  or 1.1, found with a ClientHello offering only that version.
- **Headers:** for each endpoint, its security headers (HSTS, CSP, framing
  protection, `nosniff`, CORS) and the flags on any cookie it sets.
- **Software:** the software recognized on each port (web server, language,
  framework, database, SSH and mail servers, with versions where shown), from
  headers, cookie names, product-specific paths and greetings.
- **API:** any OpenAPI or Swagger document served without auth at a
  conventional path (`/openapi.json`, `/v3/api-docs`, ...), read for the
  operations it lists and whether each requires auth.
- **Sitemap:** every path on each website found: from `/` and a URL's own path,
  `robots.txt` (disallowed paths included) and its sitemaps, its own links up to
  three deep, and the routes its scripts name, which a single-page app never
  links in its markup.
- **Client-side:** what those pages would do in a visitor's browser, so a site
  can be checked before anyone opens it. Each page and every script it loads is
  fetched and read, never run, for code that asks for location or looks up the
  visitor's IP, can reveal a local IP over WebRTC, fingerprints the device,
  reaches for the camera, microphone, sensors or clipboard, watches keystrokes,
  mines cryptocurrency or hides itself; and for hidden frames, redirects,
  trackers and session recorders. Code that only
  builds such calls as it runs can slip past it.
- **Exposure:** what the site itself gives away. Its forms: file uploads (any
  type, or limited only in the browser), passwords filled in, sent in the
  address, over plain HTTP or to another site, credentials in hidden fields, and posts with no
  anti-forgery token. Credentials left in its markup, its own scripts and the
  original source in any source maps it serves (cloud, payment and repository
  keys, private keys, passwords in addresses and in code), shown masked. Every
  request its forms and code make (`fetch`, `XMLHttpRequest`, `axios`, jQuery,
  WebSockets) with its method, flagging admin endpoints, plain HTTP and
  development addresses left in. PHP served as source, from `.php` pages and
  the `.bak`, `~`, `.old`, `.orig` and `.save` copies beside them, read for
  credentials and the parameters it takes. Paths `robots.txt` names that open
  to anyone or point to a login. On WordPress: listed users, XML-RPC, the
  login page, its version, a public debug log, a listable uploads folder,
  setup left open and copies of `wp-config.php`. Every check is a `GET`.
- **DNS:** the target's records (A, AAAA, CNAME, MX, NS, TXT, CAA, DMARC and the
  reverse name), asked of the system resolver, with SPF and DMARC checked for a
  domain that takes mail.
- **Subdomains:** other names under the target's domain, from the public
  certificate transparency logs (crt.sh and Cert Spotter) and about sixty common
  names that resolve, each with whether it still resolves.

Every response body is read up to a fixed size, so a service answering with an
endless body can't exhaust the scanner's memory.

## Findings

Findings are graded by potential impact:

- **HIGH:** an unauthenticated sensitive endpoint (`/actuator/env`, `/metrics`,
  `/.env`, `/.git/HEAD`, ...), or an exposed high-risk service (Redis, MongoDB, a
  database, the Docker API, etcd, kubelet, ...).
- **MEDIUM:** exposed services like RDP, VNC, SMB, FTP or message brokers; an
  expired TLS certificate; TLS 1.0 or 1.1 still accepted; CORS allowing any
  origin with credentials; an API document listing write operations without
  auth.
- **LOW:** cleartext HTTP carrying open endpoints; open API surfaces with no
  rate-limit headers; no throttling observed under an opt-in burst; a
  self-signed certificate, or one expiring within 30 days; no SPF or DMARC for a
  domain that takes mail; HTTPS without HSTS, pages without CSP or framing
  protection, cookies missing their flags.
- **INFO:** positive signals, such as a sensitive path that is correctly behind
  auth.

EPS reports exposure and posture, never intent: it can't know whether a host is
meant to be public. Severities help you triage; the call is yours.

## Authorized use only

Scan only hosts you own or are explicitly authorized to assess. Port scanning and
endpoint probing against systems you don't control may be unlawful and against
provider terms, even though EPS is read-only. You are responsible for how you use
it.
