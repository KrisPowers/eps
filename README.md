# portscan

**`@ <host>[:port]` - point it at a host and it tells you what's exposed.**

portscan is a read-only reconnaissance tool for network and software engineers.
Its command is `@`. Give it a host or IP address (with or without a port) and it reports, in one
command:

- **Open ports** - a TCP *connect* scan (no raw sockets, no root) across all
  65,535 ports.
- **Endpoints** - for HTTP(S) services it discovers conventional,
  framework-published paths (health probes, metrics, API docs, management
  consoles, and classic over-exposure sources like `/actuator/env` or `/.git/HEAD`).
- **Posture** - for each endpoint it checks whether it is reachable **without
  authentication**, served over **TLS**, and whether **rate limiting / throttling**
  is advertised or enforced.

The goal is to surface low-level exposure early - an endpoint that shouldn't be
open, a port that shouldn't be reachable, a sensitive path with no auth gate - so
you can fix it before someone else finds it.

> **portscan is strictly read-only.** It makes ordinary TCP connections and HTTP `GET`
> requests. It never writes, submits, logs in, mutates, or exploits anything. It
> reports exposure; **you** decide what to do about it.

It comes two ways: a **dashboard** that runs in Docker, where you type a host into
a search bar and watch the scan fill in, and a **CLI** for terminals and CI.

## Dashboard

Needs Docker with Compose v2 ([Docker Desktop](https://docs.docker.com/get-docker/)
on Windows and macOS).

```sh
curl -fsSL https://raw.githubusercontent.com/KrisPowers/portscan/main/compose.yaml -o compose.yaml
docker compose up -d
```

Then open <http://localhost:8090>. The search bar in the header is the `@` command
line: type what you'd type after `@` in a terminal, such as `192.168.1.10:8080` or
`api.internal --no-discovery --probe-rate-limit`, and press Enter. The CLI's
options all work there except `--paths` and `--serve`; an empty line scans this
computer. Focused, the bar lists your recent scans, narrowed to what you type.
The `?` beside it opens the docs, and the theme button picks light, dark or the
system's setting.

Your scans are listed as cards. A scan opens on its **Findings**: a count per
severity, then every open port, worst first. Each port opens its own page with
the findings on it and its endpoints, with the same verdict blocks as the CLI.
Inside a scan, the sidebar's back button returns to the scans. While the scan
runs, a pill carries the port being scanned, and each port shows as soon as it
is done.
The last 100 scans are kept in `%LOCALAPPDATA%\portscan\data` on Windows,
`./portscan/data` next to `compose.yaml` elsewhere.

- **This computer only.** The dashboard has no sign-in, so it's published on
  `127.0.0.1` and answers only requests addressed to `localhost`, `127.0.0.1` or
  `[::1]`. To reach it by another name, list it in `PORTSCAN_HOSTS`
  (comma-separated), and put your own sign-in in front of it.
- **Scanning this computer.** The scans run inside the container, so `localhost`
  is sent to `host.docker.internal`, the computer running Docker
  (`PORTSCAN_LOCALHOST`). Other hosts are reached the way the container reaches
  any network.
- **The CLI from the image.** Arguments run one scan instead of the dashboard:
  `docker run --rm ghcr.io/krispowers/portscan 192.168.1.10`.

From a checkout, `docker compose up -d --build` builds the image here instead.

## CLI

The binary is built as `portscan` and installed as `@`, the command you type.

**macOS / Linux (curl):**

```sh
curl -fsSL https://raw.githubusercontent.com/KrisPowers/portscan/main/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/KrisPowers/portscan/main/install.ps1 | iex
```

PowerShell's parser rejects a bare `@`, so the installer adds a small block to
your profile that runs `@ <target>` as `@.exe`. What you typed stays on screen
and in history as `@ <target>`.

**Homebrew:**

```sh
brew tap krispowers/portscan https://github.com/KrisPowers/portscan
brew install krispowers/portscan/portscan
```

**Prebuilt binaries:** download the archive for your platform from the
[releases](https://github.com/KrisPowers/portscan/releases), extract it, and move
`portscan` onto your `PATH` renamed to `@` (`@.exe` on Windows).

**From source:**

```sh
cargo build --release -p cli
cp target/release/portscan ~/.local/bin/@   # or anywhere on your PATH
```

## Usage

```sh
@                         # scan this machine (localhost)
@ 192.168.1.10            # scan all 65535 ports, then inspect any HTTP services
@ 192.168.1.10:8080       # inspect a single pinned port
@ api.internal --json     # machine-readable output for pipelines/CI
@ 10.0.0.5 --no-discovery # port scan only, skip the HTTP phase
```

IPv6 is supported as `[2001:db8::1]:443` (bracketed when a port is attached) or
`2001:db8::1` on its own. Hostnames are resolved via the system resolver.

### Options

| Flag | Meaning |
|------|---------|
| `--json` | Emit structured JSON instead of the text report. |
| `--no-discovery` | Report open ports only; skip HTTP discovery. |
| `--connect-timeout <MS>` | Per-port TCP connect timeout (default 800 ms). |
| `--http-timeout <SECS>` | Per-request HTTP timeout (default 6 s). |
| `--concurrency <N>` | Max concurrent port probes (default 256). |
| `--probe-rate-limit` | Actively send a small bounded burst to each **open** endpoint to see whether throttling kicks in. Opt-in; passive header detection is always on. |
| `--burst <N>` | Requests per active burst (default 15). |
| `--strict-tls` | Reject invalid/self-signed certs instead of inspecting them anyway. |
| `--paths <FILE>` | Use a custom endpoint list (one path per line; `!` prefix marks a path sensitive). Replaces the built-in list. |
| `--fail-on-high` | Exit `2` if any **HIGH** finding is reported - handy in CI gates. |

## What it reports

Findings are prioritized by potential impact:

- **HIGH** - an unauthenticated **sensitive** endpoint (e.g. `/actuator/env`,
  `/metrics`, `/.env`, `/.git/HEAD`), or an exposed high-risk service (Redis,
  MongoDB, a database, the Docker API, etcd, kubelet, ...).
- **MEDIUM** - exposed services like RDP, VNC, SMB, FTP, or message brokers.
- **LOW** - cleartext HTTP carrying open endpoints; open API surfaces with no
  rate-limit headers; no throttling observed under an opt-in burst.
- **INFO** - positive signals, e.g. a sensitive path that is correctly behind auth.

portscan reports *exposure and posture*, never intent - it can't know whether a given
host is meant to be public. Severities are there to help you triage; the call is
yours.

### Example

Each endpoint is one line: its status, a block per security control (`AUTH`,
`JWT`, `RATE`, `HTTPS`), its path and note. The block's color is the verdict:
green configured, yellow configured but bypassable or weakened, red not
configured, white when the response does not show either way. Piped output or
`NO_COLOR` drops the color and marks each block `+`, `~`, `-` or `?` instead,
as in the example below. When the target pins a port
(`@ host:8080`), the ports section is left out and only that port's endpoints
are shown.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ @ api.internal                                                   10.0.0.42 │
│ 2 open ports  ·  3 endpoints                                               │
└────────────────────────────────────────────────────────────────────────────┘

PORTS ────────────────────────────────────────────────────────────────────────
22/tcp     ssh
8080/tcp   http-proxy

ENDPOINTS  http://api.internal:8080 ──────────────────────────────────────────
[configured+] [insecure~] [not configured-] [not shown?]

200  [AUTH-] [JWT-] [RATE-] [HTTPS-]  /actuator/env
401  [AUTH~] [JWT-] [RATE-] [HTTPS-]  /admin         admin console
200  [AUTH-] [JWT-] [RATE+] [HTTPS-]  /api           API root
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Ran successfully. |
| `1` | Error (bad target, resolution failure, ...). |
| `2` | Ran successfully **and** a HIGH finding was reported (only with `--fail-on-high`). |

## Authorized use only

Scan only hosts you own or are **explicitly authorized** to assess. Port scanning
and endpoint probing against systems you don't control may be unlawful and against
provider terms, even though portscan is read-only. You are responsible for how you use it.

## Development

```sh
cargo test        # unit tests
cargo clippy      # lints
cargo fmt         # formatting
cd ui && npm ci && npm run build   # type-check and build the dashboard
```

Workspace layout:

- `crates/scanner` - parse the `host[:port]` syntax (`target`), the service
  catalog (`ports`), and the async TCP connect scanner (`scan`).
- `crates/endpoints` - scheme detection, endpoint discovery, auth/TLS/rate-limit
  checks, and the conventional endpoint catalog (`paths`).
- `crates/report` - severity model and text/JSON rendering.
- `crates/cli` - the binary (built as `portscan`, installed as `@`), and `--serve`, the dashboard's server
  and API (`serve.rs`).
- `ui/` - the dashboard (React, TypeScript and Vite). `npm run dev` in `ui/`
  serves it with the API proxied to `portscan --serve 127.0.0.1:8090`.
- `Formula/` - the Homebrew formula.
- `testbed/` - a local target to scan (see below).

### Testbed

`testbed/server.py` (Python 3, standard library only) serves conventional
endpoints behind different setups: open, HTTP Basic, Bearer JWT, forbidden,
login redirects, advertised and enforced rate limits, and sensitive paths left
open. A fake Redis listens on `6379` so a full scan has a risky service to show.
Nothing behind the endpoints is real.

```sh
python testbed/server.py              # HTTP on 127.0.0.1:8080
@ localhost:8080                      # endpoints on the testbed
@ localhost:8080 --probe-rate-limit   # /v1 throttles after 5 requests in 10s
@ localhost                           # full scan, picks up the fake Redis
```

## License

Apache-2.0. See [LICENSE](LICENSE).
