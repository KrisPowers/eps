# @

**`@ <ip>[:port]` - point it at a host and it tells you what's exposed.**

`@` is a read-only reconnaissance CLI for network and software engineers. Give it
an IP address (with or without a port) and it reports, in one command:

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

> **`at` is strictly read-only.** It makes ordinary TCP connections and HTTP `GET`
> requests. It never writes, submits, logs in, mutates, or exploits anything. It
> reports exposure; **you** decide what to do about it.

## Install

The crate compiles as `at` (a literal `@` crate name is rejected by the Rust
compiler, which reads `@`-prefixed tokens as argument files). The **installed
binary is named `@`**, so the command you type is `@`.

> Downloads are served from `at.krispowers.dev`. The repo is private for now, so
> these paths will start working once the first public release is cut. To build
> locally in the meantime, see [From source](#from-source).

**macOS / Linux (curl):**

```sh
curl -fsSL https://at.krispowers.dev/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://at.krispowers.dev/install.ps1 | iex
```

PowerShell's parser rejects a bare `@`, so the installer adds a small block to
your profile that runs `@ <target>` as `@.exe`. What you typed stays on screen
and in history as `@ <target>`.

**Homebrew:**

```sh
brew tap krispowers/at https://github.com/krispowers/at
brew install krispowers/at/at
```

**Prebuilt binaries:** download the archive for your platform from the
[releases](https://github.com/krispowers/at/releases), extract it, and move the
`at` binary onto your `PATH` renamed to `@` (`@.exe` on Windows).

### From source

```sh
cargo build --release -p cli
cp target/release/at ~/.local/bin/@        # or anywhere on your PATH
```

Make sure the install dir is on your `PATH` (`~/.local/bin` by default).

## Usage

```sh
@                         # scan this machine (localhost)
@ 192.168.1.10            # scan all 65535 ports, then inspect any HTTP services
@ 192.168.1.10:8080       # inspect a single pinned port
@ api.internal --json     # machine-readable output for pipelines/CI
@ 10.0.0.5 --no-discovery # port scan only, skip the HTTP phase
```

The target follows the command with a space (`@ 10.0.0.5`), as any command takes
its argument. A leading `@` on the target itself is also accepted (`@ @10.0.0.5`).
IPv6 is supported as `[2001:db8::1]:443` (bracketed when a port is attached) or
`2001:db8::1` on its own. Hostnames are resolved via the system resolver.

> **Glued form?** A single token like `@10.0.0.5` (no space) can't invoke a binary
> named `@` - the shell treats the whole token as the command name. If you want
> that exact ergonomics, add a shell function to your `~/.zshrc`:
>
> ```sh
> @() { command @ "$@"; }   # lets `@ 10.0.0.5` work even if @ isn't first on PATH
> ```
>
> True no-space `@10.0.0.5` isn't possible in a standard shell; use `@ 10.0.0.5`.

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

`at` reports *exposure and posture*, never intent - it can't know whether a given
host is meant to be public. Severities are there to help you triage; the call is
yours.

### Example

In a terminal the output is color coded: status codes, auth state and risky
services are tinted, and sensitive paths are bold. Piped output or `NO_COLOR`
drops the color and keeps the layout. When the target pins a port
(`@ host:8080`), the ports section is left out and only that port's endpoints
are shown.

```
╭────────────────────────────────────────────────────────────────────────────╮
│ @ api.internal                                                   10.0.0.42 │
│ 2 open ports  ·  3 endpoints  ·  3 findings                                │
╰────────────────────────────────────────────────────────────────────────────╯

  PORTS ──────────────────────────────────────────────────────────────────────
     22/tcp   ssh
   8080/tcp   http-proxy

  ENDPOINTS  http://api.internal:8080 ────────────────────────────────────────
  200  OPEN       no limit  /actuator/env  Actuator environment (secrets risk)
  401  PROTECTED  no limit  /admin         admin console  Basic
  200  OPEN       limited   /api           API root

  FINDINGS ───────────────────────────────────────────────────────────────────
  Unauthenticated sensitive endpoint: Actuator environment (secrets risk)
    http://api.internal:8080/actuator/env (port 8080)
    Returned 200 with no authentication. This path commonly leaks
    configuration, internals, or control. Put it behind auth or stop exposing
    it.

  ...

  Read-only scan - exposure is reported, not judged.
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
provider terms, even though `at` is read-only. You are responsible for how you use it.

## Development

```sh
cargo test        # unit tests
cargo clippy      # lints
cargo fmt         # formatting
```

Workspace layout:

- `crates/scanner` - parse the `@host[:port]` syntax (`target`), the service
  catalog (`ports`), and the async TCP connect scanner (`scan`).
- `crates/endpoints` - scheme detection, endpoint discovery, auth/TLS/rate-limit
  checks, and the conventional endpoint catalog (`paths`).
- `crates/report` - severity model and text/JSON rendering.
- `crates/cli` - the CLI binary, installed as `@`.
- `Formula/` - the Homebrew formula.

## License

Apache-2.0. See [LICENSE](LICENSE).
