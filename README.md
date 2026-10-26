# @

**`@ <ip>[:port]` - point it at a host and it tells you what's exposed.**

`@` is a read-only reconnaissance CLI for network and software engineers. Give it
an IP address (with or without a port) and it reports, in one command:

- **Open ports** - a TCP *connect* scan (no raw sockets, no root) over a curated
  list of commonly exposed ports, or any set you choose.
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

**Homebrew:**

```sh
brew install krispowers/tap/at
```

**Prebuilt binaries:** download the archive for your platform from the
[releases](https://github.com/krispowers/at/releases), extract it, and move the
`at` binary onto your `PATH` renamed to `@` (`@.exe` on Windows).

### From source

```sh
cargo build --release
cp target/release/at ~/.local/bin/@        # or anywhere on your PATH
```

Make sure the install dir is on your `PATH` (`~/.local/bin` by default).

## Usage

```sh
@ 192.168.1.10            # scan common ports, then inspect any HTTP services
@ 192.168.1.10:8080       # inspect a single pinned port
@ 10.0.0.5 --full         # scan all 65535 ports
@ 10.0.0.5 --ports 80,443,8000-8100
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
| `--full` | Scan all 65,535 ports instead of the common list. |
| `--ports <SPEC>` | Custom port set, e.g. `80,443,8000-8100`. |
| `--no-discovery` | Report open ports only; skip HTTP discovery. |
| `--connect-timeout <MS>` | Per-port TCP connect timeout (default 800 ms). |
| `--http-timeout <SECS>` | Per-request HTTP timeout (default 6 s). |
| `--concurrency <N>` | Max concurrent port probes (default 256). |
| `--probe-rate-limit` | Actively send a small bounded burst to each **open** endpoint to see whether throttling kicks in. Opt-in; passive header detection is always on. |
| `--burst <N>` | Requests per active burst (default 15). |
| `--strict-tls` | Reject invalid/self-signed certs instead of inspecting them anyway. |
| `--paths <FILE>` | Use a custom endpoint list (one path per line; `!` prefix marks a path sensitive). Replaces the built-in list. |
| `--fail-on-high` | Exit `2` if any **HIGH** finding is reported - handy in CI gates. |

