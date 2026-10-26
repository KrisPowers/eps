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

