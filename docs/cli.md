# CLI

The binary is built as `eps` and installed as `@`, the command you type.

## Install

macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/KrisPowers/eps/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/KrisPowers/eps/main/install.ps1 | iex
```

Both installers check the download against its SHA-256 from the release. Set
`EPS_INSTALL_DIR` to install somewhere else, or `EPS_VERSION` (such as `v1.0.0`)
to pin a release.

PowerShell's parser rejects a bare `@`, so the Windows installer adds a small
block to your profile that runs `@ <target>` as `@.exe`. What you typed stays on
screen and in history as `@ <target>`.

Homebrew:

```sh
brew tap krispowers/eps https://github.com/KrisPowers/eps
brew install krispowers/eps/eps
```

Prebuilt binaries: download the archive for your platform from the
[releases](https://github.com/KrisPowers/eps/releases), check it against its
`.sha256`, extract it, and move `eps` onto your `PATH` renamed to `@` (`@.exe` on
Windows).

From source:

```sh
cargo build --release -p cli
cp target/release/eps ~/.local/bin/@
```

## Usage

```sh
@                             # scan this machine (localhost)
@ 192.168.1.10                # scan all 65535 ports, then inspect any HTTP services
@ 192.168.1.10:8080           # inspect a single pinned port
@ https://shop.example/login  # a URL: scan its host, and check its path too
@ api.internal --json         # machine-readable output for pipelines and CI
@ 10.0.0.5 --no-discovery     # port scan only, skip the HTTP phase
@ 192.168.1.0/24              # a range: which hosts are up, on the common ports
```

A range (IPv4, up to a /20) probes the catalog's common ports on every address
and reports each host that answered with its open ports, plus any risky services
among them. It skips the HTTP phase; scan a host it finds on its own for that.

IPv6 is supported as `[2001:db8::1]:443` (bracketed when a port is attached) or
`2001:db8::1` on its own. Hostnames are resolved with the system resolver; when
a name has several addresses, the first is scanned and the report lists them
all. A URL, or a name with a path, is scanned as its host (and any port it
names), with its path added to the endpoints checked.

## Options

| Flag | Meaning |
| --- | --- |
| `--json` | Emit structured JSON instead of the text report. |
| `--no-discovery` | Report open ports only; skip HTTP discovery. |
| `--connect-timeout <MS>` | Per-port TCP connect timeout (default 800 ms). |
| `--http-timeout <SECS>` | Per-request HTTP timeout (default 6 s). |
| `--concurrency <N>` | Max concurrent port probes (default 256). |
| `--probe-rate-limit` | Send a small bounded burst to each open endpoint to see whether throttling kicks in. Opt-in; passive header detection is always on. |
| `--burst <N>` | Requests per active burst (default 15). |
| `--strict-tls` | Reject invalid or self-signed certificates instead of inspecting them anyway. |
| `--paths <FILE>` | Use a custom endpoint list (one path per line; a `!` prefix marks a path sensitive). Replaces the built-in list. |
| `--fail-on-high` | Exit `2` if any HIGH finding is reported, for CI gates. |

## Reading the report

Each endpoint is one line: its status, a block per security control (`AUTH`,
`JWT`, `RATE`, `HTTPS`), its path and note. The block's color is the verdict:
green configured, yellow configured but bypassable or weakened, red not
configured, white when the response does not show either way. Piped output or
`NO_COLOR` drops the color and marks each block `+`, `~`, `-` or `?` instead, as
below. When the target pins a port (`@ host:8080`), the ports section is left
out and only that port's endpoints are shown.

```text
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

What each finding means is in [How it works](how-it-works.md#findings).

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Ran successfully. |
| `1` | Error (bad target, resolution failure, ...). |
| `2` | Ran successfully and a HIGH finding was reported (only with `--fail-on-high`). |
