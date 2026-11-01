# Development

```sh
cargo test                          # unit tests
cargo clippy --all-targets          # lints
cargo fmt --all                     # formatting
cd ui && npm ci && npm run build    # type-check and build the dashboard
```

## Layout

- `crates/scanner`: parse the `host[:port]` syntax (`target`), the service
  catalog (`ports`), the async TCP connect scanner (`scan`), greetings
  (`banner`) and DNS (`dns`).
- `crates/endpoints`: scheme detection, endpoint discovery, auth, TLS and
  rate-limit checks, the conventional endpoint catalog (`paths`), API documents
  (`api`), the site crawl and client-side checks (`site`), and certificate-log
  subdomains (`names`).
- `crates/report`: the severity model and text and JSON rendering.
- `crates/cli`: the binary (built as `eps`, installed as `@`), and `--serve`,
  the dashboard's server and API (`serve.rs`).
- `ui/`: the dashboard (React, TypeScript and Vite). `npm run dev` in `ui/`
  serves it with the API proxied to `eps --serve 127.0.0.1:8090`.
- `Formula/`: the Homebrew formula.
- `testbed/`: a local target to scan.

## Testbed

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

## Releasing

Bump `version` in `Cargo.toml`, merge, and push a `vX.Y.Z` tag. The Release
workflow runs CI, builds every target and attaches the archives with their
checksums; the Image workflow publishes `ghcr.io/krispowers/eps`. Then fill the
formula's `version` and `sha256` values from the release.
