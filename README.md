<picture><source media="(prefers-color-scheme: light)" srcset="docs/images/header-light.png"><img src="docs/images/header.png" width="100%" alt="EPS, the Exposure and Posture Scanner. Runs as a dashboard in Docker with Compose v2, or as a CLI on macOS, Linux and Windows."></picture>

<a href="docs/how-it-works.md"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/how-it-works-light.png"><img src="docs/images/how-it-works.png" width="100%" alt="How it works: the CLI (@ api.internal) or the dashboard on localhost:8090 starts one read-only scan. EPS tries every TCP port on your host, nothing written: it listens for greetings such as SSH's version, checks TLS and sends GET requests to web services, and only connects to others such as Redis. It also asks DNS for the A, MX, TXT, CAA and DMARC records, and the certificate logs crt.sh and Cert Spotter for subdomains."></picture></a>

<a href="docs/cli.md#reading-the-report"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/what-it-reports-light.png"><img src="docs/images/what-it-reports.png" width="100%" alt="What it reports: each endpoint, such as /actuator/env, /admin and /api on api.internal:8080, gets a verdict for AUTH, JWT, RATE and HTTPS. Greetings, certificates, TLS versions, headers, cookies, software, OpenAPI documents, the sitemap, client-side code, DNS, SPF and DMARC, and subdomains are read too. Everything is graded into findings, worst first, from HIGH to INFO, exported as JSON, Markdown or SARIF, and --fail-on-high exits 2 for CI."></picture></a>

## Install

Dashboard (Docker with Compose v2):

```sh
curl -fsSL https://raw.githubusercontent.com/KrisPowers/eps/main/compose.yaml -o compose.yaml
docker compose up -d
```

CLI on Linux and macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/KrisPowers/eps/main/install.sh | sh
```

CLI on Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/KrisPowers/eps/main/install.ps1 | iex
```

Homebrew, prebuilt binaries and building from source are in the
[CLI guide](docs/cli.md#install).

## Get started

Open <http://localhost:8090> and type a host into the search bar, or in a
terminal:

```sh
@ 192.168.1.10
```

The [dashboard](docs/dashboard.md) and the [CLI](docs/cli.md) guides cover the
rest. Scan only hosts you own or are authorized to assess.
