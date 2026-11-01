# Dashboard

The dashboard runs in Docker. It needs Docker with Compose v2
([Docker Desktop](https://docs.docker.com/get-docker/) on Windows and macOS).

```sh
curl -fsSL https://raw.githubusercontent.com/KrisPowers/eps/main/compose.yaml -o compose.yaml
docker compose up -d
```

Then open <http://localhost:8090>. From a checkout, `docker compose up -d --build`
builds the image there instead.

## Scanning

The search bar in the header is the `@` command line: type what you'd type after
`@` in a terminal, such as `192.168.1.10:8080` or
`api.internal --no-discovery --probe-rate-limit`, and press Enter. The
[CLI's options](cli.md#options) all work there except `--paths` and `--serve`;
an empty line scans this computer. Focused, the bar lists your recent scans,
narrowed to what you type. The `?` beside it opens the docs, and the gear opens
Settings: the theme, the options every new scan starts with, exporting every
scan at once, and clearing the finished ones.

Your scans are listed a page at a time. A scan opens on its **Findings**: one
line of what it found, then every open port, worst first, a page at a time. Each
port opens its own page with its findings, certificate and endpoints, each folded
to one line until you open it. **Software**, **API** and **DNS** fill in while
the scan runs. **History** lists every scan of the same target; opening one
shows what changed from the one before it. **Export** downloads it as JSON,
Markdown or SARIF.

The last 100 scans are kept in `%LOCALAPPDATA%\eps\data` on Windows, and
`./eps/data` next to `compose.yaml` elsewhere.

## Access

- **This computer only.** The dashboard has no sign-in, so it's published on
  `127.0.0.1` and answers only requests addressed to `localhost`, `127.0.0.1` or
  `[::1]`. That also stops a web page from reaching it by pointing its own
  domain at this computer, and no other site may frame it. To reach it by
  another name, list the name in `EPS_HOSTS` (comma-separated) and put your own
  sign-in in front of it.
- **Scanning this computer.** Scans run inside the container, so `localhost` is
  sent to `host.docker.internal`, the computer running Docker
  (`EPS_LOCALHOST`). Other hosts are reached the way the container reaches any
  network.
- **The CLI from the image.** Arguments run one scan instead of the dashboard:
  `docker run --rm ghcr.io/krispowers/eps 192.168.1.10`.
