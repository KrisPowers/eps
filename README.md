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

