"""Local target for trying portscan against something app-shaped.

Serves a spread of conventional endpoints behind different security setups:
open, HTTP Basic, Bearer JWT, forbidden, login redirects, advertised and
enforced rate limits, and a few sensitive paths left open on purpose. Nothing
behind them is real; each handler only returns the status and headers a real
service would. A fake Redis port is opened too so a full scan has a risky
non-HTTP service to report.

    python testbed/server.py              # HTTP on 127.0.0.1:8080, Redis on 6379
    python testbed/server.py --port 9000  # pick another HTTP port

Then, in another shell:

    @ localhost:8080
    @ localhost:8080 --probe-rate-limit
    @ localhost
"""

import argparse
import json
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Requests allowed per window on the throttled routes.
LIMIT = 5
WINDOW = 10.0

hits = {}
hits_lock = threading.Lock()


def take(client):
    """Count a hit for `client` and return (allowed, remaining, reset_secs)."""
    now = time.monotonic()
    with hits_lock:
        start, count = hits.get(client, (now, 0))
        if now - start >= WINDOW:
            start, count = now, 0
        count += 1
        hits[client] = (start, count)
    reset = max(0, int(WINDOW - (now - start)))
    return count <= LIMIT, max(0, LIMIT - count), reset


def rate_headers(remaining, reset):
    return {
        "RateLimit-Limit": str(LIMIT),
        "RateLimit-Remaining": str(remaining),
        "RateLimit-Reset": str(reset),
    }


def open_json(body):
    return 200, {"Content-Type": "application/json"}, body


def basic(realm):
    headers = {"WWW-Authenticate": f'Basic realm="{realm}"'}
    return 401, headers, {"error": "authentication required"}


def bearer(realm):
    challenge = f'Bearer realm="{realm}", error="invalid_token"'
    return 401, {"WWW-Authenticate": challenge}, {"error": "missing or invalid JWT"}


def forbidden():
    return 403, {}, {"error": "forbidden"}


def redirect(to):
    return 302, {"Location": to}, None


def advertised():
    """Open, with rate-limit headers but no enforcement."""
    return 200, rate_headers(LIMIT - 1, int(WINDOW)), {"api": "root", "versions": ["v1", "v2"]}


# Path -> handler. Anything not listed is a 404.
ROUTES = {
    # Open and harmless.
    "/": lambda: open_json({"app": "testbed", "status": "ok"}),
    "/health": lambda: open_json({"status": "up"}),
    "/healthz": lambda: open_json({"status": "up"}),
    "/ping": lambda: open_json({"pong": True}),
    "/version": lambda: open_json({"version": "1.4.2"}),
    "/robots.txt": lambda: (200, {"Content-Type": "text/plain"}, "User-agent: *\nDisallow:\n"),
    "/docs": lambda: (200, {"Content-Type": "text/html"}, "<h1>Docs</h1>"),
    # API surfaces with different rate-limit postures.
    "/api": advertised,
    "/api/v1": lambda: open_json({"items": []}),
    "/v1": "throttled",
    "/stats": lambda: (429, {"Retry-After": "30"}, {"error": "slow down"}),
    # Bearer JWT.
    "/api/v2": lambda: bearer("api"),
    "/graphql": lambda: bearer("graphql"),
    "/actuator/metrics": lambda: bearer("actuator"),
    # HTTP Basic.
    "/admin": lambda: basic("admin"),
    "/actuator": lambda: basic("actuator"),
    "/swagger-ui.html": lambda: basic("docs"),
    # Authenticated but not authorized.
    "/management": forbidden,
    "/config": forbidden,
    # Login redirects.
    "/console": lambda: redirect("/login?next=/console"),
    "/ui/": lambda: redirect("/login?next=/ui/"),
    # Sensitive and left open.
    "/actuator/env": lambda: open_json({"DB_PASSWORD": "******", "profiles": ["prod"]}),
    "/metrics": lambda: (200, {"Content-Type": "text/plain"}, "http_requests_total 1027\n"),
    "/openapi.json": lambda: open_json({"openapi": "3.0.0", "paths": {}}),
    "/.env": lambda: (200, {"Content-Type": "text/plain"}, "SECRET_KEY=changeme\n"),
    "/debug/vars": lambda: open_json({"goroutines": 12}),
    # Present but not usable with GET.
    "/trace": lambda: (405, {"Allow": "POST"}, {"error": "method not allowed"}),
    "/dump": lambda: (500, {}, {"error": "internal error"}),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "testbed/1.0"
    sys_version = ""

    def do_GET(self):
        route = ROUTES.get(self.path.split("?", 1)[0])
        if route is None:
            status, headers, body = 404, {}, {"error": "not found"}
        elif route == "throttled":
            allowed, remaining, reset = take(self.client_address[0])
            headers = rate_headers(remaining, reset)
            if allowed:
                status, body = 200, {"items": []}
            else:
                status, body = 429, {"error": "rate limited"}
                headers["Retry-After"] = str(reset)
        else:
            status, headers, body = route()

        if isinstance(body, (dict, list)):
            payload = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
        else:
            payload = (body or "").encode()

        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} {fmt % args}", flush=True)


class FakeRedis(socketserver.BaseRequestHandler):
    """Answers like a Redis that wants a password, then hangs up."""

    def handle(self):
        self.request.sendall(b"-NOAUTH Authentication required.\r\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--redis-port", type=int, default=6379)
    args = parser.parse_args()

    try:
        redis = socketserver.ThreadingTCPServer((args.host, args.redis_port), FakeRedis)
        threading.Thread(target=redis.serve_forever, daemon=True).start()
        print(f"fake redis on {args.host}:{args.redis_port}", flush=True)
    except OSError as e:
        print(f"fake redis skipped, port {args.redis_port} unavailable: {e}", flush=True)

    http = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"testbed on http://{args.host}:{args.port}", flush=True)
    http.serve_forever()


if __name__ == "__main__":
    main()
