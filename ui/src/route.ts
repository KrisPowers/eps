// Where the page is, kept in the URL hash: `#/` the scans, `#/docs` the
// docs, `#/settings` the settings, `#/<id>` a scan's findings, `#/<id>/<port>`
// one port of it.

export interface Route {
  id: string;
  view: "scans" | "docs" | "settings" | "scan";
  port: number | null;
}

export function readHash(): Route {
  const [first = "", port = ""] = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  if (first === "docs" || first === "settings") return { id: "", view: first, port: null };
  return { id: first, view: first ? "scan" : "scans", port: Number(port) || null };
}

export function href(id: string, port?: number | null) {
  return id ? "#/" + encodeURIComponent(id) + (port ? "/" + port : "") : "#/";
}

export function go(id: string, port?: number | null) {
  location.hash = href(id, port).slice(1);
}
