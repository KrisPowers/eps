// Where the page is, kept in the URL hash: `#/` the scans, `#/docs` the
// docs, `#/<id>` a scan's findings, `#/<id>/<port>` one port of it.

export interface Route {
  id: string;
  docs: boolean;
  port: number | null;
}

export function readHash(): Route {
  const [first = "", port = ""] = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  if (first === "docs") return { id: "", docs: true, port: null };
  return { id: first, docs: false, port: Number(port) || null };
}

export function href(id: string, port?: number | null) {
  return id ? "#/" + encodeURIComponent(id) + (port ? "/" + port : "") : "#/";
}

export function go(id: string, port?: number | null) {
  location.hash = href(id, port).slice(1);
}
