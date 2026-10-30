// Where the page is, kept in the URL hash: `#/` the scans, `#/docs` the
// docs, `#/<id>` a scan's ports, `#/<id>/ports/<port>` one of them, and
// `#/<id>/endpoints` or `#/<id>/findings` everything of that kind it found.

export type Page = "ports" | "endpoints" | "findings";

export interface Route {
  id: string;
  docs: boolean;
  page: Page;
  port: number | null;
}

const PAGES: Page[] = ["ports", "endpoints", "findings"];

export function readHash(): Route {
  const [first = "", page = "", port = ""] = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  if (first === "docs") return { id: "", docs: true, page: "ports", port: null };
  return { id: first, docs: false, page: PAGES.find((p) => p === page) ?? "ports", port: Number(port) || null };
}

export function href(id: string, page: Page = "ports", port?: number | null) {
  if (!id) return "#/";
  const rest = port ? "/ports/" + port : page === "ports" ? "" : "/" + page;
  return "#/" + encodeURIComponent(id) + rest;
}

export function go(id: string, page?: Page, port?: number | null) {
  location.hash = href(id, page, port).slice(1);
}
