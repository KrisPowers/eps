// Where the page is, kept in the URL hash: `#/` the scans, `#/docs` the
// docs, `#/settings` the settings, `#/<id>` a scan's findings, `#/<id>/<page>`
// another page of it, and `#/<id>/<port>` one port of it.

export type Page = "findings" | "history" | "changes";

export interface Route {
  id: string;
  view: "scans" | "docs" | "settings" | "scan";
  page: Page;
  port: number | null;
}

const PAGES: Page[] = ["findings", "history", "changes"];

export function readHash(): Route {
  const [first = "", rest = ""] = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  if (first === "docs" || first === "settings") return { id: "", view: first, page: "findings", port: null };
  return {
    id: first,
    view: first ? "scan" : "scans",
    page: PAGES.find((p) => p === rest) ?? "findings",
    port: Number(rest) || null,
  };
}

// href is the link to a scan, one of its pages, or one of its ports.
export function href(id: string, to?: number | Page | null) {
  if (!id) return "#/";
  return "#/" + encodeURIComponent(id) + (to && to !== "findings" ? "/" + to : "");
}

export function go(id: string, to?: number | Page | null) {
  location.hash = href(id, to).slice(1);
}
