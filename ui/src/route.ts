// Where the page is, kept in the URL hash: `#/` the scans; `#/docs/<section>`
// and `#/settings/<section>`; `#/<id>` a scan's findings, `#/<id>/<page>`
// another page of it, `#/<id>/<page>/<item>` one thing on that page, and
// `#/<id>/<port>` one port of it.

export type Page = "findings" | "software" | "api" | "dns" | "history";

export interface Route {
  id: string;
  view: "scans" | "docs" | "settings" | "scan";
  page: Page;
  port: number | null;
  // One thing on a page: a piece of software, an API document.
  item: string | null;
  // A section of the docs or settings.
  section: string;
}

const PAGES: Page[] = ["findings", "software", "api", "dns", "history"];

export function readHash(): Route {
  const [first = "", second = "", third = ""] = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  const base = { id: "", page: "findings" as Page, port: null, item: null, section: second };
  if (first === "docs" || first === "settings") return { ...base, view: first };
  if (!first) return { ...base, view: "scans" };
  return {
    ...base,
    id: first,
    view: "scan",
    page: PAGES.find((p) => p === second) ?? "findings",
    port: Number(second) || null,
    item: third || null,
    section: "",
  };
}

// href is the link to a scan, one of its pages, one thing on a page, or one
// of its ports.
export function href(id: string, to?: number | Page | null, item?: string) {
  if (!id) return "#/";
  const base = "#/" + encodeURIComponent(id);
  if (typeof to === "number") return base + "/" + to;
  const page = to && to !== "findings" ? "/" + to : item ? "/findings" : "";
  return base + page + (item ? "/" + encodeURIComponent(item) : "");
}

export function go(id: string, to?: number | Page | null) {
  location.hash = href(id, to).slice(1);
}
