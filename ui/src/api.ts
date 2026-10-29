import type { ScanDetail, ScanRow } from "./types";

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, headers: { "Content-Type": "application/json" } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error ?? `The server answered ${res.status}`);
  return body as T;
}

export const api = {
  scans: () => call<{ scans: ScanRow[] }>("/api/scans").then((r) => r.scans),
  scan: (id: string) => call<ScanDetail>(`/api/scans/${encodeURIComponent(id)}`),
  start: (target: string) => call<ScanRow>("/api/scans", { method: "POST", body: JSON.stringify({ target }) }),
  remove: (id: string) => call<{ ok: boolean }>(`/api/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),
};
