// What this browser keeps: how the dashboard looks, and the options added to
// every scan started from the search bar. A line that already sets an
// option keeps its own.

export interface Defaults {
  noDiscovery: boolean;
  probeRateLimit: boolean;
  strictTls: boolean;
  // Milliseconds per port.
  connectTimeout: number;
  // Seconds per request.
  httpTimeout: number;
  concurrency: number;
  // Requests per burst, with probeRateLimit.
  burst: number;
}

// The CLI's own defaults: nothing is added for these.
export const BASE: Defaults = {
  noDiscovery: false,
  probeRateLimit: false,
  strictTls: false,
  connectTimeout: 800,
  httpTimeout: 6,
  concurrency: 256,
  burst: 15,
};

function read(key: string) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string | null) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // Not kept, still used until the page closes.
  }
}

export function loadDefaults(): Defaults {
  try {
    return { ...BASE, ...JSON.parse(read("defaults") ?? "{}") };
  } catch {
    return BASE;
  }
}

export function saveDefaults(d: Defaults) {
  write("defaults", JSON.stringify(d));
}

export function withDefaults(line: string) {
  const d = loadDefaults();
  const has = (flag: string) => new RegExp(`(^|\\s)${flag}(\\s|=|$)`).test(line);
  const add: string[] = [];
  if (d.noDiscovery && !has("--no-discovery")) add.push("--no-discovery");
  if (d.probeRateLimit && !has("--probe-rate-limit")) add.push("--probe-rate-limit");
  if (d.probeRateLimit && d.burst !== BASE.burst && !has("--burst")) add.push("--burst " + d.burst);
  if (d.strictTls && !has("--strict-tls")) add.push("--strict-tls");
  if (d.connectTimeout !== BASE.connectTimeout && !has("--connect-timeout")) add.push("--connect-timeout " + d.connectTimeout);
  if (d.httpTimeout !== BASE.httpTimeout && !has("--http-timeout")) add.push("--http-timeout " + d.httpTimeout);
  if (d.concurrency !== BASE.concurrency && !has("--concurrency")) add.push("--concurrency " + d.concurrency);
  return add.length ? line + " " + add.join(" ") : line;
}

// How the dashboard looks. Each is a data attribute on the page, which
// index.html sets before the page draws; `system` leaves it unset.
export type Look = "theme" | "motion" | "density";

export function loadLook(key: Look) {
  return read(key) ?? "system";
}

export function saveLook(key: Look, value: string) {
  const root = document.documentElement;
  if (value === "system") delete root.dataset[key];
  else root.dataset[key] = value;
  write(key, value === "system" ? null : value);
}
