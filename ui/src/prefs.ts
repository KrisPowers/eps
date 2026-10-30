// Options added to every scan started from the search bar, kept in this
// browser. A line that already sets an option keeps its own.

export interface Defaults {
  noDiscovery: boolean;
  probeRateLimit: boolean;
  strictTls: boolean;
  // Milliseconds per port.
  connectTimeout: number;
  concurrency: number;
}

// The CLI's own defaults: nothing is added for these.
export const BASE: Defaults = { noDiscovery: false, probeRateLimit: false, strictTls: false, connectTimeout: 800, concurrency: 256 };

export function loadDefaults(): Defaults {
  try {
    return { ...BASE, ...JSON.parse(localStorage.getItem("defaults") ?? "{}") };
  } catch {
    return BASE;
  }
}

export function saveDefaults(d: Defaults) {
  try {
    localStorage.setItem("defaults", JSON.stringify(d));
  } catch {
    // Not kept, still used until the page closes.
  }
}

export function withDefaults(line: string) {
  const d = loadDefaults();
  const has = (flag: string) => new RegExp(`(^|\\s)${flag}(\\s|=|$)`).test(line);
  const add: string[] = [];
  if (d.noDiscovery && !has("--no-discovery")) add.push("--no-discovery");
  if (d.probeRateLimit && !has("--probe-rate-limit")) add.push("--probe-rate-limit");
  if (d.strictTls && !has("--strict-tls")) add.push("--strict-tls");
  if (d.connectTimeout !== BASE.connectTimeout && !has("--connect-timeout")) add.push("--connect-timeout " + d.connectTimeout);
  if (d.concurrency !== BASE.concurrency && !has("--concurrency")) add.push("--concurrency " + d.concurrency);
  return add.length ? line + " " + add.join(" ") : line;
}
