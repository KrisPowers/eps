import type { Report, Severity } from "./types";

// A finished scan's report as a file to keep or hand on: the JSON the CLI
// prints, a Markdown write-up, or SARIF for code-scanning tools.

export type Format = "json" | "md" | "sarif";

export const FORMATS: [Format, string][] = [["json", "JSON"], ["md", "Markdown"], ["sarif", "SARIF"]];

export function download(report: Report, when: number, format: Format) {
  const body = format === "json" ? JSON.stringify(report, null, 2) : format === "md" ? markdown(report, when) : JSON.stringify(sarif(report), null, 2);
  const type = format === "md" ? "text/markdown" : "application/json";
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `${report.target.replace(/[^\w.-]+/g, "_")}-${new Date(when).toISOString().slice(0, 10)}.${format === "sarif" ? "sarif" : format}`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const LEVELS: Severity[] = ["high", "medium", "low", "info"];

// Cells can't hold a pipe or a line break.
const cell = (s: string) => s.replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ");

function markdown(r: Report, when: number) {
  const out = [`# ${r.target}`, "", `${r.resolved_ip}, scanned ${new Date(when).toLocaleString()}`, ""];
  out.push("## Summary", "", "| Severity | Findings |", "| --- | --- |");
  for (const s of LEVELS) out.push(`| ${s} | ${r.findings.filter((f) => f.severity === s).length} |`);
  out.push("", r.hosts ? `${r.hosts.length} hosts up.` : `${r.open_ports.length} open ports, ${r.endpoints.length} endpoints.`, "");

  if (r.hosts?.length) {
    out.push("## Hosts", "", "| Host | Open ports |", "| --- | --- |");
    for (const h of r.hosts) out.push(`| ${h.ip} | ${h.open_ports.map((p) => `${p.port}/${cell(p.service)}`).join(", ")} |`);
    out.push("");
  }
  if (r.open_ports.length) {
    out.push("## Open ports", "", "| Port | Service |", "| --- | --- |");
    for (const p of r.open_ports) out.push(`| ${p.port}/tcp | ${cell(p.service)} |`);
    out.push("");
  }
  if (r.findings.length) {
    out.push("## Findings", "");
    for (const f of r.findings) out.push(`### ${f.severity.toUpperCase()}: ${f.title}`, "", `\`${f.location}\``, "", f.detail, "");
  }
  if (r.endpoints.length) {
    out.push("## Endpoints", "", "| Status | URL | AUTH | JWT | RATE | HTTPS | Note |", "| --- | --- | --- | --- | --- | --- | --- |");
    for (const e of r.endpoints) {
      const c = e.controls;
      out.push(`| ${e.status} | ${cell(e.url)} | ${c.auth} | ${c.jwt} | ${c.rate} | ${c.https} | ${cell(e.note)} |`);
    }
    out.push("");
  }
  return out.join("\n");
}

const SARIF_LEVEL: Record<Severity, string> = { high: "error", medium: "warning", low: "note", info: "none" };

// sarif is the report as SARIF 2.1.0: a rule per kind of finding, a result
// per finding, located at the URL or host and port it was found on.
function sarif(r: Report) {
  const rules: { id: string; name: string; shortDescription: { text: string } }[] = [];
  const ruleOf = (title: string) => {
    // Titles carry the endpoint's note after a colon; the kind is before it.
    const kind = title.split(":")[0].trim();
    const id = kind.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    if (!rules.some((x) => x.id === id)) rules.push({ id, name: kind, shortDescription: { text: kind } });
    return id;
  };
  const results = r.findings.map((f) => {
    // `<url> (port N)`, `port N`, or for a range `<ip> (port N)`.
    const head = f.location.split(" (port ")[0];
    const port = /(?:^|\()port (\d+)/.exec(f.location)?.[1];
    const host = head.startsWith("port") ? r.target : head;
    const uri = head.startsWith("http") ? head : `tcp://${host}${port ? ":" + port : ""}`;
    return {
      ruleId: ruleOf(f.title),
      level: SARIF_LEVEL[f.severity],
      message: { text: `${f.title}. ${f.detail}` },
      locations: [{ physicalLocation: { artifactLocation: { uri } } }],
    };
  });
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "portscan", informationUri: "https://github.com/KrisPowers/portscan", rules } }, results }],
  };
}
