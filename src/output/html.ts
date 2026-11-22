import type { Assessment } from "../assess.ts";
import type { Finding, Snapshot } from "../model.ts";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

/**
 * Shared design tokens and components.
 *
 * Constraints that are not negotiable:
 *   - no scripts, so the document cannot depend on a runtime;
 *   - no external assets, so it renders offline in five years;
 *   - severity is encoded by colour *and* by label, never colour alone.
 */
export const BASE_CSS = `
  :root {
    color-scheme: dark light;
    --bg:#0b0d10; --bg-2:#0e1116; --panel:#12151b; --panel-2:#171b23;
    --line:#232936; --line-2:#2f3646;
    --fg:#e7eaf0; --muted:#98a0b3; --faint:#6c7488;
    --accent:#4cc2ff; --accent-dim:#1d6b8f; --accent-fg:#06121a;
    --critical:#ff6b7a; --high:#ff9a5c; --medium:#ffd166; --low:#5eead4; --info:#98a0b3;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
    --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    --radius:.55rem;
  }
  @media (prefers-color-scheme: light) {
    :root {
      --bg:#f6f7f9; --bg-2:#eef0f4; --panel:#ffffff; --panel-2:#f9fafb;
      --line:#dfe3ea; --line-2:#c9cfda;
      --fg:#15181e; --muted:#5b6375; --faint:#8790a3;
      --accent:#0b6fa4; --accent-dim:#9fd0e6; --accent-fg:#ffffff;
      --critical:#b3122a; --high:#b4471a; --medium:#8a6100; --low:#0f766e; --info:#5b6375;
    }
  }
  * { box-sizing:border-box; }
  html { -webkit-text-size-adjust:100%; }
  body {
    margin:0; min-height:100vh; background:var(--bg); color:var(--fg);
    font:16px/1.65 var(--sans);
    background-image:
      linear-gradient(color-mix(in srgb, var(--line) 42%, transparent) 1px, transparent 1px),
      linear-gradient(90deg, color-mix(in srgb, var(--line) 42%, transparent) 1px, transparent 1px);
    background-size:64px 64px, 64px 64px;
    background-position:-1px -1px;
  }
  body::before {
    content:""; position:fixed; inset:0; pointer-events:none; z-index:0;
    background:radial-gradient(ellipse at 50% 0%, color-mix(in srgb, var(--bg) 55%, transparent), var(--bg) 70%);
  }
  main { position:relative; z-index:1; max-width:74rem; margin:0 auto; padding:2rem 1.25rem 4rem; }
  .mono { font-family:var(--mono); font-variant-numeric:tabular-nums; }

  /* ---- masthead ---------------------------------------------------------- */
  .masthead {
    display:flex; align-items:center; justify-content:space-between; gap:1rem;
    padding:.55rem .85rem; border:1px solid var(--line); border-radius:var(--radius);
    background:linear-gradient(180deg, var(--panel-2), var(--panel));
    font-family:var(--mono); font-size:.73rem; letter-spacing:.13em; text-transform:uppercase;
    color:var(--muted);
  }
  .masthead .brand { display:flex; align-items:center; gap:.55rem; color:var(--fg); letter-spacing:.16em; }
  .status-dot {
    width:.5rem; height:.5rem; border-radius:50%; background:var(--low);
    box-shadow:0 0 0 3px color-mix(in srgb, var(--low) 18%, transparent);
    flex:0 0 auto;
  }
  @media (prefers-reduced-motion: no-preference) {
    .status-dot { animation:pulse 3.2s ease-in-out infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.55} }
  }
  .masthead .right { display:flex; align-items:center; gap:1rem; }
  .tlp { border:1px solid var(--line-2); border-radius:.3rem; padding:.12rem .45rem; color:var(--muted); }

  /* ---- title ------------------------------------------------------------- */
  .title-block { margin:1.75rem 0 1.5rem; }
  h1 { margin:0; font-size:clamp(1.35rem,2.4vw,1.85rem); line-height:1.25; letter-spacing:-.015em; font-weight:650; }
  h1 .accent { color:var(--accent); }
  .lede { margin:.45rem 0 0; color:var(--muted); font-size:.98rem; max-width:60ch; }

  /* ---- kpis -------------------------------------------------------------- */
  .kpis {
    display:grid; grid-template-columns:repeat(auto-fit,minmax(11.5rem,1fr));
    border:1px solid var(--line); border-radius:var(--radius); overflow:hidden;
    background:var(--panel);
  }
  .kpi { padding:.7rem .85rem; border-right:1px solid var(--line); }
  .kpi:last-child { border-right:0; }
  .kpi-label {
    display:block; font-family:var(--mono); font-size:.66rem; letter-spacing:.14em;
    text-transform:uppercase; color:var(--faint); margin-bottom:.2rem;
  }
  .kpi-value {
    display:block; font-family:var(--mono); font-size:.9rem; color:var(--fg);
    overflow-wrap:anywhere;
  }

  /* ---- severity bar ------------------------------------------------------ */
  .severity { margin:1.5rem 0 2rem; }
  .bar {
    display:flex; height:.5rem; border-radius:999px; overflow:hidden;
    background:var(--bg-2); border:1px solid var(--line);
  }
  .bar .seg { display:block; height:100%; }
  .bar .seg.critical { background:var(--critical); }
  .bar .seg.high { background:var(--high); }
  .bar .seg.medium { background:var(--medium); }
  .bar .seg.low { background:var(--low); }
  .bar .seg.info { background:var(--info); }
  .bar .empty { width:100%; background:linear-gradient(90deg,var(--line),var(--bg-2)); }
  .legend {
    display:flex; flex-wrap:wrap; gap:.35rem 1.1rem; margin-top:.65rem;
    font-family:var(--mono); font-size:.74rem; text-transform:uppercase; letter-spacing:.1em;
    color:var(--muted);
  }
  .legend b { color:var(--fg); font-weight:600; }
  .legend .dot { display:inline-block; width:.5rem; height:.5rem; border-radius:50%; margin-right:.35rem; vertical-align:middle; }
  .dot.critical{background:var(--critical)} .dot.high{background:var(--high)} .dot.medium{background:var(--medium)}
  .dot.low{background:var(--low)} .dot.info{background:var(--info)}

  /* ---- findings ---------------------------------------------------------- */
  .section-label {
    font-family:var(--mono); font-size:.68rem; letter-spacing:.16em; text-transform:uppercase;
    color:var(--faint); margin:0 0 .7rem;
  }
  details.finding {
    border:1px solid var(--line); border-left:3px solid var(--faint);
    border-radius:.4rem; background:var(--panel); margin:0 0 .55rem; overflow:hidden;
  }
  details.finding[open] { background:linear-gradient(180deg,var(--panel-2),var(--panel)); }
  details.finding.critical { border-left-color:var(--critical); }
  details.finding.high { border-left-color:var(--high); }
  details.finding.medium { border-left-color:var(--medium); }
  details.finding.low { border-left-color:var(--low); }
  details.finding.info { border-left-color:var(--info); }
  summary {
    list-style:none; cursor:pointer; display:grid; grid-template-columns:auto auto 1fr auto;
    gap:.6rem; align-items:center; padding:.7rem .85rem;
  }
  summary::-webkit-details-marker { display:none; }
  summary:focus-visible { outline:2px solid var(--accent); outline-offset:-2px; }
  .sev {
    font-family:var(--mono); font-size:.66rem; font-weight:700; letter-spacing:.1em;
    text-transform:uppercase; padding:.14rem .42rem; border-radius:.25rem;
    border:1px solid currentColor; white-space:nowrap;
  }
  .sev.critical{color:var(--critical)} .sev.high{color:var(--high)} .sev.medium{color:var(--medium)}
  .sev.low{color:var(--low)} .sev.info{color:var(--info)}
  .check-id { font-family:var(--mono); font-size:.8rem; color:var(--muted); white-space:nowrap; }
  .finding-title { font-weight:550; }
  .pill {
    font-family:var(--mono); font-size:.66rem; text-transform:uppercase; letter-spacing:.1em;
    border:1px solid var(--line-2); border-radius:999px; padding:.1rem .5rem; color:var(--muted);
    white-space:nowrap;
  }
  .pill.observed { color:var(--low); border-color:color-mix(in srgb, var(--low) 45%, var(--line-2)); }
  .pill.inferred { color:var(--medium); border-color:color-mix(in srgb, var(--medium) 45%, var(--line-2)); }
  .body { padding:.2rem .95rem 1rem 1.05rem; border-top:1px solid var(--line); }
  .body .tags {
    display:flex; flex-wrap:wrap; gap:.35rem; margin:.7rem 0 .2rem;
  }
  .field { margin-top:.85rem; }
  .field-label {
    font-family:var(--mono); font-size:.64rem; letter-spacing:.15em; text-transform:uppercase;
    color:var(--faint); margin:0 0 .2rem;
  }
  .field p { margin:0; }
  .field ul { margin:.15rem 0 0 1rem; padding:0; }
  .field li { margin:.12rem 0; }
  .field.evidence li { font-family:var(--mono); font-size:.82rem; color:var(--muted); }
  code {
    font-family:var(--mono); font-size:.88em; color:var(--fg);
    background:color-mix(in srgb, var(--fg) 8%, transparent);
    padding:.08rem .32rem; border-radius:.25rem;
  }
  .empty-state {
    border:1px dashed var(--line-2); border-radius:var(--radius); padding:1.4rem;
    color:var(--muted); text-align:center; font-family:var(--mono); font-size:.9rem;
  }
  .note {
    border:1px solid var(--line); border-left:3px solid var(--accent); border-radius:.4rem;
    background:color-mix(in srgb, var(--accent) 6%, var(--panel));
    padding:.7rem .9rem; margin:1.5rem 0; font-size:.9rem; color:var(--muted);
  }
  .note strong { color:var(--fg); }
  footer {
    margin-top:2.5rem; padding-top:.9rem; border-top:1px solid var(--line);
    font-family:var(--mono); font-size:.74rem; letter-spacing:.06em; color:var(--faint);
    display:flex; flex-wrap:wrap; gap:.5rem 1.2rem; justify-content:space-between;
  }
  @media print {
    :root {
      --bg:#ffffff; --bg-2:#ffffff; --panel:#ffffff; --panel-2:#ffffff;
      --line:#cccccc; --line-2:#b5b5b5;
      --fg:#000000; --muted:#333333; --faint:#555555;
      --accent:#000000; --accent-fg:#ffffff; --accent-dim:#999999;
      --critical:#000000; --high:#000000; --medium:#000000; --low:#000000; --info:#000000;
    }
    body { background-image:none; }
    body::before { display:none; }
    details.finding, .kpis, .masthead, .note { break-inside:avoid; }
    .status-dot { display:none; }
  }
`;

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function page(title: string, body: string, footerLeft: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<style>${BASE_CSS}</style>
</head>
<body>
<main>
${body}
<footer><span>${escapeHtml(footerLeft)}</span><span>mcp-threat-observatory</span></footer>
</main>
</body>
</html>
`;
}

function masthead(mode: string): string {
  return `<div class="masthead">
  <span class="brand"><span class="status-dot"></span>mcp threat observatory</span>
  <span class="right"><span>${escapeHtml(mode)}</span><span class="tlp">TLP:CLEAR</span></span>
</div>`;
}

function titleBlock(title: string, accent: string, lede: string): string {
  return `<div class="title-block">
  <h1>${escapeHtml(title)}<span class="accent"> ${escapeHtml(accent)}</span></h1>
  <p class="lede">${escapeHtml(lede)}</p>
</div>`;
}

function kpis(entries: Array<[string, string]>): string {
  const cells = entries
    .map(([label, value]) => `<div class="kpi"><span class="kpi-label">${escapeHtml(label)}</span><span class="kpi-value">${escapeHtml(value)}</span></div>`)
    .join("");
  return `<div class="kpis">${cells}</div>`;
}

function severityBar(counts: Record<string, number>): string {
  const total = SEVERITIES.reduce((sum, severity) => sum + (counts[severity] ?? 0), 0);
  const segments = total
    ? SEVERITIES.filter((severity) => (counts[severity] ?? 0) > 0)
        .map(
          (severity) =>
            `<span class="seg ${severity}" style="width:${(((counts[severity] ?? 0) / total) * 100).toFixed(2)}%"></span>`,
        )
        .join("")
    : '<span class="seg empty"></span>';

  const legend = SEVERITIES.map(
    (severity) =>
      `<span><span class="dot ${severity}"></span>${severity} <b>${counts[severity] ?? 0}</b></span>`,
  ).join("");

  return `<div class="severity">
  <div class="bar" role="img" aria-label="${escapeHtml(
    SEVERITIES.map((severity) => `${counts[severity] ?? 0} ${severity}`).join(", "),
  )}">${segments}</div>
  <div class="legend">${legend}</div>
</div>`;
}

function findingBlock(finding: Finding & { origin?: string }, open: boolean): string {
  const fields: string[] = [];
  fields.push(`<div class="field"><p class="field-label">Observation</p><p>${escapeHtml(finding.observation)}</p></div>`);
  if (finding.inference) {
    fields.push(`<div class="field"><p class="field-label">Inference</p><p>${escapeHtml(finding.inference)}</p></div>`);
  }
  if (finding.recommendation) {
    fields.push(`<div class="field"><p class="field-label">Recommendation</p><p>${escapeHtml(finding.recommendation)}</p></div>`);
  }
  if (finding.limitations.length > 0) {
    fields.push(
      `<div class="field"><p class="field-label">Limitations</p><ul>${finding.limitations
        .map((limitation) => `<li>${escapeHtml(limitation)}</li>`)
        .join("")}</ul></div>`,
    );
  }
  if (finding.evidence.length > 0) {
    fields.push(
      `<div class="field evidence"><p class="field-label">Evidence</p><ul>${finding.evidence
        .map(
          (evidence) =>
            `<li>${escapeHtml(evidence.locator)}${evidence.excerpt ? ` — ${escapeHtml(evidence.excerpt)}` : ""}</li>`,
        )
        .join("")}</ul></div>`,
    );
  }

  const meta = [
    finding.owasp.length ? finding.owasp.join(" · ") : "",
    finding.taxonomy.length ? finding.taxonomy.join(" · ") : "",
    `confidence: ${finding.confidence}`,
    `fingerprint: ${finding.fingerprint}`,
    finding.origin ? `origin: ${finding.origin}` : "",
  ].filter(Boolean);

  return `<details class="finding ${escapeHtml(finding.severity)}"${open ? " open" : ""}>
  <summary>
    <span class="sev ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
    <span class="check-id">${escapeHtml(finding.checkId)}</span>
    <span class="finding-title">${escapeHtml(finding.title)}</span>
    <span class="pill ${escapeHtml(finding.assertion)}">${escapeHtml(finding.assertion)}</span>
  </summary>
  <div class="body">
    <div class="tags">${meta.map((item) => `<span class="pill">${escapeHtml(item)}</span>`).join("")}</div>
    ${fields.join("\n")}
  </div>
</details>`;
}

function findingsSection(findings: Array<Finding & { origin?: string }>): string {
  if (findings.length === 0) {
    return `<p class="section-label">Findings</p>
<div class="empty-state">no findings — the collector stayed quiet</div>`;
  }
  return `<p class="section-label">Findings · ${findings.length}</p>
${findings.map((finding, index) => findingBlock(finding, index === 0)).join("\n")}`;
}

export function renderSnapshotHtml(snapshot: Snapshot): string {
  const host = safeHost(snapshot.probe.target);
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of snapshot.findings) counts[finding.severity] += 1;

  const body = [
    masthead("passive collection"),
    titleBlock("Passive observation", host, "What an ordinary MCP client sees before authenticating."),
    kpis([
      ["target", snapshot.probe.target],
      ["collected", snapshot.probe.collectedAt],
      [
        "auth required",
        snapshot.probe.auth.requiresAuth === null ? "unknown" : snapshot.probe.auth.requiresAuth ? "yes" : "no",
      ],
      ["tools", snapshot.probe.tools === null ? "unknown" : String(snapshot.probe.tools.length)],
    ]),
    severityBar(counts),
    findingsSection(snapshot.findings),
    `<div class="note"><strong>What this does not claim.</strong> No tool was invoked, nothing behind the login boundary was observed, and no finding is evidence of intent.</div>`,
  ].join("\n");

  return page(`Passive observation — ${host}`, body, `${snapshot.probe.limitations.length} stated limitations`);
}

export function renderAssessmentHtml(assessment: Assessment): string {
  const target = assessment.target.url ?? assessment.target.command?.join(" ") ?? "unknown";
  const counts = assessment.summary.bySeverity;

  const body = [
    masthead(`assessment · ${assessment.target.link}`),
    titleBlock("Assessment", target, "Two observations of one server, kept separate."),
    kpis([
      ["target", target],
      ["link", assessment.target.link],
      ["generated", assessment.generatedAt],
      ["findings", `${assessment.summary.passive} passive · ${assessment.summary.behaviour} behaviour`],
    ]),
    severityBar(counts),
    assessment.target.link === "operator-asserted"
      ? '<div class="note"><strong>Link assertion.</strong> The URL and the command were supplied together. The collector cannot prove they refer to the same server.</div>'
      : "",
    findingsSection(assessment.findings),
    `<details class="finding info"><summary><span class="sev info">note</span><span class="check-id">limitations</span><span class="finding-title">What this assessment cannot support</span><span class="pill">${assessment.limitations.length}</span></summary><div class="body"><div class="field"><ul>${assessment.limitations
      .map((limitation) => `<li>${escapeHtml(limitation)}</li>`)
      .join("")}</ul></div></div></details>`,
  ]
    .filter(Boolean)
    .join("\n");

  return page(`Assessment — ${target}`, body, "TLP:CLEAR");
}

function safeHost(target: string): string {
  try {
    return new URL(target).host;
  } catch {
    return target;
  }
}
