import type { Assessment } from "../assess.ts";
import type { Finding, Snapshot } from "../model.ts";
import { stripUnsafe } from "../lib/sanitize.ts";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

/**
 * Design direction: an instrumentation console.
 *
 * Constraints that are not negotiable:
 *   - no scripts, so the document cannot depend on a runtime;
 *   - no external assets, so it renders offline in five years;
 *   - severity is encoded by colour *and* label *and* position, never colour
 *     alone;
 *   - monospace is used for everything, which costs some reading comfort and
 *     buys a consistent, dense, operator-facing surface.
 */
export const BASE_CSS = `
  :root {
    color-scheme: dark light;
    --bg:#07090b; --panel:#0b0e11; --panel-2:#0e1216;
    --line:#1c242a; --line-2:#2b363e;
    --fg:#cfd8da; --muted:#82909a; --faint:#5a6870;
    --accent:#3fe0ff; --accent-fg:#04161c;
    --critical:#ff4d4d; --high:#ff8a3d; --medium:#ffc93c; --low:#39e08a; --info:#82909a;
    --mono: ui-monospace, "SFMono-Regular", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    --rail:3px;
  }
  @media (prefers-color-scheme: light) {
    :root {
      --bg:#f4f5f2; --panel:#fbfbf9; --panel-2:#eef0ec;
      --line:#d5d8d2; --line-2:#b9beb6;
      --fg:#14181a; --muted:#4f585c; --faint:#78828a;
      --accent:#0a6b7d; --accent-fg:#ffffff;
      --critical:#a80f1f; --high:#a33f00; --medium:#7a5a00; --low:#0b6b46; --info:#4f585c;
    }
  }
  * { box-sizing:border-box; }
  html { -webkit-text-size-adjust:100%; }
  body {
    margin:0; min-height:100vh; background:var(--bg); color:var(--fg);
    font:15px/1.65 var(--mono);
    font-variant-ligatures:none;
    background-image:
      linear-gradient(color-mix(in srgb, var(--line) 55%, transparent) 1px, transparent 1px),
      linear-gradient(90deg, color-mix(in srgb, var(--line) 55%, transparent) 1px, transparent 1px);
    background-size:48px 48px;
    background-position:-1px -1px;
  }
  body::before {
    content:""; position:fixed; inset:0; pointer-events:none; z-index:0;
    background:radial-gradient(ellipse at 50% -10%, color-mix(in srgb, var(--bg) 40%, transparent), var(--bg) 68%);
  }
  @media (prefers-color-scheme: dark) {
    body::after {
      content:""; position:fixed; inset:0; pointer-events:none; z-index:0; opacity:.5;
      background:repeating-linear-gradient(0deg, color-mix(in srgb, var(--fg) 3%, transparent) 0 1px, transparent 1px 3px);
    }
  }
  main { position:relative; z-index:1; max-width:78rem; margin:0 auto; padding:1.25rem 1.25rem 4rem; }
  .mono { font-family:var(--mono); font-variant-numeric:tabular-nums; }

  /* ---- classification deck ---------------------------------------------- */
  .deck {
    display:flex; flex-wrap:wrap; justify-content:space-between; gap:.35rem 1rem;
    padding:.3rem .1rem; border-bottom:1px solid var(--line-2);
    font-size:.68rem; letter-spacing:.18em; text-transform:uppercase; color:var(--faint);
  }
  .deck .tag { color:var(--muted); }
  .masthead {
    display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:.5rem 1rem;
    margin-top:.55rem; padding:.5rem .75rem;
    border:1px solid var(--line-2); background:linear-gradient(180deg,var(--panel-2),var(--panel));
    font-size:.72rem; letter-spacing:.16em; text-transform:uppercase; color:var(--muted);
  }
  .masthead .brand { display:flex; align-items:center; gap:.55rem; color:var(--fg); }
  .status-dot {
    width:.45rem; height:.45rem; background:var(--low); flex:0 0 auto;
    box-shadow:0 0 0 2px color-mix(in srgb, var(--low) 22%, transparent);
  }
  @media (prefers-reduced-motion: no-preference) {
    .status-dot { animation:blink 2.4s steps(1,end) infinite; }
    @keyframes blink { 0%,70%{opacity:1} 71%,100%{opacity:.35} }
  }
  .masthead .right { display:flex; align-items:center; gap:1rem; }
  .cursor { color:var(--accent); }

  /* ---- title ------------------------------------------------------------- */
  .title-block { margin:1.5rem 0 1.25rem; }
  h1 {
    margin:0; font-size:clamp(1.15rem,2.1vw,1.55rem); line-height:1.3; font-weight:600;
    letter-spacing:.045em; text-transform:uppercase;
  }
  h1 .prompt { color:var(--accent); margin-right:.35rem; }
  h1 .accent { color:var(--accent); font-weight:400; }
  .lede { margin:.4rem 0 0; color:var(--muted); font-size:.88rem; max-width:74ch; }

  /* ---- key/value block --------------------------------------------------- */
  .kv {
    border:1px solid var(--line); border-top:2px solid var(--line-2); background:var(--panel);
  }
  .kv .row {
    display:grid; grid-template-columns:minmax(8rem,14rem) 1fr; gap:.5rem 1rem;
    padding:.42rem .75rem; border-bottom:1px dashed var(--line);
  }
  .kv .row:last-child { border-bottom:0; }
  .kv .k {
    font-size:.68rem; letter-spacing:.16em; text-transform:uppercase; color:var(--faint);
    padding-top:.1rem;
  }
  .kv .v { font-size:.86rem; color:var(--fg); overflow-wrap:anywhere; font-variant-numeric:tabular-nums; }

  /* ---- severity bar ------------------------------------------------------ */
  .severity { margin:1.25rem 0 1.75rem; }
  .bar { display:flex; height:.6rem; border:1px solid var(--line-2); background:var(--bg); }
  .bar .seg { display:block; height:100%; border-right:2px solid var(--bg); }
  .bar .seg:last-child { border-right:0; }
  .bar .seg.critical { background:var(--critical); }
  .bar .seg.high { background:var(--high); }
  .bar .seg.medium { background:var(--medium); }
  .bar .seg.low { background:var(--low); }
  .bar .seg.info { background:var(--info); }
  .bar .empty { width:100%; background:repeating-linear-gradient(90deg,var(--line) 0 6px,transparent 6px 12px); }
  .legend {
    display:flex; flex-wrap:wrap; gap:.25rem 1.25rem; margin-top:.5rem;
    font-size:.7rem; letter-spacing:.14em; text-transform:uppercase; color:var(--faint);
  }
  .legend .item { display:inline-flex; align-items:center; gap:.4rem; }
  .legend b { color:var(--fg); font-weight:600; font-variant-numeric:tabular-nums; }
  .legend .swatch { width:.6rem; height:.6rem; display:inline-block; }
  .swatch.critical{background:var(--critical)} .swatch.high{background:var(--high)}
  .swatch.medium{background:var(--medium)} .swatch.low{background:var(--low)}
  .swatch.info{background:var(--info)}

  /* ---- findings ---------------------------------------------------------- */
  .section-label {
    margin:0 0 .55rem; font-size:.68rem; letter-spacing:.18em; text-transform:uppercase; color:var(--faint);
  }
  details.finding {
    border:1px solid var(--line); border-left:var(--rail) solid var(--faint);
    background:var(--panel); margin:0 0 .4rem;
  }
  details.finding[open] { background:var(--panel-2); }
  details.finding.critical { border-left-color:var(--critical); }
  details.finding.high { border-left-color:var(--high); }
  details.finding.medium { border-left-color:var(--medium); }
  details.finding.low { border-left-color:var(--low); }
  details.finding.info { border-left-color:var(--info); }
  summary {
    list-style:none; cursor:pointer; display:grid;
    grid-template-columns:2.2rem 3.2rem 1fr auto; gap:.5rem; align-items:center;
    padding:.42rem .6rem; font-size:.82rem;
  }
  summary::-webkit-details-marker { display:none; }
  summary::marker { content:""; }
  summary:hover { background:color-mix(in srgb, var(--accent) 7%, transparent); }
  summary:focus-visible { outline:2px solid var(--accent); outline-offset:-2px; }
  .marker { color:var(--accent); font-size:.8rem; }
  .idx { color:var(--faint); font-size:.72rem; text-align:right; font-variant-numeric:tabular-nums; }
  .sev {
    font-size:.66rem; font-weight:700; letter-spacing:.12em; text-transform:uppercase;
    padding:.08rem .3rem; border:1px solid currentColor; white-space:nowrap; text-align:center;
  }
  .sev.critical{color:var(--critical)} .sev.high{color:var(--high)} .sev.medium{color:var(--medium)}
  .sev.low{color:var(--low)} .sev.info{color:var(--info)}
  .headline { display:flex; flex-wrap:wrap; align-items:baseline; gap:.4rem .85rem; min-width:0; }
  .check-id { color:var(--muted); font-size:.76rem; letter-spacing:.06em; white-space:nowrap; }
  .finding-title { color:var(--fg); overflow-wrap:anywhere; }
  .pill {
    font-size:.64rem; letter-spacing:.12em; text-transform:uppercase;
    border:1px solid var(--line-2); padding:.06rem .38rem; color:var(--muted); white-space:nowrap;
  }
  .pill.observed { color:var(--low); border-color:color-mix(in srgb, var(--low) 50%, var(--line-2)); }
  .pill.inferred { color:var(--medium); border-color:color-mix(in srgb, var(--medium) 50%, var(--line-2)); }
  .body { border-top:1px solid var(--line); padding:.6rem .75rem .9rem; }
  .body .tags { display:flex; flex-wrap:wrap; gap:.3rem; margin:.15rem 0 .6rem; }
  .field { margin-top:.65rem; }
  .field-label {
    margin:0 0 .15rem; font-size:.64rem; letter-spacing:.16em; text-transform:uppercase; color:var(--faint);
  }
  .field-label::before { content:"// "; color:var(--line-2); }
  .field p { margin:0; font-size:.86rem; }
  .field ul { margin:.1rem 0 0 1.1rem; padding:0; }
  .field li { margin:.12rem 0; font-size:.84rem; }
  .field.evidence li { color:var(--muted); font-size:.8rem; }
  code {
    font-family:var(--mono); font-size:.95em; color:var(--fg);
    background:color-mix(in srgb, var(--fg) 9%, transparent);
    padding:0 .28rem;
  }
  .empty-state {
    border:1px dashed var(--line-2); padding:1.2rem; text-align:center;
    color:var(--muted); font-size:.82rem; letter-spacing:.06em;
  }
  .empty-state::before { content:"[ OK ] "; color:var(--low); }
  .note {
    border:1px solid var(--line); border-left:var(--rail) solid var(--accent);
    background:color-mix(in srgb, var(--accent) 5%, var(--panel));
    padding:.55rem .75rem; margin:1.25rem 0; font-size:.82rem; color:var(--muted);
  }
  .note strong { color:var(--fg); text-transform:uppercase; letter-spacing:.08em; font-size:.74rem; }
  footer {
    margin-top:2.25rem; padding-top:.55rem; border-top:1px solid var(--line-2);
    display:flex; flex-wrap:wrap; justify-content:space-between; gap:.35rem 1rem;
    font-size:.68rem; letter-spacing:.14em; text-transform:uppercase; color:var(--faint);
  }
  @media (max-width:640px) {
    summary { grid-template-columns:1.6rem 2.8rem 1fr; }
    summary .pill { display:none; }
    .kv .row { grid-template-columns:1fr; gap:.1rem; }
  }
  @media print {
    :root {
      --bg:#ffffff; --panel:#ffffff; --panel-2:#ffffff;
      --line:#cccccc; --line-2:#999999;
      --fg:#000000; --muted:#333333; --faint:#555555;
      --accent:#000000; --accent-fg:#ffffff;
      --critical:#000000; --high:#000000; --medium:#000000; --low:#000000; --info:#000000;
    }
    body { background-image:none; }
    body::before, body::after { display:none; }
    details.finding, .kv, .masthead, .note { break-inside:avoid; }
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
<footer><span>EOF · ${escapeHtml(footerLeft)}</span><span>mcp-threat-observatory</span></footer>
</main>
</body>
</html>
`;
}

function deck(mode: string): string {
  return `<div class="deck">
  <span><span class="tag">TLP:CLEAR</span> · public release</span>
  <span>observation only · no exploit content</span>
</div>
<div class="masthead">
  <span class="brand"><span class="status-dot"></span>[ mcp threat observatory ]</span>
  <span class="right"><span>mode: ${escapeHtml(mode)}</span><span class="cursor">█</span></span>
</div>`;
}

function titleBlock(title: string, accent: string, lede: string): string {
  return `<div class="title-block">
  <h1><span class="prompt">&gt;</span>${escapeHtml(title)}<span class="accent"> // ${escapeHtml(accent)}</span></h1>
  <p class="lede">${escapeHtml(lede)}</p>
</div>`;
}

function kv(entries: Array<[string, string]>): string {
  const rows = entries
    .map(([key, value]) => `<div class="row"><span class="k">${escapeHtml(key)}</span><span class="v">${escapeHtml(value)}</span></div>`)
    .join("");
  return `<div class="kv">${rows}</div>`;
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
      `<span class="item"><span class="swatch ${severity}"></span>${severity}<b>${String(counts[severity] ?? 0).padStart(2, "0")}</b></span>`,
  ).join("");

  return `<div class="severity">
  <div class="bar" role="img" aria-label="${escapeHtml(
    SEVERITIES.map((severity) => `${counts[severity] ?? 0} ${severity}`).join(", "),
  )}">${segments}</div>
  <div class="legend">${legend}</div>
</div>`;
}

function findingBlock(finding: Finding & { origin?: string }, index: number, open: boolean): string {
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
    finding.owasp.length ? `OWASP ${finding.owasp.join(" ")}` : "",
    finding.taxonomy.length ? finding.taxonomy.join(" · ") : "",
    `conf ${finding.confidence}`,
    `fp ${finding.fingerprint}`,
    finding.origin ? `origin ${finding.origin}` : "",
  ].filter(Boolean);

  return `<details class="finding ${escapeHtml(finding.severity)}"${open ? " open" : ""}>
  <summary>
    <span class="marker">${open ? "[-]" : "[+]"}</span>
    <span class="idx">${String(index + 1).padStart(3, "0")}</span>
    <span class="headline">
      <span class="sev ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
      <span class="check-id">${escapeHtml(finding.checkId)}</span>
      <span class="finding-title">${escapeHtml(finding.title)}</span>
    </span>
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
    return `<p class="section-label">// findings</p>
<div class="empty-state">no findings — the collector stayed quiet</div>`;
  }
  return `<p class="section-label">// findings · ${findings.length}</p>
${findings.map((finding, index) => findingBlock(finding, index, index === 0)).join("\n")}`;
}

export function renderSnapshotHtml(snapshot: Snapshot): string {
  const host = safeHost(snapshot.probe.target);
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of snapshot.findings) counts[finding.severity] += 1;

  const body = [
    deck("passive"),
    titleBlock("Passive observation", host, "What an ordinary MCP client sees before authenticating."),
    kv([
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
    `<div class="note"><strong>Does not claim</strong> — no tool was invoked, nothing behind the login boundary was observed, and no finding is evidence of intent.</div>`,
  ].join("\n");

  return stripUnsafe(page(`Passive observation — ${host}`, body, `${snapshot.probe.limitations.length} stated limitations`));
}

export function renderAssessmentHtml(assessment: Assessment): string {
  const target = assessment.target.url ?? assessment.target.command?.join(" ") ?? "unknown";
  const counts = assessment.summary.bySeverity;

  const body = [
    deck(`assessment · ${assessment.target.link}`),
    titleBlock("Assessment", target, "Two observations of one server, kept separate."),
    kv([
      ["target", target],
      ["link", assessment.target.link],
      ["generated", assessment.generatedAt],
      ["findings", `${assessment.summary.passive} passive · ${assessment.summary.behaviour} behaviour`],
    ]),
    severityBar(counts),
    assessment.target.link === "operator-asserted"
      ? '<div class="note"><strong>Link assertion</strong> — the URL and the command were supplied together. The collector cannot prove they refer to the same server.</div>'
      : "",
    findingsSection(assessment.findings),
    `<details class="finding info"><summary><span class="marker">[+]</span><span class="idx">---</span><span class="headline"><span class="sev info">note</span><span class="check-id">limitations</span><span class="finding-title">What this assessment cannot support</span></span><span class="pill">${assessment.limitations.length}</span></summary><div class="body"><div class="field"><ul>${assessment.limitations
      .map((limitation) => `<li>${escapeHtml(limitation)}</li>`)
      .join("")}</ul></div></div></details>`,
  ]
    .filter(Boolean)
    .join("\n");

  return stripUnsafe(page(`Assessment — ${target}`, body, "TLP:CLEAR"));
}

function safeHost(target: string): string {
  try {
    return new URL(target).host;
  } catch {
    return target;
  }
}
