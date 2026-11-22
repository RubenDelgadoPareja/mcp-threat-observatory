import type { Assessment } from "../assess.ts";
import type { Finding, Snapshot } from "../model.ts";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function page(title: string, subtitle: string, body: string, footer: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: light dark; --fg:#1c1d21; --muted:#5d6068; --bg:#fbfbfc; --card:#fff;
          --line:#e4e5ea; --accent:#2f5fd0; --critical:#8b1a1a; --high:#b3341f;
          --medium:#9a6b00; --low:#2f6b4f; --info:#5d6068; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e8e9ee; --muted:#a2a6b3; --bg:#16171b; --card:#1d1f25; --line:#2c2f38; --accent:#8ba8ff; }
  }
  * { box-sizing: border-box; }
  body { margin:0; padding:2.5rem 1.25rem 4rem; background:var(--bg); color:var(--fg);
         font:16px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  main { max-width: 60rem; margin: 0 auto; }
  header { border-bottom:1px solid var(--line); padding-bottom:1rem; margin-bottom:1.5rem; }
  h1 { font-size:1.5rem; line-height:1.3; margin:0 0 .35rem; letter-spacing:-.01em; }
  .sub { color:var(--muted); margin:0; font-size:.95rem; }
  .meta { display:grid; grid-template-columns:repeat(auto-fit,minmax(13rem,1fr)); gap:.5rem 1.5rem;
          margin:1rem 0 0; font-size:.9rem; }
  .meta div { color:var(--muted); }
  .meta strong { color:var(--fg); font-weight:600; }
  .chips { display:flex; flex-wrap:wrap; gap:.5rem; margin:1.25rem 0 2rem; }
  .chip { border:1px solid var(--line); background:var(--card); border-radius:999px;
          padding:.25rem .7rem; font-size:.85rem; color:var(--muted); }
  .chip b { color:var(--fg); }
  details { border:1px solid var(--line); border-radius:.6rem; background:var(--card);
            padding:.85rem 1rem; margin:0 0 .75rem; }
  details[open] { padding-bottom:1.1rem; }
  summary { cursor:pointer; list-style:none; display:flex; gap:.6rem; align-items:baseline; flex-wrap:wrap; }
  summary::-webkit-details-marker { display:none; }
  .sev { font-size:.72rem; font-weight:700; letter-spacing:.06em; text-transform:uppercase;
         padding:.1rem .45rem; border-radius:.3rem; border:1px solid currentColor; }
  .sev-critical{color:var(--critical)} .sev-high{color:var(--high)} .sev-medium{color:var(--medium)}
  .sev-low{color:var(--low)} .sev-info{color:var(--info)}
  .id { font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.85rem; color:var(--muted); }
  .tags { font-size:.8rem; color:var(--muted); }
  .body { margin-top:.9rem; }
  .body h4 { margin:1rem 0 .25rem; font-size:.78rem; letter-spacing:.07em; text-transform:uppercase; color:var(--muted); }
  .body p { margin:.2rem 0; }
  .body ul { margin:.25rem 0 .25rem 1.1rem; padding:0; }
  .body li { margin:.15rem 0; }
  code { font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.88em;
         background:color-mix(in srgb, var(--fg) 7%, transparent); padding:.1rem .3rem; border-radius:.25rem; }
  footer { margin-top:2.5rem; padding-top:1rem; border-top:1px solid var(--line);
           color:var(--muted); font-size:.82rem; }
  .note { border-left:3px solid var(--accent); padding:.6rem .9rem; margin:1.25rem 0;
          background:color-mix(in srgb, var(--accent) 7%, transparent); border-radius:.3rem; font-size:.92rem; }
  .empty { color:var(--muted); font-style:italic; }
</style>
</head>
<body>
<main>
<header>
  <h1>${escapeHtml(title)}</h1>
  <p class="sub">${escapeHtml(subtitle)}</p>
</header>
${body}
<footer>${escapeHtml(footer)}</footer>
</main>
</body>
</html>
`;
}

function metaBlock(entries: Array<[string, string]>): string {
  const rows = entries
    .map(([label, value]) => `<div>${escapeHtml(label)}<br><strong>${escapeHtml(value)}</strong></div>`)
    .join("\n    ");
  return `<div class="meta">\n    ${rows}\n  </div>`;
}

function chips(counts: Record<string, number>, extra: string[] = []): string {
  const severityChips = SEVERITIES.map(
    (severity) => `<span class="chip">${severity} <b>${counts[severity] ?? 0}</b></span>`,
  ).join("\n  ");
  const extras = extra.map((label) => `<span class="chip">${escapeHtml(label)}</span>`).join("\n  ");
  return `<div class="chips">\n  ${severityChips}\n  ${extras}\n</div>`;
}

function findingBlock(finding: Finding & { origin?: string }): string {
  const parts: string[] = [];
  parts.push(`<h4>Observation</h4><p>${escapeHtml(finding.observation)}</p>`);
  if (finding.inference) parts.push(`<h4>Inference</h4><p>${escapeHtml(finding.inference)}</p>`);
  if (finding.recommendation) parts.push(`<h4>Recommendation</h4><p>${escapeHtml(finding.recommendation)}</p>`);
  if (finding.limitations.length > 0) {
    parts.push(`<h4>Limitations</h4><ul>${finding.limitations.map((l) => `<li>${escapeHtml(l)}</li>`).join("")}</ul>`);
  }
  if (finding.evidence.length > 0) {
    parts.push(
      `<h4>Evidence</h4><ul>${finding.evidence
        .map((e) => `<li><code>${escapeHtml(e.locator)}</code>${e.excerpt ? ` — ${escapeHtml(e.excerpt)}` : ""}</li>`)
        .join("")}</ul>`,
    );
  }

  const tags = [
    finding.origin ? `origin: ${finding.origin}` : "",
    finding.confidence,
    finding.owasp.length ? finding.owasp.join(", ") : "",
  ]
    .filter(Boolean)
    .join(" · ");

  return `<details>
  <summary>
    <span class="sev sev-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
    <span class="id">${escapeHtml(finding.checkId)}</span>
    <span>${escapeHtml(finding.title)}</span>
    <span class="tags">${escapeHtml(tags)}</span>
  </summary>
  <div class="body">${parts.join("")}</div>
</details>`;
}

export function renderSnapshotHtml(snapshot: Snapshot): string {
  const host = safeHost(snapshot.probe.target);
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of snapshot.findings) counts[finding.severity] += 1;

  const body = [
    metaBlock([
      ["Target", snapshot.probe.target],
      ["Collected", snapshot.probe.collectedAt],
      ["Authentication required", snapshot.probe.auth.requiresAuth === null ? "unknown" : snapshot.probe.auth.requiresAuth ? "yes" : "no"],
      ["Tools observed", snapshot.probe.tools === null ? "unknown" : String(snapshot.probe.tools.length)],
    ]),
    chips(counts, [`${snapshot.findings.length} findings`]),
    snapshot.findings.length === 0
      ? '<p class="empty">No check produced a finding for this target.</p>'
      : snapshot.findings.map(findingBlock).join("\n"),
    `<div class="note"><strong>What this does not claim.</strong> No tool was invoked, nothing behind the login boundary was observed, and no finding is evidence of intent.</div>`,
  ].join("\n");

  return page(
    `Passive observation — ${host}`,
    "What an ordinary MCP client sees before authenticating.",
    body,
    `TLP:CLEAR · generated by mcp-threat-observatory · ${snapshot.probe.limitations.length} stated limitations`,
  );
}

export function renderAssessmentHtml(assessment: Assessment): string {
  const target = assessment.target.url ?? assessment.target.command?.join(" ") ?? "unknown";
  const counts = assessment.summary.bySeverity;

  const body = [
    metaBlock([
      ["Target", target],
      ["Link", assessment.target.link],
      ["Generated", assessment.generatedAt],
      ["Findings", `${assessment.summary.passive} passive · ${assessment.summary.behaviour} behavioural`],
    ]),
    chips(counts, [`${assessment.summary.total} findings`]),
    assessment.target.link === "operator-asserted"
      ? '<div class="note"><strong>Link assertion.</strong> The URL and the command were supplied together. The collector cannot prove they refer to the same server.</div>'
      : "",
    assessment.findings.length === 0
      ? '<p class="empty">No finding was produced by either mode.</p>'
      : assessment.findings.map(findingBlock).join("\n"),
    `<details><summary><span class="id">limitations</span><span>What this assessment cannot support</span></summary><div class="body"><ul>${assessment.limitations
      .map((limitation) => `<li>${escapeHtml(limitation)}</li>`)
      .join("")}</ul></div></details>`,
  ]
    .filter(Boolean)
    .join("\n");

  return page(
    `Assessment — ${target}`,
    "Two observations of one server, kept separate.",
    body,
    "TLP:CLEAR · generated by mcp-threat-observatory",
  );
}

function safeHost(target: string): string {
  try {
    return new URL(target).host;
  } catch {
    return target;
  }
}
