import type { Snapshot } from "../model.ts";
import { stripUnsafe } from "../lib/sanitize.ts";

/**
 * Renders a human-readable report.
 *
 * Structure is deliberate: observation, then inference, then recommendation,
 * then limitations. A reader must be able to stop after the observation and
 * still know exactly what was seen.
 */
export function renderMarkdown(snapshot: Snapshot): string {
  const { probe, findings, summary } = snapshot;
  const host = safeHost(probe.target);
  const lines: string[] = [];

  lines.push(`# Passive security observation — ${host}`);
  lines.push("");
  lines.push("> TLP:CLEAR · This document contains no exploit and no third-party victim data.");
  lines.push("");
  lines.push(`- **Target:** \`${probe.target}\``);
  lines.push(`- **Collected:** ${probe.collectedAt}`);
  lines.push(`- **Collector:** ${probe.collector.name} ${probe.collector.version}`);
  lines.push(`- **Contact:** ${probe.collector.contact ?? "_not configured_ (set `MCPOBS_CONTACT`)"}`);
  lines.push(`- **Transport:** ${probe.transport} (streamable HTTP)`);
  lines.push(`- **Reachable:** ${probe.reachable ? "yes" : "no"}`);
  lines.push(
    `- **Authentication required:** ${
      probe.auth.requiresAuth === null ? "unknown" : probe.auth.requiresAuth ? "yes" : "no"
    }`,
  );
  if (probe.handshake.serverInfo) {
    lines.push(
      `- **Server:** ${probe.handshake.serverInfo.name ?? "unnamed"} ${
        probe.handshake.serverInfo.version ?? ""
      }`.trimEnd(),
    );
  }
  lines.push(`- **Tools observed:** ${probe.tools ? probe.tools.length : "unknown"}`);
  lines.push("");

  lines.push("## Summary");
  lines.push("");
  lines.push("| Severity | Findings |");
  lines.push("| --- | --- |");
  for (const severity of ["critical", "high", "medium", "low", "info"] as const) {
    lines.push(`| ${severity} | ${summary.bySeverity[severity]} |`);
  }
  lines.push("");
  lines.push(
    `${summary.observed} observation(s) and ${summary.inferred} inference(s). ` +
      `Confidence: ${summary.byConfidence.high} high / ${summary.byConfidence.moderate} moderate / ${summary.byConfidence.low} low.`,
  );
  lines.push("");

  if (findings.length === 0) {
    lines.push("No check produced a finding for this target.");
    lines.push("");
  }

  for (const finding of findings) {
    lines.push(`## ${finding.severity.toUpperCase()} — ${finding.checkId} · ${finding.title}`);
    lines.push("");
    lines.push(
      `**Assertion:** ${finding.assertion} · **Confidence:** ${finding.confidence}` +
        (finding.owasp.length ? ` · **OWASP MCP:** ${finding.owasp.join(", ")}` : "") +
        (finding.taxonomy.length ? ` · **Facets:** ${finding.taxonomy.join(", ")}` : ""),
    );
    lines.push("");
    lines.push(`**Observation.** ${finding.observation}`);
    lines.push("");
    if (finding.inference) {
      lines.push(`**Inference.** ${finding.inference}`);
      lines.push("");
    }
    if (finding.recommendation) {
      lines.push(`**Recommendation.** ${finding.recommendation}`);
      lines.push("");
    }
    if (finding.limitations.length > 0) {
      lines.push("**Limitations.**");
      lines.push("");
      for (const limitation of finding.limitations) lines.push(`- ${limitation}`);
      lines.push("");
    }
    if (finding.evidence.length > 0) {
      lines.push("**Evidence.**");
      lines.push("");
      for (const evidence of finding.evidence) {
        const excerpt = evidence.excerpt ? ` — \`${evidence.excerpt.replace(/\n/g, " ").slice(0, 160)}\`` : "";
        lines.push(`- \`${evidence.locator}\`${excerpt}`);
      }
      lines.push("");
    }
    lines.push(`<sub>fingerprint \`${finding.fingerprint}\`</sub>`);
    lines.push("");
  }

  lines.push("## What this report does not claim");
  lines.push("");
  lines.push("- It does not claim the server is malicious, or that any finding was exploited.");
  lines.push("- It does not describe behaviour behind an authentication boundary.");
  lines.push("- It does not assess code quality, dependencies, or the publisher's identity.");
  lines.push("- It does not invoke tools, so no runtime behaviour was observed.");
  lines.push("");
  lines.push("## Method and limitations");
  lines.push("");
  lines.push(
    "A passive client handshake was performed: `initialize`, then `tools/list`, `resources/list` and `prompts/list`, " +
      "at a maximum of one request per second. No tool was called and no payload was sent. " +
      "See `docs/METHODOLOGY.md` for the evidence-grading model.",
  );
  lines.push("");
  for (const limitation of probe.limitations) lines.push(`- ${limitation}`);
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push(
    `Raw record: ${probe.probes.length} HTTP exchange(s), each with a SHA-256 body digest. ` +
      "Re-verify any excerpt against the snapshot JSON.",
  );
  lines.push("");

  return stripUnsafe(lines.join("\n"));
}

function safeHost(target: string): string {
  try {
    return new URL(target).host;
  } catch {
    return target;
  }
}
