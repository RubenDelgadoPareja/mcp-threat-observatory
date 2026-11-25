import type { BehaviourRecord } from "./types.ts";
import type { Finding } from "../model.ts";

function safeCommand(record: BehaviourRecord): string {
  return record.target.command.join(" ");
}

/**
 * Human rendering of a behaviour record.
 *
 * Same discipline as the passive report: what was observed, what it may mean,
 * and what the record cannot support — in that order.
 */
export function renderBehaviourMarkdown(record: BehaviourRecord, findings: Finding[]): string {
  const lines: string[] = [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;

  lines.push(`# Behavioural observation — ${record.tools[0]?.name ? safeCommand(record) : safeCommand(record)}`);
  lines.push("");
  lines.push("> TLP:CLEAR · The server was executed in a disposable environment with synthetic credentials.");
  lines.push("");
  lines.push(`- **Command:** \`${safeCommand(record)}\``);
  lines.push(`- **Collected:** ${record.collectedAt}`);
  lines.push(`- **Isolation:** ${record.isolation.mechanism} (network: ${record.isolation.network})`);
  lines.push(`- **Argument profile:** ${record.argumentProfile}`);
  lines.push(`- **Canaries planted:** ${record.environment.canaries.length}`);
  lines.push(`- **Tools invoked:** ${record.tools.length}`);
  lines.push(`- **Events recorded:** ${record.events.length}`);
  lines.push("");

  if (record.isolation.network === "open") {
    lines.push(
      "> **Warning:** this run was NOT network-isolated. Outbound connections could have reached real services.",
    );
    lines.push("");
  }

  lines.push("## Summary");
  lines.push("");
  lines.push("| Severity | Findings |");
  lines.push("| --- | --- |");
  for (const severity of ["critical", "high", "medium", "low", "info"] as const) {
    lines.push(`| ${severity} | ${counts[severity]} |`);
  }
  lines.push("");
  lines.push(
    `${record.summary.egressAttempts} egress attempt(s), ${record.summary.canaryReads} canary read(s), ` +
      `${record.summary.canarySends} outbound write(s) containing a canary value.`,
  );
  lines.push("");

  lines.push("## Tool calls");
  lines.push("");
  lines.push("| Tool | Outcome | Duration | Arguments |");
  lines.push("| --- | --- | --- | --- |");
  for (const tool of record.tools) {
    const args = Object.keys(tool.arguments).length
      ? `\`${JSON.stringify(tool.arguments).slice(0, 120)}\``
      : "—";
    lines.push(`| \`${tool.name}\` | ${tool.outcome} | ${tool.durationMs} ms | ${args} |`);
  }
  lines.push("");

  if (findings.length === 0) {
    lines.push("No behaviour finding was produced for this run.");
    lines.push("");
  }

  for (const finding of findings) {
    lines.push(`## ${finding.severity.toUpperCase()} — ${finding.checkId} · ${finding.title}`);
    lines.push("");
    lines.push(
      `**Assertion:** ${finding.assertion} · **Confidence:** ${finding.confidence}` +
        (finding.owasp.length ? ` · **OWASP MCP:** ${finding.owasp.join(", ")}` : ""),
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
        lines.push(`- \`${evidence.locator}\`${evidence.excerpt ? ` — \`${evidence.excerpt}\`` : ""}`);
      }
      lines.push("");
    }
    lines.push(`<sub>fingerprint \`${finding.fingerprint}\`</sub>`);
    lines.push("");
  }

  lines.push("## What this report does not claim");
  lines.push("");
  lines.push("- It does not claim the operator acted with intent. A canary is synthetic.");
  lines.push("- It does not prove the package is malicious, only what this run observed.");
  lines.push("- It does not cover behaviour the hook cannot see: native code, other runtimes, spawned non-Node processes.");
  lines.push("- It does not exercise code paths that need specific argument values or external services.");
  lines.push("");

  lines.push("## Method and limitations");
  lines.push("");
  lines.push(
    "The server was started with a temporary HOME containing canary credentials, an environment rebuilt from " +
      "scratch (no inherited tokens), and a Node preload hook that records network destinations, name " +
      "resolution, credential-file reads and child processes. Every tool was invoked once with arguments " +
      "generated deterministically from its JSON Schema.",
  );
  lines.push("");
  for (const limitation of record.limitations) lines.push(`- ${limitation}`);
  lines.push("");

  return lines.join("\n");
}
