import { severityRank } from "./checks/types.ts";
import { shortHash } from "./lib/id.ts";
import type { Finding, Snapshot } from "./model.ts";
import { analyseBehaviour } from "./behaviour/analyser.ts";
import type { BehaviourRecord } from "./behaviour/types.ts";
import { stripUnsafe } from "./lib/sanitize.ts";

export type FindingOrigin = "passive" | "behaviour";
export type LinkAssertion = "operator-asserted" | "url-only" | "command-only";

export interface AssessedFinding extends Finding {
  origin: FindingOrigin;
}

export interface Assessment {
  schemaVersion: "1";
  kind: "assessment";
  generatedAt: string;
  target: {
    url: string | null;
    command: string[] | null;
    /**
     * The collector has no way to prove that the URL and the command are the
     * same server. It records the operator's assertion as an assertion.
     */
    link: LinkAssertion;
  };
  passive: Snapshot | null;
  behaviour: BehaviourRecord | null;
  findings: AssessedFinding[];
  summary: {
    total: number;
    bySeverity: Record<string, number>;
    passive: number;
    behaviour: number;
  };
  limitations: string[];
}

export interface AssessmentInput {
  url?: string | null;
  command?: string[] | null;
  snapshot: Snapshot | null;
  record: BehaviourRecord | null;
}

const LINK_LIMITATION =
  "The URL and the command were supplied together by the operator. The collector cannot prove they are the " +
  "same server; the link is an assertion, not an observation.";

export function buildAssessment(input: AssessmentInput): Assessment {
  const url = input.url ?? null;
  const command = input.command ?? null;
  const link: LinkAssertion = url && command ? "operator-asserted" : url ? "url-only" : "command-only";

  const findings: AssessedFinding[] = [
    ...(input.snapshot?.findings ?? []).map((finding) => ({ ...finding, origin: "passive" as const })),
    ...(input.record ? buildBehaviourFindings(input.record) : []),
  ];
  findings.sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || a.checkId.localeCompare(b.checkId),
  );

  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) bySeverity[finding.severity] += 1;

  const limitations = dedupe([
    ...(input.snapshot?.probe.limitations ?? []),
    ...(input.record?.limitations ?? []),
    ...(url && command ? [LINK_LIMITATION] : []),
    "An assessment is a record of two observations, not a verdict about a publisher.",
  ]);

  return {
    schemaVersion: "1",
    kind: "assessment",
    generatedAt: new Date().toISOString(),
    target: { url, command, link },
    passive: input.snapshot,
    behaviour: input.record,
    findings,
    summary: {
      total: findings.length,
      bySeverity,
      passive: findings.filter((finding) => finding.origin === "passive").length,
      behaviour: findings.filter((finding) => finding.origin === "behaviour").length,
    },
    limitations,
  };
}

// Imported lazily to keep the assessment module free of a cycle with the analyser.
function buildBehaviourFindings(record: BehaviourRecord): AssessedFinding[] {
  return analyseBehaviour(record).map((finding) => ({ ...finding, origin: "behaviour" as const }));
}

export function assessmentFingerprint(assessment: Assessment): string {
  return shortHash(
    JSON.stringify({ target: assessment.target, findings: assessment.findings }),
    24,
  );
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}

export function renderAssessmentMarkdown(assessment: Assessment): string {
  const lines: string[] = [];
  const target = assessment.target.url ?? assessment.target.command?.join(" ") ?? "unknown";

  lines.push(`# Assessment — ${target}`);
  lines.push("");
  lines.push("> TLP:CLEAR · Two observations of one server, kept separate.");
  lines.push("");
  lines.push(`- **Generated:** ${assessment.generatedAt}`);
  if (assessment.target.url) lines.push(`- **Endpoint:** \`${assessment.target.url}\``);
  if (assessment.target.command) {
    lines.push(`- **Command:** \`${assessment.target.command.join(" ")}\``);
  }
  lines.push(`- **Link:** ${assessment.target.link}`);
  lines.push(`- **Findings:** ${assessment.summary.passive} passive, ${assessment.summary.behaviour} behavioural`);
  lines.push("");

  lines.push("## Summary");
  lines.push("");
  lines.push("| Severity | Findings |");
  lines.push("| --- | --- |");
  for (const severity of ["critical", "high", "medium", "low", "info"] as const) {
    lines.push(`| ${severity} | ${assessment.summary.bySeverity[severity]} |`);
  }
  lines.push("");

  if (assessment.findings.length === 0) {
    lines.push("No finding was produced by either mode.");
    lines.push("");
  }

  for (const finding of assessment.findings) {
    lines.push(`## ${finding.severity.toUpperCase()} — ${finding.checkId} · ${finding.title}`);
    lines.push("");
    lines.push(
      `**Origin:** ${finding.origin} · **Assertion:** ${finding.assertion} · **Confidence:** ${finding.confidence}` +
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
    lines.push(`<sub>fingerprint \`${finding.fingerprint}\`</sub>`);
    lines.push("");
  }

  lines.push("## What this assessment does not claim");
  lines.push("");
  lines.push("- It does not claim the server is malicious, or that any finding was exploited.");
  lines.push("- It does not prove the URL and the command are the same server.");
  lines.push("- It does not see behind an authentication boundary.");
  lines.push("- It does not see behaviour the runtime hooks cannot observe.");
  lines.push("");
  lines.push("## Limitations");
  lines.push("");
  for (const limitation of assessment.limitations) lines.push(`- ${limitation}`);
  lines.push("");

  return stripUnsafe(lines.join("\n"));
}
