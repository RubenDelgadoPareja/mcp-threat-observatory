import { severityRank } from "./checks/types.ts";
import { shortHash } from "./lib/id.ts";
import type { Finding, Snapshot, ToolAnnotations, ToolDescriptor } from "./model.ts";
import { stripUnsafe } from "./lib/sanitize.ts";

export interface ToolChange {
  name: string;
  change: "added" | "removed" | "modified";
  /** Definition fields whose canonical form changed. */
  fields: string[];
  /** Safety hints that became less restrictive. */
  relaxations: string[];
}

export interface SnapshotMeta {
  label: string;
  target: string;
  collectedAt: string;
  catalogKnown: boolean;
}

export interface DriftReport {
  previous: SnapshotMeta;
  current: SnapshotMeta;
  targetsMatch: boolean;
  toolChanges: ToolChange[];
  newFindings: Finding[];
  resolvedFindings: Finding[];
  driftFindings: Finding[];
  changed: boolean;
}

const FIELDS = ["title", "description", "annotations", "inputSchema"] as const;

/** Stable JSON: key order must not create a false positive. */
function canonical(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

/**
 * Signature of the parts of a tool definition a client relies on.
 * Hashing the whole definition, not just the description, is deliberate: a
 * flipped `destructiveHint` changes approval behaviour without changing a word.
 */
export function toolSignature(tool: ToolDescriptor): string {
  return shortHash(
    canonical({
      name: tool.name,
      title: tool.title,
      description: tool.description,
      annotations: tool.annotations,
      inputSchema: tool.inputSchema,
    }),
    16,
  );
}

function relaxations(
  before: ToolAnnotations | null | undefined,
  after: ToolAnnotations | null | undefined,
): string[] {
  const old = before ?? {};
  const next = after ?? {};
  const out: string[] = [];
  // A hint that disappears is also a relaxation: the signal the client used is gone.
  if (old.destructiveHint === true && next.destructiveHint !== true) out.push("destructiveHint");
  if (old.openWorldHint === true && next.openWorldHint !== true) out.push("openWorldHint");
  if (old.readOnlyHint === false && next.readOnlyHint === true) out.push("readOnlyHint");
  return out;
}

function meta(snapshot: Snapshot, label: string): SnapshotMeta {
  return {
    label,
    target: snapshot.probe.target,
    collectedAt: snapshot.probe.collectedAt,
    catalogKnown: snapshot.probe.tools !== null,
  };
}

function driftFinding(
  target: string,
  checkId: "DRIFT-001" | "DRIFT-002",
  input: {
    title: string;
    severity: Finding["severity"];
    observation: string;
    inference: string;
    limitations: string[];
    discriminator: string;
  },
): Finding {
  return {
    fingerprint: shortHash(`${checkId}|${target}|${input.discriminator}`, 16),
    checkId,
    title: input.title,
    severity: input.severity,
    confidence: "high",
    assertion: "observed",
    taxonomy: ["drift", "supply-chain"],
    owasp: ["MCP03", "MCP04"],
    observation: input.observation,
    inference: input.inference,
    recommendation:
      "Review the change against the release notes. If it was not announced, treat the server as untrusted " +
      "until the publisher explains it.",
    limitations: input.limitations,
    evidence: [{ kind: "derived", locator: `drift → ${input.discriminator}` }],
  };
}

const CHANGE_LIMITATIONS = [
  "A change is not an attack: releases change tool definitions legitimately.",
  "Only definitions are compared; server code and behaviour are not.",
];

export function diffSnapshots(
  previous: Snapshot,
  current: Snapshot,
  labels: { previous?: string; current?: string } = {},
): DriftReport {
  const previousMeta = meta(previous, labels.previous ?? "previous");
  const currentMeta = meta(current, labels.current ?? "current");
  const targetsMatch = previousMeta.target === currentMeta.target;

  const before = new Map((previous.probe.tools ?? []).map((tool) => [tool.name, tool]));
  const after = new Map((current.probe.tools ?? []).map((tool) => [tool.name, tool]));

  const toolChanges: ToolChange[] = [];
  if (previousMeta.catalogKnown && currentMeta.catalogKnown) {
    for (const [name, tool] of after) {
      if (!before.has(name)) {
        toolChanges.push({
          name,
          change: "added",
          fields: [],
          relaxations: [],
        });
        continue;
      }
      const old = before.get(name)!;
      const fields = FIELDS.filter((field) => canonical(old[field]) !== canonical(tool[field]));
      if (fields.length === 0) continue;
      toolChanges.push({
        name,
        change: "modified",
        fields: [...fields],
        relaxations: relaxations(old.annotations, tool.annotations),
      });
    }
    for (const [name] of before) {
      if (!after.has(name)) toolChanges.push({ name, change: "removed", fields: [], relaxations: [] });
    }
    toolChanges.sort((a, b) => a.name.localeCompare(b.name));
  }

  const beforeFindings = new Map(previous.findings.map((finding) => [finding.fingerprint, finding]));
  const afterFindings = new Map(current.findings.map((finding) => [finding.fingerprint, finding]));
  const newFindings = targetsMatch
    ? [...afterFindings.keys()]
        .filter((key) => !beforeFindings.has(key))
        .sort()
        .map((key) => afterFindings.get(key)!)
    : [];
  const resolvedFindings = targetsMatch
    ? [...beforeFindings.keys()]
        .filter((key) => !afterFindings.has(key))
        .sort()
        .map((key) => beforeFindings.get(key)!)
    : [];

  const driftFindings: Finding[] = [];
  for (const change of toolChanges) {
    const description =
      change.change === "modified"
        ? `fields: ${change.fields.join(", ")}`
        : change.change === "added"
          ? "the tool did not exist in the previous record"
          : "the tool no longer exists";
    driftFindings.push(
      driftFinding(currentMeta.target, "DRIFT-001", {
        title: "Tool definition changed since the previous record",
        severity: "info",
        observation: `Tool \`${change.name}\` was ${change.change} (${description}).`,
        inference:
          "A client that approved the previous catalog now sees a different one. That is expected for a release " +
          "and suspicious when it is unannounced.",
        limitations: CHANGE_LIMITATIONS,
        discriminator: `${change.change}|${change.name}`,
      }),
    );

    for (const hint of change.relaxations) {
      driftFindings.push(
        driftFinding(currentMeta.target, "DRIFT-002", {
          title: "Safety hint was relaxed since the previous record",
          severity: "medium",
          observation: `Tool \`${change.name}\`: \`${hint}\` is less restrictive than in the previous record.`,
          inference:
            "The hint is what a client uses to warn before a destructive call. Relaxing it changes approval " +
            "behaviour without changing any visible text, which is the shape of a rug pull.",
          limitations: [
            ...CHANGE_LIMITATIONS,
            "Annotations are hints, not enforcement: a publisher who lies here can lie elsewhere.",
          ],
          discriminator: `${change.name}|${hint}`,
        }),
      );
    }
  }

  driftFindings.sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || a.checkId.localeCompare(b.checkId),
  );

  return {
    previous: previousMeta,
    current: currentMeta,
    targetsMatch,
    toolChanges,
    newFindings,
    resolvedFindings,
    driftFindings,
    changed: toolChanges.length + newFindings.length + resolvedFindings.length > 0,
  };
}

export function renderDrift(report: DriftReport): string {
  const lines: string[] = [];
  lines.push(`## Drift: ${report.current.target}`);
  lines.push("");
  lines.push(`- before: ${report.previous.collectedAt} (${report.previous.label})`);
  lines.push(`- after:  ${report.current.collectedAt} (${report.current.label})`);
  lines.push(
    `- findings: +${report.newFindings.length} / -${report.resolvedFindings.length} ` +
      `· tool changes: ${report.toolChanges.length}`,
  );
  lines.push("");

  if (!report.targetsMatch) {
    lines.push(
      `> Warning: different targets (${report.previous.target} vs ${report.current.target}). ` +
        "Findings and tools were not compared.",
    );
    lines.push("");
  }

  if (!report.previous.catalogKnown || !report.current.catalogKnown) {
    lines.push(
      "> Tool catalog: unknown on one or both records, so the catalog comparison is incomplete.",
    );
    lines.push("");
  }

  if (!report.changed) {
    lines.push("No change observed between the two records.");
    lines.push("");
    return stripUnsafe(lines.join("\n"));
  }

  if (report.toolChanges.length > 0) {
    lines.push("### Tool catalog changes");
    lines.push("");
    for (const change of report.toolChanges) {
      const detail =
        change.change === "modified"
          ? ` — ${change.fields.join(", ")}`
          : change.change === "added"
            ? " — new tool"
            : " — removed";
      const relaxed = change.relaxations.length ? ` · **relaxed: ${change.relaxations.join(", ")}**` : "";
      lines.push(`- \`${change.name}\` **${change.change}**${detail}${relaxed}`);
    }
    lines.push("");
  }

  for (const [label, findings] of [
    ["New findings", report.newFindings],
    ["Resolved findings", report.resolvedFindings],
  ] as const) {
    if (findings.length === 0) continue;
    lines.push(`### ${label}`);
    lines.push("");
    for (const finding of findings) {
      lines.push(`- \`${finding.checkId}\` ${finding.severity} — ${finding.title}`);
      lines.push(`  - ${finding.observation}`);
    }
    lines.push("");
  }

  if (report.driftFindings.length > 0) {
    lines.push("### Drift findings");
    lines.push("");
    for (const finding of report.driftFindings) {
      lines.push(`- **${finding.severity.toUpperCase()}** \`${finding.checkId}\` — ${finding.observation}`);
      lines.push(`  - inference: ${finding.inference ?? "—"}`);
      for (const limitation of finding.limitations) lines.push(`  - limitation: ${limitation}`);
    }
    lines.push("");
  }

  return stripUnsafe(lines.join("\n"));
}
