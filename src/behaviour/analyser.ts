import { severityRank } from "../checks/types.ts";
import { shortHash } from "../lib/id.ts";
import type { AssertionKind, Confidence, EvidenceRef, Finding, Severity } from "../model.ts";
import { isLoopback, type BehaviourEvent, type BehaviourRecord, type ToolInvocation } from "./types.ts";

export interface BehaviourRule {
  id: string;
  title: string;
  owasp: string[];
  taxonomy: string[];
  rationale: string;
}

export const BEHAVIOUR_RULES: BehaviourRule[] = [
  {
    id: "BEHAV-001",
    title: "Canary value was written to an external destination",
    owasp: ["MCP01"],
    taxonomy: ["behaviour", "exfiltration"],
    rationale:
      "A synthetic credential planted in the environment appeared in an outbound payload. This is observed, not inferred: the value left the process and was addressed somewhere.",
  },
  {
    id: "BEHAV-002",
    title: "Outbound connection attempted to a non-loopback destination",
    owasp: [],
    taxonomy: ["behaviour", "egress"],
    rationale:
      "Expected API traffic and exfiltration are indistinguishable without the package's documented endpoints, so this is reported at low severity as a destination fact, not a verdict.",
  },
  {
    id: "BEHAV-003",
    title: "Canary credential file was read",
    owasp: ["MCP01"],
    taxonomy: ["behaviour", "credential-access"],
    rationale:
      "The process opened a file planted as a credential. Reading it is observed; what it did with the value may be recorded separately.",
  },
];

interface BuildInput {
  severity: Severity;
  confidence: Confidence;
  assertion: AssertionKind;
  observation: string;
  inference?: string;
  recommendation?: string;
  limitations: string[];
  evidence: EvidenceRef[];
  discriminator: string;
}

function build(record: BehaviourRecord, rule: BehaviourRule, input: BuildInput): Finding {
  return {
    fingerprint: shortHash(
      `${rule.id}|${record.target.command.join(" ")}|${input.discriminator}`,
      16,
    ),
    checkId: rule.id,
    title: rule.title,
    severity: input.severity,
    confidence: input.confidence,
    assertion: input.assertion,
    taxonomy: rule.taxonomy,
    owasp: rule.owasp,
    observation: input.observation,
    inference: input.inference,
    recommendation: input.recommendation,
    limitations: input.limitations,
    evidence: input.evidence,
  };
}

function toolAt(record: BehaviourRecord, at: string): ToolInvocation | undefined {
  return record.tools.find((tool) => at >= tool.startedAt && at <= tool.endedAt);
}

function describeTool(tool: ToolInvocation | undefined): string {
  if (!tool) return "outside any tool call";
  return `the call to \`${tool.name}\` (${tool.outcome})`;
}

function rule(id: string): BehaviourRule {
  const found = BEHAVIOUR_RULES.find((candidate) => candidate.id === id);
  if (!found) throw new Error(`unknown behaviour rule ${id}`);
  return found;
}

const CANARY_LIMITATIONS = [
  "A canary is synthetic: this proves a planted value left the process, not that the operator acted with intent. It is not proof of intent.",
  "The hook observes Node APIs; native code or an independent runtime can bypass it.",
];

/**
 * Turns a behaviour record into findings, keeping observation and inference
 * separate exactly as the passive collector does.
 */
export function analyseBehaviour(record: BehaviourRecord): Finding[] {
  const findings: Finding[] = [];

  // ---- BEHAV-001: canary in an outbound write -------------------------------
  const sends = record.events.filter(
    (event: BehaviourEvent) => event.type === "net.write" && (event.canaryIds?.length ?? 0) > 0,
  );
  const grouped = new Map<
    string,
    { host?: string; port?: number; ids: Set<string>; first: BehaviourEvent }
  >();
  for (const event of sends) {
    const ids = [...(event.canaryIds ?? [])].sort();
    const key = `${event.host ?? "unknown"}:${event.port ?? "unknown"}|${ids.join(",")}`;
    const existing = grouped.get(key);
    if (existing) {
      for (const id of ids) existing.ids.add(id);
    } else {
      grouped.set(key, { host: event.host, port: event.port, ids: new Set(ids), first: event });
    }
  }
  for (const [key, group] of grouped) {
    const ids = [...group.ids].sort();
    const destination = `${group.host ?? "unknown host"}${group.port ? `:${group.port}` : ""}`;
    const tool = toolAt(record, group.first.at);
    findings.push(
      build(record, rule("BEHAV-001"), {
        severity: "high",
        confidence: "high",
        assertion: "observed",
        observation:
          `During ${describeTool(tool)}, the server wrote ${ids.length} canary value` +
          `${ids.length === 1 ? "" : "s"} (${ids.join(", ")}) to ${destination}.`,
        inference:
          "Credential material planted for this run left the process and was addressed to a destination " +
          "that the tool metadata does not describe.",
        recommendation:
          "Treat the package as untrusted until the destination is explained. Remove the server from any " +
          "environment holding real credentials, and report the package to the registry.",
        limitations: CANARY_LIMITATIONS,
        evidence: [
          { kind: "derived", locator: `net.write → ${destination}`, excerpt: ids.join(", ") },
        ],
        discriminator: key,
      }),
    );
  }

  const canaryDestinations = new Set<string>();
  for (const group of grouped.values()) {
    if (group.host) canaryDestinations.add(group.host);
  }

  // ---- BEHAV-002: egress to a non-loopback destination ----------------------
  // A name lookup counts: inside an isolated namespace it is often the only
  // observable step before a connection fails.
  const targets = new Map<string, { host: string; port?: number }>();
  for (const event of record.events) {
    if (event.type !== "net.connect" && event.type !== "dns.lookup" && event.type !== "net.write") continue;
    if (isLoopback(event.host)) continue;
    const host = event.host ?? "unknown";
    // A destination that received a canary is already reported as BEHAV-001.
    if (canaryDestinations.has(host)) continue;
    const existing = targets.get(host);
    if (!existing) targets.set(host, { host, port: event.port });
    else if (existing.port === undefined && event.port !== undefined) existing.port = event.port;
  }
  for (const [host, target] of targets) {
    const destination = target.port !== undefined ? `${host}:${target.port}` : host;
    findings.push(
      build(record, rule("BEHAV-002"), {
        severity: "low",
        confidence: "high",
        assertion: "observed",
        observation: `An outbound connection was attempted to ${destination}.`,
        inference:
          "Without the package's documented endpoints, this collector cannot tell a legitimate API call " +
          "from exfiltration. The destination is a fact; the intent is not.",
        recommendation:
          "Compare the destination with the package's documentation and requested scopes. If it is not a " +
          "documented dependency, ask the publisher to explain it.",
        limitations: [
          "Any outbound call is reported, including legitimate ones: this is a signal, not a vulnerability.",
          "Destinations that received a canary are reported under BEHAV-001 instead of here.",
          ...(record.isolation.network === "open"
            ? ["The run was not network-isolated, so the connection may have reached a real service."]
            : ["The connection was attempted inside a network namespace and could not complete."]),
        ],
        evidence: [{ kind: "derived", locator: `egress → ${destination}` }],
        discriminator: host,
      }),
    );
  }

  // ---- BEHAV-003: canary credential file read -------------------------------
  const canaryPaths = new Map(
    record.environment.canaries
      .filter((canary) => canary.kind === "file")
      .map((canary) => [canary.locator, canary.id] as const),
  );
  const reads = new Map<string, { path: string; canaryId: string; at: string }>();
  for (const event of record.events) {
    if (event.type !== "fs.read" || !event.path) continue;
    if (!canaryPaths.has(event.path)) continue;
    if (!reads.has(event.path)) {
      reads.set(event.path, {
        path: event.path,
        canaryId: canaryPaths.get(event.path)!,
        at: event.at,
      });
    }
  }
  for (const [path, read] of reads) {
    const tool = toolAt(record, read.at);
    findings.push(
      build(record, rule("BEHAV-003"), {
        severity: "medium",
        confidence: "high",
        assertion: "observed",
        observation: `During ${describeTool(tool)}, the server read the credential file at ${path}.`,
        inference:
          "The tool's declared purpose does not require this file. Reading it is the first step of " +
          "credential theft and, on its own, does not prove what happened to the value.",
        recommendation:
          "Do not run this package with real credentials. Report the read path to the publisher and the registry.",
        limitations: [
          "Only files planted as canaries are reported; other reads are not assessed.",
          ...CANARY_LIMITATIONS,
        ],
        evidence: [{ kind: "derived", locator: `fs.read → ${path}`, excerpt: read.canaryId }],
        discriminator: path,
      }),
    );
  }

  findings.sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || a.checkId.localeCompare(b.checkId),
  );
  return findings;
}
