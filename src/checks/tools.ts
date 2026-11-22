import type { Check } from "./types.ts";
import { hasUnconstrainedString, catalogText, classifyCapabilities } from "./capabilities.ts";
import { dedupeAnomalies, scanMetadataText } from "../lib/text.ts";
import type { Severity } from "../model.ts";

const MAX_REPORTED_PATHS = 6;

export const toolChecks: Check[] = [
  {
    id: "TOOL-001",
    title: "Tool metadata is incomplete",
    owasp: ["MCP03", "MCP02"],
    taxonomy: ["metadata-quality"],
    rationale:
      "Clients render annotations as safety affordances (read-only, destructive) and use titles in approval prompts. Missing annotations do not break the protocol, but they remove the signals a human or client relies on before approving a call.",
    run(probe) {
      const tools = probe.tools;
      if (!tools || tools.length === 0) return [];

      const missingAnnotations = tools.filter((t) => !t.annotations || Object.keys(t.annotations).length === 0);
      const missingTitle = tools.filter((t) => !t.title && !t.annotations?.title);
      const missingDescription = tools.filter((t) => !t.description);

      if (missingAnnotations.length === 0 && missingTitle.length === 0 && missingDescription.length === 0) {
        return [];
      }

      return [
        {
          severity: "info",
          confidence: "high",
          assertion: "observed",
          observation:
            `Of ${tools.length} tools: ${missingAnnotations.length} have no annotations, ` +
            `${missingTitle.length} have no title, ${missingDescription.length} have no description.`,
          inference:
            "Clients cannot warn users about destructive or open-world behaviour, and LLM tool selection relies on descriptions that are missing.",
          recommendation:
            "Annotate every tool with title, readOnlyHint, destructiveHint, idempotentHint and openWorldHint, and write a description that states when the tool should and should not be used.",
          limitations: ["Annotations are hints, not enforcement; correct annotation does not imply correct behaviour."],
          evidence: [{ kind: "mcp", locator: "tools/list → annotations/title/description" }],
          discriminator: `${missingAnnotations.length}/${missingTitle.length}/${missingDescription.length}`,
        },
      ];
    },
  },

  {
    id: "TOOL-002",
    title: "Tool metadata contains language aimed at the model",
    owasp: ["MCP03", "MCP06"],
    taxonomy: ["supply-chain", "prompt-injection"],
    rationale:
      "Tool descriptions are injected into the model context as trusted text. An adversary who controls them controls model behaviour without touching executable code. This check is deliberately narrow and precision-first: it reports signals for human review, never a verdict.",
    run(probe) {
      const entries = catalogText(probe);
      if (entries.length === 0) return [];

      const hits: Array<{ path: string; kinds: Set<string>; notes: string[]; matches: string[] }> = [];
      for (const entry of entries) {
        const anomalies = dedupeAnomalies(scanMetadataText(entry.text));
        if (anomalies.length === 0) continue;
        hits.push({
          path: entry.path,
          kinds: new Set(anomalies.map((a) => a.kind)),
          notes: [...new Set(anomalies.map((a) => a.note))],
          matches: [...new Set(anomalies.map((a) => a.match))].slice(0, 4),
        });
      }

      if (hits.length === 0) return [];

      const allKinds = new Set(hits.flatMap((h) => [...h.kinds]));
      const severity: Severity = allKinds.has("hidden-character") || allKinds.has("tag-character")
        ? "medium"
        : allKinds.has("instruction-override") || allKinds.has("credential-path")
          ? "medium"
          : "low";
      const confidence = allKinds.size >= 2 ? "moderate" : "low";

      const pathList = hits.slice(0, MAX_REPORTED_PATHS).map((h) => `${h.path} (${[...h.kinds].join(", ")})`);

      return [
        {
          severity,
          confidence,
          assertion: "inferred",
          observation:
            `${hits.length} metadata field${hits.length === 1 ? "" : "s"} matched narrow injection heuristics: ` +
            `${pathList.join("; ")}${hits.length > MAX_REPORTED_PATHS ? "; …" : ""}.`,
          inference:
            "Text in tool metadata may be intended to steer the model rather than describe the tool. This is a signal, not proof of malice.",
          recommendation:
            "Review the matched fields manually. If the wording is not justified by the tool's function, treat the server as untrusted until the publisher explains it. Prefer servers that pin tool definitions by hash.",
          limitations: [
            "Pattern matching cannot distinguish adversarial metadata from unusual but legitimate documentation.",
            "Novel or paraphrased instructions will not be detected.",
            "Absence of a match is not evidence of safety.",
          ],
          evidence: hits.slice(0, MAX_REPORTED_PATHS).map((h) => ({
            kind: "mcp" as const,
            locator: h.path,
            excerpt: h.matches.join(" | "),
          })),
          discriminator: [...allKinds].sort().join(","),
        },
      ];
    },
  },

  {
    id: "TOOL-003",
    title: "Tool input schemas accept unconstrained input",
    owasp: ["MCP05", "MCP02"],
    taxonomy: ["input-validation"],
    rationale:
      "A parameter typed only as `string` with no pattern, enum, format or length bound is where injection and SSRF start. The schema is the contract the model is asked to satisfy; a loose contract produces loose calls.",
    run(probe) {
      const tools = probe.tools;
      if (!tools || tools.length === 0) return [];

      const loose = tools.filter((t) => hasUnconstrainedString(t.inputSchema));
      const openObjects = tools.filter((t) => {
        const schema = t.inputSchema as Record<string, unknown> | undefined;
        return !!schema && schema.type === "object" && schema.additionalProperties !== false;
      });

      if (loose.length === 0 && openObjects.length === 0) return [];

      const capabilities = classifyCapabilities(tools);
      const risky = loose.map((t) => t.name).filter((name) => capabilities.highImpact.includes(name));
      const severity: Severity = risky.length > 0 ? "low" : "info";

      return [
        {
          severity,
          confidence: "high",
          assertion: "observed",
          observation:
            `${loose.length} of ${tools.length} tools accept an unconstrained string parameter; ` +
            `${openObjects.length} use an object schema without additionalProperties: false.` +
            (risky.length > 0 ? ` High-impact tools affected: ${risky.slice(0, 6).join(", ")}.` : ""),
          inference:
            "Unconstrained input widens the path from model output to a shell, a query, a filesystem path or an outbound request.",
          recommendation:
            "Set additionalProperties: false and constrain every string parameter with enum, pattern, format or maxLength.",
          limitations: ["Schema strictness is a proxy: a strict schema does not guarantee safe handling downstream."],
          evidence: [{ kind: "mcp", locator: "tools/list → inputSchema" }],
          discriminator: `${loose.length}/${openObjects.length}`,
        },
      ];
    },
  },
];
