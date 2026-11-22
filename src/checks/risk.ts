import type { Check } from "./types.ts";
import { classifyCapabilities } from "./capabilities.ts";

export const riskChecks: Check[] = [
  {
    id: "RISK-001",
    title: "Catalog combines private-data access, untrusted input and egress",
    owasp: ["MCP02", "MCP06"],
    taxonomy: ["capability-composition"],
    rationale:
      "Individually reasonable tools become dangerous when one server can read private data, ingest content the operator does not control, and send data outward. This is the 'lethal trifecta' indicator: it describes an attack path, not a demonstrated attack.",
    run(probe) {
      const capabilities = classifyCapabilities(probe.tools);
      const hasTrifecta =
        capabilities.privateData.length > 0 &&
        capabilities.freeTextIngress.length > 0 &&
        capabilities.egress.length > 0;

      if (!hasTrifecta) return [];

      return [
        {
          severity: "medium",
          confidence: "low",
          assertion: "inferred",
          observation:
            `The catalog contains tools that read private data (${capabilities.privateData.slice(0, 4).join(", ")}), ` +
            `tools that accept unconstrained external input (${capabilities.freeTextIngress.slice(0, 4).join(", ")}) ` +
            `and tools that can send data outward (${capabilities.egress.slice(0, 4).join(", ")}).`,
          inference:
            "A single injected instruction reaching the ingress tool could move data from the reader to the egress tool. This is a structural risk indicator inferred from tool metadata, not an observed exploit.",
          recommendation:
            "Separate private-data readers from egress tools across servers, require explicit confirmation before outbound actions, and scope credentials per tool rather than per server.",
          limitations: [
            "Capability classes are inferred from tool names, descriptions and annotations; they may be wrong.",
            "No tool was invoked, so no data flow was observed.",
            "A trifecta indicator is not a vulnerability and must not be reported as one.",
          ],
          evidence: [{ kind: "derived", locator: "tools/list → capability composition" }],
        },
      ];
    },
  },
];
