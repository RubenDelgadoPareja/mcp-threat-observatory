import type { Check } from "./types.ts";

const METHOD_NOT_FOUND = -32601;

export const protocolChecks: Check[] = [
  {
    id: "PROTO-001",
    title: "Discovery methods are unimplemented rather than empty",
    owasp: [],
    taxonomy: ["interoperability"],
    rationale:
      "Directory crawlers, IDE inspectors and marketplace scanners call resources/list and prompts/list unconditionally. A server that answers -32601 instead of an empty array is logged as broken even when it is perfectly healthy.",
    run(probe) {
      if (!probe.handshake.initialized) return [];

      const failing: string[] = [];
      if (probe.resources && probe.resources.errorCode === METHOD_NOT_FOUND) failing.push("resources/list");
      if (probe.prompts && probe.prompts.errorCode === METHOD_NOT_FOUND) failing.push("prompts/list");

      if (failing.length === 0) return [];

      return [
        {
          severity: "low",
          confidence: "high",
          assertion: "observed",
          observation: `${failing.join(" and ")} returned JSON-RPC ${METHOD_NOT_FOUND} (Method not found).`,
          inference:
            "Tooling that enumerates capabilities will report the server as partially broken, and marketplace listings may be rejected or incomplete.",
          recommendation: "Return an empty array ({ resources: [] } / { prompts: [] }) when the capability is not offered.",
          limitations: ["This affects interoperability, not the security of the server itself."],
          evidence: failing.map((method) => ({ kind: "mcp" as const, locator: `${method} → ${METHOD_NOT_FOUND}` })),
          discriminator: failing.join(","),
        },
      ];
    },
  },
];
