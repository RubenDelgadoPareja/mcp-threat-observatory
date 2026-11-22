import type { ProbeResult, Severity } from "../model.ts";

export interface Check {
  id: string;
  title: string;
  /** OWASP MCP Top 10 identifiers this check maps to. */
  owasp: string[];
  /** Extra facets used in reports (interoperability, supply-chain, ...). */
  taxonomy?: string[];
  /** Why this check exists. Rendered by `mcpobs checks`. */
  rationale: string;
  run(probe: ProbeResult): import("../model.ts").CheckResult[];
}

export function severityRank(severity: Severity): number {
  return ["info", "low", "medium", "high", "critical"].indexOf(severity);
}
