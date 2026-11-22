import type { Check } from "./types.ts";
import { authChecks } from "./auth.ts";
import { toolChecks } from "./tools.ts";
import { protocolChecks } from "./protocol.ts";
import { riskChecks } from "./risk.ts";

export const ALL_CHECKS: Check[] = [...authChecks, ...toolChecks, ...protocolChecks, ...riskChecks];

export function getCheck(id: string): Check | undefined {
  return ALL_CHECKS.find((check) => check.id === id);
}

export type { Check } from "./types.ts";
export { severityRank } from "./types.ts";
