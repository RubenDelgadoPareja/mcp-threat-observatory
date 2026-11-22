/**
 * Core data model.
 *
 * Design rule: `null` means "we do not know". It is never replaced by a
 * comfortable default. A record that says "unknown" is honest; a record that
 * says "0" when we never looked is a lie that propagates into published
 * intelligence.
 */

export const SCHEMA_VERSION = "1" as const;
export const COLLECTOR_NAME = "mcp-threat-observatory";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** How strongly a finding's *observation* is supported by raw evidence. */
export type Confidence = "high" | "moderate" | "low";

/**
 * Distinguishes what we saw from what we think it means.
 * Every finding must declare this. Mixing the two in a single sentence is how
 * threat reports lose credibility.
 */
export type AssertionKind = "observed" | "inferred";

export interface EvidenceRef {
  kind: "http" | "mcp" | "derived";
  /** Human-readable pointer into the raw record, e.g. "POST /mcp -> 401". */
  locator: string;
  /** Truncated excerpt of the raw artifact. */
  excerpt?: string;
  /** SHA-256 of the full raw artifact, so the excerpt can be verified. */
  digest?: string;
}

export interface Finding {
  /** Stable across snapshots: checkId + target + discriminator. */
  fingerprint: string;
  checkId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  assertion: AssertionKind;
  taxonomy: string[];
  owasp: string[];
  observation: string;
  inference?: string;
  recommendation?: string;
  limitations: string[];
  evidence: EvidenceRef[];
}

/** What a check returns before the engine attaches identity and target data. */
export interface CheckResult {
  severity: Severity;
  confidence: Confidence;
  assertion: AssertionKind;
  observation: string;
  inference?: string;
  recommendation?: string;
  limitations?: string[];
  evidence?: EvidenceRef[];
  /** Extra entropy for the fingerprint when a check can fire more than once. */
  discriminator?: string;
  /** Optional per-result title override. */
  title?: string;
}

export interface HttpProbe {
  at: string;
  durationMs: number;
  request: {
    method: string;
    url: string;
    /** Header names only. Values may contain credentials and are not stored. */
    headers: string[];
  };
  response: {
    status: number;
    /** Lower-cased header names. Multi-valued headers are joined with ", ". */
    headers: Record<string, string>;
    bodyExcerpt?: string;
    bodyDigest?: string;
    bodyBytes?: number;
  } | null;
  error?: string;
}

export interface ToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface ToolDescriptor {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: ToolAnnotations | null;
}

export interface ProtectedResourceMetadata {
  found: boolean;
  url: string | null;
  status: number | null;
  /** Parsed JSON body when the response was valid JSON. */
  body?: unknown;
  authorizationServers?: string[];
  error?: string;
}

export interface ProbeResult {
  schemaVersion: typeof SCHEMA_VERSION;
  target: string;
  transport: "http";
  collectedAt: string;
  reachable: boolean;
  auth: {
    /** Did the endpoint return any HTTP response at all? */
    networkAccessible: boolean;
    /**
     * `false` = we completed the MCP handshake with no credential.
     * `true`  = the endpoint refused us (401/403) or demanded auth.
     * `null`  = we could not determine this.
     */
    requiresAuth: boolean | null;
    statusOnUnauthenticatedInitialize: number | null;
    wwwAuthenticate: string | null;
    resourceMetadataUrl: string | null;
    protectedResourceMetadata: ProtectedResourceMetadata | null;
  };
  handshake: {
    initialized: boolean;
    protocolVersion?: string;
    serverInfo?: { name?: string; version?: string };
    errorCode?: number;
    errorMessage?: string;
  };
  capabilities: Record<string, unknown> | null;
  /** `null` = we never got a usable tool list, for any reason. */
  tools: ToolDescriptor[] | null;
  toolsErrorCode: number | null;
  resources: { ok: boolean; count: number | null; errorCode: number | null } | null;
  prompts: { ok: boolean; count: number | null; errorCode: number | null } | null;
  probes: HttpProbe[];
  /** Known blind spots of this collection run. Always non-empty. */
  limitations: string[];
  collector: {
    name: string;
    version: string;
    userAgent: string;
    contact: string | null;
  };
}

export interface Snapshot {
  schemaVersion: typeof SCHEMA_VERSION;
  generatedAt: string;
  probe: ProbeResult;
  findings: Finding[];
  summary: Summary;
}

export interface Summary {
  total: number;
  bySeverity: Record<Severity, number>;
  byConfidence: Record<Confidence, number>;
  observed: number;
  inferred: number;
}

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function emptySummary(): Summary {
  return {
    total: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byConfidence: { high: 0, moderate: 0, low: 0 },
    observed: 0,
    inferred: 0,
  };
}
