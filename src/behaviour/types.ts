/**
 * Behaviour records describe what a server *did*, as opposed to what it
 * advertised. They are a separate artefact from the passive snapshot on
 * purpose: passive observation never executes code, and mixing the two would
 * blur both the ethics and the schema.
 */

export const BEHAVIOUR_SCHEMA_VERSION = "1" as const;

export type IsolationMechanism = "unshare-rn" | "none";
export type NetworkIsolation = "isolated" | "open";

export interface Canary {
  id: string;
  kind: "env" | "file";
  /** Env var name, or absolute path for files. */
  locator: string;
}

export interface BehaviourEvent {
  at: string;
  type:
    | "net.connect"
    | "net.write"
    | "dns.lookup"
    | "fs.read"
    | "process.spawn";
  host?: string;
  port?: number;
  path?: string;
  canaryIds?: string[];
  bytes?: number;
  detail?: string;
}

export interface ToolInvocation {
  name: string;
  arguments: Record<string, unknown>;
  /** Choices the argument generator could not honour, kept for honesty. */
  argumentsNotes?: string[];
  outcome: "result" | "error" | "timeout" | "skipped";
  startedAt: string;
  endedAt: string;
  durationMs: number;
  error?: string;
}

export interface BehaviourRecord {
  schemaVersion: typeof BEHAVIOUR_SCHEMA_VERSION;
  kind: "behaviour";
  collectedAt: string;
  target: { command: string[]; cwd: string };
  isolation: { mechanism: IsolationMechanism; network: NetworkIsolation };
  environment: { home: string; seed: number; canaries: Canary[] };
  tools: ToolInvocation[];
  events: BehaviourEvent[];
  summary: {
    events: number;
    toolCalls: number;
    egressAttempts: number;
    canaryReads: number;
    canarySends: number;
  };
  limitations: string[];
}

export const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);

export function isLoopback(host: string | undefined): boolean {
  if (!host) return true;
  if (LOOPBACK_HOSTS.has(host)) return true;
  return host.startsWith("127.") || host === "::" || host.endsWith(".localhost");
}
