import { sha256 } from "../lib/id.ts";
import type { HttpProbe } from "../model.ts";

export interface PacerOptions {
  /** Requests per second per host. Policy floor is 1. */
  rateLimitRps: number;
  timeoutMs: number;
  userAgent: string;
  maxBodyBytes: number;
}

export const DEFAULT_PACER: PacerOptions = {
  rateLimitRps: 1,
  timeoutMs: 15_000,
  userAgent: "mcp-threat-observatory/0.1 (passive research; contact not configured)",
  maxBodyBytes: 256 * 1024,
};

/**
 * Enforces a minimum interval between requests to the same host.
 * Deliberately conservative: this collector must be indistinguishable from a
 * slow, polite client, not a scanner.
 */
export class Pacer {
  private readonly intervalMs: number;
  private lastAt = 0;

  constructor(options: Pick<PacerOptions, "rateLimitRps">) {
    const rps = Math.max(1, Math.min(10, options.rateLimitRps));
    this.intervalMs = Math.ceil(1000 / rps);
  }

  async wait(): Promise<void> {
    const now = Date.now();
    const delta = now - this.lastAt;
    if (delta < this.intervalMs) {
      await new Promise((resolve) => setTimeout(resolve, this.intervalMs - delta));
    }
    this.lastAt = Date.now();
  }
}

export interface SendOptions {
  method: "GET" | "POST" | "HEAD" | "OPTIONS";
  url: string;
  headers?: Record<string, string>;
  body?: string;
  /** Defaults to "manual" so redirects are recorded, not silently followed. */
  redirect?: "follow" | "error" | "manual";
}

/**
 * One HTTP exchange, fully recorded. Never throws: transport errors are part
 * of the observation and must appear in the evidence, not crash a batch run.
 */
export async function send(
  pacer: Pacer,
  options: PacerOptions,
  req: SendOptions,
): Promise<HttpProbe> {
  await pacer.wait();
  const at = new Date().toISOString();
  const started = Date.now();

  const headerNames = Object.keys(req.headers ?? {}).map((h) => h.toLowerCase());

  try {
    const response = await fetch(req.url, {
      method: req.method,
      headers: req.headers,
      body: req.body,
      redirect: req.redirect ?? "manual",
      signal: AbortSignal.timeout(options.timeoutMs),
    });

    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    let bodyText = "";
    try {
      bodyText = await response.text();
    } catch {
      bodyText = "";
    }

    const bytes = Buffer.byteLength(bodyText, "utf8");
    const truncated =
      bytes > options.maxBodyBytes
        ? Buffer.from(bodyText, "utf8").subarray(0, options.maxBodyBytes).toString("utf8")
        : bodyText;

    return {
      at,
      durationMs: Date.now() - started,
      request: { method: req.method, url: req.url, headers: headerNames },
      response: {
        status: response.status,
        headers,
        bodyExcerpt: truncated.slice(0, 4_000),
        bodyDigest: sha256(bodyText),
        bodyBytes: bytes,
      },
    };
  } catch (error) {
    return {
      at,
      durationMs: Date.now() - started,
      request: { method: req.method, url: req.url, headers: headerNames },
      response: null,
      error: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
    };
  }
}

/**
 * Extracts a JSON value from either a plain JSON body or a server-sent events
 * stream. Streamable HTTP servers may answer either way for the same request.
 */
export function parseJsonRpcBody(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) return undefined;

  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return JSON.parse(trimmed);
    } catch {
      // Fall through: some servers emit an SSE frame without a content-type
      // that says so.
    }
  }

  const frames = trimmed.split(/\r?\n\r?\n/);
  for (let i = frames.length - 1; i >= 0; i -= 1) {
    const frame = frames[i]!;
    const data = frame
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .join("\n");
    if (!data || data === "[DONE]") continue;
    try {
      return JSON.parse(data);
    } catch {
      continue;
    }
  }
  return undefined;
}

export interface JsonRpcMessage {
  jsonrpc?: string;
  id?: number | string | null;
  result?: unknown;
  error?: { code?: number; message?: string; data?: unknown };
}

export function asJsonRpc(value: unknown): JsonRpcMessage | undefined {
  if (!value || typeof value !== "object") return undefined;
  const candidate = value as JsonRpcMessage;
  if (candidate.result === undefined && candidate.error === undefined && candidate.id === undefined) {
    return undefined;
  }
  return candidate;
}

/**
 * Parses a WWW-Authenticate header for `resource_metadata` and `scope`.
 * Quoted and unquoted values both occur in the wild.
 */
export function parseWwwAuthenticate(value: string | null): {
  scheme: string | null;
  resourceMetadata: string | null;
  scope: string | null;
  error: string | null;
} {
  if (!value) return { scheme: null, resourceMetadata: null, scope: null, error: null };
  const schemeMatch = /^\s*([A-Za-z]+)/.exec(value);
  const param = (name: string): string | null => {
    const re = new RegExp(`${name}\\s*=\\s*(?:"([^"]*)"|([^,\\s]+))`, "i");
    const m = re.exec(value);
    return m ? (m[1] ?? m[2] ?? null) : null;
  };
  return {
    scheme: schemeMatch?.[1] ?? null,
    resourceMetadata: param("resource_metadata"),
    scope: param("scope"),
    error: param("error"),
  };
}
