import {
  asJsonRpc,
  DEFAULT_PACER,
  Pacer,
  parseJsonRpcBody,
  parseWwwAuthenticate,
  send,
  type PacerOptions,
} from "./http.ts";
import {
  COLLECTOR_NAME,
  SCHEMA_VERSION,
  type ProbeResult,
  type ProtectedResourceMetadata,
  type ToolDescriptor,
} from "../model.ts";

const PROTOCOL_VERSION = "2025-06-18";

export interface ProbeConfig extends PacerOptions {
  contact: string | null;
  version: string;
}

export function defaultProbeConfig(overrides: Partial<ProbeConfig> = {}): ProbeConfig {
  const contact = overrides.contact ?? process.env.MCPOBS_CONTACT ?? null;
  const userAgent =
    overrides.userAgent ??
    `${COLLECTOR_NAME}/${overrides.version ?? "0.1.0"} (passive research${
      contact ? `; +${contact}` : "; contact not configured"
    })`;
  return {
    ...DEFAULT_PACER,
    ...overrides,
    contact,
    userAgent,
    version: overrides.version ?? "0.1.0",
  };
}

interface RpcExchange {
  status: number | null;
  jsonrpc: ReturnType<typeof asJsonRpc>;
  sessionId: string | null;
  probeIndex: number;
}

async function rpc(
  pacer: Pacer,
  config: ProbeConfig,
  url: string,
  message: Record<string, unknown>,
  sessionId: string | null,
  protocolVersion: string | null,
  probes: ProbeResult["probes"],
): Promise<RpcExchange> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    "user-agent": config.userAgent,
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  if (protocolVersion) headers["mcp-protocol-version"] = protocolVersion;

  const probe = await send(pacer, config, {
    method: "POST",
    url,
    headers,
    body: JSON.stringify(message),
  });
  probes.push(probe);

  const body = probe.response?.bodyExcerpt ?? "";
  const parsed = parseJsonRpcBody(body);
  return {
    status: probe.response?.status ?? null,
    jsonrpc: asJsonRpc(parsed),
    sessionId: probe.response?.headers["mcp-session-id"] ?? null,
    probeIndex: probes.length - 1,
  };
}

async function discoverProtectedResource(
  target: string,
  pacer: Pacer,
  config: ProbeConfig,
  probes: ProbeResult["probes"],
  hintUrl: string | null,
): Promise<ProtectedResourceMetadata> {
  const url = new URL(target);
  const path = url.pathname.replace(/\/+$/, "");
  const origin = url.origin;

  const candidates: string[] = [];
  if (hintUrl) candidates.push(hintUrl);
  candidates.push(`${origin}/.well-known/oauth-protected-resource${path}`);
  candidates.push(`${origin}/.well-known/oauth-protected-resource`);

  const seen = new Set<string>();
  let lastStatus: number | null = null;
  let lastError: string | undefined;

  for (const candidate of candidates) {
    let absolute: string;
    try {
      absolute = new URL(candidate, origin).toString();
    } catch {
      continue;
    }
    if (seen.has(absolute)) continue;
    seen.add(absolute);

    const probe = await send(pacer, config, {
      method: "GET",
      url: absolute,
      headers: { "user-agent": config.userAgent, accept: "application/json" },
      redirect: "follow",
    });
    probes.push(probe);
    lastStatus = probe.response?.status ?? null;

    if (probe.error) {
      lastError = probe.error;
      continue;
    }
    if (probe.response?.status !== 200) continue;

    const parsed = parseJsonRpcBody(probe.response.bodyExcerpt ?? "");
    if (!parsed || typeof parsed !== "object") continue;

    const body = parsed as Record<string, unknown>;
    const servers = Array.isArray(body.authorization_servers)
      ? body.authorization_servers.filter((s): s is string => typeof s === "string")
      : undefined;

    // A document without `resource` and without authorization servers is
    // probably a catch-all SPA response, not a real PRM document.
    if (!body.resource && !servers?.length) continue;

    return {
      found: true,
      url: absolute,
      status: 200,
      body,
      authorizationServers: servers,
    };
  }

  return { found: false, url: null, status: lastStatus, error: lastError };
}

function extractTools(result: unknown): ToolDescriptor[] | null {
  if (!result || typeof result !== "object") return null;
  const tools = (result as { tools?: unknown }).tools;
  if (!Array.isArray(tools)) return null;
  return tools
    .filter((t): t is Record<string, unknown> => !!t && typeof t === "object")
    .map((t) => ({
      name: typeof t.name === "string" ? t.name : "(unnamed)",
      title: typeof t.title === "string" ? t.title : undefined,
      description: typeof t.description === "string" ? t.description : undefined,
      inputSchema: t.inputSchema,
      annotations:
        t.annotations && typeof t.annotations === "object"
          ? (t.annotations as ToolDescriptor["annotations"])
          : null,
    }));
}

function countList(result: unknown, key: "resources" | "prompts"): number | null {
  if (!result || typeof result !== "object") return null;
  const value = (result as Record<string, unknown>)[key];
  return Array.isArray(value) ? value.length : null;
}

/**
 * Collects one passive record for a remote MCP endpoint.
 *
 * Passive means: an ordinary client handshake plus discovery requests.
 * No tool is ever invoked, no payload is sent, nothing is brute-forced.
 */
export async function probeServer(
  target: string,
  options: Partial<ProbeConfig> = {},
): Promise<ProbeResult> {
  const config = defaultProbeConfig(options);
  const pacer = new Pacer(config);
  const probes: ProbeResult["probes"] = [];
  const limitations: string[] = [
    "No authenticated session was attempted: behaviour behind the login boundary is unobserved.",
    "Only the streamable HTTP transport was probed; stdio-only servers are out of scope.",
    "No tool was invoked; only discovery methods (initialize, tools/list, resources/list, prompts/list) were called.",
    "Body excerpts are truncated; SHA-256 digests cover the full response body.",
  ];
  if (!config.contact) {
    limitations.push(
      "Collector contact is not configured (MCPOBS_CONTACT); provenance is weaker than it should be.",
    );
  }

  const collectedAt = new Date().toISOString();

  const init = await rpc(
    pacer,
    config,
    target,
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: COLLECTOR_NAME, version: config.version },
      },
    },
    null,
    null,
    probes,
  );

  const reachable = probes[0]?.response !== null;
  const status = init.status;
  const wwwAuth = probes[0]?.response?.headers["www-authenticate"] ?? null;
  const authParams = parseWwwAuthenticate(wwwAuth);

  const requiresAuth =
    status === 401 || status === 403 ? true : init.jsonrpc?.result ? false : null;

  let initialized = false;
  let protocolVersion: string | undefined;
  let serverInfo: { name?: string; version?: string } | undefined;
  let capabilities: Record<string, unknown> | null = null;
  let errorCode: number | undefined;
  let errorMessage: string | undefined;

  let tools: ToolDescriptor[] | null = null;
  let toolsErrorCode: number | null = null;
  let resources: ProbeResult["resources"] = null;
  let prompts: ProbeResult["prompts"] = null;

  if (init.jsonrpc?.result) {
    const result = init.jsonrpc.result as Record<string, unknown>;
    initialized = true;
    protocolVersion = typeof result.protocolVersion === "string" ? result.protocolVersion : undefined;
    serverInfo =
      result.serverInfo && typeof result.serverInfo === "object"
        ? (result.serverInfo as { name?: string; version?: string })
        : undefined;
    capabilities =
      result.capabilities && typeof result.capabilities === "object"
        ? (result.capabilities as Record<string, unknown>)
        : null;

    const sessionId = init.sessionId;

    // The spec requires this notification after initialize. A server that
    // answers with a protocol error here is still observable.
    await rpc(
      pacer,
      config,
      target,
      { jsonrpc: "2.0", method: "notifications/initialized" },
      sessionId,
      protocolVersion ?? PROTOCOL_VERSION,
      probes,
    );

    const toolsCall = await rpc(
      pacer,
      config,
      target,
      { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
      sessionId,
      protocolVersion ?? PROTOCOL_VERSION,
      probes,
    );
    if (toolsCall.jsonrpc?.error) {
      toolsErrorCode = toolsCall.jsonrpc.error.code ?? null;
    } else {
      tools = extractTools(toolsCall.jsonrpc?.result);
    }

    const resourcesCall = await rpc(
      pacer,
      config,
      target,
      { jsonrpc: "2.0", id: 3, method: "resources/list", params: {} },
      sessionId,
      protocolVersion ?? PROTOCOL_VERSION,
      probes,
    );
    resources = resourcesCall.jsonrpc?.error
      ? { ok: false, count: null, errorCode: resourcesCall.jsonrpc.error.code ?? null }
      : { ok: true, count: countList(resourcesCall.jsonrpc?.result, "resources"), errorCode: null };

    const promptsCall = await rpc(
      pacer,
      config,
      target,
      { jsonrpc: "2.0", id: 4, method: "prompts/list", params: {} },
      sessionId,
      protocolVersion ?? PROTOCOL_VERSION,
      probes,
    );
    prompts = promptsCall.jsonrpc?.error
      ? { ok: false, count: null, errorCode: promptsCall.jsonrpc.error.code ?? null }
      : { ok: true, count: countList(promptsCall.jsonrpc?.result, "prompts"), errorCode: null };
  } else if (init.jsonrpc?.error) {
    errorCode = init.jsonrpc.error.code;
    errorMessage = init.jsonrpc.error.message;
  }

  const prm =
    requiresAuth === true
      ? await discoverProtectedResource(target, pacer, config, probes, authParams.resourceMetadata)
      : null;

  return {
    schemaVersion: SCHEMA_VERSION,
    target,
    transport: "http",
    collectedAt,
    reachable,
    auth: {
      networkAccessible: reachable,
      requiresAuth,
      statusOnUnauthenticatedInitialize: status,
      wwwAuthenticate: wwwAuth,
      resourceMetadataUrl: authParams.resourceMetadata,
      protectedResourceMetadata: prm,
    },
    handshake: { initialized, protocolVersion, serverInfo, errorCode, errorMessage },
    capabilities,
    tools,
    toolsErrorCode,
    resources,
    prompts,
    probes,
    limitations,
    collector: {
      name: COLLECTOR_NAME,
      version: config.version,
      userAgent: config.userAgent,
      contact: config.contact,
    },
  };
}
