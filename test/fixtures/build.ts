import type { ProbeResult, ToolDescriptor } from "../../src/model.ts";

const BASE: ProbeResult = {
  schemaVersion: "1",
  target: "https://example.test/mcp",
  transport: "http",
  collectedAt: "2026-11-22T00:00:00.000Z",
  reachable: true,
  auth: {
    networkAccessible: true,
    requiresAuth: false,
    statusOnUnauthenticatedInitialize: 200,
    wwwAuthenticate: null,
    resourceMetadataUrl: null,
    protectedResourceMetadata: null,
  },
  handshake: {
    initialized: true,
    protocolVersion: "2025-06-18",
    serverInfo: { name: "fixture-server", version: "1.0.0" },
  },
  capabilities: { tools: {} },
  tools: [],
  toolsErrorCode: null,
  resources: { ok: true, count: 0, errorCode: null },
  prompts: { ok: true, count: 0, errorCode: null },
  probes: [],
  limitations: ["fixture"],
  collector: {
    name: "mcp-threat-observatory",
    version: "0.1.0",
    userAgent: "test",
    contact: null,
  },
};

export function makeProbe(overrides: {
  target?: string;
  tools?: ToolDescriptor[] | null;
  auth?: Partial<ProbeResult["auth"]>;
  handshake?: Partial<ProbeResult["handshake"]>;
  resources?: ProbeResult["resources"];
  prompts?: ProbeResult["prompts"];
  reachable?: boolean;
}): ProbeResult {
  return {
    ...BASE,
    ...overrides,
    auth: { ...BASE.auth, ...overrides.auth },
    handshake: { ...BASE.handshake, ...overrides.handshake },
  };
}

export function tool(overrides: Partial<ToolDescriptor> & { name: string }): ToolDescriptor {
  return {
    description: `${overrides.name} tool`,
    annotations: {
      title: overrides.name,
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    ...overrides,
  };
}
