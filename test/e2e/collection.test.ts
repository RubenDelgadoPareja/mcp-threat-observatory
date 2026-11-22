import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { analyze } from "../../src/analyze.ts";
import { probeServer } from "../../src/collect/probe.ts";

interface Fixture {
  url: string;
  close: () => Promise<void>;
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
    ...headers,
  });
  res.end(payload);
}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? (JSON.parse(text) as Record<string, unknown>) : {};
}

async function openServer(): Promise<Fixture> {
  const server = createServer(async (req, res) => {
    const body = await readBody(req);
    const method = body.method;

    if (method === "initialize") {
      return json(
        res,
        200,
        {
          jsonrpc: "2.0",
          id: body.id,
          result: {
            protocolVersion: "2025-06-18",
            capabilities: { tools: {} },
            serverInfo: { name: "fixture-open", version: "1.0.0" },
          },
        },
        { "mcp-session-id": "session-1" },
      );
    }
    if (method === "notifications/initialized") {
      res.writeHead(202).end();
      return;
    }
    if (method === "tools/list") {
      return json(res, 200, {
        jsonrpc: "2.0",
        id: body.id,
        result: {
          tools: [
            {
              name: "delete_workspace",
              description: "Delete a workspace permanently",
              annotations: { destructiveHint: true },
              inputSchema: { type: "object", properties: { id: { type: "string" } } },
            },
            {
              name: "list_notes",
              description: "List notes",
              annotations: { readOnlyHint: true },
              inputSchema: { type: "object", properties: {}, additionalProperties: false },
            },
          ],
        },
      });
    }
    if (method === "resources/list") {
      return json(res, 200, { jsonrpc: "2.0", id: body.id, result: { resources: [] } });
    }
    if (method === "prompts/list") {
      return json(res, 200, {
        jsonrpc: "2.0",
        id: body.id,
        error: { code: -32601, message: "Method not found" },
      });
    }
    return json(res, 400, { jsonrpc: "2.0", id: body.id, error: { code: -32600, message: "Invalid Request" } });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function protectedServer(): Promise<Fixture> {
  const server = createServer(async (req, res) => {
    if (req.url?.startsWith("/.well-known/oauth-protected-resource")) {
      return json(res, 200, {
        resource: "http://127.0.0.1/mcp",
        authorization_servers: ["https://auth.example.test"],
        bearer_methods_supported: ["header"],
      });
    }
    const body = await readBody(req);
    if (body.method === "initialize") {
      res.writeHead(401, {
        "content-type": "application/json",
        "www-authenticate": `Bearer resource_metadata="http://127.0.0.1:${(server.address() as AddressInfo).port}/.well-known/oauth-protected-resource/mcp"`,
      });
      return res.end(JSON.stringify({ error: "unauthorized" }));
    }
    res.writeHead(401).end();
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

let fixture: Fixture | null = null;

afterEach(async () => {
  if (fixture) await fixture.close();
  fixture = null;
});

describe("collection end to end", () => {
  it("records an open server, its tools and its discovery semantics", async () => {
    fixture = await openServer();
    const probe = await probeServer(fixture.url, { rateLimitRps: 10, timeoutMs: 3_000 });

    expect(probe.reachable).toBe(true);
    expect(probe.auth.requiresAuth).toBe(false);
    expect(probe.handshake.initialized).toBe(true);
    expect(probe.handshake.serverInfo?.name).toBe("fixture-open");
    expect(probe.tools).toHaveLength(2);
    expect(probe.resources).toEqual({ ok: true, count: 0, errorCode: null });
    expect(probe.prompts?.errorCode).toBe(-32601);
    expect(probe.probes.length).toBeGreaterThanOrEqual(5);

    const findings = analyze(probe).findings;
    const auth = findings.find((f) => f.checkId === "AUTH-001");
    expect(auth?.severity).toBe("high");
    expect(findings.some((f) => f.checkId === "PROTO-001")).toBe(true);
  });

  it("records a protected server and resolves its protected resource metadata", async () => {
    fixture = await protectedServer();
    const probe = await probeServer(fixture.url, { rateLimitRps: 10, timeoutMs: 3_000 });

    expect(probe.auth.requiresAuth).toBe(true);
    expect(probe.auth.statusOnUnauthenticatedInitialize).toBe(401);
    expect(probe.auth.resourceMetadataUrl).toContain("/.well-known/oauth-protected-resource");
    expect(probe.auth.protectedResourceMetadata?.found).toBe(true);
    expect(probe.auth.protectedResourceMetadata?.authorizationServers).toEqual([
      "https://auth.example.test",
    ]);

    const findings = analyze(probe).findings;
    expect(findings.some((f) => f.checkId === "AUTH-003")).toBe(false);
    expect(findings.some((f) => f.checkId === "AUTH-004")).toBe(false);
  });

  it("records a transport failure without throwing", async () => {
    const probe = await probeServer("http://127.0.0.1:1/mcp", { rateLimitRps: 10, timeoutMs: 500 });
    expect(probe.reachable).toBe(false);
    expect(probe.auth.requiresAuth).toBeNull();
    expect(probe.limitations.length).toBeGreaterThan(0);
    expect(analyze(probe).findings).toEqual([]);
  });
});
