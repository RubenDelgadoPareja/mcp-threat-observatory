import { createServer, type ServerResponse } from "node:http";
import { mkdtemp } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { startUiServer, type UiServer } from "../src/ui.ts";

interface Fixture {
  url: string;
  close: () => Promise<void>;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(payload) });
  res.end(payload);
}

async function openMcpFixture(): Promise<Fixture> {
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const message = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
    switch (message.method) {
      case "initialize":
        return json(res, 200, {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: "2025-06-18",
            capabilities: { tools: {} },
            serverInfo: { name: "ui-fixture", version: "1.0.0" },
          },
        });
      case "notifications/initialized":
        res.writeHead(202).end();
        return;
      case "tools/list":
        return json(res, 200, {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            tools: [
              {
                name: "list_docs",
                description: "List documents",
                annotations: { readOnlyHint: true },
                inputSchema: { type: "object", properties: {}, additionalProperties: false },
              },
            ],
          },
        });
      case "resources/list":
        return json(res, 200, { jsonrpc: "2.0", id: message.id, result: { resources: [] } });
      case "prompts/list":
        return json(res, 200, { jsonrpc: "2.0", id: message.id, result: { prompts: [] } });
      default:
        return json(res, 200, { jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "nope" } });
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

let ui: UiServer | null = null;
let fixture: Fixture | null = null;

afterEach(async () => {
  if (ui) await ui.close();
  if (fixture) await fixture.close();
  ui = null;
  fixture = null;
});

describe("local ui", () => {
  it("refuses a request without the token", async () => {
    ui = await startUiServer({ port: 0, outDir: await mkdtemp(join(tmpdir(), "mcpobs-ui-")) });
    const response = await fetch(ui.url.replace(/\?token=.*/, ""));
    expect(response.status).toBe(403);
  });

  it("serves the form with the token", async () => {
    ui = await startUiServer({ port: 0, outDir: await mkdtemp(join(tmpdir(), "mcpobs-ui-")) });
    const response = await fetch(ui.url);
    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain("Passive MCP observation");
    expect(html).toContain("I operate this server");
  });

  it("requires the attestation", async () => {
    ui = await startUiServer({ port: 0, outDir: await mkdtemp(join(tmpdir(), "mcpobs-ui-")) });
    fixture = await openMcpFixture();
    const base = new URL(ui.url);
    const response = await fetch(`http://127.0.0.1:${base.port}/scan${base.search}`, {
      method: "POST",
      body: new URLSearchParams({ url: fixture.url }),
    });
    expect(response.status).toBe(400);
  });

  it("scans a loopback server and returns a report", async () => {
    ui = await startUiServer({
      port: 0,
      outDir: await mkdtemp(join(tmpdir(), "mcpobs-ui-")),
      rateLimitRps: 10,
      timeoutMs: 3_000,
    });
    fixture = await openMcpFixture();

    const base = new URL(ui.url);
    const response = await fetch(`http://127.0.0.1:${base.port}/scan${base.search}`, {
      method: "POST",
      body: new URLSearchParams({ url: fixture.url, attest: "yes" }),
    });

    expect(response.status).toBe(200);
    const html = await response.text();
    expect(html).toContain("<!doctype html>");
    expect(html).toContain("AUTH-001");
  }, 20_000);

  it("refuses to scan itself", async () => {
    ui = await startUiServer({ port: 0, outDir: await mkdtemp(join(tmpdir(), "mcpobs-ui-")) });
    const base = new URL(ui.url);
    const response = await fetch(`http://127.0.0.1:${base.port}/scan${base.search}`, {
      method: "POST",
      body: new URLSearchParams({ url: `http://127.0.0.1:${base.port}/mcp`, attest: "yes" }),
    });
    expect(response.status).toBe(400);
    expect(await response.text()).toContain("not an MCP endpoint");
  });

  it("refuses a cross-origin request even with the token", async () => {
    ui = await startUiServer({ port: 0, outDir: await mkdtemp(join(tmpdir(), "mcpobs-ui-")) });
    fixture = await openMcpFixture();
    const base = new URL(ui.url);
    const response = await fetch(`http://127.0.0.1:${base.port}/scan${base.search}`, {
      method: "POST",
      headers: { origin: "https://evil.example.test" },
      body: new URLSearchParams({ url: fixture.url, attest: "yes" }),
    });
    expect(response.status).toBe(403);
  });
});
