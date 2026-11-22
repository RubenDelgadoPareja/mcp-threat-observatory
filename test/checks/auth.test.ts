import { describe, expect, it } from "vitest";
import { analyze } from "../../src/analyze.ts";
import { makeProbe, tool } from "../fixtures/build.ts";

function ids(target = "https://example.test/mcp", tools = [tool({ name: "list_docs" })]) {
  const probe = makeProbe({ target, tools });
  return analyze(probe).findings;
}

describe("AUTH-001 unauthenticated access", () => {
  it("fires at low severity when the exposed catalog is read-mostly", () => {
    const findings = ids();
    const finding = findings.find((f) => f.checkId === "AUTH-001");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("low");
    expect(finding?.assertion).toBe("observed");
    expect(finding?.confidence).toBe("high");
  });

  it("escalates to high when a destructive tool is exposed", () => {
    const findings = ids("https://example.test/mcp", [
      tool({
        name: "delete_repository",
        description: "Delete a repository permanently",
        annotations: { title: "Delete repository", destructiveHint: true },
      }),
    ]);
    const finding = findings.find((f) => f.checkId === "AUTH-001");
    expect(finding?.severity).toBe("high");
  });

  it("does not fire when authentication is required", () => {
    const probe = makeProbe({
      tools: null,
      auth: { requiresAuth: true, statusOnUnauthenticatedInitialize: 401 },
      handshake: { initialized: false },
    });
    const findings = analyze(probe).findings;
    expect(findings.some((f) => f.checkId === "AUTH-001")).toBe(false);
  });
});

describe("AUTH-002 403 instead of 401", () => {
  it("fires on 403", () => {
    const probe = makeProbe({
      tools: null,
      auth: { requiresAuth: true, statusOnUnauthenticatedInitialize: 403 },
      handshake: { initialized: false },
    });
    const finding = analyze(probe).findings.find((f) => f.checkId === "AUTH-002");
    expect(finding?.severity).toBe("medium");
  });

  it("does not fire on 401", () => {
    const probe = makeProbe({
      tools: null,
      auth: {
        requiresAuth: true,
        statusOnUnauthenticatedInitialize: 401,
        resourceMetadataUrl: "https://example.test/.well-known/oauth-protected-resource/mcp",
      },
      handshake: { initialized: false },
    });
    const finding = analyze(probe).findings.find((f) => f.checkId === "AUTH-002");
    expect(finding).toBeUndefined();
  });
});

describe("AUTH-003 protected resource metadata", () => {
  it("fires when auth is required and no metadata document exists", () => {
    const probe = makeProbe({
      tools: null,
      auth: {
        requiresAuth: true,
        statusOnUnauthenticatedInitialize: 401,
        resourceMetadataUrl: "https://example.test/.well-known/oauth-protected-resource/mcp",
        protectedResourceMetadata: { found: false, url: null, status: 404 },
      },
      handshake: { initialized: false },
    });
    const finding = analyze(probe).findings.find((f) => f.checkId === "AUTH-003");
    expect(finding?.severity).toBe("medium");
    expect(finding?.inference).toContain("cannot auto-discover");
  });

  it("stays quiet when the document is found", () => {
    const probe = makeProbe({
      tools: null,
      auth: {
        requiresAuth: true,
        statusOnUnauthenticatedInitialize: 401,
        resourceMetadataUrl: "https://example.test/.well-known/oauth-protected-resource/mcp",
        protectedResourceMetadata: {
          found: true,
          url: "https://example.test/.well-known/oauth-protected-resource/mcp",
          status: 200,
          authorizationServers: ["https://auth.example.test"],
        },
      },
      handshake: { initialized: false },
    });
    expect(analyze(probe).findings.some((f) => f.checkId === "AUTH-003")).toBe(false);
  });
});

describe("AUTH-004 challenge quality", () => {
  it("fires when a 401 challenge omits resource_metadata", () => {
    const probe = makeProbe({
      tools: null,
      auth: {
        requiresAuth: true,
        statusOnUnauthenticatedInitialize: 401,
        wwwAuthenticate: 'Bearer realm="mcp"',
      },
      handshake: { initialized: false },
    });
    const finding = analyze(probe).findings.find((f) => f.checkId === "AUTH-004");
    expect(finding?.severity).toBe("low");
  });
});
