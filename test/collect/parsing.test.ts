import { describe, expect, it } from "vitest";
import { parseJsonRpcBody, parseWwwAuthenticate } from "../../src/collect/http.ts";
import { dedupeAnomalies, excerpt, scanMetadataText } from "../../src/lib/text.ts";

describe("parseWwwAuthenticate", () => {
  it("extracts quoted parameters", () => {
    const parsed = parseWwwAuthenticate(
      'Bearer resource_metadata="https://example.test/.well-known/oauth-protected-resource/mcp", scope="api.read"',
    );
    expect(parsed.scheme).toBe("Bearer");
    expect(parsed.resourceMetadata).toBe("https://example.test/.well-known/oauth-protected-resource/mcp");
    expect(parsed.scope).toBe("api.read");
  });

  it("extracts unquoted parameters", () => {
    const parsed = parseWwwAuthenticate("Bearer error=invalid_token, scope=api.read");
    expect(parsed.error).toBe("invalid_token");
    expect(parsed.scope).toBe("api.read");
    expect(parsed.resourceMetadata).toBeNull();
  });

  it("handles a missing header", () => {
    expect(parseWwwAuthenticate(null)).toEqual({
      scheme: null,
      resourceMetadata: null,
      scope: null,
      error: null,
    });
  });
});

describe("parseJsonRpcBody", () => {
  it("parses a plain JSON body", () => {
    expect(parseJsonRpcBody('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}')).toEqual({
      jsonrpc: "2.0",
      id: 1,
      result: { ok: true },
    });
  });

  it("parses the last JSON frame of an SSE stream", () => {
    const body = [
      "event: message",
      'data: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}',
      "",
      "event: message",
      'data: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"x"}]}}',
      "",
    ].join("\n");
    const parsed = parseJsonRpcBody(body) as { result: { tools: Array<{ name: string }> } };
    expect(parsed.result.tools[0]?.name).toBe("x");
  });

  it("returns undefined for an empty body", () => {
    expect(parseJsonRpcBody("   ")).toBeUndefined();
  });
});

describe("metadata text inspection", () => {
  it("detects zero-width characters", () => {
    const anomalies = scanMetadataText("hello\u200bworld");
    expect(anomalies.some((a) => a.kind === "hidden-character")).toBe(true);
  });

  it("detects bidi controls", () => {
    const anomalies = scanMetadataText("abc\u202edef");
    expect(anomalies.some((a) => a.kind === "bidi-control")).toBe(true);
  });

  it("detects Unicode tag characters", () => {
    const anomalies = scanMetadataText("normal\u{E0041}\u{E0042}");
    expect(anomalies.some((a) => a.kind === "tag-character")).toBe(true);
  });

  it("does not flag a benign description", () => {
    expect(
      scanMetadataText("Return the weather forecast for a city. Use the IANA timezone."),
    ).toEqual([]);
  });

  it("deduplicates repeated matches", () => {
    const anomalies = dedupeAnomalies(scanMetadataText("<IMPORTANT> a <IMPORTANT> b"));
    expect(anomalies).toHaveLength(1);
  });

  it("bounds excerpts", () => {
    const long = "a".repeat(2_000);
    expect(excerpt(long, 50)).toHaveLength(51);
    expect(excerpt(long, 50).endsWith("…")).toBe(true);
  });
});
