import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildAssessment } from "../src/assess.ts";
import { parseSnapshot } from "../src/output/json.ts";
import { renderAssessmentHtml, renderSnapshotHtml } from "../src/output/html.ts";

const repo = join(import.meta.dirname, "..");
const snapshot = () =>
  parseSnapshot(readFileSync(join(repo, "examples", "corpus", "mixed.json"), "utf8"));

describe("snapshot html", () => {
  it("is a self-contained document with the findings", () => {
    const html = renderSnapshotHtml(snapshot());
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).toContain("AUTH-001");
    expect(html).toContain("RISK-001");
    expect(html).toContain("Observation");
    expect(html).toContain("TLP:CLEAR");
  });

  it("never references an external resource", () => {
    const html = renderSnapshotHtml(snapshot());
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/src="https?:/i);
    expect(html).not.toMatch(/href="https?:/i);
    expect(html).not.toContain("cdn.");
  });

  it("escapes content that could break the document", () => {
    const input = snapshot();
    input.findings[0]!.observation = "<script>alert(1)</script>";
    const html = renderSnapshotHtml(input);
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });
});

describe("assessment html", () => {
  it("shows the link assertion when both halves are present", () => {
    const record = {
      schemaVersion: "1" as const,
      kind: "behaviour" as const,
      argumentProfile: "neutral" as const,
      collectedAt: "2026-11-22T00:00:00.000Z",
      target: { command: ["node", "server.mjs"], cwd: "/tmp" },
      isolation: { mechanism: "unshare-rn" as const, network: "isolated" as const },
      environment: { home: "/tmp/home", seed: 1, canaries: [] },
      tools: [],
      events: [],
      summary: { events: 0, toolCalls: 0, egressAttempts: 0, canaryReads: 0, canarySends: 0 },
      limitations: [],
    };
    const assessment = buildAssessment({
      url: "https://example.test/mcp",
      command: ["node", "server.mjs"],
      snapshot: snapshot(),
      record,
    });
    const html = renderAssessmentHtml(assessment);
    expect(html).toContain("operator-asserted");
    expect(html).toContain("cannot prove they refer to the same server");
  });
});
