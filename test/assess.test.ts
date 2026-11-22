import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { assessmentFingerprint, buildAssessment, renderAssessmentMarkdown } from "../src/assess.ts";
import { parseSnapshot } from "../src/output/json.ts";
import type { BehaviourRecord } from "../src/behaviour/types.ts";

const repo = join(import.meta.dirname, "..");
const snapshot = () =>
  parseSnapshot(readFileSync(join(repo, "examples", "corpus", "open-readonly.json"), "utf8"));

function behaviourRecord(): BehaviourRecord {
  return {
    schemaVersion: "1",
    kind: "behaviour",
    collectedAt: "2026-11-22T00:00:00.000Z",
    target: { command: ["node", "/abs/server.mjs"], cwd: "/tmp/work" },
    isolation: { mechanism: "unshare-rn", network: "isolated" },
    environment: {
      home: "/tmp/home",
      seed: 1,
      canaries: [{ id: "CANARY-aaaaaaaaaaaaaaaa", kind: "file", locator: "/tmp/home/.ssh/id_ed25519" }],
    },
    tools: [],
    events: [
      {
        at: "2026-11-22T00:00:01.000Z",
        type: "net.write",
        host: "smtp.example.test",
        port: 587,
        canaryIds: ["CANARY-aaaaaaaaaaaaaaaa"],
      },
    ],
    summary: { events: 1, toolCalls: 0, egressAttempts: 1, canaryReads: 0, canarySends: 1 },
    limitations: ["fixture limitation"],
  };
}

describe("buildAssessment", () => {
  it("marks a url-only assessment as such", () => {
    const assessment = buildAssessment({ url: "https://example.test/mcp", command: null, snapshot: snapshot(), record: null });
    expect(assessment.target.link).toBe("url-only");
    expect(assessment.summary.passive).toBeGreaterThan(0);
    expect(assessment.summary.behaviour).toBe(0);
    expect(assessment.findings.every((finding) => finding.origin === "passive")).toBe(true);
  });

  it("records the link as an operator assertion, not a fact", () => {
    const assessment = buildAssessment({
      url: "https://example.test/mcp",
      command: ["node", "server.mjs"],
      snapshot: snapshot(),
      record: behaviourRecord(),
    });
    expect(assessment.target.link).toBe("operator-asserted");
    expect(assessment.limitations.join(" ")).toContain("cannot prove they are the same server");
  });

  it("keeps the two origins separate", () => {
    const assessment = buildAssessment({
      url: "https://example.test/mcp",
      command: ["node", "server.mjs"],
      snapshot: snapshot(),
      record: behaviourRecord(),
    });
    expect(assessment.summary.behaviour).toBe(1);
    expect(assessment.findings.some((finding) => finding.origin === "behaviour")).toBe(true);
    expect(assessment.findings.some((finding) => finding.checkId === "BEHAV-001")).toBe(true);
    expect(assessment.findings.some((finding) => finding.checkId === "AUTH-001")).toBe(true);
  });

  it("deduplicates limitations", () => {
    const assessment = buildAssessment({
      url: "https://example.test/mcp",
      command: null,
      snapshot: snapshot(),
      record: null,
    });
    expect(new Set(assessment.limitations).size).toBe(assessment.limitations.length);
  });

  it("is deterministic for the same content", () => {
    const first = buildAssessment({ url: "https://example.test/mcp", command: null, snapshot: snapshot(), record: null });
    const second = buildAssessment({ url: "https://example.test/mcp", command: null, snapshot: snapshot(), record: null });
    expect(assessmentFingerprint(first)).toBe(assessmentFingerprint(second));
  });

  it("renders markdown with both origins and the link caveat", () => {
    const assessment = buildAssessment({
      url: "https://example.test/mcp",
      command: ["node", "server.mjs"],
      snapshot: snapshot(),
      record: behaviourRecord(),
    });
    const markdown = renderAssessmentMarkdown(assessment);
    expect(markdown).toContain("Assessment — https://example.test/mcp");
    expect(markdown).toContain("**Origin:** passive");
    expect(markdown).toContain("**Origin:** behaviour");
    expect(markdown).toContain("operator-asserted");
    expect(markdown).toContain("does not prove the URL and the command are the same server");
  });
});
