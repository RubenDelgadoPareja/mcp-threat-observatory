import { describe, expect, it } from "vitest";
import { analyseBehaviour } from "../../src/behaviour/analyser.ts";
import type { BehaviourRecord } from "../../src/behaviour/types.ts";

const TARGET = { command: ["node", "server.mjs"], cwd: "/tmp/work" };

function record(overrides: Partial<BehaviourRecord> = {}): BehaviourRecord {
  return {
    schemaVersion: "1",
    kind: "behaviour",
    argumentProfile: "neutral",
    collectedAt: "2026-11-22T00:00:00.000Z",
    target: TARGET,
    isolation: { mechanism: "unshare-rn", network: "isolated" },
    environment: {
      home: "/tmp/home",
      seed: 1,
      canaries: [
        { id: "CANARY-aaaaaaaaaaaaaaaa", kind: "file", locator: "/tmp/home/.ssh/id_ed25519" },
        { id: "CANARY-bbbbbbbbbbbbbbbb", kind: "env", locator: "GITHUB_TOKEN" },
      ],
    },
    tools: [
      {
        name: "get_notes",
        arguments: {},
        outcome: "result",
        startedAt: "2026-11-22T00:00:01.000Z",
        endedAt: "2026-11-22T00:00:02.000Z",
        durationMs: 1000,
      },
    ],
    events: [],
    summary: { events: 0, toolCalls: 1, egressAttempts: 0, canaryReads: 0, canarySends: 0 },
    limitations: [],
    ...overrides,
  };
}

describe("analyseBehaviour", () => {
  it("reports a canary sent to an external destination as an observation", () => {
    const findings = analyseBehaviour(
      record({
        events: [
          {
            at: "2026-11-22T00:00:01.500Z",
            type: "net.write",
            host: "smtp.collect.example.test",
            port: 587,
            canaryIds: ["CANARY-aaaaaaaaaaaaaaaa"],
          },
        ],
      }),
    );
    const finding = findings.find((candidate) => candidate.checkId === "BEHAV-001");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
    expect(finding?.assertion).toBe("observed");
    expect(finding?.confidence).toBe("high");
    expect(finding?.observation).toContain("smtp.collect.example.test:587");
    expect(finding?.observation).toContain("get_notes");
    expect(finding?.limitations.join(" ")).toMatch(/not proof of intent/i);
    expect(finding?.evidence[0]?.excerpt).toContain("CANARY-");
  });

  it("does not claim a destination when the write was never bound to a peer", () => {
    const findings = analyseBehaviour(
      record({
        events: [
          {
            at: "2026-11-22T00:00:01.500Z",
            type: "net.write",
            canaryIds: ["CANARY-aaaaaaaaaaaaaaaa"],
            bytes: 200,
          },
        ],
      }),
    );
    const finding = findings.find((candidate) => candidate.checkId === "BEHAV-001");
    expect(finding?.observation).toContain("destination was not observed");
    expect(finding?.confidence).toBe("moderate");
    expect(finding?.limitations.join(" ")).toContain("cannot have left the machine");
    expect(finding?.limitations.join(" ")).toContain("not attributed to a peer");
  });

  it("attributes an event outside any tool call honestly", () => {
    const findings = analyseBehaviour(
      record({
        events: [
          {
            at: "2026-11-22T00:00:09.000Z",
            type: "net.write",
            host: "evil.example.test",
            port: 443,
            canaryIds: ["CANARY-bbbbbbbbbbbbbbbb"],
          },
        ],
      }),
    );
    const finding = findings.find((candidate) => candidate.checkId === "BEHAV-001");
    expect(finding?.observation).toContain("outside any tool call");
  });

  it("reports egress at low severity and never as a vulnerability", () => {
    const findings = analyseBehaviour(
      record({
        events: [{ at: "2026-11-22T00:00:01.500Z", type: "net.connect", host: "api.example.test", port: 443 }],
      }),
    );
    const finding = findings.find((candidate) => candidate.checkId === "BEHAV-002");
    expect(finding?.severity).toBe("low");
    expect(finding?.observation).toContain("api.example.test:443");
    expect(finding?.limitations.join(" ")).toMatch(/not a vulnerability/i);
  });

  it("ignores loopback destinations", () => {
    const findings = analyseBehaviour(
      record({
        events: [
          { at: "2026-11-22T00:00:01.500Z", type: "net.connect", host: "127.0.0.1", port: 8080 },
          { at: "2026-11-22T00:00:01.600Z", type: "net.connect", host: "localhost", port: 3000 },
        ],
      }),
    );
    expect(findings.some((candidate) => candidate.checkId === "BEHAV-002")).toBe(false);
  });

  it("reports a canary credential read at medium severity", () => {
    const findings = analyseBehaviour(
      record({
        events: [
          {
            at: "2026-11-22T00:00:01.500Z",
            type: "fs.read",
            path: "/tmp/home/.ssh/id_ed25519",
          },
        ],
      }),
    );
    const finding = findings.find((candidate) => candidate.checkId === "BEHAV-003");
    expect(finding?.severity).toBe("medium");
    expect(finding?.observation).toContain("/tmp/home/.ssh/id_ed25519");
    expect(finding?.observation).toContain("get_notes");
  });

  it("does not report reads of files that are not canaries", () => {
    const findings = analyseBehaviour(
      record({
        events: [{ at: "2026-11-22T00:00:01.500Z", type: "fs.read", path: "/usr/lib/node_modules/x/index.js" }],
      }),
    );
    expect(findings).toEqual([]);
  });

  it("produces no findings for a clean record", () => {
    expect(analyseBehaviour(record())).toEqual([]);
  });

  it("keeps fingerprints stable and unique", () => {
    const input = record({
      events: [
        { at: "2026-11-22T00:00:01.500Z", type: "net.connect", host: "a.example.test", port: 443 },
        { at: "2026-11-22T00:00:01.600Z", type: "net.connect", host: "b.example.test", port: 443 },
      ],
    });
    const first = analyseBehaviour(input).map((finding) => finding.fingerprint);
    const second = analyseBehaviour(input).map((finding) => finding.fingerprint);
    expect(first).toEqual(second);
    expect(new Set(first).size).toBe(first.length);
  });

  it("does not duplicate a canary destination as generic egress", () => {
    const findings = analyseBehaviour(
      record({
        events: [
          {
            at: "2026-11-22T00:00:01.500Z",
            type: "net.write",
            host: "smtp.example.test",
            port: 587,
            canaryIds: ["CANARY-aaaaaaaaaaaaaaaa"],
          },
          { at: "2026-11-22T00:00:01.600Z", type: "net.connect", host: "smtp.example.test", port: 587 },
        ],
      }),
    );
    expect(findings.filter((finding) => finding.checkId === "BEHAV-001")).toHaveLength(1);
    expect(findings.filter((finding) => finding.checkId === "BEHAV-002")).toHaveLength(0);
  });

  it("orders findings by severity", () => {
    const findings = analyseBehaviour(
      record({
        events: [
          { at: "2026-11-22T00:00:01.500Z", type: "net.connect", host: "api.example.test", port: 443 },
          {
            at: "2026-11-22T00:00:01.600Z",
            type: "net.write",
            host: "smtp.example.test",
            port: 587,
            canaryIds: ["CANARY-aaaaaaaaaaaaaaaa"],
          },
        ],
      }),
    );
    expect(findings.map((finding) => finding.severity)).toEqual(["high", "low"]);
  });
});
