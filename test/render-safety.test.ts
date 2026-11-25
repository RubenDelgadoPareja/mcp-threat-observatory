import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseSnapshot } from "../src/output/json.ts";
import { renderMarkdown } from "../src/output/markdown.ts";
import { renderSnapshotHtml } from "../src/output/html.ts";
import { renderBehaviourMarkdown } from "../src/behaviour/report.ts";
import { sanitizeText } from "../src/lib/sanitize.ts";
import type { BehaviourRecord } from "../src/behaviour/types.ts";

const repo = join(import.meta.dirname, "..");
const ESC = "\u001b";
const BEL = "\u0007";
const ZWSP = "\u200b";
const RLO = "\u202e";

function poisoned() {
  const snapshot = parseSnapshot(readFileSync(join(repo, "examples", "corpus", "mixed.json"), "utf8"));
  snapshot.findings[0]!.observation = `before ${ESC}[2J${ESC}[H ${ESC}]0;pwned${BEL} after`;
  snapshot.findings[0]!.title = `Title ${ZWSP}with${RLO} hidden`;
  return snapshot;
}

describe("sanitizeText", () => {
  it("removes control, bidi and invisible characters", () => {
    const clean = sanitizeText(`a${ESC}[31mb${BEL}c${ZWSP}d${RLO}e`);
    expect(clean).toBe("a[31mbcde");
  });

  it("keeps newlines and tabs", () => {
    expect(sanitizeText("a\nb\tc")).toBe("a\nb\tc");
  });

  it("bounds the output", () => {
    const clean = sanitizeText("x".repeat(10_000), 50);
    expect(clean.length).toBeLessThan(100);
    expect(clean).toContain("truncated");
  });
});

describe("reports never emit terminal control sequences", () => {
  it("markdown report", () => {
    const markdown = renderMarkdown(poisoned());
    expect(markdown).not.toContain(ESC);
    expect(markdown).not.toContain(BEL);
    expect(markdown).not.toContain(ZWSP);
    expect(markdown).not.toContain(RLO);
  });

  it("html report", () => {
    const html = renderSnapshotHtml(poisoned());
    expect(html).not.toContain(ESC);
    expect(html).not.toContain(BEL);
  });

  it("behaviour report", () => {
    const record: BehaviourRecord = {
      schemaVersion: "1",
      kind: "behaviour",
      argumentProfile: "neutral",
      collectedAt: "2026-11-25T00:00:00.000Z",
      target: { command: ["node", "server.mjs"], cwd: "/tmp" },
      isolation: { mechanism: "unshare-rn", network: "isolated" },
      environment: { home: "/tmp/home", seed: 1, canaries: [] },
      tools: [
        {
          name: `evil${ESC}[2J`,
          arguments: {},
          outcome: "result",
          startedAt: "2026-11-25T00:00:01.000Z",
          endedAt: "2026-11-25T00:00:02.000Z",
          durationMs: 1000,
        },
      ],
      events: [],
      summary: { events: 0, toolCalls: 1, egressAttempts: 0, canaryReads: 0, canarySends: 0 },
      limitations: [`limitation ${ESC}]0;pwned${BEL}`],
    };
    const markdown = renderBehaviourMarkdown(record, []);
    expect(markdown).not.toContain(ESC);
    expect(markdown).not.toContain(BEL);
  });
});
