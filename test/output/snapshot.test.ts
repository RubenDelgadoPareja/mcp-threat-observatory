import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildSnapshot } from "../../src/analyze.ts";
import { parseSnapshot, snapshotFingerprint } from "../../src/output/json.ts";
import { writeSnapshot } from "../../src/output/snapshot.ts";
import { makeProbe, tool } from "../fixtures/build.ts";

describe("snapshot persistence", () => {
  it("writes an immutable file and an append-only index line", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcpobs-"));
    const snapshot = buildSnapshot(makeProbe({ tools: [tool({ name: "read_docs" })] }));

    const first = await writeSnapshot(dir, snapshot);
    const second = await writeSnapshot(dir, snapshot);

    expect(first.fingerprint).toBe(second.fingerprint);
    expect(first.file).toBe(second.file);
    expect(first.file).toContain("2026-11-22");

    const raw = await readFile(first.file, "utf8");
    const parsed = parseSnapshot(raw);
    expect(parsed.probe.target).toBe(snapshot.probe.target);
    expect(snapshotFingerprint(parsed)).toBe(first.fingerprint);

    const index = await readFile(first.indexPath, "utf8");
    const lines = index.trim().split("\n");
    expect(lines).toHaveLength(2);
    for (const line of lines) {
      const entry = JSON.parse(line) as { target: string; fingerprint: string };
      expect(entry.target).toBe(snapshot.probe.target);
      expect(entry.fingerprint).toHaveLength(24);
    }
  });

  it("rejects files that are not snapshots", () => {
    expect(() => parseSnapshot('{"hello":"world"}')).toThrow(/Not a snapshot/);
  });
});
