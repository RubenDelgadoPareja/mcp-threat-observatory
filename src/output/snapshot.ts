import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { slugify } from "../lib/id.ts";
import type { Snapshot } from "../model.ts";
import { renderJson, snapshotFingerprint } from "./json.ts";

export interface WrittenSnapshot {
  file: string;
  indexPath: string;
  fingerprint: string;
}

/**
 * Writes an immutable snapshot plus one append-only index line.
 *
 * The index is the basis for longitudinal analysis later: one line per
 * observation, never rewritten, so drift can be computed without trusting
 * any single file.
 */
export async function writeSnapshot(outDir: string, snapshot: Snapshot): Promise<WrittenSnapshot> {
  const fingerprint = snapshotFingerprint(snapshot);
  const day = snapshot.probe.collectedAt.slice(0, 10);
  const dir = join(outDir, day);
  await mkdir(dir, { recursive: true });

  const host = safeHost(snapshot.probe.target);
  const file = join(dir, `${slugify(host)}-${fingerprint.slice(0, 8)}.json`);
  await writeFile(file, renderJson(snapshot), "utf8");

  const indexPath = join(outDir, "index.jsonl");
  const line = JSON.stringify({
    at: snapshot.generatedAt,
    target: snapshot.probe.target,
    file,
    fingerprint,
    summary: snapshot.summary,
  });
  await appendFile(indexPath, `${line}\n`, "utf8");

  return { file, indexPath, fingerprint };
}

function safeHost(target: string): string {
  try {
    return new URL(target).host;
  } catch {
    return target;
  }
}
