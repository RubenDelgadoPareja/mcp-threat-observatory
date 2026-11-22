import { shortHash } from "../lib/id.ts";
import type { Snapshot } from "../model.ts";

export function renderJson(snapshot: Snapshot): string {
  return `${JSON.stringify(snapshot, null, 2)}\n`;
}

/** Stable identifier for the exact content of a snapshot. */
export function snapshotFingerprint(snapshot: Snapshot): string {
  return shortHash(JSON.stringify({ probe: snapshot.probe, findings: snapshot.findings }), 24);
}

export function parseSnapshot(text: string): Snapshot {
  const parsed = JSON.parse(text) as Partial<Snapshot>;
  if (!parsed || typeof parsed !== "object" || !parsed.probe || !Array.isArray(parsed.findings)) {
    throw new Error("Not a snapshot file: expected { probe, findings }.");
  }
  return parsed as Snapshot;
}
