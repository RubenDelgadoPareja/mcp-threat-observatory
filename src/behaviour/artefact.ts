import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { shortHash, slugify } from "../lib/id.ts";
import type { Finding } from "../model.ts";
import type { BehaviourRecord } from "./types.ts";

export interface BehaviourArtefact {
  schemaVersion: "1";
  kind: "behaviour-artefact";
  generatedAt: string;
  record: BehaviourRecord;
  findings: Finding[];
  summary: {
    total: number;
    bySeverity: Record<string, number>;
    egressAttempts: number;
    canaryReads: number;
    canarySends: number;
  };
}

export function buildArtefact(record: BehaviourRecord, findings: Finding[]): BehaviourArtefact {
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) bySeverity[finding.severity] += 1;

  return {
    schemaVersion: "1",
    kind: "behaviour-artefact",
    generatedAt: new Date().toISOString(),
    record,
    findings,
    summary: {
      total: findings.length,
      bySeverity,
      egressAttempts: record.summary.egressAttempts,
      canaryReads: record.summary.canaryReads,
      canarySends: record.summary.canarySends,
    },
  };
}

export function artefactFingerprint(artefact: BehaviourArtefact): string {
  return shortHash(
    JSON.stringify({ record: artefact.record, findings: artefact.findings }),
    24,
  );
}

export interface WrittenArtefact {
  file: string;
  indexPath: string;
  fingerprint: string;
}

/**
 * Same storage contract as the passive snapshots: immutable file, append-only
 * index. Behaviour is a separate lineage, so it gets its own directory.
 */
export async function writeBehaviourArtefact(
  outDir: string,
  artefact: BehaviourArtefact,
): Promise<WrittenArtefact> {
  const fingerprint = artefactFingerprint(artefact);
  const day = artefact.record.collectedAt.slice(0, 10);
  const dir = join(outDir, day);
  await mkdir(dir, { recursive: true });

  const label = artefact.record.tools[0]?.name ?? "server";
  const file = join(dir, `${slugify(label)}-${fingerprint.slice(0, 8)}.json`);
  await writeFile(file, `${JSON.stringify(artefact, null, 2)}\n`, "utf8");

  const indexPath = join(outDir, "index.jsonl");
  await appendFile(
    indexPath,
    `${JSON.stringify({
      at: artefact.generatedAt,
      command: artefact.record.target.command.join(" "),
      file,
      fingerprint,
      summary: artefact.summary,
    })}\n`,
    "utf8",
  );

  return { file, indexPath, fingerprint };
}
