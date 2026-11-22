import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { assessmentFingerprint, type Assessment } from "../assess.ts";
import { slugify } from "../lib/id.ts";
import { renderAssessmentHtml } from "./html.ts";

export interface WrittenAssessment {
  json: string;
  html: string;
  fingerprint: string;
}

export async function writeAssessment(outDir: string, assessment: Assessment): Promise<WrittenAssessment> {
  const fingerprint = assessmentFingerprint(assessment);
  const day = assessment.generatedAt.slice(0, 10);
  const dir = join(outDir, day);
  await mkdir(dir, { recursive: true });

  const label = assessment.target.url ?? assessment.target.command?.[0] ?? "assessment";
  const base = join(dir, `${slugify(label)}-${fingerprint.slice(0, 8)}`);

  await writeFile(`${base}.json`, `${JSON.stringify(assessment, null, 2)}\n`, "utf8");
  await writeFile(`${base}.html`, renderAssessmentHtml(assessment), "utf8");

  return { json: `${base}.json`, html: `${base}.html`, fingerprint };
}
