import { ALL_CHECKS } from "./checks/index.ts";
import { severityRank } from "./checks/types.ts";
import { shortHash } from "./lib/id.ts";
import {
  emptySummary,
  SCHEMA_VERSION,
  type Finding,
  type ProbeResult,
  type Snapshot,
} from "./model.ts";

export interface AnalysisResult {
  findings: Finding[];
  /** Checks that threw. A broken check must never abort a collection run. */
  errors: Array<{ checkId: string; message: string }>;
}

export function analyze(probe: ProbeResult): AnalysisResult {
  const findings: Finding[] = [];
  const errors: AnalysisResult["errors"] = [];

  for (const check of ALL_CHECKS) {
    let results;
    try {
      results = check.run(probe);
    } catch (error) {
      errors.push({
        checkId: check.id,
        message: error instanceof Error ? error.message : String(error),
      });
      continue;
    }

    for (const result of results) {
      findings.push({
        fingerprint: shortHash(`${check.id}|${probe.target}|${result.discriminator ?? ""}`, 16),
        checkId: check.id,
        title: result.title ?? check.title,
        severity: result.severity,
        confidence: result.confidence,
        assertion: result.assertion,
        taxonomy: check.taxonomy ?? [],
        owasp: check.owasp,
        observation: result.observation,
        inference: result.inference,
        recommendation: result.recommendation,
        limitations: result.limitations ?? [],
        evidence: result.evidence ?? [],
      });
    }
  }

  findings.sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || a.checkId.localeCompare(b.checkId),
  );

  return { findings, errors };
}

export function summarize(findings: Finding[]): Snapshot["summary"] {
  const summary = emptySummary();
  for (const finding of findings) {
    summary.total += 1;
    summary.bySeverity[finding.severity] += 1;
    summary.byConfidence[finding.confidence] += 1;
    if (finding.assertion === "observed") summary.observed += 1;
    else summary.inferred += 1;
  }
  return summary;
}

export function buildSnapshot(probe: ProbeResult): Snapshot {
  const { findings } = analyze(probe);
  return {
    schemaVersion: SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    probe,
    findings,
    summary: summarize(findings),
  };
}
