#!/usr/bin/env node
/**
 * Aggregates corpus results into an anonymised summary.
 *
 * Output distinguishes servers by id (S1, S2, …). Names, versions, tool names
 * and egress destinations stay in the private results directory and are never
 * written to the summary, so the summary can be published.
 */
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const outRoot = process.env.CORPUS_OUT ?? join(tmpdir(), "mcpobs-corpus");
const resultsRoot = join(outRoot, "results");

if (!existsSync(resultsRoot)) {
  console.error(`no results in ${resultsRoot}; run scripts/corpus-run.mjs first`);
  process.exit(1);
}

const files = readdirSync(resultsRoot).filter((file) => file.endsWith(".json")).sort();
const rows = [];

for (const file of files) {
  const artefact = JSON.parse(readFileSync(join(resultsRoot, file), "utf8"));
  const record = artefact.record;
  const events = record.events ?? [];
  const egress = new Set(
    events
      .filter((event) => event.type === "net.connect" || event.type === "dns.lookup" || event.type === "net.write")
      .map((event) => event.host)
      .filter((host) => host && !host.startsWith("127.") && host !== "localhost" && host !== "::1"),
  );

  const outcomes = record.tools.reduce((acc, tool) => {
    acc[tool.outcome] = (acc[tool.outcome] ?? 0) + 1;
    return acc;
  }, {});

  rows.push({
    id: file.replace(/\.json$/, "").split("-")[0],
    profile: record.argumentProfile,
    started: (record.tools?.length ?? 0) > 0,
    tools: record.tools?.length ?? 0,
    callsOk: outcomes.result ?? 0,
    callsError: outcomes.error ?? 0,
    callsTimeout: outcomes.timeout ?? 0,
    canaryReads: events.filter((event) => event.type === "fs.read").length,
    canarySends: events.filter((event) => event.type === "net.write" && (event.canaryIds?.length ?? 0) > 0).length,
    egressHosts: egress.size,
    findings: artefact.findings.length,
    checks: [...new Set(artefact.findings.map((finding) => finding.checkId))].sort(),
    isolation: record.isolation?.network ?? "unknown",
  });
}

const byProfile = (profile) => rows.filter((row) => row.profile === profile);
const started = (list) => list.filter((row) => row.started);

const summary = {
  generatedAt: new Date().toISOString(),
  note: "Anonymised. Ids map to packages in the private results directory.",
  total: rows.length,
  neutral: {
    runs: byProfile("neutral").length,
    started: started(byProfile("neutral")).length,
    withCanaryRead: byProfile("neutral").filter((row) => row.canaryReads > 0).length,
    withCanarySend: byProfile("neutral").filter((row) => row.canarySends > 0).length,
    withEgress: byProfile("neutral").filter((row) => row.egressHosts > 0).length,
    tools: byProfile("neutral").reduce((sum, row) => sum + row.tools, 0),
  },
  targeted: {
    runs: byProfile("targeted").length,
    started: started(byProfile("targeted")).length,
    withCanaryRead: byProfile("targeted").filter((row) => row.canaryReads > 0).length,
    withCanarySend: byProfile("targeted").filter((row) => row.canarySends > 0).length,
    withEgress: byProfile("targeted").filter((row) => row.egressHosts > 0).length,
    tools: byProfile("targeted").reduce((sum, row) => sum + row.tools, 0),
  },
  rows,
};

writeFileSync(join(outRoot, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`, "utf8");

const header = "id  profile   started  tools  ok  err  t/o  canaryRead  canarySend  egress  findings";
const lines = rows.map(
  (row) =>
    `${row.id.padEnd(3)} ${row.profile.padEnd(9)} ${String(row.started).padEnd(7)} ` +
    `${String(row.tools).padStart(5)} ${String(row.callsOk).padStart(3)} ${String(row.callsError).padStart(4)} ` +
    `${String(row.callsTimeout).padStart(4)} ${String(row.canaryReads).padStart(11)} ${String(row.canarySends).padStart(11)} ` +
    `${String(row.egressHosts).padStart(7)} ${String(row.findings).padStart(9)}`,
);

console.log(header);
console.log("-".repeat(header.length));
console.log(lines.join("\n"));
console.log("");
console.log(
  `neutral : ${summary.neutral.started}/${summary.neutral.runs} started · ` +
    `${summary.neutral.withCanaryRead} read a canary · ${summary.neutral.withCanarySend} sent one · ` +
    `${summary.neutral.withEgress} attempted egress`,
);
console.log(
  `targeted: ${summary.targeted.started}/${summary.targeted.runs} started · ` +
    `${summary.targeted.withCanaryRead} read a canary · ${summary.targeted.withCanarySend} sent one · ` +
    `${summary.targeted.withEgress} attempted egress`,
);
console.log(`\nwritten: ${join(outRoot, "summary.json")}`);
