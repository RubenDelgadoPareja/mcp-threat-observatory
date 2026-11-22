import { readFile } from "node:fs/promises";
import { Command } from "commander";
import { buildSnapshot } from "./analyze.ts";
import { ALL_CHECKS } from "./checks/index.ts";
import { probeServer } from "./collect/probe.ts";
import { analyseBehaviour, BEHAVIOUR_RULES } from "./behaviour/analyser.ts";
import { buildArtefact, writeBehaviourArtefact } from "./behaviour/artefact.ts";
import { renderBehaviourMarkdown } from "./behaviour/report.ts";
import { runBehaviour } from "./behaviour/runner.ts";
import { diffSnapshots, renderDrift } from "./drift.ts";
import { snapshotFingerprint, parseSnapshot, renderJson } from "./output/json.ts";
import { renderMarkdown } from "./output/markdown.ts";
import { writeSnapshot } from "./output/snapshot.ts";
import { toStixBundle } from "./output/stix.ts";
import {
  BEHAVIOUR_NOTICE,
  CONSENT_NOTICE,
  assertScannableTarget,
  isAuthorized,
  UnsafeTargetError,
} from "./safety.ts";
import { VERSION } from "./version.ts";
import type { Snapshot } from "./model.ts";

const program = new Command();

program
  .name("mcpobs")
  .description(
    "Passive, evidence-graded observation of MCP server endpoints.\n" +
      "Collects what an ordinary client sees, then separates observation from inference.",
  )
  .version(VERSION, "-v, --version");

program
  .command("checks")
  .description("List the checks this collector runs")
  .action(() => {
    const rows = ALL_CHECKS.map((check) => ({
      id: check.id,
      title: check.title,
      owasp: check.owasp.length ? check.owasp.join(", ") : "—",
      facets: (check.taxonomy ?? []).join(", "),
    }));
    const width = Math.max(...rows.map((r) => r.id.length));
    console.log("");
    for (const row of rows) {
      console.log(`${row.id.padEnd(width)}  ${row.title}`);
      console.log(`${" ".repeat(width)}  OWASP: ${row.owasp} · ${row.facets}`);
    }
    console.log("");
    console.log(`${rows.length} checks. A check reports a signal for review, not a verdict.`);
    console.log("");
    console.log("Behavioural checks (mcpobs behaviour)");
    for (const rule of BEHAVIOUR_RULES) {
      console.log(`  ${rule.id.padEnd(width)}  ${rule.title}`);
      console.log(`  ${" ".repeat(width)}  OWASP: ${rule.owasp.length ? rule.owasp.join(", ") : "—"} · ${rule.taxonomy.join(", ")}`);
    }
    console.log("");
  });

program
  .command("scan")
  .argument("[target]", "MCP endpoint URL (https, or http on loopback)")
  .description("Collect one passive observation and render a report")
  .option("--authorized", "confirm you operate or are authorised to test the target")
  .option("--from <file>", "read targets from a file, one per line")
  .option("--out <dir>", "snapshot directory", "snapshots")
  .option("--rate <n>", "requests per second per host (default 1, max 10)", "1")
  .option("--timeout <ms>", "per-request timeout in milliseconds", "15000")
  .option("--json", "print the snapshot JSON instead of the markdown report")
  .option("--stix", "print a STIX 2.1 bundle instead of the markdown report")
  .option("--quiet", "write files but print only a summary line")
  .action(async (target: string | undefined, options: Record<string, string | boolean | undefined>) => {
    if (!isAuthorized(options.authorized === true)) {
      console.error(CONSENT_NOTICE);
      process.exit(2);
    }

    const targets: string[] = [];
    const from = typeof options.from === "string" ? options.from : undefined;
    if (from) {
      const text = await readFile(from, "utf8");
      for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("#")) targets.push(trimmed);
      }
    } else if (target) {
      targets.push(target);
    }

    if (targets.length === 0) {
      console.error("No target. Pass a URL or --from <file>.");
      process.exit(2);
    }

    const rate = Number(options.rate ?? 1);
    const timeoutMs = Number(options.timeout ?? 15000);
    const outDir = typeof options.out === "string" ? options.out : "snapshots";
    const quiet = options.quiet === true;

    let failed = 0;
    for (const raw of targets) {
      try {
        const url = assertScannableTarget(raw);
        const probe = await probeServer(url.toString(), {
          rateLimitRps: Number.isFinite(rate) ? rate : 1,
          timeoutMs: Number.isFinite(timeoutMs) ? timeoutMs : 15000,
        });
        const snapshot = buildSnapshot(probe);
        const written = await writeSnapshot(outDir, snapshot);

        if (!quiet) {
          if (options.stix === true) {
            console.log(JSON.stringify(toStixBundle(snapshot), null, 2));
          } else if (options.json === true) {
            console.log(renderJson(snapshot));
          } else {
            console.log(renderMarkdown(snapshot));
          }
        }
        console.error(
          `[${written.fingerprint.slice(0, 8)}] ${snapshot.probe.target} → ` +
            `${snapshot.summary.total} finding(s) · ${written.file}`,
        );
      } catch (error) {
        failed += 1;
        if (error instanceof UnsafeTargetError) {
          console.error(`refused: ${error.message}`);
        } else {
          console.error(`failed: ${raw}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }

    if (failed > 0) process.exitCode = 1;
  });

program
  .command("behaviour")
  .argument("<command...>", "command that starts a stdio MCP server")
  .description("Execute a server in isolation and record what it does")
  .option("--authorized", "confirm you wrote or are authorised to execute this code")
  .option("--allow-unisolated", "run without a network namespace (unsafe, own code only)")
  .option("--out <dir>", "artefact directory", "behaviour")
  .option("--timeout <ms>", "wall-clock budget for the whole run", "60000")
  .option("--tool-timeout <ms>", "budget per tool call", "5000")
  .option("--seed <n>", "deterministic argument seed", "1")
  .option("--json", "print the artefact JSON instead of the report")
  .option("--keep-workspace", "keep the temporary sandbox for inspection")
  .action(async (command: string[], options: Record<string, string | boolean | undefined>) => {
    if (!isAuthorized(options.authorized === true)) {
      console.error(BEHAVIOUR_NOTICE);
      process.exit(2);
    }
    if (!Array.isArray(command) || command.length === 0) {
      console.error("No command. Usage: mcpobs behaviour -- <command...>");
      process.exit(2);
    }

    const outDir = typeof options.out === "string" ? options.out : "behaviour";
    try {
      const record = await runBehaviour({
        command,
        timeoutMs: Number(options.timeout ?? 60_000),
        toolTimeoutMs: Number(options.toolTimeout ?? 5_000),
        allowUnisolated: options.allowUnisolated === true,
        seed: Number(options.seed ?? 1),
        keepWorkspace: options.keepWorkspace === true,
      });
      const findings = analyseBehaviour(record);
      const artefact = buildArtefact(record, findings);
      const written = await writeBehaviourArtefact(outDir, artefact);

      console.log(
        options.json === true ? JSON.stringify(artefact, null, 2) : renderBehaviourMarkdown(record, findings),
      );
      console.error(
        `[${written.fingerprint.slice(0, 8)}] ${record.target.command.join(" ")} → ` +
          `${findings.length} finding(s) · ${written.file}`,
      );
    } catch (error) {
      console.error(`behaviour failed: ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
    }
  });

program
  .command("report")
  .argument("<snapshot>", "path to a snapshot JSON file")
  .description("Re-render a stored snapshot without touching the network")
  .option("--format <format>", "md | json | stix", "md")
  .option("--out <file>", "write to a file instead of stdout")
  .action(async (file: string, options: Record<string, string | undefined>) => {
    const snapshot = parseSnapshot(await readFile(file, "utf8"));
    const format = options.format ?? "md";
    let output: string;
    if (format === "json") output = renderJson(snapshot);
    else if (format === "stix") output = `${JSON.stringify(toStixBundle(snapshot), null, 2)}\n`;
    else output = renderMarkdown(snapshot);

    if (options.out) {
      const { writeFile } = await import("node:fs/promises");
      await writeFile(options.out, output, "utf8");
      console.error(`wrote ${options.out}`);
    } else {
      console.log(output);
    }
  });

program
  .command("inspect")
  .argument("<snapshot>", "path to a snapshot JSON file")
  .description("Print the provenance and integrity details of a snapshot")
  .action(async (file: string) => {
    const snapshot: Snapshot = parseSnapshot(await readFile(file, "utf8"));
    console.log(
      JSON.stringify(
        {
          target: snapshot.probe.target,
          collectedAt: snapshot.probe.collectedAt,
          collector: snapshot.probe.collector,
          fingerprint: snapshotFingerprint(snapshot),
          exchanges: snapshot.probe.probes.length,
          reachable: snapshot.probe.reachable,
          limitations: snapshot.probe.limitations,
          summary: snapshot.summary,
        },
        null,
        2,
      ),
    );
  });

program
  .command("drift")
  .argument("<previous>", "earlier snapshot JSON")
  .argument("<current>", "later snapshot JSON")
  .description("Compare two snapshots of the same target")
  .option("--json", "print the report as JSON")
  .option("--fail-on-change", "exit 1 when anything changed (use as a CI gate)")
  .action(async (previousFile: string, currentFile: string, options: Record<string, boolean | undefined>) => {
    try {
      const previous = parseSnapshot(await readFile(previousFile, "utf8"));
      const current = parseSnapshot(await readFile(currentFile, "utf8"));

      if (previous.probe.target !== current.probe.target) {
        console.error(
          `drift: different targets (${previous.probe.target} vs ${current.probe.target}). ` +
            "Finding fingerprints are per-target, so a comparison would be meaningless.",
        );
        process.exit(2);
      }

      const report = diffSnapshots(previous, current, { previous: previousFile, current: currentFile });
      console.log(options.json === true ? JSON.stringify(report, null, 2) : renderDrift(report));

      if (options.failOnChange === true && report.changed) {
        process.exitCode = 1;
      }
    } catch (error) {
      console.error(`drift failed: ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 2;
    }
  });

await program.parseAsync(process.argv);
