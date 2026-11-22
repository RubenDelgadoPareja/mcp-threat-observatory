import { readFile } from "node:fs/promises";
import { Command } from "commander";
import { buildSnapshot } from "./analyze.ts";
import { ALL_CHECKS } from "./checks/index.ts";
import { probeServer } from "./collect/probe.ts";
import { snapshotFingerprint, parseSnapshot, renderJson } from "./output/json.ts";
import { renderMarkdown } from "./output/markdown.ts";
import { writeSnapshot } from "./output/snapshot.ts";
import { toStixBundle } from "./output/stix.ts";
import { CONSENT_NOTICE, assertScannableTarget, isAuthorized, UnsafeTargetError } from "./safety.ts";
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

await program.parseAsync(process.argv);
