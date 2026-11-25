#!/usr/bin/env node
/**
 * Consented-by-licence corpus runner.
 *
 * Installs a fixed set of open-source MCP servers into a private directory with
 * `--ignore-scripts` (no third-party code runs at install time), then executes
 * each one twice under `mcpobs behaviour`: once with neutral arguments and once
 * with credential-shaped paths and URLs.
 *
 * Nothing here contacts a third-party server: the MCP servers run locally, in a
 * network namespace with no route, against a temporary HOME full of canaries.
 *
 * Usage:
 *   node scripts/corpus-run.mjs --install          # install only
 *   node scripts/corpus-run.mjs S1 S2              # run selected ids
 *   node scripts/corpus-run.mjs                    # run everything
 *
 * Results land in $CORPUS_OUT (default: <tmp>/mcpobs-corpus) and are NOT meant
 * to be committed: the id-to-package mapping stays private.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outRoot = process.env.CORPUS_OUT ?? join(tmpdir(), "mcpobs-corpus");
const installRoot = join(outRoot, "packages");
const runsRoot = join(outRoot, "runs");
const resultsRoot = join(outRoot, "results");

// The corpus mapping is deliberately NOT in this repository: publishing the id
// to package mapping would de-anonymise the note derived from it.
const corpusFile = process.env.CORPUS_FILE ?? join(repo, "corpus.local.json");
if (!existsSync(corpusFile)) {
  console.error(
    `missing corpus file: ${corpusFile}\n` +
      "Create it locally (it is git-ignored) with entries like:\n" +
      '  [{ "id": "S1", "pkg": "@scope/server-name", "version": "1.2.3", "args": [] }]',
  );
  process.exit(2);
}
const CORPUS = JSON.parse(readFileSync(corpusFile, "utf8"));

const PROFILES = ["neutral", "targeted"];

function install(entry) {
  const dir = join(installRoot, entry.id);
  if (existsSync(join(dir, "node_modules", entry.pkg, "package.json"))) {
    console.log(`${entry.id}: already installed`);
    return true;
  }
  mkdirSync(dir, { recursive: true });
  console.log(`${entry.id}: installing ${entry.pkg}@${entry.version} (no install scripts)`);
  const result = spawnSync(
    "npm",
    [
      "install",
      "--prefix",
      dir,
      "--no-audit",
      "--no-fund",
      "--ignore-scripts",
      "--no-package-lock",
      `${entry.pkg}@${entry.version}`,
    ],
    { encoding: "utf8", timeout: 180_000 },
  );
  if (result.status !== 0) {
    console.error(`${entry.id}: install failed\n${(result.stderr ?? "").slice(0, 600)}`);
    return false;
  }
  return true;
}

function resolveEntry(entry) {
  const pkgJsonPath = join(installRoot, entry.id, "node_modules", entry.pkg, "package.json");
  const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
  const bin = pkg.bin;
  const relative = typeof bin === "string" ? bin : Object.values(bin ?? {})[0];
  if (!relative) return null;
  return resolve(dirname(pkgJsonPath), relative);
}

function runOnce(entry, profile, entryFile) {
  const outDir = join(runsRoot, `${entry.id}-${profile}`);
  const started = Date.now();
  const result = spawnSync(
    process.execPath,
    [
      join(repo, "dist", "cli.js"),
      "behaviour",
      "--authorized",
      "--profile",
      profile,
      "--out",
      outDir,
      "--json",
      "--",
      process.execPath,
      entryFile,
      ...entry.args,
    ],
    { encoding: "utf8", timeout: 150_000, killSignal: "SIGKILL", maxBuffer: 64 * 1024 * 1024 },
  );

  const record = { id: entry.id, profile, durationMs: Date.now() - started, ok: false };
  if (result.stdout && result.stdout.trim().startsWith("{")) {
    try {
      const artefact = JSON.parse(result.stdout);
      record.ok = true;
      record.tools = artefact.record?.tools?.length ?? 0;
      record.findings = artefact.findings?.length ?? 0;
      record.summary = artefact.summary ?? null;
      record.isolation = artefact.record?.isolation ?? null;
      writeFileSync(join(resultsRoot, `${entry.id}-${profile}.json`), JSON.stringify(artefact, null, 2));
    } catch (error) {
      record.error = `parse: ${error.message}`;
    }
  } else {
    record.error = (result.stderr ?? "").slice(0, 400) || `exit ${result.status}`;
  }
  return record;
}

function main() {
  const args = process.argv.slice(2);
  const installOnly = args.includes("--install");
  const selected = args.filter((arg) => !arg.startsWith("-"));
  const corpus = selected.length ? CORPUS.filter((entry) => selected.includes(entry.id)) : CORPUS;

  for (const dir of [installRoot, runsRoot, resultsRoot]) mkdirSync(dir, { recursive: true });

  const installed = new Map();
  for (const entry of corpus) installed.set(entry.id, install(entry));
  if (installOnly) {
    console.log(`installed into ${installRoot}`);
    return;
  }

  const runs = [];
  for (const entry of corpus) {
    if (!installed.get(entry.id)) {
      runs.push({ id: entry.id, profile: "n/a", ok: false, error: "install failed" });
      continue;
    }
    const entryFile = resolveEntry(entry);
    if (!entryFile) {
      runs.push({ id: entry.id, profile: "n/a", ok: false, error: "no bin entry" });
      continue;
    }
    for (const profile of PROFILES) {
      console.log(`${entry.id} [${profile}] …`);
      const record = runOnce(entry, profile, entryFile);
      console.log(
        `${entry.id} [${profile}] ${record.ok ? `tools=${record.tools} findings=${record.findings}` : `failed: ${record.error}`}`,
      );
      runs.push(record);
    }
  }

  writeFileSync(join(outRoot, "runs.json"), `${JSON.stringify(runs, null, 2)}\n`, "utf8");
  console.log(`\nresults in ${resultsRoot}`);
}

main();
