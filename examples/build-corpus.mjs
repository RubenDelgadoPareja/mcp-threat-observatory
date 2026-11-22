#!/usr/bin/env node
/**
 * Builds the synthetic corpus used by the Python analysis layer and notebook.
 *
 * Every snapshot is produced by collecting against examples/demo-server.mjs
 * with a different posture. No third-party server is contacted.
 *
 *   npm run build && node examples/build-corpus.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(root, "examples", "corpus");
const tmpDir = join(outDir, ".tmp");

const PROFILES = [
  ["open-readonly", 8788],
  ["open-destructive", 8789],
  ["protected-ok", 8790],
  ["protected-no-prm", 8791],
  ["forbidden", 8792],
  ["poisoned", 8793],
  ["no-discovery", 8794],
  ["mixed", 8795],
  ["sparse", 8796],
];

function waitForLine(child, needle, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout waiting for ${needle}`)), timeoutMs);
    child.stdout.on("data", (chunk) => {
      if (chunk.toString().includes(needle)) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.on("error", reject);
  });
}

async function main() {
  await mkdir(outDir, { recursive: true });
  await rm(tmpDir, { recursive: true, force: true });
  await mkdir(tmpDir, { recursive: true });

  for (const [profile, port] of PROFILES) {
    const child = spawn(process.execPath, [join(root, "examples", "demo-server.mjs")], {
      env: { ...process.env, PROFILE: profile, PORT: String(port) },
      stdio: ["ignore", "pipe", "inherit"],
    });

    try {
      await waitForLine(child, "demo MCP endpoint");
      const result = spawnSync(
        process.execPath,
        [
          join(root, "dist", "cli.js"),
          "scan",
          `http://127.0.0.1:${port}/mcp`,
          "--authorized",
          "--quiet",
          "--out",
          join(tmpDir, profile),
        ],
        { encoding: "utf8" },
      );
      if (result.status !== 0) throw new Error(result.stderr || `scan failed for ${profile}`);

      const { readdir, readFile } = await import("node:fs/promises");
      const profileDir = join(tmpDir, profile);
      const day = (await readdir(profileDir)).find((entry) => /^\d{4}-\d{2}-\d{2}$/.test(entry));
      const files = await readdir(join(profileDir, day));
      const snapshot = JSON.parse(await readFile(join(profileDir, day, files[0]), "utf8"));
      await writeFile(join(outDir, `${profile}.json`), `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
      console.log(`${profile.padEnd(20)} ${snapshot.findings.length} finding(s)`);
    } finally {
      child.kill("SIGTERM");
    }
  }

  await rm(tmpDir, { recursive: true, force: true });
  console.log(`\ncorpus written to ${outDir}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
