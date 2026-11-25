import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSnapshot } from "./analyze.ts";
import { probeServer } from "./collect/probe.ts";
import { stripUnsafe } from "./lib/sanitize.ts";
import { renderMarkdown } from "./output/markdown.ts";
import type { Snapshot } from "./model.ts";

const START_TIMEOUT_MS = 8_000;

function findFixture(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 5; depth += 1) {
    const candidate = join(dir, "examples", "demo-server.mjs");
    if (existsSync(candidate)) return candidate;
    dir = dirname(dir);
  }
  throw new Error("examples/demo-server.mjs not found; the package is incomplete");
}

/**
 * Starts the bundled synthetic server on a free port and returns its endpoint.
 * The port is read from the server's own output, so there is no race and no
 * fixed port to collide with.
 */
async function startFixture(): Promise<{ url: string; stop: () => void }> {
  const fixture = findFixture();
  const child = spawn(process.execPath, [fixture], {
    env: { ...process.env, PORT: "0", PROFILE: "mixed" },
    stdio: ["ignore", "pipe", "pipe"],
  });

  const stop = () => {
    try {
      child.kill("SIGTERM");
    } catch {
      /* already gone */
    }
  };

  const url = await new Promise<string>((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => {
      stop();
      reject(new Error("the demo server did not start in time"));
    }, START_TIMEOUT_MS);

    child.stdout?.on("data", (chunk: Buffer) => {
      output += chunk.toString();
      const match = /http:\/\/127\.0\.0\.1:\d+\/mcp/.exec(output);
      if (match) {
        clearTimeout(timer);
        resolve(match[0]);
      }
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`the demo server exited early (code ${code})`));
    });
  });

  return { url, stop };
}

export interface DemoResult {
  snapshot: Snapshot;
  markdown: string;
}

/**
 * A first run that needs no target, no flags and no network: the repository's
 * own synthetic server, observed with the ordinary passive collector.
 */
export async function runDemo(): Promise<DemoResult> {
  const fixture = await startFixture();
  try {
    const probe = await probeServer(fixture.url, { rateLimitRps: 10, timeoutMs: 5_000 });
    const snapshot = buildSnapshot(probe);
    return { snapshot, markdown: stripUnsafe(renderMarkdown(snapshot)) };
  } finally {
    fixture.stop();
  }
}
