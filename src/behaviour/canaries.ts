import { randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Canary } from "./types.ts";

export interface SandboxEnvironment {
  root: string;
  home: string;
  workdir: string;
  logPath: string;
  env: NodeJS.ProcessEnv;
  canaries: Canary[];
}

export interface SandboxOptions {
  /** Overrides hook discovery. Mostly useful in tests. */
  hookPath?: string;
  pythonHookPath?: string;
  baseDir?: string;
}

function newCanary(): string {
  return `CANARY-${randomBytes(8).toString("hex")}`;
}

function findRuntimeFile(relative: string, explicit?: string): string {
  if (explicit) return explicit;
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 5; depth += 1) {
    const candidate = join(dir, "runtime", relative);
    if (existsSync(candidate)) return candidate;
    dir = dirname(dir);
  }
  throw new Error(`runtime/${relative} not found; the package is incomplete`);
}

/**
 * Finds runtime/node-hook.cjs from either src/ or dist/, without relying on a
 * bundler-specific relative depth.
 */
export function findHookPath(explicit?: string): string {
  return findRuntimeFile("node-hook.cjs", explicit);
}

export function findPythonHookPath(explicit?: string): string {
  return findRuntimeFile(join("python", "sitecustomize.py"), explicit);
}

/**
 * Builds a disposable environment for one run.
 *
 * Two things happen here that matter more than they look:
 *   - the child gets a temporary HOME, so a server that reads ~/.ssh reads a
 *     canary and never the operator's real key;
 *   - the environment is rebuilt from scratch instead of inherited, so no real
 *     token leaks into a process we are about to let loose.
 */
export function createSandboxEnvironment(options: SandboxOptions = {}): SandboxEnvironment {
  const root = mkdtempSync(join(options.baseDir ?? tmpdir(), "mcpobs-behaviour-"));
  const home = join(root, "home");
  const workdir = join(root, "work");
  const tmp = join(root, "tmp");
  for (const dir of [home, workdir, tmp, join(home, ".ssh"), join(home, ".aws")]) {
    mkdirSync(dir, { recursive: true });
  }

  const canaries: Canary[] = [];

  const files: Array<{ path: string; kind: Canary["kind"] }> = [
    { path: join(home, ".ssh", "id_ed25519"), kind: "file" },
    { path: join(home, ".aws", "credentials"), kind: "file" },
    { path: join(home, ".npmrc"), kind: "file" },
    { path: join(workdir, ".env"), kind: "file" },
  ];

  const contents: Record<string, string> = {
    ".ssh/id_ed25519": `-----BEGIN OPENSSH PRIVATE KEY-----\n{canary}\n-----END OPENSSH PRIVATE KEY-----\n`,
    ".aws/credentials": `[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = {canary}\n`,
    ".npmrc": `//registry.npmjs.org/:_authToken={canary}\n`,
    ".env": `API_TOKEN={canary}\nDATABASE_URL=postgres://canary@localhost/db\n`,
  };

  for (const file of files) {
    const canary = newCanary();
    canaries.push({ id: canary, kind: "file", locator: file.path });
    const relative = file.path.startsWith(join(home, ""))
      ? file.path.slice(home.length + 1).replaceAll("\\", "/")
      : ".env";
    const template = contents[relative] ?? `{canary}\n`;
    writeFileSync(file.path, template.replace("{canary}", canary), "utf8");
  }

  const envCanaries: Array<{ name: string; locator: string }> = [
    { name: "AWS_SECRET_ACCESS_KEY", locator: "AWS_SECRET_ACCESS_KEY" },
    { name: "GITHUB_TOKEN", locator: "GITHUB_TOKEN" },
    { name: "NPM_TOKEN", locator: "NPM_TOKEN" },
  ];
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH ?? "",
    HOME: home,
    TMPDIR: tmp,
    LANG: "C.UTF-8",
  };
  for (const entry of envCanaries) {
    const canary = newCanary();
    canaries.push({ id: canary, kind: "env", locator: entry.locator });
    env[entry.name] = canary;
  }

  const hookSource = findHookPath(options.hookPath);
  const hookTarget = join(root, "node-hook.cjs");
  copyFileSync(hookSource, hookTarget);
  env.NODE_OPTIONS = `--require=${hookTarget}`;

  // Both hooks are installed unconditionally. Each runtime loads the one it
  // understands and ignores the other, so no language detection is needed.
  const pythonSource = findPythonHookPath(options.pythonHookPath);
  const pythonDir = join(root, "python");
  mkdirSync(pythonDir, { recursive: true });
  copyFileSync(pythonSource, join(pythonDir, "sitecustomize.py"));
  env.PYTHONPATH = pythonDir;
  env.PYTHONDONTWRITEBYTECODE = "1";

  return {
    root,
    home,
    workdir,
    logPath: join(root, "behaviour.jsonl"),
    env,
    canaries,
  };
}

export function disposeSandboxEnvironment(environment: SandboxEnvironment): void {
  try {
    rmSync(environment.root, { recursive: true, force: true });
  } catch {
    /* a leftover temp directory must never fail a run */
  }
}
