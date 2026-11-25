import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { generateArguments, type ArgumentContext, type ArgumentProfile } from "./args.ts";
import { absolutizeCommand } from "./command.ts";
import {
  createSandboxEnvironment,
  disposeSandboxEnvironment,
  type SandboxEnvironment,
} from "./canaries.ts";
import { StdioSession, TimeoutError } from "./stdio.ts";
import {
  BEHAVIOUR_SCHEMA_VERSION,
  isLoopback,
  type BehaviourEvent,
  type BehaviourRecord,
  type IsolationMechanism,
  type NetworkIsolation,
  type ToolInvocation,
} from "./types.ts";

export interface RunBehaviourOptions {
  command: string[];
  /** Wall-clock budget for the whole run. */
  timeoutMs?: number;
  /** Per tool call budget. */
  toolTimeoutMs?: number;
  /** Required to run without a network namespace. */
  allowUnisolated?: boolean;
  /** `targeted` substitutes canary paths and URLs for path/URL parameters. */
  profile?: ArgumentProfile;
  seed?: number;
  keepWorkspace?: boolean;
}

interface Isolation {
  mechanism: IsolationMechanism;
  network: NetworkIsolation;
  prefix: string[];
}

let unshareAvailable: boolean | undefined;

export function canIsolateNetwork(): boolean {
  if (unshareAvailable !== undefined) return unshareAvailable;
  try {
    execFileSync("unshare", ["-rn", "true"], { stdio: "ignore", timeout: 3_000 });
    unshareAvailable = true;
  } catch {
    unshareAvailable = false;
  }
  return unshareAvailable;
}

function resolveIsolation(allowUnisolated: boolean): Isolation {
  if (canIsolateNetwork()) {
    return { mechanism: "unshare-rn", network: "isolated", prefix: ["unshare", "-rn", "--"] };
  }
  if (!allowUnisolated) {
    throw new Error(
      "behaviour: network isolation is unavailable (`unshare -rn` failed). Refusing to execute code. " +
        "Pass --allow-unisolated only for code you wrote and understand.",
    );
  }
  return { mechanism: "none", network: "open", prefix: [] };
}

function readEvents(path: string): BehaviourEvent[] {
  if (!existsSync(path)) return [];
  const events: BehaviourEvent[] = [];
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line) as BehaviourEvent);
    } catch {
      /* a truncated final line is not a reason to lose the run */
    }
  }
  return events;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function terminate(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    child.stdin?.end();
  } catch {
    /* ignore */
  }
  const exited = await Promise.race([
    new Promise<boolean>((resolve) => child.once("exit", () => resolve(true))),
    sleep(1_500).then(() => false),
  ]);
  if (exited) return;
  try {
    if (process.platform !== "win32" && child.pid) process.kill(-child.pid, "SIGKILL");
    else child.kill("SIGKILL");
  } catch {
    /* the process may already be gone */
  }
}

async function withDeadline<T>(work: () => Promise<T>, ms: number, onTimeout: () => void): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      work(),
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => {
          onTimeout();
          reject(new TimeoutError(`run exceeded ${ms}ms`));
        }, ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Executes a stdio MCP server, invokes every tool with generated arguments, and
 * records what the process tried to do.
 *
 * Reads as a sequence of honest steps: isolate, scrub, spawn, drive, record,
 * label what the record cannot support.
 */
export async function runBehaviour(options: RunBehaviourOptions): Promise<BehaviourRecord> {
  if (!options.command || options.command.length === 0) {
    throw new Error("behaviour: no command provided");
  }

  const seed = options.seed ?? 1;
  const profile: ArgumentProfile = options.profile ?? "neutral";
  const timeoutMs = options.timeoutMs ?? 60_000;
  const toolTimeoutMs = options.toolTimeoutMs ?? 5_000;
  const isolation = resolveIsolation(options.allowUnisolated === true);
  const sandbox: SandboxEnvironment = createSandboxEnvironment();
  const collectedAt = new Date().toISOString();
  const command = absolutizeCommand(options.command);
  const argumentContext: ArgumentContext = {
    profile,
    canaryPaths: sandbox.canaries.filter((canary) => canary.kind === "file").map((canary) => canary.locator),
    canaryUrl: "https://canary.example.test/probe",
  };

  const limitations: string[] = [
    "The hook observes Node APIs only: native addons, worker threads with an independent loader, and spawned non-Node processes can bypass it.",
    "Only the stdio transport is driven; remote HTTP servers are not executed.",
    "Tool arguments are generated from the JSON schema; a tool that requires a specific value may not have exercised its real path.",
    "A canary is a synthetic credential. Its presence in a payload proves the value left the process; it is not proof of intent.",
  ];
  if (isolation.network === "open") {
    limitations.push(
      "Network isolation was NOT applied (--allow-unisolated): outbound connections could reach real destinations. This run is not isolated.",
    );
  }

  const argv = [...isolation.prefix, ...command];
  const [bin, ...args] = argv;
  if (!bin) throw new Error("behaviour: empty command");

  const child = spawn(bin, args, {
    cwd: sandbox.workdir,
    env: { ...sandbox.env, MCPOBS_BEHAVIOUR_LOG: sandbox.logPath },
    stdio: ["pipe", "pipe", "pipe"],
    detached: process.platform !== "win32",
  });

  let stderr = "";
  child.stderr?.on("data", (chunk: Buffer) => {
    if (stderr.length < 4_096) stderr += chunk.toString();
  });

  const tools: ToolInvocation[] = [];

  try {
    await withDeadline(
      async () => {
        const session = new StdioSession(child, toolTimeoutMs);
        await session.request(
          "initialize",
          {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "mcp-threat-observatory", version: "0.2.0" },
          },
          toolTimeoutMs,
        );
        session.notify("notifications/initialized");

        const listed = (await session.request("tools/list", {}, toolTimeoutMs)) as
          | { tools?: Array<Record<string, unknown>> }
          | undefined;
        const definitions = Array.isArray(listed?.tools) ? listed.tools : [];

        for (const definition of definitions) {
          const name = typeof definition.name === "string" ? definition.name : "(unnamed)";
          const generated = generateArguments(definition.inputSchema, seed, argumentContext);
          const startedAt = new Date().toISOString();
          const started = Date.now();
          let outcome: ToolInvocation["outcome"] = "result";
          let error: string | undefined;

          try {
            await session.request(
              "tools/call",
              { name, arguments: generated.arguments },
              toolTimeoutMs,
            );
          } catch (caught) {
            outcome = caught instanceof TimeoutError ? "timeout" : "error";
            error = caught instanceof Error ? caught.message : String(caught);
          }

          tools.push({
            name,
            arguments: generated.arguments,
            argumentsNotes: generated.notes,
            outcome,
            startedAt,
            endedAt: new Date().toISOString(),
            durationMs: Date.now() - started,
            ...(error ? { error } : {}),
          });
        }

        session.close();
      },
      timeoutMs,
      () => {
        try {
          if (child.pid) process.kill(-child.pid, "SIGKILL");
        } catch {
          /* ignore */
        }
      },
    );
  } catch (error) {
    limitations.push(
      `The run did not complete: ${error instanceof Error ? error.message : String(error)}. ` +
        "Any behaviour observed before the failure is still recorded.",
    );
  } finally {
    await terminate(child);
  }

  if (tools.length === 0 && stderr.trim()) {
    limitations.push(`The server produced no tools. First stderr bytes: ${stderr.trim().slice(0, 300)}`);
  }

  const events = readEvents(sandbox.logPath);
  const egressAttempts = events.filter(
    (event) =>
      (event.type === "net.connect" || event.type === "dns.lookup" || event.type === "net.write") &&
      !isLoopback(event.host),
  ).length;
  const canaryReads = events.filter((event) => event.type === "fs.read").length;
  const canarySends = events.filter(
    (event) => event.type === "net.write" && (event.canaryIds?.length ?? 0) > 0,
  ).length;

  const record: BehaviourRecord = {
    schemaVersion: BEHAVIOUR_SCHEMA_VERSION,
    kind: "behaviour",
    collectedAt,
    argumentProfile: profile,
    target: { command, cwd: sandbox.workdir },
    isolation: { mechanism: isolation.mechanism, network: isolation.network },
    environment: { home: sandbox.home, seed, canaries: sandbox.canaries },
    tools,
    events,
    summary: {
      events: events.length,
      toolCalls: tools.length,
      egressAttempts,
      canaryReads,
      canarySends,
    },
    limitations,
  };

  if (!options.keepWorkspace) disposeSandboxEnvironment(sandbox);
  return record;
}
