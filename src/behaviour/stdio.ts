import type { ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";

export class TimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TimeoutError";
  }
}

export class ServerExitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ServerExitError";
  }
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

interface JsonRpcMessage {
  id?: number | string | null;
  result?: unknown;
  error?: { code?: number; message?: string };
}

/**
 * Minimal MCP client over stdio: newline-delimited JSON-RPC 2.0.
 *
 * Deliberately small. The collector needs to drive a server, not to be a
 * general-purpose SDK, and a small client is easier to audit.
 */
export class StdioSession {
  private readonly pending = new Map<number, Pending>();
  private nextId = 1;
  private closed = false;

  constructor(
    private readonly child: ChildProcess,
    private readonly defaultTimeoutMs = 5_000,
  ) {
    if (!child.stdout) throw new Error("behaviour: server has no stdout");
    createInterface({ input: child.stdout }).on("line", (line) => this.onLine(line));
    child.on("exit", (code, signal) =>
      this.failAll(new ServerExitError(`server exited (${code ?? signal ?? "unknown"})`)),
    );
    child.on("error", (error) => this.failAll(error));
  }

  request(method: string, params: unknown, timeoutMs = this.defaultTimeoutMs): Promise<unknown> {
    if (this.closed) return Promise.reject(new ServerExitError("session is closed"));
    const id = this.nextId;
    this.nextId += 1;
    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new TimeoutError(`${method} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.write({ jsonrpc: "2.0", id, method, params });
    });
  }

  notify(method: string, params?: unknown): void {
    this.write(params === undefined ? { jsonrpc: "2.0", method } : { jsonrpc: "2.0", method, params });
  }

  close(): void {
    this.closed = true;
    try {
      this.child.stdin?.end();
    } catch {
      /* already closed */
    }
  }

  private write(message: Record<string, unknown>): void {
    const stdin = this.child.stdin;
    if (!stdin || stdin.destroyed) return;
    try {
      stdin.write(`${JSON.stringify(message)}\n`);
    } catch {
      /* a dead server is reported by the exit handler */
    }
  }

  private onLine(line: string): void {
    if (!line.trim()) return;
    let message: JsonRpcMessage;
    try {
      message = JSON.parse(line) as JsonRpcMessage;
    } catch {
      return;
    }
    if (typeof message.id !== "number") return;
    const pending = this.pending.get(message.id);
    if (!pending) return;
    this.pending.delete(message.id);
    clearTimeout(pending.timer);
    if (message.error) {
      pending.reject(
        new Error(`${message.error.code ?? "error"}: ${message.error.message ?? "unknown error"}`),
      );
    } else {
      pending.resolve(message.result);
    }
  }

  private failAll(error: Error): void {
    this.closed = true;
    for (const [id, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(error);
      this.pending.delete(id);
    }
  }
}
