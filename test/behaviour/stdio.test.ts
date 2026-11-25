import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import type { ChildProcess } from "node:child_process";
import { describe, expect, it } from "vitest";
import { MAX_LINE_BYTES, StdioSession } from "../../src/behaviour/stdio.ts";

function fakeChild(): { child: ChildProcess; stdout: PassThrough } {
  const stdout = new PassThrough();
  const stdin = new PassThrough();
  const emitter = new EventEmitter() as unknown as Record<string, unknown>;
  emitter.stdout = stdout;
  emitter.stdin = stdin;
  emitter.kill = () => true;
  return { child: emitter as unknown as ChildProcess, stdout };
}

describe("StdioSession framing", () => {
  it("parses newline-delimited JSON-RPC responses", async () => {
    const { child, stdout } = fakeChild();
    const session = new StdioSession(child, 1_000);
    const pending = session.request("initialize", {});
    stdout.write('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n');
    await expect(pending).resolves.toEqual({ ok: true });
  });

  it("rejects instead of buffering an unbounded line", async () => {
    const { child, stdout } = fakeChild();
    const session = new StdioSession(child, 1_000);
    const pending = session.request("initialize", {});
    stdout.write("x".repeat(MAX_LINE_BYTES + 1024));
    await expect(pending).rejects.toThrow(/line limit/);
  });

  it("handles a response split across chunks", async () => {
    const { child, stdout } = fakeChild();
    const session = new StdioSession(child, 1_000);
    const pending = session.request("initialize", {});
    stdout.write('{"jsonrpc":"2.0","id":1,');
    stdout.write('"result":{"ok":true}}\n');
    await expect(pending).resolves.toEqual({ ok: true });
  });
});
