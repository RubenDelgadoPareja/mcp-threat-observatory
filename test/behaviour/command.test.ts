import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { absolutizeCommand } from "../../src/behaviour/command.ts";

const repo = join(import.meta.dirname, "../..");

describe("absolutizeCommand", () => {
  it("leaves bare command names alone", () => {
    expect(absolutizeCommand(["node", "-e", "x"], repo)).toEqual(["node", "-e", "x"]);
  });

  it("resolves an existing relative script path", () => {
    const [bin, script] = absolutizeCommand(["node", "examples/behaviour/clean-server.mjs"], repo);
    expect(bin).toBe("node");
    expect(script).toBe(join(repo, "examples/behaviour/clean-server.mjs"));
  });

  it("leaves a path that does not exist untouched, so the error is honest", () => {
    const [, missing] = absolutizeCommand(["node", "examples/nope.mjs"], repo);
    expect(missing).toBe("examples/nope.mjs");
  });

  it("does not touch absolute paths, flags or URLs", () => {
    const input = ["/usr/bin/node", "--flag=examples/x.mjs", "https://example.test/x.js"];
    expect(absolutizeCommand(input, repo)).toEqual(input);
  });

  it("resolves a package script written without a slash", () => {
    const [, script] = absolutizeCommand(["node", "server.mjs"], repo);
    expect(script).toBe("server.mjs");
  });
});
