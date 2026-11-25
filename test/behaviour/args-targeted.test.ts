import { describe, expect, it } from "vitest";
import { generateArguments } from "../../src/behaviour/args.ts";

const canary = {
  profile: "targeted" as const,
  canaryPaths: ["/tmp/mcpobs/home/.ssh/id_ed25519"],
  canaryUrl: "https://canary.example.test/probe",
};

describe("targeted argument profile", () => {
  it("substitutes a canary path for a path parameter", () => {
    const { arguments: args, notes } = generateArguments(
      {
        type: "object",
        properties: { path: { type: "string" } },
        required: ["path"],
      },
      1,
      canary,
    );
    expect(args.path).toBe("/tmp/mcpobs/home/.ssh/id_ed25519");
    expect(notes.join(" ")).toContain("canary path");
  });

  it("substitutes the canary URL for a uri-format parameter", () => {
    const { arguments: args } = generateArguments(
      {
        type: "object",
        properties: { resource: { type: "string", format: "uri" } },
        required: ["resource"],
      },
      1,
      canary,
    );
    expect(args.resource).toBe("https://canary.example.test/probe");
  });

  it("recognises url-shaped parameter names", () => {
    const { arguments: args } = generateArguments(
      {
        type: "object",
        properties: { webhook_url: { type: "string" }, endpoint: { type: "string" } },
        required: ["webhook_url", "endpoint"],
      },
      1,
      canary,
    );
    expect(args.webhook_url).toBe("https://canary.example.test/probe");
    expect(args.endpoint).toBe("https://canary.example.test/probe");
  });

  it("includes optional path parameters, because that is where confinement is tested", () => {
    const { arguments: args, notes } = generateArguments(
      {
        type: "object",
        properties: {
          query: { type: "string", maxLength: 40 },
          file_path: { type: "string" },
          comment: { type: "string" },
        },
        required: ["query"],
      },
      1,
      canary,
    );
    expect(args.query).toBe("mcpobs-test");
    expect(args.file_path).toBe("/tmp/mcpobs/home/.ssh/id_ed25519");
    expect(notes.join(" ")).toContain("omitted optional comment");
    expect(notes.join(" ")).not.toContain("omitted optional file_path");
  });

  it("does not touch parameters that are neither paths nor URLs", () => {
    const { arguments: args } = generateArguments(
      {
        type: "object",
        properties: { message: { type: "string" } },
        required: ["message"],
      },
      1,
      canary,
    );
    expect(args.message).toBe("mcpobs-test");
  });
});

describe("neutral profile", () => {
  it("ignores the canary context", () => {
    const { arguments: args } = generateArguments(
      {
        type: "object",
        properties: { path: { type: "string" }, url: { type: "string" } },
        required: ["path", "url"],
      },
      1,
      { ...canary, profile: "neutral" },
    );
    expect(args.path).toBe("mcpobs-test");
    expect(args.url).toBe("mcpobs-test");
  });
});
