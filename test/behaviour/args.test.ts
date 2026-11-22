import { describe, expect, it } from "vitest";
import { generateArguments } from "../../src/behaviour/args.ts";

describe("generateArguments", () => {
  it("fills required properties and omits optional ones", () => {
    const { arguments: args, notes } = generateArguments({
      type: "object",
      properties: {
        text: { type: "string" },
        limit: { type: "integer" },
      },
      required: ["text"],
    });
    expect(args).toEqual({ text: "mcpobs-test" });
    expect(notes.join(" ")).toContain("omitted optional limit");
  });

  it("returns an empty object when nothing is required", () => {
    const { arguments: args } = generateArguments({
      type: "object",
      properties: { anything: { type: "string" } },
      required: [],
    });
    expect(args).toEqual({});
  });

  it("chooses enum values deterministically from the seed", () => {
    const schema = { type: "object", properties: { mode: { type: "string", enum: ["a", "b", "c"] } }, required: ["mode"] };
    expect(generateArguments(schema, 1).arguments.mode).toBe("a");
    expect(generateArguments(schema, 2).arguments.mode).toBe("b");
    expect(generateArguments(schema, 4).arguments.mode).toBe("a");
  });

  it("uses the schema minimum for integers and never goes negative", () => {
    expect(
      generateArguments({
        type: "object",
        properties: { n: { type: "integer", minimum: 5, maximum: 10 } },
        required: ["n"],
      }).arguments.n,
    ).toBe(5);

    expect(
      generateArguments({
        type: "object",
        properties: { n: { type: "integer" } },
        required: ["n"],
      }).arguments.n,
    ).toBe(1);
  });

  it("never opts into a boolean behaviour", () => {
    expect(
      generateArguments({
        type: "object",
        properties: { destructive: { type: "boolean" } },
        required: ["destructive"],
      }).arguments.destructive,
    ).toBe(false);
  });

  it("respects string formats and maximum lengths", () => {
    const { arguments: args } = generateArguments({
      type: "object",
      properties: {
        to: { type: "string", format: "email" },
        code: { type: "string", maxLength: 3 },
      },
      required: ["to", "code"],
    });
    expect(args.to).toBe("mcpobs@example.test");
    expect(String(args.code)).toHaveLength(3);
  });

  it("records a note when a pattern cannot be synthesised", () => {
    const { notes } = generateArguments({
      type: "object",
      properties: { id: { type: "string", pattern: "^ws_[a-z0-9]{8}$" } },
      required: ["id"],
    });
    expect(notes.join(" ")).toContain("pattern");
  });

  it("is deterministic for the same schema and seed", () => {
    const schema = {
      type: "object",
      properties: {
        mode: { type: "string", enum: ["x", "y"] },
        n: { type: "integer", minimum: 1 },
        nested: { type: "object", properties: { a: { type: "string" } }, required: ["a"] },
      },
      required: ["mode", "n", "nested"],
    };
    expect(generateArguments(schema, 2)).toEqual(generateArguments(schema, 2));
  });

  it("wraps a non-object schema instead of guessing", () => {
    const { arguments: args, notes } = generateArguments({ type: "string" });
    expect(args).toEqual({ value: "mcpobs-test" });
    expect(notes.join(" ")).toContain("not an object");
  });

  it("handles a missing schema", () => {
    const { arguments: args, notes } = generateArguments(undefined);
    expect(args).toEqual({});
    expect(notes.join(" ")).toContain("no input schema");
  });
});
