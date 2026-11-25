import { describe, expect, it } from "vitest";
import { runDemo } from "../src/demo.ts";

describe("demo", () => {
  it("observes the bundled synthetic server", async () => {
    const { snapshot, markdown } = await runDemo();
    expect(snapshot.probe.target).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/mcp$/);
    expect(snapshot.findings.some((finding) => finding.checkId === "AUTH-001")).toBe(true);
    expect(markdown).toContain("AUTH-001");
  }, 20_000);
});
