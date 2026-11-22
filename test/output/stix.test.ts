import { describe, expect, it } from "vitest";
import { buildSnapshot } from "../../src/analyze.ts";
import { toStixBundle } from "../../src/output/stix.ts";
import { makeProbe, tool } from "../fixtures/build.ts";

function bundleFor() {
  const probe = makeProbe({
    tools: [
      tool({ name: "delete_repo", annotations: { destructiveHint: true } }),
      tool({ name: "read_docs", annotations: null }),
    ],
  });
  const snapshot = buildSnapshot(probe);
  return { snapshot, bundle: toStixBundle(snapshot) };
}

describe("STIX 2.1 export", () => {
  it("produces a bundle with a TLP:CLEAR marking", () => {
    const { bundle } = bundleFor();
    expect(bundle.type).toBe("bundle");
    expect(String(bundle.id)).toMatch(/^bundle--[0-9a-f-]{36}$/);
    const objects = bundle.objects as Array<Record<string, unknown>>;
    const marking = objects.find((o) => o.type === "marking-definition");
    expect(marking?.id).toBe("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9");
    expect(marking?.definition).toEqual({ tlp: "clear" });
  });

  it("maps findings to vulnerability, relationship and note objects", () => {
    const { bundle, snapshot } = bundleFor();
    const objects = bundle.objects as Array<Record<string, unknown>>;
    const vulnerabilities = objects.filter((o) => o.type === "vulnerability");
    const relationships = objects.filter((o) => o.type === "relationship");
    const notes = objects.filter((o) => o.type === "note");

    expect(vulnerabilities).toHaveLength(snapshot.findings.length);
    expect(relationships).toHaveLength(snapshot.findings.length);
    expect(notes).toHaveLength(snapshot.findings.length);
    expect(objects.some((o) => o.type === "infrastructure")).toBe(true);
    expect(objects.some((o) => o.type === "identity")).toBe(true);
  });

  it("carries evidence grading in an extension, not in a standard field", () => {
    const { bundle } = bundleFor();
    const objects = bundle.objects as Array<Record<string, unknown>>;
    for (const vulnerability of objects.filter((o) => o.type === "vulnerability")) {
      expect(vulnerability).not.toHaveProperty("confidence");
      expect(vulnerability).toHaveProperty("x_mcp_observatory");
      expect(vulnerability.spec_version).toBe("2.1");
    }
  });

  it("is deterministic for identical input", () => {
    const first = JSON.stringify(bundleFor().bundle);
    const second = JSON.stringify(bundleFor().bundle);
    expect(first).toBe(second);
  });
});
