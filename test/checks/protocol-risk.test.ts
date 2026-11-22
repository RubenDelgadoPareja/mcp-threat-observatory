import { describe, expect, it } from "vitest";
import { analyze } from "../../src/analyze.ts";
import { makeProbe, tool } from "../fixtures/build.ts";

describe("PROTO-001 discovery semantics", () => {
  it("fires when resources/list is unimplemented", () => {
    const probe = makeProbe({
      tools: [tool({ name: "echo" })],
      resources: { ok: false, count: null, errorCode: -32601 },
    });
    const finding = analyze(probe).findings.find((f) => f.checkId === "PROTO-001");
    expect(finding?.severity).toBe("low");
    expect(finding?.observation).toContain("resources/list");
  });

  it("does not fire when empty arrays are returned", () => {
    const probe = makeProbe({
      tools: [tool({ name: "echo" })],
      resources: { ok: true, count: 0, errorCode: null },
      prompts: { ok: true, count: 0, errorCode: null },
    });
    expect(analyze(probe).findings.some((f) => f.checkId === "PROTO-001")).toBe(false);
  });
});

describe("RISK-001 capability composition", () => {
  it("fires when reader, ingress and egress coexist", () => {
    const probe = makeProbe({
      tools: [
        tool({
          name: "read_customer_invoices",
          description: "Read invoices and customer records",
          inputSchema: {
            type: "object",
            properties: { id: { type: "string", pattern: "^inv_[0-9]+$" } },
            additionalProperties: false,
          },
        }),
        tool({
          name: "fetch_webpage",
          description: "Fetch a webpage and return its text",
          inputSchema: { type: "object", properties: { url: { type: "string" } } },
        }),
        tool({
          name: "send_email",
          description: "Send an email to a recipient",
          inputSchema: {
            type: "object",
            properties: { to: { type: "string", format: "email" } },
            additionalProperties: false,
          },
        }),
      ],
    });
    const finding = analyze(probe).findings.find((f) => f.checkId === "RISK-001");
    expect(finding?.assertion).toBe("inferred");
    expect(finding?.confidence).toBe("low");
    expect(finding?.limitations.join(" ")).toContain("not a vulnerability");
  });

  it("does not fire on a read-only catalog", () => {
    const probe = makeProbe({
      tools: [tool({ name: "list_docs", description: "List documents" })],
    });
    expect(analyze(probe).findings.some((f) => f.checkId === "RISK-001")).toBe(false);
  });
});

describe("finding identity", () => {
  it("is deterministic across runs", () => {
    const probe = makeProbe({ tools: [tool({ name: "list_docs" })] });
    const a = analyze(probe).findings.map((f) => f.fingerprint);
    const b = analyze(probe).findings.map((f) => f.fingerprint);
    expect(a).toEqual(b);
    expect(new Set(a).size).toBe(a.length);
  });

  it("orders findings by severity", () => {
    const probe = makeProbe({
      tools: [
        tool({ name: "delete_all", annotations: { destructiveHint: true } }),
        tool({ name: "read_docs" }),
      ],
    });
    const findings = analyze(probe).findings;
    const order = ["critical", "high", "medium", "low", "info"];
    const ranks = findings.map((f) => order.indexOf(f.severity));
    expect(ranks).toEqual([...ranks].sort((x, y) => x - y));
  });
});
