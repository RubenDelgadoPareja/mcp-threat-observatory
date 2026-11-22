import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { analyseBehaviour } from "../../src/behaviour/analyser.ts";
import { runBehaviour } from "../../src/behaviour/runner.ts";

const repo = join(fileURLToPath(new URL(".", import.meta.url)), "../..");
const fixture = (name: string) => join(repo, "examples", "behaviour", name);

function hasNetworkNamespace(): boolean {
  try {
    execFileSync("unshare", ["-rn", "true"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const unisolatedFallback = !hasNetworkNamespace();

describe("behaviour acceptance", () => {
  it(
    "records credential exfiltration by a server that looks useful",
    async () => {
      const record = await runBehaviour({
        command: [process.execPath, fixture("exfil-server.mjs")],
        timeoutMs: 10_000,
        toolTimeoutMs: 4_000,
        allowUnisolated: unisolatedFallback,
      });

      expect(record.tools.map((tool) => tool.name)).toContain("get_notes");

      const findings = analyseBehaviour(record);
      const exfiltration = findings.find((finding) => finding.checkId === "BEHAV-001");

      expect(exfiltration).toBeDefined();
      expect(exfiltration?.severity).toBe("high");
      expect(exfiltration?.confidence).toBe("high");
      expect(exfiltration?.assertion).toBe("observed");
      expect(exfiltration?.observation).toContain("smtp.collect.example.test");
      expect(exfiltration?.limitations.join(" ")).toMatch(/not proof of intent/i);
    },
    30_000,
  );

  it(
    "does not accuse a server that only echoes",
    async () => {
      const record = await runBehaviour({
        command: [process.execPath, fixture("clean-server.mjs")],
        timeoutMs: 10_000,
        toolTimeoutMs: 4_000,
        allowUnisolated: unisolatedFallback,
      });

      expect(record.tools.map((tool) => tool.name)).toContain("echo");

      const findings = analyseBehaviour(record);
      expect(findings.filter((finding) => finding.checkId.startsWith("BEHAV-"))).toEqual([]);
    },
    30_000,
  );

  it(
    "labels the isolation mechanism it actually used",
    async () => {
      const record = await runBehaviour({
        command: [process.execPath, fixture("clean-server.mjs")],
        timeoutMs: 10_000,
        toolTimeoutMs: 4_000,
        allowUnisolated: unisolatedFallback,
      });

      if (unisolatedFallback) {
        expect(record.isolation.network).toBe("open");
        expect(record.limitations.join(" ")).toMatch(/not isolated/i);
      } else {
        expect(record.isolation.network).toBe("isolated");
        expect(record.isolation.mechanism).toBe("unshare-rn");
      }
    },
    30_000,
  );
});
