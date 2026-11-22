import { execFileSync, spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { analyseBehaviour } from "../../src/behaviour/analyser.ts";
import { runBehaviour } from "../../src/behaviour/runner.ts";

const repo = join(fileURLToPath(new URL(".", import.meta.url)), "../..");
const fixture = (name: string) => join(repo, "examples", "behaviour", name);

const hasPython = spawnSync("python3", ["--version"], { stdio: "ignore" }).status === 0;
const hasNamespace = (() => {
  try {
    execFileSync("unshare", ["-rn", "true"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

describe.skipIf(!hasPython)("python behavioural collection", () => {
  it(
    "records a credential tunnelled out over UDP",
    async () => {
      const record = await runBehaviour({
        command: ["python3", fixture("exfil-server.py")],
        timeoutMs: 12_000,
        toolTimeoutMs: 6_000,
        allowUnisolated: !hasNamespace,
      });

      expect(record.tools.map((tool) => tool.name)).toContain("get_notes");
      expect(record.events.length).toBeGreaterThan(0);

      const findings = analyseBehaviour(record);
      const exfiltration = findings.find((finding) => finding.checkId === "BEHAV-001");
      expect(exfiltration).toBeDefined();
      expect(exfiltration?.severity).toBe("high");
      expect(exfiltration?.assertion).toBe("observed");
      expect(exfiltration?.observation).toContain("collect.example.test:53");

      const credentialRead = findings.find((finding) => finding.checkId === "BEHAV-003");
      expect(credentialRead).toBeDefined();
      expect(credentialRead?.observation).toContain(".ssh/id_ed25519");
    },
    40_000,
  );

  it(
    "does not accuse a python server that only echoes",
    async () => {
      const record = await runBehaviour({
        command: ["python3", fixture("clean-server.py")],
        timeoutMs: 12_000,
        toolTimeoutMs: 6_000,
        allowUnisolated: !hasNamespace,
      });

      expect(record.tools.map((tool) => tool.name)).toContain("echo");
      expect(analyseBehaviour(record).filter((finding) => finding.checkId.startsWith("BEHAV-"))).toEqual([]);
    },
    40_000,
  );
});
