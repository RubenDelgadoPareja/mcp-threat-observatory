export { VERSION } from "./version.ts";

export { probeServer, defaultProbeConfig, type ProbeConfig } from "./collect/probe.ts";
export { Pacer, send, parseJsonRpcBody, parseWwwAuthenticate } from "./collect/http.ts";

export { analyze, buildSnapshot, summarize, type AnalysisResult } from "./analyze.ts";
export { ALL_CHECKS, getCheck, severityRank, type Check } from "./checks/index.ts";
export { classifyCapabilities, type CapabilityProfile } from "./checks/capabilities.ts";

export { renderMarkdown } from "./output/markdown.ts";
export { renderJson, parseSnapshot, snapshotFingerprint } from "./output/json.ts";
export { toStixBundle } from "./output/stix.ts";
export { writeSnapshot, type WrittenSnapshot } from "./output/snapshot.ts";

export { assertScannableTarget, isAuthorized, UnsafeTargetError, CONSENT_NOTICE } from "./safety.ts";

export {
  SCHEMA_VERSION,
  COLLECTOR_NAME,
  SEVERITY_ORDER,
  emptySummary,
  type AssertionKind,
  type CheckResult,
  type Confidence,
  type EvidenceRef,
  type Finding,
  type HttpProbe,
  type ProbeResult,
  type Severity,
  type Snapshot,
  type Summary,
  type ToolDescriptor,
} from "./model.ts";
