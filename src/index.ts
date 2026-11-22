export { VERSION } from "./version.ts";

export { probeServer, defaultProbeConfig, type ProbeConfig } from "./collect/probe.ts";
export { Pacer, send, parseJsonRpcBody, parseWwwAuthenticate } from "./collect/http.ts";

export { analyze, buildSnapshot, summarize, type AnalysisResult } from "./analyze.ts";
export { ALL_CHECKS, getCheck, severityRank, type Check } from "./checks/index.ts";
export { classifyCapabilities, type CapabilityProfile } from "./checks/capabilities.ts";

export { renderMarkdown } from "./output/markdown.ts";export { renderJson, parseSnapshot, snapshotFingerprint } from "./output/json.ts";
export { toStixBundle } from "./output/stix.ts";
export { writeSnapshot, type WrittenSnapshot } from "./output/snapshot.ts";

export { assertScannableTarget, isAuthorized, UnsafeTargetError, CONSENT_NOTICE, BEHAVIOUR_NOTICE } from "./safety.ts";

export { diffSnapshots, renderDrift, toolSignature, type DriftReport, type ToolChange } from "./drift.ts";

export {
  buildAssessment,
  renderAssessmentMarkdown,
  assessmentFingerprint,
  type Assessment,
  type AssessedFinding,
  type LinkAssertion,
} from "./assess.ts";
export { writeAssessment, type WrittenAssessment } from "./output/assessment.ts";
export { renderSnapshotHtml, renderAssessmentHtml } from "./output/html.ts";
export { startUiServer, type UiOptions, type UiServer } from "./ui.ts";

export { runBehaviour, canIsolateNetwork, type RunBehaviourOptions } from "./behaviour/runner.ts";
export { analyseBehaviour, BEHAVIOUR_RULES, type BehaviourRule } from "./behaviour/analyser.ts";
export { generateArguments, type GeneratedArguments } from "./behaviour/args.ts";
export { createSandboxEnvironment, disposeSandboxEnvironment, findHookPath } from "./behaviour/canaries.ts";
export { buildArtefact, writeBehaviourArtefact, artefactFingerprint, type BehaviourArtefact } from "./behaviour/artefact.ts";
export { renderBehaviourMarkdown } from "./behaviour/report.ts";
export type {
  BehaviourEvent,
  BehaviourRecord,
  Canary,
  IsolationMechanism,
  NetworkIsolation,
  ToolInvocation,
} from "./behaviour/types.ts";
export { BEHAVIOUR_SCHEMA_VERSION, isLoopback } from "./behaviour/types.ts";

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
