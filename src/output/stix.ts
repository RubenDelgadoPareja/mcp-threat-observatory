import { uuidv5 } from "../lib/id.ts";
import type { Snapshot } from "../model.ts";
import { VERSION } from "../version.ts";
import { snapshotFingerprint } from "./json.ts";

// Canonical STIX 2.1 TLP:CLEAR marking. The old TLP:WHITE id (613f2e26-…) is a
// different definition and is rejected by the reference implementation.
const TLP_CLEAR_ID = "marking-definition--94868c89-83c2-496f-b23b-7d1b3d2f0e0f";
const TLP_CLEAR_CREATED = "2022-10-01T00:00:00.000Z";
const CREATED = "2026-01-01T00:00:00.000Z";
const OWASP_URL = "https://owasp.org/projects/mcp-top-10";

/**
 * Maps a snapshot to a STIX 2.1 bundle.
 *
 * Mapping decisions (documented in docs/DATA-MODEL.md):
 *   infrastructure  → the remote MCP endpoint
 *   vulnerability   → one per check that produced a finding
 *   relationship    → infrastructure `has` vulnerability
 *   note            → the evidence, inference and limitations for that finding
 *
 * `confidence` is not a common property in STIX 2.1, so grading is carried in
 * an `x_mcp_observatory` extension rather than smuggled into a standard field.
 */
export function toStixBundle(snapshot: Snapshot): Record<string, unknown> {
  const { probe, findings } = snapshot;
  const host = safeHost(probe.target);
  const fingerprint = snapshotFingerprint(snapshot);
  // Timestamps describe when the observation was made, not when the bundle
  // was rendered. That keeps re-exports byte-identical for the same record.
  const created = probe.collectedAt;

  const identityId = `identity--${uuidv5(`identity|${probe.collector.name}`)}`;
  const infraId = `infrastructure--${uuidv5(`infrastructure|${probe.target}`)}`;

  const objects: Array<Record<string, unknown>> = [
    {
      type: "marking-definition",
      spec_version: "2.1",
      id: TLP_CLEAR_ID,
      created: TLP_CLEAR_CREATED,
      definition_type: "tlp",
      name: "TLP:CLEAR",
      definition: { tlp: "clear" },
    },
    {
      type: "identity",
      spec_version: "2.1",
      id: identityId,
      created: CREATED,
      modified: CREATED,
      name: probe.collector.name,
      identity_class: "system",
      description: `Passive collector, version ${VERSION}. Contact: ${probe.collector.contact ?? "not configured"}.`,
    },
    {
      type: "infrastructure",
      spec_version: "2.1",
      id: infraId,
      created,
      modified: created,
      created_by_ref: identityId,
      object_marking_refs: [TLP_CLEAR_ID],
      name: host,
      description: `Remote MCP endpoint observed with a passive handshake. Target: ${probe.target}`,
      infrastructure_types: ["hosting"],
      first_seen: probe.collectedAt,
      last_seen: probe.collectedAt,
      x_mcp_observatory: {
        target: probe.target,
        transport: probe.transport,
        snapshot_fingerprint: fingerprint,
        tools_observed: probe.tools ? probe.tools.length : null,
        authentication_required: probe.auth.requiresAuth,
      },
    },
  ];

  for (const finding of findings) {
    const vulnId = `vulnerability--${uuidv5(`vulnerability|${finding.checkId}|${finding.title}`)}`;
    const externalReferences: Array<{ source_name: string; external_id: string; url?: string }> = [
      ...finding.owasp.map((id) => ({ source_name: "OWASP MCP Top 10", external_id: id, url: OWASP_URL })),
    ];
    if (externalReferences.length === 0) {
      externalReferences.push({ source_name: "mcp-threat-observatory", external_id: "interoperability" });
    }

    objects.push({
      type: "vulnerability",
      spec_version: "2.1",
      id: vulnId,
      created,
      modified: created,
      created_by_ref: identityId,
      object_marking_refs: [TLP_CLEAR_ID],
      name: `${finding.checkId}: ${finding.title}`,
      description: finding.observation,
      external_references: externalReferences,
      x_mcp_observatory: {
        check_id: finding.checkId,
        severity: finding.severity,
        confidence: finding.confidence,
        assertion: finding.assertion,
        fingerprint: finding.fingerprint,
        taxonomy: finding.taxonomy,
      },
    });

    objects.push({
      type: "relationship",
      spec_version: "2.1",
      id: `relationship--${uuidv5(`relationship|${infraId}|${vulnId}`)}`,
      created,
      modified: created,
      created_by_ref: identityId,
      object_marking_refs: [TLP_CLEAR_ID],
      relationship_type: "has",
      source_ref: infraId,
      target_ref: vulnId,
    });

    const content = [
      `Observation: ${finding.observation}`,
      finding.inference ? `Inference: ${finding.inference}` : "",
      finding.recommendation ? `Recommendation: ${finding.recommendation}` : "",
      finding.limitations.length ? `Limitations: ${finding.limitations.join(" | ")}` : "",
      finding.evidence.length
        ? `Evidence: ${finding.evidence.map((e) => `${e.locator}${e.digest ? ` (sha256:${e.digest})` : ""}`).join(" | ")}`
        : "",
    ]
      .filter(Boolean)
      .join("\n");

    objects.push({
      type: "note",
      spec_version: "2.1",
      id: `note--${uuidv5(`note|${infraId}|${finding.fingerprint}`)}`,
      created,
      modified: created,
      created_by_ref: identityId,
      object_marking_refs: [TLP_CLEAR_ID],
      abstract: `${finding.checkId} evidence for ${host}`,
      content,
      object_refs: [infraId, vulnId],
      x_mcp_observatory: {
        assertion: finding.assertion,
        confidence: finding.confidence,
        snapshot_fingerprint: fingerprint,
      },
    });
  }

  return {
    type: "bundle",
    id: `bundle--${uuidv5(`bundle|${infraId}|${fingerprint}`)}`,
    objects,
  };
}

function safeHost(target: string): string {
  try {
    return new URL(target).host;
  } catch {
    return target;
  }
}
