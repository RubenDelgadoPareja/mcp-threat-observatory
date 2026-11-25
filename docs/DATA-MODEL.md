# Data model and STIX mapping

Two principles govern the model:

1. **`null` means unknown.** It is never replaced with `0`, `false` or `""`. A
   record that reports zero because nobody looked is a lie that survives into
   every downstream analysis.
2. **Observation and inference are separate fields.** They are never merged into
   one sentence, because a reader must be able to stop after the observation and
   still know what was seen.

## 1. `ProbeResult`

The raw record of one collection run.

| Field | Type | Meaning |
| --- | --- | --- |
| `schemaVersion` | `"1"` | Model version |
| `target` | `string` | Absolute URL that was observed |
| `transport` | `"http"` | Streamable HTTP only in v0.1 |
| `collectedAt` | ISO 8601 | When the observation started |
| `reachable` | `boolean` | At least one HTTP response was received |
| `auth.networkAccessible` | `boolean` | A response arrived, regardless of status |
| `auth.requiresAuth` | `boolean \| null` | `false` = handshake completed unauthenticated; `true` = refused; `null` = undetermined |
| `auth.statusOnUnauthenticatedInitialize` | `number \| null` | Status of the first `initialize` |
| `auth.wwwAuthenticate` | `string \| null` | Header as received |
| `auth.resourceMetadataUrl` | `string \| null` | `resource_metadata` from the challenge |
| `auth.protectedResourceMetadata` | object \| `null` | Discovery result: found, URL, status, parsed body, authorization servers |
| `handshake.initialized` | `boolean` | `initialize` returned a result |
| `handshake.protocolVersion` | `string?` | Negotiated version |
| `handshake.serverInfo` | object? | Self-reported name and version |
| `capabilities` | object \| `null` | As advertised |
| `tools` | array \| `null` | `null` = no usable catalog, for any reason |
| `toolsErrorCode` | `number \| null` | JSON-RPC error if `tools/list` failed |
| `resources` / `prompts` | object \| `null` | `{ ok, count, errorCode }` — distinguishes empty from unimplemented |
| `probes` | array | Every HTTP exchange, with body digest |
| `limitations` | `string[]` | Blind spots of this run. Always non-empty |
| `collector` | object | Name, version, user agent, contact |

Why `tools: null` rather than `[]`: an empty array means the server has no
tools; `null` means we do not know. The distinction matters when the whole point
is to avoid unfounded claims.

## 2. `Finding`

| Field | Meaning |
| --- | --- |
| `fingerprint` | `sha256(checkId \| target \| discriminator)`, first 16 hex chars |
| `checkId` | e.g. `AUTH-003` |
| `title` | Human title, may be specialised per result |
| `severity` | `critical \| high \| medium \| low \| info` |
| `confidence` | `high \| moderate \| low` — support for the finding |
| `assertion` | `observed \| inferred` |
| `taxonomy` | Facets: authentication, interoperability, supply-chain, … |
| `owasp` | OWASP MCP Top 10 identifiers |
| `observation` | What was seen. Must be supportable by `evidence` |
| `inference` | What it may mean. Optional, never disguised as fact |
| `recommendation` | Remediation, with a spec reference where one exists |
| `limitations` | What this finding cannot support |
| `evidence` | Locators, truncated excerpts, full-body digests |

`fingerprint` is stable for the same check, target and discriminator across
runs, which is what makes drift detection possible later.

## 3. `Snapshot`

```json
{
  "schemaVersion": "1",
  "generatedAt": "…",
  "probe": { … },
  "findings": [ … ],
  "summary": {
    "total": 6,
    "bySeverity": { "critical": 0, "high": 1, "medium": 2, "low": 2, "info": 1 },
    "byConfidence": { "high": 4, "moderate": 1, "low": 1 },
    "observed": 4,
    "inferred": 2
  }
}
```

`generatedAt` is deliberately excluded from the content fingerprint: two
renderings of the same observation must have the same identity.

## 4. Storage layout

```
snapshots/
├── index.jsonl                                   append-only
└── YYYY-MM-DD/<slug>-<fingerprint8>.json         immutable
```

The index is the only mutable-adjacent artifact, and it is append-only. Rewriting
history is how a dataset loses its value.

## 6. Behavioural artefacts

A different lineage from snapshots, because it answers a different question and
carries different ethics.

```json
{
  "schemaVersion": "1",
  "kind": "behaviour-artefact",
  "generatedAt": "…",
  "record": { "kind": "behaviour", "tools": [ … ], "events": [ … ], "limitations": [ … ] },
  "findings": [ … ],
  "summary": { "total": 4, "bySeverity": { … }, "egressAttempts": 1, "canaryReads": 2, "canarySends": 1 }
}
```

Key differences from a snapshot:

| Snapshot | Behaviour artefact |
| --- | --- |
| `probe`, passive | `record`, executed |
| `null` tools = unknown | `tools` = what was invoked |
| No credentials involved | Canaries planted and tracked |
| Network side effects possible | Network isolated by default |
| `AUTH-*`, `TOOL-*`, `PROTO-*`, `RISK-*` | `BEHAV-*` |

The passive schema is untouched, so v0.1 consumers keep working. `BEHAV-*`
findings reuse the same `Finding` shape, including `assertion`, `confidence`
and `limitations`.

## 7. STIX 2.1 mapping

| STIX object | Maps to |
| --- | --- |
| `marking-definition` | TLP:CLEAR (canonical identifier `94868c89-…`) |
| `identity` | The collector, `identity_class: system` |
| `infrastructure` | The remote endpoint, `infrastructure_types: ["hosting"]` |
| `vulnerability` | One per check that produced a finding |
| `relationship` | `infrastructure —has→ vulnerability` |
| `note` | Observation, inference, recommendation, limitations, evidence |

Identifiers are UUIDv5 over a fixed namespace, so re-exporting the same snapshot
produces byte-identical objects. Timestamps use `collectedAt`, not the render
time, for the same reason.

### Two honest caveats

1. **`vulnerability` is a compromise.** STIX models vulnerabilities as named
   weaknesses with external identifiers. A metadata-quality finding is not a CVE.
   The mapping is used because it is the closest standard object with an
   evidence relationship, and it is stated here rather than hidden.
2. **`confidence` is not a common property in STIX 2.1.** Grading therefore
   lives in an `x_mcp_observatory` extension rather than being smuggled into a
   standard field. Custom properties with the `x_` prefix are explicitly
   permitted.

A future version may emit `x-mcp-server` SCOs for the endpoint and its tools
once the community converges on a representation.
