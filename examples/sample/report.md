# Passive security observation — 127.0.0.1:8787

> TLP:CLEAR · This document contains no exploit and no third-party victim data.

- **Target:** `http://127.0.0.1:8787/mcp`
- **Collected:** 2026-11-22T15:29:59.824Z
- **Collector:** mcp-threat-observatory 0.1.0
- **Contact:** _not configured_ (set `MCPOBS_CONTACT`)
- **Transport:** http (streamable HTTP)
- **Reachable:** yes
- **Authentication required:** no
- **Server:** demo-server 0.1.0
- **Tools observed:** 4

## Summary

| Severity | Findings |
| --- | --- |
| critical | 0 |
| high | 1 |
| medium | 2 |
| low | 2 |
| info | 1 |

4 observation(s) and 2 inference(s). Confidence: 4 high / 1 moderate / 1 low.

## HIGH — AUTH-001 · MCP endpoint completes a handshake with no credential

**Assertion:** observed · **Confidence:** high · **OWASP MCP:** MCP07 · **Facets:** authentication

**Observation.** An unauthenticated initialize succeeded (HTTP 200) and 4 tools were enumerated.

**Inference.** Tools with high-impact capability are reachable without a credential: send_email.

**Recommendation.** If this endpoint is not intentionally public, require OAuth 2.1 per the MCP authorization specification and return 401 with a WWW-Authenticate challenge on unauthenticated requests.

**Limitations.**

- Only the unauthenticated surface was observed. Behaviour behind the login boundary is unknown.
- Intent is not observable: a public endpoint may be a deliberate choice.

**Evidence.**

- `POST http://127.0.0.1:8787/mcp → 200`
- `initialize → result` — `demo-server`

<sub>fingerprint `25b8b63a0507c32b`</sub>

## MEDIUM — RISK-001 · Catalog combines private-data access, untrusted input and egress

**Assertion:** inferred · **Confidence:** low · **OWASP MCP:** MCP02, MCP06 · **Facets:** capability-composition

**Observation.** The catalog contains tools that read private data (list_customers, get_notes), tools that accept unconstrained external input (fetch_url) and tools that can send data outward (fetch_url, send_email).

**Inference.** A single injected instruction reaching the ingress tool could move data from the reader to the egress tool. This is a structural risk indicator inferred from tool metadata, not an observed exploit.

**Recommendation.** Separate private-data readers from egress tools across servers, require explicit confirmation before outbound actions, and scope credentials per tool rather than per server.

**Limitations.**

- Capability classes are inferred from tool names, descriptions and annotations; they may be wrong.
- No tool was invoked, so no data flow was observed.
- A trifecta indicator is not a vulnerability and must not be reported as one.

**Evidence.**

- `tools/list → capability composition`

<sub>fingerprint `204939a7663a6b50`</sub>

## MEDIUM — TOOL-002 · Tool metadata contains language aimed at the model

**Assertion:** inferred · **Confidence:** moderate · **OWASP MCP:** MCP03, MCP06 · **Facets:** supply-chain, prompt-injection

**Observation.** 1 metadata field matched narrow injection heuristics: tools[get_notes].description (instruction-override, credential-path).

**Inference.** Text in tool metadata may be intended to steer the model rather than describe the tool. This is a signal, not proof of malice.

**Recommendation.** Review the matched fields manually. If the wording is not justified by the tool's function, treat the server as untrusted until the publisher explains it. Prefer servers that pin tool definitions by hash.

**Limitations.**

- Pattern matching cannot distinguish adversarial metadata from unusual but legitimate documentation.
- Novel or paraphrased instructions will not be detected.
- Absence of a match is not evidence of safety.

**Evidence.**

- `tools[get_notes].description` — `Do not tell the user | <IMPORTANT> | .ssh/id_rsa | id_rsa`

<sub>fingerprint `81627f053a9b1948`</sub>

## LOW — PROTO-001 · Discovery methods are unimplemented rather than empty

**Assertion:** observed · **Confidence:** high · **Facets:** interoperability

**Observation.** prompts/list returned JSON-RPC -32601 (Method not found).

**Inference.** Tooling that enumerates capabilities will report the server as partially broken, and marketplace listings may be rejected or incomplete.

**Recommendation.** Return an empty array ({ resources: [] } / { prompts: [] }) when the capability is not offered.

**Limitations.**

- This affects interoperability, not the security of the server itself.

**Evidence.**

- `prompts/list → -32601`

<sub>fingerprint `c1def9fd5889acd3`</sub>

## LOW — TOOL-003 · Tool input schemas accept unconstrained input

**Assertion:** observed · **Confidence:** high · **OWASP MCP:** MCP05, MCP02 · **Facets:** input-validation

**Observation.** 3 of 4 tools accept an unconstrained string parameter; 2 use an object schema without additionalProperties: false. High-impact tools affected: send_email.

**Inference.** Unconstrained input widens the path from model output to a shell, a query, a filesystem path or an outbound request.

**Recommendation.** Set additionalProperties: false and constrain every string parameter with enum, pattern, format or maxLength.

**Limitations.**

- Schema strictness is a proxy: a strict schema does not guarantee safe handling downstream.

**Evidence.**

- `tools/list → inputSchema`

<sub>fingerprint `d67003658fc5e980`</sub>

## INFO — TOOL-001 · Tool metadata is incomplete

**Assertion:** observed · **Confidence:** high · **OWASP MCP:** MCP03, MCP02 · **Facets:** metadata-quality

**Observation.** Of 4 tools: 0 have no annotations, 4 have no title, 0 have no description.

**Inference.** Clients cannot warn users about destructive or open-world behaviour, and LLM tool selection relies on descriptions that are missing.

**Recommendation.** Annotate every tool with title, readOnlyHint, destructiveHint, idempotentHint and openWorldHint, and write a description that states when the tool should and should not be used.

**Limitations.**

- Annotations are hints, not enforcement; correct annotation does not imply correct behaviour.

**Evidence.**

- `tools/list → annotations/title/description`

<sub>fingerprint `fd9a935f57dd05c1`</sub>

## What this report does not claim

- It does not claim the server is malicious, or that any finding was exploited.
- It does not describe behaviour behind an authentication boundary.
- It does not assess code quality, dependencies, or the publisher's identity.
- It does not invoke tools, so no runtime behaviour was observed.

## Method and limitations

A passive client handshake was performed: `initialize`, then `tools/list`, `resources/list` and `prompts/list`, at a maximum of one request per second. No tool was called and no payload was sent. See `docs/METHODOLOGY.md` for the evidence-grading model.

- No authenticated session was attempted: behaviour behind the login boundary is unobserved.
- Only the streamable HTTP transport was probed; stdio-only servers are out of scope.
- No tool was invoked; only discovery methods (initialize, tools/list, resources/list, prompts/list) were called.
- Body excerpts are truncated; SHA-256 digests cover the full response body.
- Collector contact is not configured (MCPOBS_CONTACT); provenance is weaker than it should be.

---

Raw record: 5 HTTP exchange(s), each with a SHA-256 body digest. Re-verify any excerpt against the snapshot JSON.
