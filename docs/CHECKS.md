# Check catalogue

Nine checks. Each one states what it observes, why it matters, what it does
**not** mean, and how severity is derived. A check that cannot answer the third
question should not exist.

---

## AUTH-001 — Handshake completes with no credential

**Observes.** An unauthenticated `initialize` returned a result, and
`tools/list` returned a catalog.

**Why it matters.** The endpoint is reachable by anyone who can route to it.
A December 2026 study of the official MCP registry found 55.7% of assessable
remote servers answered without a login. That number is often quoted as a
vulnerability count; it is not. It is a population-level exposure indicator.

**What it does not mean.** That the server is vulnerable. Public, read-only
servers are a legitimate design. Severity is therefore derived from what the
tools can do:

| Condition | Severity |
| --- | --- |
| No auth, at least one high-impact tool (exec, destroy, payment, admin) | `high` |
| No auth, read-mostly catalog | `low` |

**Confidence.** `high`. The status code and the tool list are both observed.

**OWASP MCP:** MCP07 (Insufficient authentication and authorisation).

---

## AUTH-002 — 403 where a 401 challenge is required

**Observes.** The unauthenticated `initialize` was answered with HTTP 403.

**Why it matters.** MCP clients start the login flow from the
`WWW-Authenticate` challenge on a 401. A 403 carries no challenge, so a
compliant client cannot discover how to authenticate and surfaces a generic
connection failure. This is the single most common interoperability bug reported
in MCP server frameworks.

**What it does not mean.** That authentication is missing, or that the server is
insecure. It is an interoperability defect with a security-shaped symptom.

**False-positive modes.** The 403 may come from an edge WAF in front of a
correctly implemented server. Some clients fall back to well-known discovery and
never notice.

**Severity.** `medium`. **Confidence.** `high`.

**OWASP MCP:** MCP07.

---

## AUTH-003 — Protected Resource Metadata (RFC 9728) is not discoverable

**Observes.** The endpoint demanded authentication, and no valid protected
resource metadata document was found at the advertised hint URL or the
well-known paths.

**Why it matters.** Without the metadata document, a client has no
protocol-level way to learn which authorization server to use. The November 2026
registry study found 15.1% of login-requiring servers in this state: they
authenticate, but no compliant client can get there automatically.

**What it does not mean.** That a human cannot log in. Manual configuration
still works; automated connection does not.

**False-positive modes.** Non-standard discovery mechanisms are not probed. A
document served behind a redirect chain longer than the client tolerates may be
reported as missing.

**Severity.** `medium`. **Confidence.** `high` (for absence; the impact is
inferred).

**OWASP MCP:** MCP07.

---

## AUTH-004 — 401 challenge omits `resource_metadata`

**Observes.** A 401 response whose `WWW-Authenticate` header has no
`resource_metadata` parameter.

**Why it matters.** The challenge is the fastest discovery path. Without it,
clients guess well-known locations, adding a failure mode that looks like a
network error to the user.

**What it does not mean.** That discovery is impossible; the well-known paths may
still work.

**Severity.** `low`. **Confidence.** `high`.

**OWASP MCP:** MCP07.

---

## TOOL-001 — Tool metadata is incomplete

**Observes.** Tools missing `title`, `description`, or annotations
(`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`).

**Why it matters.** Annotations are the affordances clients use to warn users
before a destructive call, and titles appear in approval prompts. Descriptions
are what a model uses to select a tool at all. Only 19.6% of open servers in the
November 2026 study annotated every tool consistently.

**What it does not mean.** That the tools are dangerous. Annotations are hints,
not enforcement: a correct annotation does not imply correct behaviour, and a
missing one does not imply malice.

**Severity.** `info`. **Confidence.** `high`.

**OWASP MCP:** MCP03, MCP02.

---

## TOOL-002 — Metadata contains language aimed at the model

**Observes.** Narrow heuristic matches in tool names, titles, descriptions and
JSON-schema text: instruction-override phrases, requests to conceal behaviour
from the user, references to credential files, exfiltration wording, zero-width
characters, bidirectional controls and Unicode tag characters.

**Why it matters.** Tool descriptions are injected into the model context as
trusted text. An adversary who controls them influences behaviour without
touching executable code. This is the mechanism behind every documented
tool-poisoning case.

**What it does not mean.** That the publisher is malicious. This check is
`inferred` for a reason: pattern matching cannot distinguish an attack from
unusual documentation. Every finding requires human review.

**False-positive modes.** Deliberately broad patterns were excluded ("ignore",
"system", "important" alone are not matched). Remaining noise sources:
localisation, security documentation that quotes attack strings, and test
fixtures.

**False-negative modes.** Paraphrased instructions, non-English instructions,
and instructions split across fields.

**Severity.** `medium` for hidden characters or instruction overrides, `low`
otherwise. **Confidence.** `moderate` when several distinct signal classes
match, `low` otherwise.

**OWASP MCP:** MCP03, MCP06.

---

## TOOL-003 — Input schemas accept unconstrained input

**Observes.** Tools with a string parameter that has no `enum`, `pattern`,
`format` or `maxLength`, or an object schema without
`additionalProperties: false`.

**Why it matters.** The schema is the contract the model is asked to satisfy. A
loose contract produces loose calls, and unconstrained strings are where
injection, path traversal and SSRF begin.

**What it does not mean.** That injection is possible. Server-side validation may
exist and is not visible in the schema. Conversely, a strict schema does not
guarantee safe handling downstream.

**Severity.** `low` when a high-impact tool is affected, `info` otherwise.
**Confidence.** `high`.

**OWASP MCP:** MCP05, MCP02.

---

## PROTO-001 — Discovery methods unimplemented rather than empty

**Observes.** `resources/list` or `prompts/list` returned JSON-RPC `-32601`
instead of an empty array.

**Why it matters.** Directory crawlers, IDE inspectors and marketplace scanners
call both methods unconditionally. `-32601` is logged as a broken server even
when the server is healthy, which blocks listings and confuses users.

**What it does not mean.** That anything is insecure. This is a pure
interoperability finding, included because a security record that ignores
whether the server works is not useful to anyone.

**Severity.** `low`. **Confidence.** `high`.

**OWASP MCP:** none.

---

## RISK-001 — Reader, untrusted input and egress coexist

**Observes.** The catalog contains at least one tool that reads data an operator
would consider private, one tool that accepts unconstrained external input, and
one tool that can send data outward.

**Why it matters.** Each tool can be reasonable alone. Together they form the
"lethal trifecta": a single injected instruction can move data from the reader
to the egress tool. 18.1% of open servers in the November 2026 study showed this
composition.

**What it does not mean.** That an exploit exists. This is a structural risk
indicator inferred from metadata. No tool was invoked and no data flow was
observed. It must never be reported as a vulnerability.

**False-positive modes.** Capability classes are inferred from names,
descriptions and annotations, so a well-described server can still be
misclassified. A server whose egress tool requires human confirmation for every
call is far less exposed than the indicator suggests.

**Severity.** `medium`. **Confidence.** `low`.

**OWASP MCP:** MCP02, MCP06.

---

## Adding a check

A new check must ship with:

1. A deterministic observation rule.
2. A documented false-positive mode.
3. At least one positive fixture and one negative fixture in `test/`.
4. An explicit severity rule that explains itself without the finding text.
5. An `observed` or `inferred` assertion — never both.

Checks that cannot meet these conditions belong in research notes, not in the
collector.
