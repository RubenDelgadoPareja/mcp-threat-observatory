# If you are coming from frontend

This repository was built by someone who is not a career security engineer, and
the ramp is real. This page maps what you already know to what this project
needs, in the order that makes the code easiest to read.

## 1. What transfers directly

| Frontend skill | Where it is used here |
| --- | --- |
| TypeScript strictness | The whole codebase; `tsc --noEmit` is part of CI |
| `fetch`, headers, status codes | `src/collect/http.ts` — every exchange is recorded |
| Reading a spec and matching a schema | MCP is JSON-RPC + JSON Schema; you already do this daily |
| Dev tooling (vitest, tsup, npm scripts) | `test/`, `tsup.config.ts`, `package.json` |
| Accessibility-style reasoning | "What does the user see when this fails?" is the same question as "what does the client see when auth breaks?" |

## 2. Five concepts, in order

### a. HTTP status semantics that carry security meaning

`401` means "you are not authenticated, here is how to authenticate".
`403` means "I know who you are and you may not do this". Confusing them breaks
protocol-level discovery, which is exactly AUTH-002.

**Exercise:** read `parseWwwAuthenticate` in `src/collect/http.ts`, then write a
test for a header with a quoted comma inside `resource_metadata`.

### b. OAuth 2.1 for MCP, specifically RFC 9728

MCP delegates login to OAuth. The client discovers the authorization server by
fetching a *protected resource metadata* document, usually at
`/.well-known/oauth-protected-resource<path>`.

**Exercise:** fetch that path by hand against a public server you are allowed to
probe (yours), with `curl -i`. Compare the body to `Auth-003` in
`docs/CHECKS.md`.

### c. JSON-RPC 2.0

Every MCP message is `{ jsonrpc, id, method, params }` and the answer is either
`result` or `error.code`. `-32601` means "method not implemented", which is
different from "implemented, returned an empty list".

**Exercise:** explain, in one sentence, why PROTO-001 is an interoperability
finding and not a security one.

### d. Vulnerability vs risk indicator

A vulnerability is something that can be exploited. A risk indicator is a
structure that makes exploitation cheaper. Most of what this tool finds are
indicators.

This distinction is the single most valuable thing you can learn for threat
intelligence work. It is also the easiest to demonstrate: see the
`assertion` field on every finding.

**Exercise:** pick a `RISK-001` finding and write the paragraph you would send to
a vendor. Notice how much of it is "this is not a claim of compromise".

### e. Evidence grading

Analysts grade confidence separately from severity, and state what they could
not see. `docs/METHODOLOGY.md` section 4 is the model used here.

**Exercise:** take any published security report and mark each sentence as
observation or inference. Most reports blur them. Yours should not.

## 3. First contributions, smallest first

1. **Add a positive and negative fixture** for a check that lacks one.
2. **Write a check** from the v0.2 list that needs no network: e.g. detect tools
   whose description contradicts their `readOnlyHint`.
3. **Improve one false-positive mode**: find a legitimate server description that
   trips TOOL-002 and narrow the pattern.
4. **Validate the STIX bundle** with an external tool, and file an issue for
   every deviation.
5. **Add YARA rule generation** from the tool descriptors (static, no execution).

Each of these is a small, reviewable PR that teaches one part of the domain.

## 4. Reading list

**Protocol**

- MCP specification, transports and authorization sections
- JSON-RPC 2.0 specification (it is one page)
- RFC 9728 — OAuth 2.0 Protected Resource Metadata
- RFC 6750 — the Bearer token usage rules that define the `WWW-Authenticate` challenge

**Threat landscape**

- OWASP MCP Top 10 (currently beta — note that in anything you write)
- The public post-mortems of `postmark-mcp`, the Oura Ring clone, Miasma, and the
  Mittwald incident. Read the primary sources, not the summaries.

**Tradecraft**

- Structured Analytic Techniques (Heuer) — the chapter on avoiding
  "mirror-imaging" is the reason half of this repo exists
- The Admiralty source-reliability scale
- STIX 2.1 object reference, at least the SDOs used here
- Sigma and YARA rule authoring guides

## 5. How to talk about this in an interview

Do not say "I built a security scanner". Say what it actually is:

> "I built a passive collector for MCP endpoints that produces evidence-graded
> records: every finding is either observed or inferred, with a confidence level
> and a list of what the collection could not see. The interesting part was not
> detection — it was making the record defensible a month later, which is why
> every HTTP exchange carries a body digest and every finding has a stable
> fingerprint."

Three stories you can tell from this codebase:

1. **A design decision with a cost.** "I chose precision over recall for the
   poisoning check. It means I miss paraphrased instructions. I documented that
   instead of adding broad rules that would have made the tool unusable."
2. **A bug caught by a test that was not about the bug.** "A determinism test
   failed because I was stamping STIX objects with render time instead of
   observation time. That would have made every re-export look like a new event
   in a feed."
3. **A judgement about scope.** "I refused to add a security score. A single
   number would collapse observed facts and low-confidence inferences into one
   value, which is exactly the failure mode the project is meant to avoid."

Interviewers at threat-intelligence teams care more about those three than about
the number of checks.
