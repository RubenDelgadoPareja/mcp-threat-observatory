# Methodology

This document describes exactly what the collector does, how findings are
graded, and what the resulting record cannot support. It is written so that a
reader can reproduce a run and challenge a conclusion.

## 1. Scope

**In scope (v0.1):** remote MCP servers reachable over the Streamable HTTP
transport, observed without credentials.

**Out of scope:** stdio servers, authenticated surfaces, server source code,
package dependencies, publisher identity, runtime behaviour, tool invocation.

The scope is intentionally narrow. A narrow record that holds up is worth more
than a broad one that does not.

## 2. Collection procedure

For a target `https://host/path`, the collector performs the following
exchanges, in order, with no credential:

| # | Exchange | Purpose |
| --- | --- | --- |
| 1 | `POST /path` with `initialize` | Establish whether the endpoint answers, and how it refuses |
| 2 | `POST /path` with `notifications/initialized` | Complete the handshake, only if (1) succeeded |
| 3 | `POST /path` with `tools/list` | Enumerate the tool catalog |
| 4 | `POST /path` with `resources/list` | Distinguish "empty" from "unimplemented" |
| 5 | `POST /path` with `prompts/list` | Same, for prompts |
| 6 | `GET /.well-known/oauth-protected-resource{path}` | RFC 9728 discovery, only if auth was demanded |
| 7 | `GET /.well-known/oauth-protected-resource` | Fallback discovery root |

Requests 6 and 7 are only issued when the endpoint refused unauthenticated
access, because discovery is only meaningful in that case. If a
`resource_metadata` URL is advertised in the `WWW-Authenticate` challenge, it is
fetched first and the well-known guesses are skipped when it succeeds.

No tool is ever invoked. No method outside the list above is sent.

### Request hygiene

- **User agent** identifies the collector and, when configured, a contact URL.
  A record without a contact is marked as weaker provenance.
- **Rate limit**: one request per second per host by default, configurable up to
  ten, floored at one.
- **Timeout**: 15 seconds per request by default.
- **Redirects** on the MCP endpoint are recorded, not followed: a redirect is an
  observation, and following it could silently move the observation to a
  different host.
- **Credentials in URLs** are rejected before any request is made.

## 3. What is recorded

Every exchange is stored with method, URL, request header *names* (never
values), response status, response headers, a truncated body excerpt, the full
body length and a SHA-256 digest of the full body.

Header values are excluded on purpose: they are the most likely place for a
token to appear, and a collector that hoards credentials is a liability.

The record distinguishes three states for every field: a value, `null` (we could
not determine it), and absence (the concept did not apply). `null` is never
rendered as zero.

## 4. Evidence grading

Every finding carries two independent judgements.

### 4.1 Assertion kind

- **`observed`** — the statement describes something present in a captured
  exchange. If the observation is wrong, the collector is broken.
- **`inferred`** — the statement is a conclusion drawn from what was observed.
  If the inference is wrong, the collector is still correct about the
  observation.

A single sentence must not do both. This is the main defence against the most
common failure in threat reporting: a claim that reads as fact but rests on a
guess.

### 4.2 Confidence

| Level | Meaning | Example |
| --- | --- | --- |
| `high` | Directly read from a captured exchange, with no interpretation step | HTTP 403 was returned |
| `moderate` | One inference step, or an observation with a known ambiguity | Pattern match across several metadata fields |
| `low` | Heuristic classification of free text or names | Capability classes derived from tool descriptions |

Confidence describes support for the finding, **not** the severity of the issue.
A low-confidence finding can be severe enough to investigate; a high-confidence
finding can be trivial.

## 5. Severity derivation

Severity is derived from exposure plus capability, not from a status code.

| Situation | Severity | Rationale |
| --- | --- | --- |
| No auth + at least one high-impact tool | `high` | Reachable capability that can destroy, execute or move money |
| No auth + read-mostly catalog | `low` | Frequently a deliberate public design |
| 403 instead of 401 | `medium` | Breaks OAuth discovery for compliant clients |
| Auth required, no discoverable metadata | `medium` | Login cannot be bootstrapped by a compliant client |
| Metadata aimed at the model | `medium` | Potential instruction channel; requires review |
| Capability trifecta | `medium` | Structural attack path, not a demonstrated exploit |

Nothing in v0.1 is graded `critical`. That grade is reserved for demonstrated
impact, which a passive handshake cannot establish.

## 6. Precision policy

Checks are accepted only if they meet three conditions:

1. **The observation is deterministic.** Given the same response, the finding
   must appear every time.
2. **The false-positive mode is documented.** Every check has a "what this does
   not mean" section in [CHECKS.md](CHECKS.md).
3. **It survives an honest corpus.** A check that fires on well-behaved servers
   is removed or downgraded, not shipped with a disclaimer.

Pattern-matching checks (TOOL-002) are deliberately narrow. Phrases like
"ignore", "system" or "important" on their own are not matched, because honest
tool documentation uses them. The cost is recall: novel or paraphrased
instructions are missed. That trade is intentional and stated in every finding.

## 7. Known blind spots

- Everything behind an authentication boundary.
- Runtime behaviour: exfiltration, rug pulls, malicious side effects.
- Dynamic catalogs: a server may return a different tool set on the next
  request. One record is a snapshot, not a property.
- Server code and dependencies.
- Intent. A public server may be public on purpose.
- Transport variants: SSE-only servers, stdio servers, and servers behind
  interactive bot protection.

## 8. Reproducibility

- Each snapshot carries a content fingerprint over `probe + findings`.
- Each exchange carries a body digest, so any quoted excerpt can be checked
  against the full body if the raw record is retained.
- Finding fingerprints are deterministic for a given check, target and
  discriminator, which makes cross-snapshot comparison possible.
- STIX object identifiers are UUIDv5, so re-exporting the same snapshot produces
  byte-identical objects.

What reproducibility cannot give you: the target may have changed. A record is
evidence of what was served at a moment, not a permanent property of the server.

## 9. What a record can and cannot support

| Claim | Supported? |
| --- | --- |
| "On 2026-11-22 the endpoint answered without credentials and listed these tools" | Yes |
| "The server is insecure" | No — depends on intent and context |
| "The publisher is malicious" | No — not observable at all |
| "The server exfiltrates data" | No — no tool was invoked |
| "The catalog exposes a reader + egress combination" | Yes, as an inference with `low` confidence |
| "This server was involved in campaign X" | No — requires evidence outside this record |

If a conclusion needs more than the table allows, it needs more collection.
