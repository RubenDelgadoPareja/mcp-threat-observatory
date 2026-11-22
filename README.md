# mcp-threat-observatory

> Passive, evidence-graded observation of Model Context Protocol endpoints —
> and the raw material for longitudinal threat intelligence on the MCP ecosystem.

**Status: v0.1.** Passive collection only. No sandbox, no clustering, no tool invocation.
See [ROADMAP](docs/ROADMAP.md) for what is deliberately missing and why.

---

## Why this exists

MCP went from a specification to a supply-chain target in under a year. The
public record now includes a trojanised package that BCC'd every outgoing email
to an attacker (`postmark-mcp`, Sep 2025), a fake registry listing that shipped
an infostealer after three months of fabricated GitHub history (SmartLoader /
Oura Ring, Feb 2026), `.mcp.json` files planted across 73 repositories including
Microsoft's `azure/durabletask` (Miasma, Jun 2026), and a hosting provider whose
own MCP server leaked session tokens for 56 customer projects (Mittwald, Oct 2026).

Detecting an individual bad server is a solved-enough problem: several scanners
exist. What is missing is **records that can be trusted later** — what was seen,
when, from where, with what evidence, and what the observer could *not* see.

This collector produces those records. It is not a scanner with a nicer report;
it is a provenance layer.

## What it does

One command performs what an ordinary MCP client does, and nothing more:

```
initialize → notifications/initialized → tools/list → resources/list → prompts/list
```

No tool is invoked. No payload is sent. At most one request per second.

From that handshake it derives nine checks across authentication posture,
metadata quality, input-schema strictness, interoperability semantics and
capability composition — each reported as either **observed** or **inferred**,
with an explicit confidence level and an explicit list of limitations.

## Quickstart

```bash
npm install
npm run build

# 1. Start a local, deliberately imperfect MCP endpoint
node examples/demo-server.mjs

# 2. Observe it
node dist/cli.js scan http://127.0.0.1:8787/mcp --authorized
```

You do not need internet access or a third-party target to see the tool work.
A rendered example lives in [`examples/sample/`](examples/sample/): record,
Markdown report and STIX bundle, all generated from the local fixture.

```bash
node dist/cli.js checks                    # list checks and OWASP MCP mapping
node dist/cli.js scan <url> --json         # snapshot JSON instead of markdown
node dist/cli.js scan <url> --stix         # STIX 2.1 bundle
node dist/cli.js scan --from targets.txt   # batch, one target per line
node dist/cli.js report <snapshot.json> --format md|json|stix
node dist/cli.js inspect <snapshot.json>   # provenance and integrity details
```

Set `MCPOBS_CONTACT` to a URL or address before collecting. Records without a
contact are recorded as weaker provenance, on purpose.

## Output

Every run writes an immutable snapshot and appends one line to an index:

```
snapshots/
├── index.jsonl                                  # append-only, never rewritten
└── 2026-11-22/
    └── 127-0-0-1-8787-b1828bbd.json             # probe + findings + summary
```

Each snapshot contains every HTTP exchange it made, with a SHA-256 digest of the
full response body. Any excerpt in a report can be verified against the raw
record. That is the difference between a claim and evidence.

Three renderings from one record: Markdown (human), JSON (machine), STIX 2.1
(interchange with `infrastructure`, `vulnerability`, `relationship` and `note`
objects, TLP:CLEAR, deterministic UUIDv5 identifiers).

## Design decisions worth arguing about

| Decision | Reason |
| --- | --- |
| `observed` vs `inferred` on every finding | Mixing what was seen with what it means is how reports lose credibility. |
| `null` means "unknown", never `0` | A record that reports zero because nobody looked is a lie that propagates. |
| Confidence is per finding, not per report | A report-level score hides which claims are weak. |
| Precision over recall | A tool that cries wolf gets muted, and then it observes nothing. |
| Capability-based severity | An open server is not automatically a vulnerability; an open server with `delete_repo` is a different conversation. |
| Consent gate in the CLI | Passive is not the same as authorised. |
| Evidence digests | The record must remain verifiable after the target changes. |

## What this does **not** do

- It does not execute server code. Behaviour, exfiltration and rug pulls are invisible to it. That is v0.2.
- It does not authenticate, so everything behind a login boundary is unobserved.
- It does not assess publishers, dependencies or intent.
- It does not attribute activity to an adversary. Ever.
- It does not call tools, so it cannot confirm an exploit path.

## Checks

| ID | Title | OWASP MCP |
| --- | --- | --- |
| AUTH-001 | Handshake completes with no credential | MCP07 |
| AUTH-002 | 403 where a 401 challenge is required | MCP07 |
| AUTH-003 | Protected Resource Metadata not discoverable | MCP07 |
| AUTH-004 | 401 challenge omits `resource_metadata` | MCP07 |
| TOOL-001 | Tool metadata incomplete | MCP03, MCP02 |
| TOOL-002 | Metadata contains language aimed at the model | MCP03, MCP06 |
| TOOL-003 | Input schemas accept unconstrained input | MCP05, MCP02 |
| PROTO-001 | Discovery methods unimplemented rather than empty | — |
| RISK-001 | Reader + untrusted input + egress coexist | MCP02, MCP06 |

Rationale, false-positive behaviour and interpretation for each check:
[docs/CHECKS.md](docs/CHECKS.md).

## Documentation

- [Methodology and evidence grading](docs/METHODOLOGY.md)
- [Check catalogue](docs/CHECKS.md)
- [Ethics and authorisation](docs/ETHICS.md)
- [Disclosure policy](docs/DISCLOSURE.md)
- [Data model and STIX mapping](docs/DATA-MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md)

## Ethics

This tool contacts servers. It performs a passive handshake, but that still
requires authorisation. The CLI refuses to run without an explicit
`--authorized` acknowledgement, refuses non-HTTPS targets except loopback, and
rate-limits to one request per second. Read [docs/ETHICS.md](docs/ETHICS.md)
before pointing it anywhere.

## License

MIT.
