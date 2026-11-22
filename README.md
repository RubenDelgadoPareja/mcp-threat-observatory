# mcp-threat-observatory

> Passive, evidence-graded observation of Model Context Protocol endpoints —
> and the raw material for longitudinal threat intelligence on the MCP ecosystem.

**Status: v0.2.** Two modes: passive observation (no code executed) and
behavioural collection (server executed inside a network namespace, with
canary credentials). No clustering yet, and no attribution ever.
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

Two modes, two contracts.

**Passive (`mcpobs scan`)** performs what an ordinary MCP client does, and
nothing more:

```
initialize → notifications/initialized → tools/list → resources/list → prompts/list
```

No tool is invoked. No payload is sent. At most one request per second.

**Behavioural (`mcpobs behaviour`)** executes a stdio server inside a network
namespace with no route, a temporary `HOME` and seven canary credentials, then
invokes every tool once with arguments generated deterministically from its
schema. It records network destinations, DNS lookups, credential-file reads and
child processes. It is a separate command with its own consent gate because it
runs code.

From those two records it derives twelve checks: nine passive (authentication
posture, metadata quality, schema strictness, interoperability, capability
composition) and three behavioural (`BEHAV-001`…`003`). Each is reported as
either **observed** or **inferred**, with an explicit confidence level and an
explicit list of limitations.

## Two languages, one reason

| Layer | Language | Why |
| --- | --- | --- |
| Collection | TypeScript | Runs on a developer's machine and ships through `npx`. One command, no environment. |
| Analysis | Python | Notebooks, pandas, and the reference `stix2` implementation — where threat-intelligence work actually happens. |

The Python layer is not a port. It validates the STIX the collector emits against
the ecosystem's own parser, computes corpus distributions, and implements drift
detection over tool definitions.

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

### Behavioural collection

```bash
# Executes the fixture inside a network namespace with canary credentials
node dist/cli.js behaviour --authorized -- node examples/behaviour/exfil-server.mjs

# Negative control: a server that does exactly what it says
node dist/cli.js behaviour --authorized -- node examples/behaviour/clean-server.mjs
```

The first produces `BEHAV-001` (a canary written to `smtp.collect.example.test:587`),
`BEHAV-003` for the credential files it read, and `BEHAV-002` for the egress
attempt. The second produces nothing. Artefacts land in `behaviour/YYYY-MM-DD/`.

Requires `unshare` with user namespaces. Without it the command refuses to run;
`--allow-unisolated` exists for code you wrote yourself.

Set `MCPOBS_CONTACT` to a URL or address before collecting. Records without a
contact are recorded as weaker provenance, on purpose.

### Analysis (Python, standard library only)

```bash
python3 -m unittest discover -s python/tests -t python     # 45 tests
PYTHONPATH=python/src python3 -m mcpobs_analysis summarize examples/corpus
PYTHONPATH=python/src python3 -m mcpobs_analysis checks examples/corpus
PYTHONPATH=python/src python3 -m mcpobs_analysis compare <a.json> <b.json>
PYTHONPATH=python/src python3 -m mcpobs_analysis validate-stix examples/sample/bundle.stix.json --deep
```

Optional extras: `pip install -e "python[analysis]"` for pandas and matplotlib,
`"python[stix]"` for deep validation with the reference implementation. See
[python/README.md](python/README.md) and
[python/notebooks/01_corpus_overview.ipynb](python/notebooks/01_corpus_overview.ipynb).

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

- Behavioural mode does not contain the filesystem or child processes: only the network. That is stated in every artefact.
- It does not see behaviour a Node API hook cannot observe: native addons, other runtimes, spawned non-Node processes.
- It does not authenticate, so everything behind a login boundary is unobserved.
- It does not assess publishers, dependencies or intent.
- It does not attribute activity to an adversary. Ever.
- It does not prove an exploit path.

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
| BEHAV-001 | Canary value written to an external destination | MCP01 |
| BEHAV-002 | Outbound connection to a non-loopback destination | — |
| BEHAV-003 | Canary credential file was read | MCP01 |

Rationale, false-positive behaviour and interpretation for each check:
[docs/CHECKS.md](docs/CHECKS.md).

## Documentation

- [Project brief](docs/BRIEF.md) — one page, for forwarding
- [Methodology and evidence grading](docs/METHODOLOGY.md)
- [Check catalogue](docs/CHECKS.md)
- [Behavioural collection](docs/BEHAVIOUR.md)
- [Ethics and authorisation](docs/ETHICS.md)
- [Disclosure policy](docs/DISCLOSURE.md)
- [Data model and STIX mapping](docs/DATA-MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Python analysis layer](python/README.md)
- [If you are coming from frontend](docs/LEARNING.md)
- [Contributing](CONTRIBUTING.md)

## Ethics

This tool contacts servers. It performs a passive handshake, but that still
requires authorisation. The CLI refuses to run without an explicit
`--authorized` acknowledgement, refuses non-HTTPS targets except loopback, and
rate-limits to one request per second. Read [docs/ETHICS.md](docs/ETHICS.md)
before pointing it anywhere.

## License

MIT.
