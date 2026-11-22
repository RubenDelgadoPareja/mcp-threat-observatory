# Project brief

**One line.** A passive collector and analysis pipeline that turns MCP server
observations into records another analyst can trust a year later — every claim
separated into what was observed and what was inferred, with the blind spots
stated.

## The problem

MCP moved from specification to supply-chain target in under a year:

- `postmark-mcp` (Sep 2025): 15 clean versions, then one line that BCC'd every
  outgoing email to an attacker. First malicious MCP server found in the wild.
- SmartLoader / Oura Ring clone (Feb 2026): three months of fabricated GitHub
  history, then a trojanised listing in a legitimate registry.
- Miasma (Jun 2026): adversarial `.mcp.json` files across 73 repositories,
  executing on repository open, no user interaction.
- Mittwald (Oct 2026): a hosting provider's own MCP server leaked session tokens
  for 56 customer projects; 7 days 20 hours of dwell time.
- OX Security (Apr 2026): a systemic flaw in every official MCP SDK, affecting an
  estimated 200,000 instances. The behaviour was confirmed as intentional and the
  protocol architecture was left unchanged, so remediation falls to individual
  downstream developers.

Detection tooling exists and is crowded. What is scarce is **provenance**: a
record that says what was seen, when, from where, with what evidence, and what
the observer could not see.

## What exists today (v0.1)

- Passive collection over Streamable HTTP: `initialize`, `tools/list`,
  `resources/list`, `prompts/list`. No tool is ever invoked.
- Nine checks across authentication posture, metadata, input schemas,
  interoperability and capability composition, mapped to the OWASP MCP Top 10.
- Every finding carries `assertion: observed | inferred`, a confidence level, and
  mandatory limitations.
- Immutable snapshots, append-only index, SHA-256 digest per HTTP exchange.
- Markdown, JSON and deterministic STIX 2.1 export, validated against the
  `stix2` reference implementation.
- Analysis layer in Python: corpus distributions, drift detection, dataset
  export, STIX validation.
- Consent gate, 1 req/s rate limit, loopback-only plaintext HTTP.
- 42 TypeScript tests (including end-to-end collection) and 45 Python tests.

## Why it is different

1. **Author-side, not consumer-side.** Existing tools answer "should I trust this
   third-party server". This one produces the evidence base for "what is the
   state of the ecosystem, and how did it change".
2. **Epistemic discipline as a feature.** The `observed`/`inferred` split and
   per-finding confidence are enforced by tests, not by good intentions.
3. **Precision over recall, with the cost documented.** The metadata-poisoning
   check deliberately misses paraphrased instructions, and says so in every
   finding.
4. **Verifiable records.** Any excerpt can be checked against the raw body digest
   months later.

## What is next (v0.2, the part that matters)

Static analysis reads metadata. Nobody records what an MCP server *does*.

The next step is behavioural collection: run server code inside a container with
no egress except a sinkhole, record every outbound attempt, and detect the
`postmark-mcp` pattern — a package that behaves as advertised and also sends data
somewhere else. That turns a metadata corpus into a behavioural one, which is the
dataset that does not currently exist publicly.

## Honest limits

- The corpus published today is synthetic; no third-party server was contacted.
- No attribution. Ever. This produces observations, not adversary naming.
- No security score. A single number would collapse exactly the distinction the
  project exists to preserve.
- v0.1 cannot see behind a login boundary, cannot execute code, and cannot
  confirm an exploit path.

## Why this is relevant to a threat-intelligence team

The MCP ecosystem is a young attack surface with real adversaries, real victims,
a large unauthenticated population, and almost no longitudinal telemetry. The
interesting work is not another scanner; it is instrumentation that produces
defensible records at ecosystem scale, and the discipline to publish what it
cannot see.
