# Portfolio notes

How to present this project without overclaiming. Overclaiming is the fastest way
to lose a technical interview; underclaiming is the fastest way to be forgotten.

## The twelve-second version

> Open-source observatory for the MCP supply chain: passive metadata collection
> plus isolated behavioural execution, with evidence-graded findings and STIX 2.1
> export.

If someone only reads one line, that is the line.

## CV

**One line**

> Built `mcp-threat-observatory`: an open-source collector that produces
> evidence-graded threat-intelligence records for MCP servers, including isolated
> behavioural analysis with canary credentials and STIX 2.1 export.

**Three bullets**

> - Designed and built a two-language pipeline (TypeScript collector, Python
>   analysis) that records what an MCP server advertises and what it does, with
>   every finding graded as observed or inferred.
> - Implemented behavioural analysis inside a network namespace: temporary HOME,
>   seven canary credentials, deterministic schema-driven tool invocation, and
>   detection of credential exfiltration in a controlled fixture.
> - Enforced evidence integrity: SHA-256 digests per HTTP exchange, deterministic
>   finding fingerprints, and STIX 2.1 bundles validated against the reference
>   `stix2` implementation. 114 tests.

**Technical bullet (for a security-focused CV)**

> Built passive and behavioural collection for Model Context Protocol servers:
> RFC 9728 discovery analysis, OWASP MCP Top 10 mapping, `unshare`-based network
> isolation, a Node API observation hook, and a drift detector over full tool
> definitions that catches annotation-only changes.

## Profile / LinkedIn

> I build instrumentation for emerging attack surfaces. Currently: MCP supply
> chain — separating what a server claims from what it does, and making the
> record defensible a year later.

## Six interview questions, and where the answer lives

**1. "How do you know a finding is true?"**
Every finding has `assertion: observed | inferred`, a confidence level, and
mandatory limitations. Evidence carries a SHA-256 digest of the full body, so an
excerpt can be verified later. See `src/model.ts` and `docs/METHODOLOGY.md` §4.

**2. "Tell me about a bug you got wrong."**
Three, all instructive:
- The STIX exporter stamped objects with render time instead of observation time;
  a determinism test caught it. Re-exports would have looked like new events.
- The Python validator claimed "deep validation passed" when `stix2` was not
  installed. A test now asserts the claim is only made when it is true.
- `net.connect` normalises its arguments before `socket.connect`, so the hook
  lost the host and reported `localhost`. The end-to-end test caught what the
  unit tests could not see.

**3. "How do you avoid false positives?"**
Precision over recall, with the cost documented. `BEHAV-002` is deliberately
`low` because expected API traffic and exfiltration look identical without the
package's documented endpoints. The poisoning check excludes broad keywords.
Every check ships with a negative fixture (`test/behaviour/acceptance.test.ts`).

**4. "What was the hardest design constraint?"**
Evidence has to survive the target changing. That is why records are immutable,
indexes append-only, and `null` never becomes zero. A record that reports "0"
because nobody looked is a lie that propagates into every downstream analysis.

**5. "Why two languages?"**
TypeScript at the edge, because it ships through `npx` onto a developer's
machine. Python for analysis, because that is where notebooks, pandas and the
reference `stix2` parser live. The Python layer validates the STIX the
TypeScript layer emits — interoperability checked by the ecosystem's own parser.

**6. "What would you do with more data?"**
Correlate passive and behavioural records per server, add drift detection across
days (the rug-pull primitive already exists in `python/src/mcpobs_analysis/drift.py`),
and cluster publishers by typosquat distance, version velocity and template
reuse. All gated behind authorisation: no scanning third-party infrastructure
without permission.

## What not to say

| Do not say | Say instead |
| --- | --- |
| "I built a security scanner" | "I built a provenance layer; detection is a by-product" |
| "It scans the MCP ecosystem" | "It collects from servers I am authorised to observe" |
| "It detects malicious servers" | "It records behaviour and grades the evidence" |
| "I found X vulnerable servers" | "The published corpus is synthetic; here is the method" |
| "It attributes activity to actors" | "It never attributes; that requires evidence this cannot produce" |

## The honest gap, stated once

The project demonstrates method, engineering and judgement. It does not yet
demonstrate ecosystem-scale findings, because it has not been pointed at a
consented corpus at scale. Say that before anyone asks. It reads as rigour, not
as a limitation — and the roadmap shows exactly how it closes.
