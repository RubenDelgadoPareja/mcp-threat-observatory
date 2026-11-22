# Evidence, not verdicts

*A method for recording what MCP servers do, and for keeping that record usable
after the target changes.*

Published 2026-11-22 · TLP:CLEAR

Every claim below is either something I observed by running the tooling in this
repository, or something I inferred from a cited source. Where I could not see, I
say so.

## The gap is provenance, not detection

Detecting a single bad MCP server is a solved-enough problem. Open-source scanners
exist (Snyk Agent Scan, Cisco MCP Scanner, mcpprobe among others), and the
registries are starting to scan on publish. That is progress, and it is also why
another scanner would be a poor use of a year.

What is scarce is a **record**: what was seen, when, from where, with what
evidence, and what the observer could not see. Scanners produce verdicts. Verdicts
do not survive six months, a re-release, or a disagreement with the publisher.
Records do.

The distinction is not academic. A verdict says "this server is risky". A record
says: on this date, this endpoint answered without credentials and listed these
tools, here is the digest of the response body, here is what that implies and
here is the list of things it cannot support. Only the second one can be
re-examined when the server changes.

## Three properties that make a record usable

**Observation is separated from inference, in the schema.** Every finding carries
`assertion: observed | inferred`. "HTTP 403 was returned" is observed. "Compliant
clients cannot discover the authorization server" is inferred from it. Both can be
right, but only the first survives being wrong.

**Confidence is per claim, not per document.** A report-level score hides which
sentences are weak. A `low`-confidence finding can be severe enough to
investigate; a `high`-confidence one can be trivial.

**Limitations live next to the finding.** Not in an appendix. A reader who stops
after the observation must still know what it cannot support.

Under those three sits the substrate: every HTTP exchange is stored with a
SHA-256 digest of the full body, and every finding has a deterministic
fingerprint. Any excerpt can be checked later against the record it came from.

## Two modes, two contracts

| | Passive (`mcpobs scan`) | Behavioural (`mcpobs behaviour`) |
| --- | --- | --- |
| Executes code | No | Yes |
| Sees | What a client sees before consent | What the process tries to do |
| Isolation | None needed | Network namespace, temporary HOME, canaries |
| Consent | Written authorisation to observe | Written authorisation to execute |
| Blind to | Everything behind a login | Everything the runtime hook cannot see |

The asymmetry is the point. Passive collection can be pointed at a remote
endpoint you are authorised to observe. Behavioural collection executes code, so
it only runs against something you wrote or were permitted to run — and it refuses
to start when isolation is unavailable.

Both produce the same kind of finding, with the same grading. That is what makes
the two comparable instead of two unrelated tools.

## A worked example

The repository ships a fixture that behaves like a useful tool and does something
else. It reads `~/.ssh/id_ed25519` and a `.env` file, then sends both to an
unrelated host. Against the Node variant:

```text
Isolation: unshare-rn (network: isolated) · Canaries: 7 · Tools invoked: 1

HIGH    BEHAV-001  canary value written to smtp.collect.example.test:587
MEDIUM  BEHAV-003  read ~/.ssh/id_ed25519
MEDIUM  BEHAV-003  read .env
```

The Python variant produces the same grades with a different mechanism: it uses
`sys.addaudithook` and tunnels the values over UDP to port 53, because inside the
namespace no TCP handshake can complete. DNS tunnelling is not a demo artefact;
it is an exfiltration technique the instrumentation should see.

The important line is the one that is not there. The same run against a fixture
that only echoes produces **zero findings**:

```text
No behaviour finding was produced for this run.
```

An instrument that only ever produces positives is not measuring. The negative
control is part of the test suite, not a courtesy.

## The change a text diff cannot see

The third piece is drift. Given two records of the same server:

```text
### Tool catalog changes

- `delete_workspace` **modified** — description, annotations · **relaxed: destructiveHint**

### Drift findings

- **MEDIUM** `DRIFT-002` — Tool `delete_workspace`: `destructiveHint` is less
  restrictive than in the previous record.
```

The description still says "delete". A text diff sees a one-word edit at most. The
record sees that the annotation a client uses to ask for confirmation has been
switched off — which changes approval behaviour without changing any visible
word. That is the shape of a rug pull, and it is why the comparison hashes the
whole definition rather than the prose.

The same comparison is what turns the tool into something a publisher can use:
pin the reviewed definition, and let CI fail when it changes silently.

## What this method cannot see

- **Behind authentication.** Nothing here authenticates, so the authenticated
  surface is unobserved.
- **Native code.** The hooks patch Node and Python APIs. A native addon, another
  runtime, or a spawned non-Node process can bypass them. The network namespace is
  the boundary, and it covers the network only.
- **The filesystem.** A temporary `HOME` limits accidents; it does not contain a
  determined process. That needs a container or mount namespace.
- **Intent.** A canary proves a value left the process. It does not prove the
  publisher meant harm.
- **The ecosystem.** The corpus in this repository is synthetic. No third-party
  server was contacted and no third-party package was executed to produce it.
  Every number below about the wider ecosystem comes from someone else's
  measurement, with the denominator attached.

## Why it matters now

The population is large and young. One measurement of the official registry in
November 2026 found 20,981 remote servers, of which 55.7% answered without any
login; among those requiring login, 15.1% published no discoverable resource
metadata; 19.6% of open servers annotated every tool consistently. Those figures
are indicators of exposure, not vulnerability counts, and they describe one
snapshot of one registry.

The incident record is more concrete. `postmark-mcp` shipped fifteen clean
versions and then BCC'd outgoing email to an address the publisher controlled
(September 2025, reported by Koi Security, Snyk and the impersonated vendor). A
cloned Oura Ring server reached a registry after three months of fabricated
GitHub history (February 2026, reported by Straiker). Adversarial `.mcp.json`
files appeared in 73 repositories, executing on checkout (June 2026, in a Cloud
Security Alliance research note). A hosting provider's own MCP server leaked
session tokens for 56 customer projects, with a dwell time of seven days and
twenty hours as described in its own incident report (October 2026).

And a research note published by OX Security in April 2026 reported a systemic
flaw in the official SDKs affecting an estimated 200,000 instances, with the
behaviour confirmed as intentional and remediation left to downstream developers.

If that last detail is right, the conclusion for anyone building on MCP is
uncomfortable but simple: remediation is placed on whoever writes the server. The
evidence has to be produced by the party closest to the code — and produced in a
form that survives being questioned.

## How to check any of this

```bash
npm install && npm run build

node dist/cli.js behaviour --authorized -- node examples/behaviour/exfil-server.mjs
node dist/cli.js behaviour --authorized -- node examples/behaviour/clean-server.mjs

node dist/cli.js drift examples/corpus/open-destructive.json after.json --fail-on-change
```

84 TypeScript tests and 45 Python tests cover the claims above, including the
negative controls. The passive outputs are committed in `examples/sample/`; the
behavioural fixtures are one command away; and every assertion about isolation is
a test, not a promise.

## What comes next

The next milestone is not more code. It is one server, analysed with its
maintainer's permission, published with their response. Everything here is
method; method without a case study is a claim about intentions.

After that: correlating the two modes into one view per server, and real
filesystem containment. In that order — because a record nobody can act on is
just a well-formatted opinion.
