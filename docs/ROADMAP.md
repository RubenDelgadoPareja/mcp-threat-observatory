# Roadmap

Ordered by what makes the records more useful, not by what is most fun to build.

## v0.1 — Passive observation (current)

- [x] Streamable HTTP handshake, unauthenticated
- [x] Nine checks across auth, metadata, schema, interoperability, composition
- [x] Observed/inferred split, per-finding confidence, explicit limitations
- [x] Immutable snapshots, append-only index, body digests
- [x] Markdown, JSON and STIX 2.1 output
- [x] Consent gate, rate limiting, loopback-only HTTP
- [x] 42 tests, including end-to-end collection against local fixtures

**Deliberately absent:** sandbox, drift, clustering, dataset publication.

## v0.2 — Behavioural collection (the differentiator)

The gap that matters: static analysis reads metadata, nobody records what an MCP
server *does*.

- [x] Run a stdio server with a rebuilt environment, temporary `HOME` and
      canary credentials
- [x] Network namespace isolation via `unshare -rn`, fail-closed without it
- [x] Node API hook: destinations, DNS, credential-file reads, child processes
- [x] Deterministic, schema-driven tool arguments (no model involved)
- [x] `BEHAV-001` canary exfiltration, `BEHAV-002` egress, `BEHAV-003` credential read
- [x] Separate artefact lineage, append-only index, evidence-graded findings
- [ ] Python `sys.addaudithook` support (FastMCP servers are the larger population)
- [ ] Docker backend: filesystem and process containment, not only network
- [ ] Egress sinkhole that records packets the hook cannot see
- [ ] Correlation with the passive record: same server, both modes, one view

**Acceptance (met for the Node slice):** the malicious fixture produces
`BEHAV-001` with the exact destination and a canary id; the clean fixture
produces zero behavioural findings; both are covered by e2e tests.

**Safety:** no third-party code outside the sandbox; no network egress except the
namespace's own (absent) route; no publication of payloads.

## v0.3 — Longitudinal drift

- [ ] Compare snapshots by fingerprint across days
- [ ] Flag description, schema and annotation changes (rug-pull detection)
- [ ] Distinguish "server changed" from "collector changed"
- [ ] Publish a drift feed per target

**Acceptance:** an injected change to a local fixture is detected within one
collection cycle, with a diff that quotes both versions.

## v0.4 — Infrastructure and publisher clustering

- [ ] Publisher identity from registry metadata (account age, version velocity)
- [ ] Typosquat distance against popular server names
- [ ] Template and code reuse across packages
- [ ] Shared endpoints and addresses across findings
- [ ] Cluster view: one object per suspected campaign, with links to evidence

**Acceptance:** the SmartLoader pattern (new accounts, fabricated history,
cloned package) is surfaced as a cluster, not as N unrelated findings.

## v0.5 — Dataset and detections

- [ ] Versioned public dataset (JSON + Parquet) with a schema and a changelog
- [ ] YARA rules for malicious MCP server packages
- [ ] Sigma rules for `.mcp.json`-based execution patterns
- [ ] ATT&CK mapping for the delivery techniques observed
- [ ] Reproducible benchmark: precision and recall against a held-out corpus

**Acceptance:** a third party can reproduce the headline numbers from the
published dataset alone.

## v1.0 — Continuous observatory

- [ ] Scheduled collection over a defined, consented corpus
- [ ] Public dashboard with methodology inline
- [ ] Quarterly report with an evidence-grading appendix
- [ ] Stable schema and a deprecation policy

## Not planned

- **Exploitation.** No payloads, no attempts to prove impact by attacking.
- **Attribution.** Naming actors or campaigns requires evidence this project
  cannot produce.
- **Authenticated collection of third-party accounts.** Out of scope by design.
- **A "security score".** A single number would hide exactly the distinction
  between observation and inference that this project exists to preserve.
