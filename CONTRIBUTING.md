# Contributing

## Local setup

```bash
npm install
npm run check      # typecheck + tests
npm run build
node examples/demo-server.mjs &
node dist/cli.js scan http://127.0.0.1:8787/mcp --authorized
```

No network access is required to develop or test. Every test runs against local
fixtures.

## Ground rules

1. **No check without a negative fixture.** A check that has never been shown to
   stay quiet on a clean server is not finished.
2. **Observation and inference stay separate.** If a finding mixes them, it is
   not mergeable.
3. **`null` is not zero.** Do not fill unknown values with defaults.
4. **Document the false-positive mode.** In `docs/CHECKS.md`, before the code.
5. **No new runtime dependency** without a reason in the pull request. The
   collector should stay installable in a single `npm i`.
6. **No exploitation code, ever.** This includes payloads used "just to prove"
   impact.

## Adding a check

A check is a small object in `src/checks/`:

```ts
export const myChecks: Check[] = [
  {
    id: "AREA-001",
    title: "Short, falsifiable statement",
    owasp: ["MCPxx"],
    taxonomy: ["..."],
    rationale: "Why this exists, and what it cannot see.",
    run(probe) {
      if (!conditionObservedIn(probe)) return [];
      return [{
        severity: "low",
        confidence: "high",
        assertion: "observed",
        observation: "Exactly what the record contains.",
        inference: "What it may mean, kept separate.",
        recommendation: "What to change, with a spec reference.",
        limitations: ["What this finding cannot support."],
        evidence: [{ kind: "http", locator: "POST <target> → 401" }],
      }];
    },
  },
];
```

Then add it to `src/checks/index.ts` and cover both branches in `test/`.

## Style

- TypeScript strict mode. `npm run typecheck` must pass.
- Python 3.11+, standard library only in the core package. No dependency may be
  added without a reason in the pull request.
- Comments explain *why*, never *what*. The code already says what.
- English in code, docs and commit messages.
- Small commits with a reason in the message, not a description of the diff.

## Python side

```bash
python3 -m unittest discover -s python/tests -t python -v
PYTHONPATH=python/src python3 -m mcpobs_analysis checks examples/corpus
```

Rules specific to the analysis layer:

1. **The schema is the contract.** If the collector changes a field, the Python
   `Snapshot.from_dict` must change in the same pull request, and
   `test_corpus_contract.py` must still pass.
2. **`None` is not zero.** Never coerce an unknown into a default to make a
   number look complete.
3. **No network.** The analysis layer reads files and prints results. Fetching
   belongs to the collector.
4. **Optional dependencies stay optional.** `pandas` and `stix2` are extras, and
   every code path that uses them must degrade with a clear message.

### Regenerating the synthetic corpus

The corpus is generated, not hand-written:

```bash
npm run build
node examples/build-corpus.mjs
```

If a check changes, regenerate and review the diff in `examples/corpus/`. A
change there is a change in what the project claims to observe.

## Data and privacy

Never commit a real snapshot. `snapshots/` is git-ignored on purpose: response
bodies can contain personal data or internal hostnames even when no credential
was sent.

If you need a fixture from a real server, rewrite it: change hostnames, replace
identifiers, keep the structure that the check depends on.
