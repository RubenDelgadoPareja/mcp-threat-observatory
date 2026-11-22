# Drift

A server that passes review and then changes is the problem the MCP ecosystem has
no answer for. `mcpobs drift` compares two records of the same target and states
what changed.

```bash
mcpobs drift snapshots/2026-11-01/example.json snapshots/2026-11-22/example.json
mcpobs drift a.json b.json --fail-on-change   # exit 1 if anything changed
```

## What is compared

| Layer | How |
| --- | --- |
| Findings | By deterministic fingerprint (check + target + discriminator) |
| Tool definitions | By a canonical hash of `name`, `title`, `description`, `annotations`, `inputSchema` |
| Added / removed tools | By name |

Canonical hashing means key order in a JSON Schema never produces a false
positive. Hashing the **whole** definition, not just the description, is the
point: a flipped `destructiveHint` changes how a client asks for approval without
changing a single visible word.

## Rules

| Rule | What it reports | Severity |
| --- | --- | --- |
| `DRIFT-001` | A tool was added, removed or modified | `info` |
| `DRIFT-002` | A safety hint became less restrictive | `medium` |

A hint is "relaxed" when:

- `destructiveHint` was `true` and is no longer `true`;
- `openWorldHint` was `true` and is no longer `true`;
- `readOnlyHint` was `false` and is now `true`.

The first two include the hint being **removed**, because the signal the client
relied on has disappeared. `readOnlyHint` going from `false` to absent is
ambiguous, so it is not escalated.

A change that *tightens* a hint (`destructiveHint: false → true`) is a normal
definition change, reported only as `DRIFT-001`.

## CI gate

```yaml
- name: Tool definitions must not change silently
  run: |
    node dist/cli.js drift previous.json current.json --fail-on-change
```

For a publisher, this is the useful offer: pin the reviewed definition, and let
the build fail when a change is not deliberate. It is also the difference between
"audited once" and "audited continuously".

## What this does not claim

- A change is not an attack. Releases change tool definitions legitimately.
- Only definitions are compared. Server code, dependencies and runtime behaviour
  are not.
- An annotation is a hint, not enforcement. A publisher who lies in an annotation
  can lie elsewhere; `mcpobs behaviour` exists for that.
- If either record has no catalog (authentication required), the comparison is
  incomplete and says so.
- Different targets are refused by the CLI: finding fingerprints are per-target,
  so comparing two servers would produce a meaningless diff.

## Relationship to the Python layer

`python/src/mcpobs_analysis/drift.py` implements the same idea for analysis
notebooks, including annotation-only changes. The TypeScript version adds the
CLI surface, the exit code and the `DRIFT-*` findings; the two must agree on what
counts as a change.
