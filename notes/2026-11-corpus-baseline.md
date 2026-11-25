# A baseline for six MCP servers, measured in a sandbox

*What happens when you hand a real MCP server a credential-shaped path, and what
the record can and cannot prove.*

Published 2026-11-25 · TLP:CLEAR

Six open-source MCP servers, two argument profiles, twelve runs, all local. No
third-party server was contacted: the packages were installed from their public
registries under their own licences and executed inside a network namespace with
no route.

This is a small study. It is published because the baseline did not exist, and
because one of its results is a limitation of the instrument rather than a
property of the servers.

## Method

| Control | Value |
| --- | --- |
| Servers | 6, Node, one pinned version each |
| Installation | `npm install --ignore-scripts`, so no third-party install script ran |
| Isolation | `unshare -rn`: no route, no DNS |
| Home directory | Temporary, seeded with 7 canary credentials |
| Environment | Rebuilt from scratch; no inherited tokens |
| Tool calls | Every tool once per profile, arguments from its JSON Schema |
| Runs | 2 profiles × 6 servers = 12 |

Two argument profiles:

- **neutral** — strings are `mcpobs-test`. This measures default behaviour.
- **targeted** — parameters that look like a path or a URL receive a canary path
  (`$HOME/.ssh/id_ed25519`) or a host that does not exist. This tests whether the
  server stays inside whatever root it was configured with.

The canaries are synthetic. `$HOME` is a temporary directory, so nothing real was
ever exposed.

## Results

| | Neutral | Targeted |
| --- | --- | --- |
| Servers that started and listed tools | 6 / 6 | 6 / 6 |
| Tool definitions exercised | 69 | 69 |
| Tool calls returned a result | 67 / 68 | 67 / 68 |
| Servers that read a canary file | **0 / 6** | **1 / 6** |
| Servers that wrote a canary value to a socket | **0 / 6** | **1 / 6** |
| Servers that attempted egress | 3 / 6 | 3 / 6 |

One call per profile timed out; it belongs to a server whose tool waits for a
long-running operation. It is counted, not hidden.

Three observations, in order of how much they can support.

### 1. Where a root model exists, it held (observed)

One server in the corpus takes an allowed-root directory at startup and exposes
file tools relative to it. It received the absolute path of the canary as the
`path` argument in the targeted profile. It read nothing outside its root: zero
canary reads across 16 tool calls.

That is one server, one version, one run. It is a data point, not a property of
the ecosystem.

### 2. Reading a path you were given is a capability, not a vulnerability (observed, then inferred)

The single server that read the canary is a general-purpose file and terminal
manager. It has no root confinement by design: it is the equivalent of handing
someone a shell. It read the path because the path was the argument, and it
returned the content. Eleven `fs.read` events, all of them the planted file.

The finding here is not "this server is unsafe". It is that a tool which can read
any path will read any path a model is persuaded to supply. The interesting
surface is the client's decision to pass it, not the server's willingness to
honour it.

### 3. Two writes we could not attribute (observed, and a limit of the instrument)

That same server wrote canary content to a socket twice: once immediately after
reading the file (231 bytes) and once during a tool that reports recent tool
calls (17 KB).

**The record does not name a destination.** The socket had not connected when the
payload was queued, so neither the tracked target nor `remoteAddress` was
available. And because the run was network-isolated, no route existed: the
payload could not have left the machine.

So the honest statement is: *a canary value was written to an unconnected socket*.
Not exfiltration. Not telemetry. Not a vulnerability claim. A write we could not
attribute, which is exactly the kind of gap this project exists to make visible.

## What this does not show

- **No exfiltration occurred, and none could.** The namespace had no route. Every
  external connection attempt failed.
- **The sample is six.** Node only, one pinned version each, one run per profile.
  No variance measurement.
- **The most interesting servers are excluded by construction.** A server that
  needs an API key or a database is precisely the one holding privileges, and it
  is the one this method cannot exercise without real credentials.
- **No authenticated surface was observed.**
- **The instrument is API-level.** Native addons, other runtimes and spawned
  non-Node processes bypass the hook. Static analysis of the packages was not
  performed.
- **A capability is not a vulnerability.** Reading a file it was told to read is
  what a file manager does.

## Why publish a result this small

Three reasons, and only the third is about the numbers.

1. **A baseline is useful.** "Well-behaved servers behave" is not a headline, but
   it is the denominator against which a future finding means something.
2. **Negative results are results.** The corpus attempted egress from three
   servers, to destinations their documentation describes. Nothing anomalous
   happened. Saying so is cheaper than implying otherwise.
3. **The limitation is the finding.** Two writes escaped attribution because the
   socket was not yet connected. That is a concrete engineering gap in the
   instrument, and it sets the next milestone: a sinkhole that observes packets,
   not APIs, so that a destination is a fact rather than a guess.

## Reproduce it

The runner and the aggregator are in `scripts/`. The corpus and the raw records
stay outside the repository on purpose: the id-to-package mapping is private, and
the artefacts contain tool names and destinations that would identify the
servers. The runner reads `corpus.local.json`, which is git-ignored.

```bash
# create corpus.local.json locally, then:
node scripts/corpus-run.mjs --install
node scripts/corpus-run.mjs
node scripts/corpus-aggregate.mjs
```

What you get is the same table, with the same caveats.
