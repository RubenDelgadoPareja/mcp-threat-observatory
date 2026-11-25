# Behavioural collection

Passive collection reads metadata. Behavioural collection **executes the
server** and records what the process tries to do. That is the difference
between "this tool says it reads notes" and "this tool read `~/.ssh/id_ed25519`
and wrote it to an SMTP server".

## The ethical shift, stated plainly

`mcpobs scan` never invokes a tool. `mcpobs behaviour` does, which means it runs
code. It is a separate command with its own consent gate for that reason.

Rules that the implementation enforces:

- The process runs inside a network namespace with no route (`unshare -rn`).
- If that isolation is unavailable, the command **refuses to run** unless
  `--allow-unisolated` is passed. Fail closed.
- `HOME` is a temporary directory containing canaries, never the real one.
- The environment is rebuilt from scratch: no inherited tokens, no inherited
  cloud credentials.
- Only code you wrote, or are authorised to execute, may be run.

## Pipeline

```
isolate  →  scrub env  →  plant canaries  →  spawn  →  drive MCP over stdio
        →  record events (JSONL)  →  analyse  →  artefact + report
```

## Isolation: what it covers and what it does not

| Dimension | Covered by `unshare -rn`? |
| --- | --- |
| Outbound network | **Yes.** No route, no DNS. The attempt still gets recorded by the hook before it fails. |
| Loopback | Present but down; an MCP stdio server does not need it. |
| Filesystem | **No.** The mount namespace is shared. A temporary `HOME` limits accidents, not a determined process. |
| Processes | **No.** A child process stays in the same namespaces. |
| Privileges | A user namespace maps a fake root inside; it grants nothing on the host. |

The hook observes at the Node API level, so it records destinations even when the
connection cannot complete. That combination — impossible to succeed, still
observable — is why the first slice works without Docker.

## Canaries

Seven synthetic credentials are planted per run:

| Locator | Kind |
| --- | --- |
| `$HOME/.ssh/id_ed25519` | file |
| `$HOME/.aws/credentials` | file |
| `$HOME/.npmrc` | file |
| `$CWD/.env` | file |
| `AWS_SECRET_ACCESS_KEY` | env |
| `GITHUB_TOKEN` | env |
| `NPM_TOKEN` | env |

Each value is `CANARY-<16 hex>`. This changes the *evidence class*: "the server
probably reads credentials" becomes "this exact value left the process and was
addressed to this exact host". It is an observation, not an inference.

A canary does not prove intent. A legitimate integration that forwards a token
would trip it. The finding says so, every time.

## Argument generation

Arguments come from each tool's JSON Schema, deterministically, in one of two
profiles:

| Profile | String parameters | Measures |
| --- | --- | --- |
| `neutral` | `mcpobs-test` | default behaviour |
| `targeted` | canary paths for path-like parameters, a dead host for URL-like ones | whether the server stays inside its configured root |

Rules that apply in both profiles:

- only `required` properties, except that `targeted` also fills optional path and
  URL parameters, because that is where confinement is tested;
- `enum` → an element selected by the seed;
- `integer`/`number` → the schema minimum, clamped to the maximum;
- `boolean` → `false`, so the sandbox never opts into a destructive path;
- `string` → `format`-aware values, truncated to `maxLength`;
- `pattern` that cannot be synthesised → a plain string, with a note.

No model is involved. The same schema, seed and profile produce the same call, so
anyone can reproduce the run. Notes are stored per tool call, because a tool that
errored on a generated value exercised a different path than one that succeeded.

```bash
mcpobs behaviour --authorized --profile targeted -- node server.mjs
```

## What the hook sees

`runtime/node-hook.cjs` is loaded with `--require` and patches:

| API | Event |
| --- | --- |
| `net.Socket.prototype.connect` | `net.connect` (host, port) |
| `net.Socket.prototype.write` | `net.write` (canary ids, byte count) |
| `dns.lookup`, `dns.promises.lookup` | `dns.lookup` |
| `fs.readFile*`, `fs.open*`, `fs.createReadStream` | `fs.read` (sensitive paths only) |
| `child_process.spawn/exec/execFile*` | `process.spawn` |

It writes JSONL to `MCPOBS_BEHAVIOUR_LOG` and **never to stdout**, because for a
stdio server stdout is the protocol channel.

## Python

Injected through `PYTHONPATH` plus a `sitecustomize.py`, which CPython imports at
startup before the server module runs. Two mechanisms, for two reasons:

| Mechanism | Covers |
| --- | --- |
| `sys.addaudithook` | `socket.getaddrinfo`, `socket.connect`, `open`, `subprocess.Popen`, `os.system` |
| `socket.send/sendall/sendto` patch | payload contents, for canary detection |

Audit events do not carry the bytes being written, which is why the socket
methods are also patched. `sys.addaudithook` cannot be removed once installed,
but `-I` and `-S` skip `sitecustomize` entirely, and a C extension or a spawned
non-Python process bypasses both mechanisms.

Both hooks are installed unconditionally: each runtime loads the one it
understands and ignores the other, so no language detection is required.

### Why the Python fixture exfiltrates over UDP

Inside the namespace no TCP handshake can complete, so a `sendall` after
`connect` is never reached. A UDP `sendto` takes the payload as an argument and
is attempted regardless of reachability, which is where the instrumentation can
observe it. This is not a workaround for the demo: DNS tunnelling over UDP is a
real exfiltration technique, and the fixture reproduces that shape.

### What bypasses them

- native addons;
- a worker thread with its own loader;
- a spawned non-Node process;
- a different runtime entirely.

The hook is observation, not a security boundary. The network namespace is the
boundary, and it only covers the network.

## The record

`BehaviourRecord` (see `src/behaviour/types.ts`):

```json
{
  "kind": "behaviour",
  "target": { "command": ["node", "/abs/server.mjs"], "cwd": "/tmp/.../work" },
  "isolation": { "mechanism": "unshare-rn", "network": "isolated" },
  "environment": { "home": "/tmp/.../home", "seed": 1, "canaries": [ … ] },
  "tools": [ { "name": "get_notes", "arguments": {}, "outcome": "result", … } ],
  "events": [ { "type": "net.write", "host": "smtp.collect.example.test", "port": 587, "canaryIds": [ … ] } ],
  "summary": { "egressAttempts": 1, "canaryReads": 2, "canarySends": 1 },
  "limitations": [ … ]
}
```

Artefacts are wrapped as `{ kind: "behaviour-artefact", record, findings, summary }`
and written to `behaviour/YYYY-MM-DD/`, with an append-only `index.jsonl`. The
passive snapshot schema is untouched.

## Rules

| Rule | What it observes | Severity | Assertion |
| --- | --- | --- | --- |
| `BEHAV-001` | A canary value appears in an outbound write | `high` | observed |
| `BEHAV-002` | A connection to a non-loopback destination was attempted | `low` | observed |
| `BEHAV-003` | A canary credential file was read | `medium` | observed |

`BEHAV-002` is deliberately `low`: without the package's documented endpoints,
expected API traffic and exfiltration look identical. Inflating it would trade
precision for drama. A destination that received a canary is reported only as
`BEHAV-001`; there is no ambiguity left to report at `low`.

## Reading a finding

1. Did the event happen inside a tool call? The observation names it, or says
   "outside any tool call".
2. Which tool? `BEHAV-001`/`003` attribute events to the tool whose time window
   contains them.
3. Was the destination documented? The collector cannot know; that is a human
   judgement, and the finding says so.
4. What did the run not exercise? Tool errors, skipped optional arguments, and
   code paths behind external services.

## Non-goals

- Proving malice. It records behaviour.
- Containment of the filesystem or of child processes.
- Running third-party packages at scale without review.
- Attribution.
