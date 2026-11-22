# Try it locally

Everything below runs on your machine. No account, no internet, no third-party
server. Two terminals are easier than background processes.

## Prerequisites

- Node 22 or newer (`node --version`)
- Linux, macOS, or WSL2
- `unshare` for the behavioural mode (`unshare -rn true` should exit 0)

## 1. Passive scan in the browser (60 seconds)

**Terminal A** — a synthetic MCP server that is deliberately imperfect:

```bash
git clone https://github.com/RubenDelgadoPareja/mcp-threat-observatory
cd mcp-threat-observatory
npm install            # also builds, via the prepare script
node examples/demo-server.mjs
```

It prints `demo MCP endpoint: http://127.0.0.1:8787/mcp`.

**Terminal B** — the local UI:

```bash
cd mcp-threat-observatory
node dist/cli.js ui
```

Open the URL it prints (it contains a token), paste
`http://127.0.0.1:8787/mcp`, tick the attestation, and press **Scan**.

Do not open `http://127.0.0.1:8787/mcp` in a browser tab. An MCP server answers
protocol requests, not web pages: a browser sends `GET` and gets
`{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"}}`. That is
the server working correctly.

You should get **five findings**: `AUTH-001` (high, unauthenticated endpoint with
a destructive tool), `RISK-001` (medium, reader + input + egress in one catalog),
`TOOL-002` (medium, poisoned tool description), `PROTO-001` (low) and `TOOL-003`
(low).

From WSL2, the same URL also works in a Windows browser at
`http://127.0.0.1:4040/?token=…`.

## 2. Behavioural analysis (code executed, isolated)

Back in terminal B:

```bash
node dist/cli.js behaviour --authorized -- node examples/behaviour/exfil-server.mjs
```

Expect one `high` (`BEHAV-001`, a canary written to `smtp.collect.example.test:587`)
and two `medium` (`BEHAV-003`, credential files read).

Then the control — this must produce **zero** findings:

```bash
node dist/cli.js behaviour --authorized -- node examples/behaviour/clean-server.mjs
```

## 3. Drift, the rug-pull primitive

```bash
node -e '
  const fs = require("fs");
  const s = JSON.parse(fs.readFileSync("examples/corpus/open-destructive.json", "utf8"));
  const t = s.probe.tools.find((x) => x.name === "delete_workspace");
  t.annotations.destructiveHint = false;
  fs.writeFileSync("/tmp/after.json", JSON.stringify(s));
'

node dist/cli.js drift examples/corpus/open-destructive.json /tmp/after.json --fail-on-change
echo "exit code: $?"     # 1: something changed
```

The description is unchanged. What changed is the annotation a client uses to ask
for confirmation.

## 4. Both modes, one artefact

```bash
node dist/cli.js assess --authorized -- node examples/behaviour/exfil-server.mjs
ls assessments/*/
```

Each assessment writes a `.json` and a self-contained `.html`.

## 5. A shareable report

```bash
node examples/demo-server.mjs &          # if terminal A is not running
node dist/cli.js scan http://127.0.0.1:8787/mcp --authorized --html /tmp/report.html
xdg-open /tmp/report.html                # or open it from the file manager
```

The HTML has inline CSS, no scripts and no external assets. It works offline.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `EADDRINUSE` | Port already taken | `PORT=9000 node examples/demo-server.mjs`, or `--port 4041` for the UI |
| UI answers `403 Invalid or missing token` | Opened the URL without the token | Use the full URL printed by `ui` |
| Browser shows `{"jsonrpc":"2.0","error":{"code":-32601,...}}` | You opened the MCP endpoint in a tab | Open the UI URL and paste the endpoint into the form |
| UI answers `That is this UI, not an MCP endpoint` | Pasted the UI's own URL | Paste the server's `/mcp` URL |
| `network isolation is unavailable` | `unshare` is not permitted | Use `--allow-unisolated` **only** for the fixtures in this repo |
| `command not found: mcpobs` | You are running from source | Use `node dist/cli.js …`, or `npx github:RubenDelgadoPareja/mcp-threat-observatory …` |
| Browser cannot reach the UI from Windows | WSL2 forwarding is off | Run `node dist/cli.js ui --port 4040` and open `http://localhost:4040/?token=…` in Windows; if it still fails, use the WSL IP printed by `hostname -I` |

## What you are looking at

A record, not a verdict. Every finding separates what was observed from what was
inferred, states its confidence, and lists what it cannot support. The negative
control in step 2 is the part that makes the positive result mean something.
