# Assessment, HTML reports and the local UI

Three ways to get from "I have a server" to "I have something to read", with one
rule: **everything runs on your machine**.

## `mcpobs assess`

Combines the two collection modes into one artefact.

```bash
mcpobs assess --url https://server.example/mcp -- node dist/index.js
mcpobs assess --url https://server.example/mcp      # passive only
mcpobs assess -- node dist/index.js                 # behavioural only
```

Output: `assessments/YYYY-MM-DD/<label>-<fingerprint>.json` plus a matching
`.html`, and the report on stdout.

### The link is an assertion, not an observation

The collector has no way to prove that the URL and the command are the same
server. So the artefact records how the link was established:

| `target.link` | Meaning |
| --- | --- |
| `url-only` | Only a passive record exists |
| `command-only` | Only a behavioural record exists |
| `operator-asserted` | Both were supplied together by the operator |

The `operator-asserted` case adds a limitation to every assessment that uses it.
This is the same discipline as `observed` vs `inferred`, applied to a different
question: not "is this true" but "how do you know these two things are the same
thing".

## HTML reports

```bash
mcpobs scan https://server.example/mcp --html report.html
mcpobs assess --url https://server.example/mcp -- node dist/index.js
```

The document is self-contained: inline CSS, no scripts, no fonts or assets
fetched from anywhere. It opens from disk, survives being emailed, and makes no
network request when viewed.

Severity, assertion and confidence stay visible per finding; the limitations are
collapsible but present.

## `mcpobs ui`

```bash
mcpobs ui --port 4040 --open
# http://127.0.0.1:4040/?token=<random>
```

Paste an endpoint, tick the attestation, get the report in the browser.

### Why it is local, and why that is not a limitation

| Constraint | Reason |
| --- | --- |
| Binds to `127.0.0.1` only | It is not reachable from the network |
| Token in the URL, required | Another local process or a website cannot drive it |
| `Origin` checked on POST | A cross-origin form cannot trigger a scan |
| No command field | Executing arbitrary code from a browser request is remote code execution, not a feature |
| Passive only | The behavioural mode executes code and stays on the CLI |

A public page that scans arbitrary URLs looks convenient and creates three
problems at once: your host becomes scanning infrastructure for anyone, the
service is an SSRF pivot unless it blocks private ranges, link-local addresses and
DNS rebinding, and it contradicts the authorisation model the rest of the project
enforces.

The local UI gets the same experience without any of that. The scan happens on
the operator's machine, under the operator's responsibility.

### What the attestation means

The form requires a checkbox: *"I operate this server, or I have written
permission to observe it."* The snapshot records that the authorisation was
attested by the operator and that the collector cannot verify it. An attestation
is not a permission check; it is a record of who claimed what.
