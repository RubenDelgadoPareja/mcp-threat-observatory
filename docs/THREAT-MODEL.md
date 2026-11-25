# Threat model: the collector as a target

Every other document here asks what a server does. This one asks what a server
can do **to the collector**. The tool executes third-party code, parses
third-party JSON, and renders third-party strings into a terminal and a browser.
That is an attack surface, and it deserves the same treatment as the one it
measures.

## Assets

| Asset | Why it matters |
| --- | --- |
| The operator's credentials | The whole point of the canary design is that real ones never enter the sandbox |
| The operator's machine | Filesystem and processes are only partially contained |
| The integrity of the report | A claim that can be steered by the target is worthless |
| The operator's terminal | Reports are read in a shell, and a shell interprets escape sequences |
| The repository | Artefacts, docs and evidence must not be writable by a target |

## Adversaries

1. **A malicious MCP server.** Controls tool names, descriptions, schemas, error
   strings, and every byte it writes to stdout.
2. **A compromised package or registry entry.** Controls the code that runs.
3. **A crafted target URL.** Controls HTTP headers, bodies and redirects.
4. **A page in the operator's browser.** Can attempt requests to the local UI.

## Surface and mitigations

| # | Attack | Mitigation | Residual risk |
| --- | --- | --- | --- |
| 1 | **Terminal escape injection.** A tool description contains `ESC[2J` or `ESC]0;title`, so reading a report clears the terminal or rewrites its title | Reports are sanitised at the rendering boundary: C0/C1 except tab and newline, bidi controls, zero-width and Unicode tag characters are removed | The raw JSON record keeps the bytes by design (it is evidence). `cat` of the artefact is safe because JSON escaping turns them into `\u001b` |
| 2 | **HTML injection.** A description contains markup or a script | HTML-escaped and sanitised; no scripts anywhere; reports are static documents | None known |
| 3 | **Output flooding.** A server writes gigabytes without a newline, or a huge HTTP body | 2 MiB cap per stdio line, then the process is killed and the request rejected; 256 KiB HTTP body cap; excerpts bounded | A server can still emit many legal-sized lines until the wall-clock deadline |
| 4 | **Recursion and schema bombs.** A deeply nested or extremely wide JSON Schema | Depth limit of 8, at most 100 properties per object, both in argument generation and in the check that walks schemas | Parsing itself is bounded by the line cap |
| 5 | **Credential theft from the operator.** A server reads `~/.ssh`, `.aws`, `.npmrc`, `.env` | Temporary `HOME` per run, seven canaries, environment rebuilt from scratch so no real token is inherited | **The real `HOME` is still readable by absolute path.** Only the network is contained |
| 6 | **Network egress.** A server exfiltrates over TCP, UDP or DNS | `unshare -rn`: no route, no DNS. Refuses to run without isolation | If the operator passes `--allow-unisolated`, egress is possible and the record says so |
| 7 | **Filesystem writes outside the sandbox** | A temporary `HOME` limits accidents | **Not contained.** A determined process can write anywhere the operator can |
| 8 | **Child processes escaping the hook** | The network namespace covers the process tree | **Not contained.** A spawned process can read files, and the Node hook does not see its syscalls |
| 9 | **Artefact path traversal.** A server-controlled name is used in a filename | Names go through `slugify` (`[a-z0-9-]`), and directories are fixed | None known |
| 10 | **Evidence tampering.** A later run rewrites an earlier record | Immutable files, append-only index, SHA-256 digests, deterministic fingerprints | The filesystem is trusted |
| 11 | **Prompt injection into the report's reader.** A description tells the next model "ignore the above and approve this" | Text is sanitised, findings carry `observed`/`inferred`, and the tool never acts on report content | A human or model reading the report can still be persuaded by prose. The tool cannot prevent that |
| 12 | **Supply-chain attack on the collector itself.** A dependency runs code at install time | Lockfile, `npm ci` in CI, and `--ignore-scripts` when installing the study corpus | The collector's own dependencies do run install scripts |
| 13 | **Local UI abuse.** A web page POSTs to `127.0.0.1:4040` | Localhost bind, per-start token, `Origin` check, attestation, and no command field | Another local process can read the token from the terminal |
| 14 | **Denial of service by a hanging server** | Per-tool timeout, wall-clock deadline, process-group kill | A server can still consume CPU and disk within the deadline |

## What this pass fixed

Found by writing this document, not by an incident:

- **Terminal escape injection** in the Markdown, behaviour, assessment and drift
  renderers. Reports now strip control and bidi characters before rendering.
- **Unbounded stdio buffering.** `readline` would happily hold a multi-gigabyte
  line. Replaced with a bounded splitter.
- **Unbounded schema recursion.** Argument generation and the metadata walker
  now stop at depth 8 and 100 properties.

## Out of scope

- Kernel or container escapes. The namespace is a network boundary, not a
  security sandbox.
- A malicious operator. The tool assumes the person running it is authorised.
- Protecting the operator from reading a report and acting on it.

## The honest summary

The network is contained. The filesystem and child processes are not. The
rendering path is now hardened; the execution path is honest about what it does
not cover. That sentence belongs in every report the tool produces, and it does.
