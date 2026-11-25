# I threat-modelled my own collector and found an injection

*Security tools parse hostile input. Mine parsed it and then printed it to your
terminal.*

Published 2026-11-25 · TLP:CLEAR

The collector in this repository exists to inspect untrusted MCP servers. It
reads their tool names, descriptions, schemas, error strings and stdout. Then it
writes a report that a human reads in a shell.

That last step is the problem. I had escaped HTML. I had not thought about what a
shell does with the bytes.

## The finding

A tool description is attacker-controlled text. This one is synthetic:

```json
{
  "name": "get_notes",
  "description": "Get notes\u001b[2J\u001b[H\u001b]0;pwned\u0007"
}
```

Rendered into a Markdown report, that sequence does three things: clears the
screen, moves the cursor home, and sets the terminal window title. The reader
sees an empty terminal and a report that appears to have vanished. Nothing is
corrupted — the bytes are in the file — but the instrument has just been made to
lie about what it printed.

I wrote a failing test before the fix:

```ts
const markdown = renderMarkdown(poisoned());
expect(markdown).not.toContain("\u001b");
```

It failed, as it should.

## Why the asymmetry existed

The HTML renderer escaped `<`, `>`, `&`, quotes. That is the reflex every web
developer has, and it is correct.

The Markdown renderer did nothing, because Markdown feels like plain text. It is
not: `renderMarkdown` output is printed to a terminal, and a terminal is an
interpreter with its own control language. The same applies to `less`, `tmux`,
CI logs, and the terminal inside an IDE.

The rule I had missed: **escaping is a property of the output medium, not of the
string.** One string needs different treatment for HTML, for a shell, and for a
JSON file.

## The fix, and the line I drew

Sanitisation happens at the **rendering boundary**, not at ingestion.

| Layer | Treatment |
| --- | --- |
| Raw record (`snapshot.json`, behaviour artefact) | Bytes preserved. It is evidence. |
| Markdown report (terminal) | C0/C1 except tab and newline, bidi controls, zero-width and Unicode tag characters removed |
| HTML report (browser) | Same, plus HTML escaping |
| `cat snapshot.json` | Safe already: `JSON.stringify` turns control characters into `\u001b` |

That asymmetry is worth stating plainly: the machine-readable artefact was never
the dangerous one. The human-readable report was. Stripping the bytes from the
record would have destroyed evidence to protect a display; sanitising the display
keeps both.

## Two more, found by writing the document

Threat modelling is a reading exercise that keeps producing findings, which is
why it is worth doing before someone else does it.

**Unbounded line buffering.** The stdio client used `readline`, which buffers
until it sees a newline. A server that writes gigabytes without one is a memory
exhaustion primitive against the collector. The fix is a bounded splitter: 2 MiB
per line, then kill the process and reject the request. The test writes
`MAX_LINE_BYTES + 1024` bytes and expects a rejection, not a hang.

**Unbounded schema recursion.** Argument generation walked a JSON Schema
recursively. A deeply nested schema is a stack overflow, and a schema with tens of
thousands of properties is a slow loop before every tool call. Both are now
bounded: depth 8, 100 properties.

## What is still not contained

This is the part that belongs in the same document as the fixes, not in a
footnote.

| Dimension | Contained? |
| --- | --- |
| Network egress | **Yes.** `unshare -rn`, no route, no DNS, fail-closed |
| Filesystem | **No.** A temporary `HOME` limits accidents, not a determined process |
| Child processes | **No.** A spawned process stays in the namespaces and leaves the Node hook behind |
| Terminal and HTML output | Hardened in this pass |

The network is a boundary. The rest is a seatbelt. Every artefact says so, and
now there is a document with the full table.

## The general lesson

Every security tool is a renderer of hostile input. Scanners print banners, HTTP
headers, certificate subjects, package descriptions, error messages. Most of them
were written by someone thinking about the target and not about their own output
path.

Two questions catch most of it:

1. **Which strings in this output came from the thing I am inspecting?**
2. **What interprets this output — a browser, a shell, a log viewer, an LLM?**

If the answer to the second is "something with its own control language", the
first question has a follow-up: what is the escape function for that language,
and did I call it?

## Reproduce it

```bash
npx vitest run test/render-safety.test.ts
npx vitest run test/behaviour/stdio.test.ts
```

The threat model is in `docs/THREAT-MODEL.md`. It includes what the tool does not
contain, because a security document that only lists mitigations is marketing.

## One honest caveat

This is a design bug in my own tool, found by reading my own code. No CVE, no
third party affected, no clever exploitation. The value is not the severity; it
is that the instrument was measuring one attack surface while standing on
another, and nobody had written that down.
