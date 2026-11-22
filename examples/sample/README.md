# Sample output

Generated from `examples/demo-server.mjs`, a synthetic local endpoint. No
third-party server was contacted to produce these files.

| File | What it is |
| --- | --- |
| `snapshot.json` | The immutable record: probe, findings, summary |
| `report.md` | Human rendering, with observation/inference/limitations separated |
| `bundle.stix.json` | STIX 2.1 bundle (21 objects, TLP:CLEAR) |
| `report.html` | Self-contained HTML report — open it in a browser |

Reproduce them:

```bash
node examples/demo-server.mjs &
node dist/cli.js scan http://127.0.0.1:8787/mcp --authorized --out snapshots
node dist/cli.js report snapshots/*/*.json --format md
```
