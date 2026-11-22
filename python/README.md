# Analysis layer (Python)

The collector is TypeScript because it runs on a developer's machine and ships
through `npx`. The analysis is Python because that is where threat-intelligence
work actually happens: notebooks, pandas, and the reference `stix2`
implementation.

Two languages, two reasons. This is not a port.

## What lives here

| Module | Purpose |
| --- | --- |
| `schema.py` | Typed, validating view over a snapshot. `None` stays `None`. |
| `loader.py` | Loading snapshots, directories and the append-only index. |
| `metrics.py` | Distributions, check matrix, auth posture, CSV/DataFrame export. |
| `drift.py` | Diff between two snapshots, including annotation-only changes. |
| `stix.py` | Structural STIX 2.1 validation, plus optional deep validation with `stix2`. |
| `cli.py` | `summarize`, `checks`, `compare`, `export`, `validate-stix`. |

## Design: zero dependencies in the core

The core package imports only the standard library. A researcher on a locked-down
laptop can run it without a package index. Heavier stacks are explicit extras:

```bash
pip install -e ".[analysis]"   # pandas, matplotlib
pip install -e ".[stix]"       # stix2 reference implementation
```

## Quickstart

```bash
# from the repository root
python3 -m unittest discover -s python/tests -t python -v
cd python
PYTHONPATH=src python3 -m mcpobs_analysis summarize ../examples/corpus
PYTHONPATH=src python3 -m mcpobs_analysis checks ../examples/corpus
PYTHONPATH=src python3 -m mcpobs_analysis export ../examples/corpus --csv /tmp/findings.csv
PYTHONPATH=src python3 -m mcpobs_analysis validate-stix ../examples/sample/bundle.stix.json --deep
```

If you install the package (`pip install -e .`), the `mcpobs-analysis` entry
point replaces `PYTHONPATH=src python3 -m mcpobs_analysis`.

## Notebook

`notebooks/01_corpus_overview.ipynb` walks through the corpus: distributions,
check coverage, the observation/inference split, and a drift demonstration that
flips a single annotation without changing any visible text.

## Why validate STIX in Python

The collector writes STIX 2.1 by hand. Validating it with the ecosystem's own
parser is the difference between "my objects look right to me" and "a reference
implementation accepts them". The structural validator runs everywhere; the
deep one needs `stix2` and says so explicitly when it is unavailable rather than
claiming a check it did not perform.

## Tests

45 tests, standard library `unittest` (also runs under `pytest`):

- schema rejection cases
- corpus contract: every fixture produces exactly the expected check ids
- record invariants: every inference has moderate or low confidence, every
  finding states its limitations
- drift: description, annotation, added tool, new finding, mismatched targets
- STIX: id/type mismatch, dangling references, STIX 2.0 `confidence` field,
  missing TLP marking
