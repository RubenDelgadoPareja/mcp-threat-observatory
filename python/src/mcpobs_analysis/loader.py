"""Reading snapshots and indexes from disk."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Iterator

from .schema import SchemaError, Snapshot


def _looks_like_snapshot(data: object) -> bool:
    return isinstance(data, dict) and "probe" in data and "findings" in data


def load_snapshot(path: str | Path) -> Snapshot:
    file = Path(path)
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SchemaError(f"{file}: not found") from error
    except json.JSONDecodeError as error:
        raise SchemaError(f"{file}: invalid JSON ({error.msg} at line {error.lineno})") from error
    return Snapshot.from_dict(data, file)


def iter_snapshot_paths(paths: Iterable[str | Path]) -> Iterator[Path]:
    """Expands files and directories into snapshot files, deterministically."""
    for entry in paths:
        path = Path(entry)
        if path.is_dir():
            for candidate in sorted(path.rglob("*.json")):
                if candidate.name.startswith("."):
                    continue
                yield candidate
        elif path.exists():
            yield path
        else:
            raise SchemaError(f"{path}: no such file or directory")


def load_corpus(paths: Iterable[str | Path]) -> list[Snapshot]:
    """Loads every snapshot under the given paths.

    Files that parse as JSON but are not snapshots (for example a STIX bundle)
    are skipped when found by directory scan, and rejected when named
    explicitly. Silence would hide a typo; a hard error on an explicit path
    keeps the reader honest.
    """
    explicit_files = {Path(p) for p in paths if Path(p).is_file()}
    snapshots: list[Snapshot] = []

    for file in iter_snapshot_paths(paths):
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            if file in explicit_files:
                raise SchemaError(f"{file}: invalid JSON ({error.msg})") from error
            continue

        if not _looks_like_snapshot(data):
            if file in explicit_files:
                raise SchemaError(f"{file}: not a snapshot (expected 'probe' and 'findings')")
            continue

        snapshots.append(Snapshot.from_dict(data, file))

    if not snapshots:
        raise SchemaError("no snapshots found in the given paths")
    return snapshots


def load_index(path: str | Path) -> list[dict]:
    """Reads the append-only index.jsonl written by the collector."""
    file = Path(path)
    entries: list[dict] = []
    for line_no, line in enumerate(file.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise SchemaError(f"{file}:{line_no}: invalid JSON line") from error
    return entries


def find_duplicate_targets(snapshots: Iterable[Snapshot]) -> dict[str, int]:
    """Targets observed more than once. Useful before computing distributions."""
    counts: dict[str, int] = {}
    for snapshot in snapshots:
        counts[snapshot.target] = counts.get(snapshot.target, 0) + 1
    return {target: count for target, count in counts.items() if count > 1}
