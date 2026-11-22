"""Aggregations over a corpus of snapshots.

Every function takes an iterable of `Snapshot` and returns plain Python data,
so the same numbers can be printed in a terminal, exported to CSV, or handed to
pandas without a second code path.
"""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .schema import CONFIDENCES, SEVERITIES, Snapshot

AUTH_LABELS = ("unauthenticated", "401 challenge", "403 forbidden", "unreachable", "unknown")


def severity_counts(snapshots: Iterable[Snapshot]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for snapshot in snapshots:
        for finding in snapshot.findings:
            counts[finding.severity] += 1
    return counts


def confidence_counts(snapshots: Iterable[Snapshot]) -> dict[str, int]:
    counts = {level: 0 for level in CONFIDENCES}
    for snapshot in snapshots:
        for finding in snapshot.findings:
            counts[finding.confidence] += 1
    return counts


def assertion_counts(snapshots: Iterable[Snapshot]) -> dict[str, int]:
    counts = {"observed": 0, "inferred": 0}
    for snapshot in snapshots:
        for finding in snapshot.findings:
            counts[finding.assertion] += 1
    return counts


def findings_by_check(snapshots: Iterable[Snapshot]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for snapshot in snapshots:
        for finding in snapshot.findings:
            counter[finding.check_id] += 1
    return dict(sorted(counter.items()))


def check_matrix(snapshots: Iterable[Snapshot]) -> dict[str, dict[str, int]]:
    """Findings per check, broken down by severity."""
    matrix: dict[str, dict[str, int]] = {}
    for snapshot in snapshots:
        for finding in snapshot.findings:
            row = matrix.setdefault(finding.check_id, {severity: 0 for severity in SEVERITIES})
            row[finding.severity] += 1
    return dict(sorted(matrix.items()))


def auth_posture(snapshots: Iterable[Snapshot]) -> dict[str, int]:
    counts = {label: 0 for label in AUTH_LABELS}
    for snapshot in snapshots:
        counts[snapshot.auth_label] = counts.get(snapshot.auth_label, 0) + 1
    return counts


def owasp_coverage(snapshots: Iterable[Snapshot]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for snapshot in snapshots:
        for finding in snapshot.findings:
            for identifier in finding.owasp:
                counter[identifier] += 1
    return dict(sorted(counter.items()))


def target_rows(snapshots: Iterable[Snapshot]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for snapshot in snapshots:
        rows.append(
            {
                "target": snapshot.target,
                "collected_at": snapshot.collected_at,
                "reachable": snapshot.reachable,
                "auth": snapshot.auth_label,
                "tools_known": snapshot.tools_count is not None,
                "tools": snapshot.tools_count,
                "findings": len(snapshot.findings),
                "highest_severity": _highest(snapshot),
            }
        )
    return rows


def _highest(snapshot: Snapshot) -> str:
    for severity in SEVERITIES:
        if any(finding.severity == severity for finding in snapshot.findings):
            return severity
    return "none"


FINDING_COLUMNS = (
    "target",
    "collected_at",
    "check_id",
    "severity",
    "confidence",
    "assertion",
    "owasp",
    "taxonomy",
    "fingerprint",
)


def rows(snapshots: Iterable[Snapshot]) -> list[dict[str, Any]]:
    """One row per finding, flat and CSV/DataFrame ready."""
    out: list[dict[str, Any]] = []
    for snapshot in snapshots:
        for finding in snapshot.findings:
            out.append(
                {
                    "target": snapshot.target,
                    "collected_at": snapshot.collected_at,
                    "check_id": finding.check_id,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "assertion": finding.assertion,
                    "owasp": ";".join(finding.owasp),
                    "taxonomy": ";".join(finding.taxonomy),
                    "fingerprint": finding.fingerprint,
                }
            )
    return out


def write_csv(path: str | Path, data: list[dict[str, Any]], columns: tuple[str, ...] = FINDING_COLUMNS) -> int:
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    with file.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(columns))
        writer.writeheader()
        for row in data:
            writer.writerow({column: row.get(column, "") for column in columns})
    return len(data)


def to_dataframe(snapshots: Iterable[Snapshot]):
    """Returns a pandas DataFrame, or explains how to install pandas.

    Import is deliberately lazy: the core package stays installable on a
    locked-down analyst laptop with no package index.
    """
    try:
        import pandas as pd
    except ImportError as error:  # pragma: no cover - depends on environment
        raise RuntimeError(
            "pandas is not installed. Use `pip install \"mcpobs-analysis[analysis]\"` "
            "or call rows() and build the DataFrame yourself."
        ) from error

    return pd.DataFrame(rows(snapshots))
