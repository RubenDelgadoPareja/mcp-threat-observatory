"""Command line interface for the analysis layer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .drift import compare, render_drift
from .loader import find_duplicate_targets, load_corpus, load_snapshot
from .metrics import (
    assertion_counts,
    auth_posture,
    check_matrix,
    confidence_counts,
    findings_by_check,
    owasp_coverage,
    rows,
    severity_counts,
    target_rows,
    write_csv,
)
from .schema import CONFIDENCES, SEVERITIES, SchemaError
from .stix import validate_bundle
from .table import render


def _print_json(data: object) -> None:
    print(json.dumps(data, indent=2, default=str))


def cmd_summarize(args: argparse.Namespace) -> int:
    snapshots = load_corpus(args.paths)
    severities = severity_counts(snapshots)
    confidences = confidence_counts(snapshots)
    assertions = assertion_counts(snapshots)
    posture = auth_posture(snapshots)
    duplicates = find_duplicate_targets(snapshots)

    if args.json:
        _print_json(
            {
                "snapshots": len(snapshots),
                "targets": len({snapshot.target for snapshot in snapshots}),
                "severity": severities,
                "confidence": confidences,
                "assertion": assertions,
                "auth_posture": posture,
                "duplicate_targets": duplicates,
                "findings_by_check": findings_by_check(snapshots),
            }
        )
        return 0

    total = sum(severities.values())
    print(
        f"Snapshots: {len(snapshots)}   "
        f"Targets: {len({snapshot.target for snapshot in snapshots})}   "
        f"Findings: {total}"
    )
    if duplicates:
        print(
            f"\nWarning: {len(duplicates)} target(s) observed more than once. "
            "Distributions count every observation, not every server."
        )

    print("\nSeverity")
    print(render(["severity", "count"], [[s, severities[s]] for s in SEVERITIES], {1: "right"}))

    print("\nConfidence")
    print(render(["level", "count"], [[c, confidences[c]] for c in CONFIDENCES], {1: "right"}))

    print("\nAssertion")
    print(
        render(
            ["kind", "count"],
            [["observed", assertions["observed"]], ["inferred", assertions["inferred"]]],
            {1: "right"},
        )
    )

    print("\nAuthentication posture")
    print(render(["posture", "servers"], [[k, v] for k, v in posture.items()], {1: "right"}))

    print("\nTargets")
    print(
        render(
            ["target", "auth", "tools", "findings", "highest"],
            [
                [row["target"], row["auth"], "?" if row["tools"] is None else row["tools"], row["findings"], row["highest_severity"]]
                for row in sorted(target_rows(snapshots), key=lambda row: row["target"])
            ],
            {2: "right", 3: "right"},
        )
    )
    return 0


def cmd_checks(args: argparse.Namespace) -> int:
    snapshots = load_corpus(args.paths)
    matrix = check_matrix(snapshots)

    if args.json:
        _print_json(matrix)
        return 0

    if not matrix:
        print("No findings in the corpus.")
        return 0

    header = ["check", *SEVERITIES, "total"]
    body = []
    totals = {severity: 0 for severity in SEVERITIES}
    for check_id, counts in matrix.items():
        row = [check_id]
        row.extend(counts[severity] for severity in SEVERITIES)
        row.append(sum(counts.values()))
        body.append(row)
        for severity in SEVERITIES:
            totals[severity] += counts[severity]
    body.append(["total", *(totals[s] for s in SEVERITIES), sum(totals.values())])

    print(render(header, body, {1: "right", 2: "right", 3: "right", 4: "right", 5: "right"}))
    print("\nA finding is a signal for review, not a verdict.")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    previous = load_snapshot(args.previous)
    current = load_snapshot(args.current)
    drift = compare(previous, current)

    if args.json:
        _print_json(
            {
                "targets_match": drift.targets_match,
                "counts": drift.counts(),
                "added": [finding.fingerprint for finding in drift.added],
                "removed": [finding.fingerprint for finding in drift.removed],
                "tool_changes": [
                    {"name": change.name, "change": change.change, "detail": change.detail}
                    for change in drift.tool_changes
                ],
            }
        )
        return 0

    print(render_drift(drift))
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    snapshots = load_corpus(args.paths)
    data = rows(snapshots)
    if args.format == "csv":
        count = write_csv(args.out, data)
        print(f"wrote {count} finding row(s) to {args.out}")
    else:
        target = Path(args.out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"wrote {len(data)} finding row(s) to {args.out}")
    return 0


def cmd_validate_stix(args: argparse.Namespace) -> int:
    result = validate_bundle(args.bundle, deep=args.deep)
    print(result.summary())
    return 0 if result.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpobs-analysis",
        description="Longitudinal analysis of mcp-threat-observatory snapshots.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    summarize = sub.add_parser("summarize", help="corpus-level distributions")
    summarize.add_argument("paths", nargs="+", help="snapshot files or directories")
    summarize.add_argument("--json", action="store_true")
    summarize.set_defaults(handler=cmd_summarize)

    checks = sub.add_parser("checks", help="finding frequency per check")
    checks.add_argument("paths", nargs="+")
    checks.add_argument("--json", action="store_true")
    checks.set_defaults(handler=cmd_checks)

    compare_cmd = sub.add_parser("compare", help="drift between two snapshots of one target")
    compare_cmd.add_argument("previous")
    compare_cmd.add_argument("current")
    compare_cmd.add_argument("--json", action="store_true")
    compare_cmd.set_defaults(handler=cmd_compare)

    export = sub.add_parser("export", help="flat dataset export")
    export.add_argument("paths", nargs="+")
    export.add_argument("--csv", dest="out", required=True, help="output path")
    export.add_argument("--format", choices=("csv", "json"), default="csv")
    export.set_defaults(handler=cmd_export)

    stix = sub.add_parser("validate-stix", help="validate a STIX 2.1 bundle")
    stix.add_argument("bundle")
    stix.add_argument("--deep", action="store_true", help="also parse with the stix2 reference library")
    stix.set_defaults(handler=cmd_validate_stix)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except SchemaError as error:
        print(f"schema error: {error}", file=sys.stderr)
        return 2
