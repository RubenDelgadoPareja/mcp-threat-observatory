"""Analysis layer for mcp-threat-observatory snapshots.

The collector is TypeScript because it runs at the edge of a developer's
workstation. The analysis is Python because that is where threat-intelligence
work actually happens: notebooks, pandas, and the reference `stix2`
implementation.

Core has no third-party dependencies. Heavier stacks are optional extras:

    pip install "mcpobs-analysis[analysis]"   # pandas, matplotlib
    pip install "mcpobs-analysis[stix]"       # stix2 reference implementation
"""

from .drift import Drift, ToolChange, compare, render_drift
from .loader import load_corpus, load_index, load_snapshot
from .metrics import (
    auth_posture,
    check_matrix,
    confidence_counts,
    findings_by_check,
    owasp_coverage,
    rows,
    severity_counts,
    to_dataframe,
    write_csv,
)
from .schema import Finding, SchemaError, Snapshot
from .stix import ValidationResult, validate_bundle

__version__ = "0.1.0"

__all__ = [
    "Drift",
    "Finding",
    "SchemaError",
    "Snapshot",
    "ToolChange",
    "ValidationResult",
    "auth_posture",
    "check_matrix",
    "compare",
    "confidence_counts",
    "findings_by_check",
    "load_corpus",
    "load_index",
    "load_snapshot",
    "owasp_coverage",
    "render_drift",
    "rows",
    "severity_counts",
    "to_dataframe",
    "validate_bundle",
    "write_csv",
]
