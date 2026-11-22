"""Dependency-free table rendering. Terminal output, no colour, no magic."""

from __future__ import annotations

from typing import Iterable, Sequence


def render(
    headers: Sequence[str],
    rows: Iterable[Sequence[object]],
    aligns: dict[int, str] | None = None,
) -> str:
    materialised = [[str(cell) for cell in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in materialised:
        for index, cell in enumerate(row):
            if index < len(widths):
                widths[index] = max(widths[index], len(cell))

    aligns = aligns or {}

    def fmt(cells: Sequence[str]) -> str:
        parts = []
        for index, cell in enumerate(cells):
            width = widths[index] if index < len(widths) else len(cell)
            if aligns.get(index) == "right":
                parts.append(cell.rjust(width))
            else:
                parts.append(cell.ljust(width))
        return "  ".join(parts).rstrip()

    lines = [fmt(list(headers))]
    lines.append("  ".join("-" * width for width in widths).rstrip())
    lines.extend(fmt(row) for row in materialised)
    return "\n".join(lines)
