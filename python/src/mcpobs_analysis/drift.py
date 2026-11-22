"""Drift between two snapshots of the same target.

This is the rug-pull primitive: a server that passes review and then changes a
tool description, a schema, or an annotation. Comparing only descriptions misses
the most important change, because flipping `destructiveHint` alters approval
behaviour without touching a single visible word.
"""

from __future__ import annotations

from dataclasses import dataclass

from .schema import Finding, Snapshot, tool_signature


@dataclass(frozen=True)
class ToolChange:
    name: str
    change: str
    detail: str


@dataclass(frozen=True)
class Drift:
    previous: Snapshot
    current: Snapshot
    added: tuple[Finding, ...]
    removed: tuple[Finding, ...]
    retained: tuple[Finding, ...]
    tool_changes: tuple[ToolChange, ...]

    @property
    def targets_match(self) -> bool:
        return self.previous.target == self.current.target

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.tool_changes)

    def counts(self) -> dict[str, int]:
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "retained": len(self.retained),
            "tool_changes": len(self.tool_changes),
        }


def _explain_tool_change(before: dict, after: dict) -> str:
    parts: list[str] = []
    if before.get("description") != after.get("description"):
        parts.append("description")
    if before.get("title") != after.get("title"):
        parts.append("title")
    if before.get("annotations") != after.get("annotations"):
        parts.append("annotations")
    if before.get("inputSchema") != after.get("inputSchema"):
        parts.append("inputSchema")
    return ", ".join(parts) or "unknown"


def compare(previous: Snapshot, current: Snapshot) -> Drift:
    before = {finding.fingerprint: finding for finding in previous.findings}
    after = {finding.fingerprint: finding for finding in current.findings}

    added = tuple(after[key] for key in sorted(after.keys() - before.keys()))
    removed = tuple(before[key] for key in sorted(before.keys() - after.keys()))
    retained = tuple(after[key] for key in sorted(after.keys() & before.keys()))

    before_tools = {tool.get("name"): tool for tool in previous.tools if tool.get("name")}
    after_tools = {tool.get("name"): tool for tool in current.tools if tool.get("name")}

    changes: list[ToolChange] = []
    for name in sorted(after_tools.keys() - before_tools.keys()):
        changes.append(ToolChange(name=name, change="added", detail="tool appeared in the catalog"))
    for name in sorted(before_tools.keys() - after_tools.keys()):
        changes.append(ToolChange(name=name, change="removed", detail="tool disappeared from the catalog"))
    for name in sorted(before_tools.keys() & after_tools.keys()):
        old, new = before_tools[name], after_tools[name]
        if tool_signature(old) != tool_signature(new):
            changes.append(
                ToolChange(
                    name=name,
                    change="modified",
                    detail=f"changed: {_explain_tool_change(old, new)}",
                )
            )

    return Drift(
        previous=previous,
        current=current,
        added=added,
        removed=removed,
        retained=retained,
        tool_changes=tuple(changes),
    )


def render_drift(drift: Drift) -> str:
    counts = drift.counts()
    lines: list[str] = []
    lines.append(f"## Drift: {drift.previous.target}")
    lines.append("")
    if not drift.targets_match:
        lines.append(
            f"> Warning: comparing different targets (`{drift.previous.target}` vs "
            f"`{drift.current.target}`). Fingerprints are per-target, so every finding "
            "will appear as removed and added."
        )
        lines.append("")
    lines.append(f"- before: {drift.previous.collected_at}")
    lines.append(f"- after:  {drift.current.collected_at}")
    lines.append(
        f"- findings: +{counts['added']} / -{counts['removed']} / ={counts['retained']} "
        f"· catalog changes: {counts['tool_changes']}"
    )
    lines.append("")

    if drift.is_empty:
        lines.append("No change observed between the two records.")
        lines.append("")
        return "\n".join(lines)

    if drift.tool_changes:
        lines.append("### Tool catalog changes")
        lines.append("")
        for change in drift.tool_changes:
            lines.append(f"- `{change.name}` — **{change.change}** ({change.detail})")
        lines.append("")

    for label, findings in (("New findings", drift.added), ("Resolved findings", drift.removed)):
        if not findings:
            continue
        lines.append(f"### {label}")
        lines.append("")
        for finding in findings:
            lines.append(
                f"- `{finding.check_id}` **{finding.severity}** / {finding.confidence} — {finding.title}"
            )
            lines.append(f"  - {finding.observation}")
        lines.append("")

    return "\n".join(lines)
