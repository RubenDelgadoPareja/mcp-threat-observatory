"""Typed view over a snapshot record.

Mirrors `src/model.ts`. The rule is the same: `None` means unknown, and it is
never coerced into a default. A Python analysis that silently turns "we did not
look" into zero is how a dataset starts lying.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "moderate", "low")
ASSERTIONS = ("observed", "inferred")


class SchemaError(ValueError):
    """Raised when a file is not a usable snapshot."""


def _get(mapping: Any, key: str, where: str, types: tuple[type, ...], *, nullable: bool = False):
    if not isinstance(mapping, dict):
        raise SchemaError(f"{where}: expected an object")
    if key not in mapping:
        raise SchemaError(f"{where}: missing required key '{key}'")
    value = mapping[key]
    if value is None:
        if nullable:
            return None
        raise SchemaError(f"{where}.{key}: null is not allowed here")
    if not isinstance(value, types):
        expected = ", ".join(t.__name__ for t in types)
        raise SchemaError(f"{where}.{key}: expected {expected}, got {type(value).__name__}")
    return value


def _str_tuple(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise SchemaError(f"{where}: expected a list of strings")
    return tuple(value)


@dataclass(frozen=True)
class Finding:
    fingerprint: str
    check_id: str
    title: str
    severity: str
    confidence: str
    assertion: str
    taxonomy: tuple[str, ...]
    owasp: tuple[str, ...]
    observation: str
    inference: str | None
    recommendation: str | None
    limitations: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: Any, where: str) -> "Finding":
        severity = _get(data, "severity", where, (str,))
        if severity not in SEVERITIES:
            raise SchemaError(f"{where}.severity: unknown value {severity!r}")
        confidence = _get(data, "confidence", where, (str,))
        if confidence not in CONFIDENCES:
            raise SchemaError(f"{where}.confidence: unknown value {confidence!r}")
        assertion = _get(data, "assertion", where, (str,))
        if assertion not in ASSERTIONS:
            raise SchemaError(f"{where}.assertion: unknown value {assertion!r}")

        return cls(
            fingerprint=_get(data, "fingerprint", where, (str,)),
            check_id=_get(data, "checkId", where, (str,)),
            title=_get(data, "title", where, (str,)),
            severity=severity,
            confidence=confidence,
            assertion=assertion,
            taxonomy=_str_tuple(data.get("taxonomy"), f"{where}.taxonomy"),
            owasp=_str_tuple(data.get("owasp"), f"{where}.owasp"),
            observation=_get(data, "observation", where, (str,)),
            inference=data.get("inference"),
            recommendation=data.get("recommendation"),
            limitations=_str_tuple(data.get("limitations"), f"{where}.limitations"),
        )

    @property
    def is_inference(self) -> bool:
        return self.assertion == "inferred"


@dataclass(frozen=True)
class Snapshot:
    path: Path
    target: str
    collected_at: str
    reachable: bool
    requires_auth: bool | None
    status_on_initialize: int | None
    tools: tuple[dict, ...]
    findings: tuple[Finding, ...]
    raw: dict

    @classmethod
    def from_dict(cls, data: Any, path: Path = Path("<memory>")) -> "Snapshot":
        where = str(path)
        if not isinstance(data, dict) or "probe" not in data or "findings" not in data:
            raise SchemaError(f"{where}: not a snapshot (expected 'probe' and 'findings')")

        probe = data["probe"]
        auth = probe.get("auth") or {}
        handshake = probe.get("handshake") or {}
        raw_findings = data["findings"]
        if not isinstance(raw_findings, list):
            raise SchemaError(f"{where}.findings: expected a list")

        tools = probe.get("tools")
        if tools is not None and not isinstance(tools, list):
            raise SchemaError(f"{where}.probe.tools: expected a list or null")

        return cls(
            path=path,
            target=_get(probe, "target", f"{where}.probe", (str,)),
            collected_at=_get(probe, "collectedAt", f"{where}.probe", (str,)),
            reachable=bool(_get(probe, "reachable", f"{where}.probe", (bool,))),
            requires_auth=auth.get("requiresAuth"),
            status_on_initialize=auth.get("statusOnUnauthenticatedInitialize"),
            tools=tuple(tools or ()),
            findings=tuple(
                Finding.from_dict(item, f"{where}.findings[{index}]")
                for index, item in enumerate(raw_findings)
            ),
            raw=data,
        )

    @property
    def tools_count(self) -> int | None:
        """`None` means the catalog was never obtained. Not zero."""
        if self.raw.get("probe", {}).get("tools") is None:
            return None
        return len(self.tools)

    @property
    def auth_label(self) -> str:
        if not self.reachable:
            return "unreachable"
        if self.requires_auth is True:
            return "403 forbidden" if self.status_on_initialize == 403 else "401 challenge"
        if self.requires_auth is False:
            return "unauthenticated"
        return "unknown"


def tool_signature(tool: dict) -> str:
    """Stable hash of the parts of a tool definition that matter to a client.

    Hashing the whole definition, not just the description, is deliberate: a
    flipped `destructiveHint` changes approval behaviour without changing any
    visible text.
    """
    material = {
        "name": tool.get("name"),
        "title": tool.get("title"),
        "description": tool.get("description"),
        "annotations": tool.get("annotations"),
        "inputSchema": tool.get("inputSchema"),
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
