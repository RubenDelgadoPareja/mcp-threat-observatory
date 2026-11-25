"""Validation of STIX 2.1 bundles produced by the TypeScript collector.

Two levels:

* **structural** (no dependencies): identifiers, references, markings, timestamps.
  This catches the mistakes a hand-rolled exporter actually makes.
* **deep** (optional): hands the document to `stix2`, the reference
  implementation. That is the difference between "my objects look right to me"
  and "the ecosystem's own parser accepts them".

The second level is why this file exists in Python at all.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[45][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")

REF_FIELDS = ("created_by_ref", "source_ref", "target_ref")
REF_LIST_FIELDS = ("object_refs", "object_marking_refs")


@dataclass
class ValidationResult:
    issues: list[str] = field(default_factory=list)
    objects: int = 0
    deep_requested: bool = False
    deep_used: bool = False
    deep_note: str | None = None

    @property
    def ok(self) -> bool:
        return not self.issues

    def summary(self) -> str:
        state = "OK" if self.ok else f"{len(self.issues)} issue(s)"
        lines = [f"{state} — {self.objects} object(s) checked"]
        if self.deep_used:
            lines.append("deep validation: passed with the stix2 reference implementation")
        elif self.deep_requested:
            lines.append(f"deep validation: skipped — {self.deep_note or 'reference implementation unavailable'}")
        for issue in self.issues:
            lines.append(f"  - {issue}")
        return "\n".join(lines)


def _check_object(obj: dict, ids: set[str], index: int, issues: list[str]) -> None:
    where = f"objects[{index}]"
    if not isinstance(obj, dict):
        issues.append(f"{where}: not an object")
        return

    obj_type = obj.get("type")
    obj_id = obj.get("id")
    if not isinstance(obj_type, str):
        issues.append(f"{where}: missing 'type'")
        return
    if not isinstance(obj_id, str):
        issues.append(f"{where}: missing 'id'")
        return

    prefix, _, uuid_part = obj_id.partition("--")
    if prefix != obj_type:
        issues.append(f"{where}: id prefix {prefix!r} does not match type {obj_type!r}")
    if not UUID_RE.match(uuid_part):
        issues.append(f"{where}: id {obj_id!r} is not a UUIDv4/v5")

    if obj.get("spec_version") != "2.1":
        issues.append(f"{where} ({obj_type}): spec_version must be '2.1'")

    if obj_type != "marking-definition":
        for key in ("created", "modified"):
            value = obj.get(key)
            if not isinstance(value, str) or not ISO_RE.match(value):
                issues.append(f"{where} ({obj_type}): {key} is not an ISO 8601 UTC timestamp")

    # `confidence` was a common property in STIX 2.0 and is not one in 2.1.
    # An exporter that emits it in 2.1 is silently non-conformant.
    if "confidence" in obj:
        issues.append(f"{where} ({obj_type}): 'confidence' is not a STIX 2.1 common property")

    for key in REF_FIELDS:
        ref = obj.get(key)
        if ref is None:
            continue
        if not isinstance(ref, str) or ref not in ids:
            issues.append(f"{where} ({obj_type}): {key} does not resolve: {ref!r}")

    for key in REF_LIST_FIELDS:
        refs = obj.get(key)
        if refs is None:
            continue
        if not isinstance(refs, list):
            issues.append(f"{where} ({obj_type}): {key} must be a list")
            continue
        for ref in refs:
            if not isinstance(ref, str) or ref not in ids:
                issues.append(f"{where} ({obj_type}): {key} entry does not resolve: {ref!r}")


def validate_bundle(path: str | Path, deep: bool = False) -> ValidationResult:
    file = Path(path)
    result = ValidationResult(deep_requested=deep)

    try:
        text = file.read_text(encoding="utf-8")
        bundle = json.loads(text)
    except FileNotFoundError:
        result.issues.append(f"{file}: not found")
        return result
    except json.JSONDecodeError as error:
        result.issues.append(f"{file}: invalid JSON ({error.msg} at line {error.lineno})")
        return result

    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        result.issues.append("root object is not a STIX bundle")
        return result

    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        result.issues.append("bundle has no objects")
        return result

    result.objects = len(objects)

    ids = {obj.get("id") for obj in objects if isinstance(obj, dict) and isinstance(obj.get("id"), str)}
    if len(ids) != len(objects):
        result.issues.append("object identifiers are missing or not unique")

    for index, obj in enumerate(objects):
        _check_object(obj, ids, index, result.issues)

    markings = [
        obj for obj in objects if isinstance(obj, dict) and obj.get("type") == "marking-definition"
    ]
    if not markings:
        result.issues.append("bundle has no marking-definition (TLP marking missing)")

    if deep:
        try:
            import stix2  # type: ignore
        except ImportError:
            result.deep_note = 'install stix2: pip install "mcpobs-analysis[stix]"'
        else:
            try:
                # STIX 2.1 permits `x_`-prefixed custom properties; the reference
                # parser only accepts them when explicitly told to.
                stix2.parse(text, version="2.1", allow_custom=True)
                result.deep_used = True
            except Exception as error:  # the library raises several types
                result.issues.append(f"stix2 rejected the bundle: {error}")

    return result
