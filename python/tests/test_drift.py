import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcpobs_analysis.drift import compare, render_drift
from mcpobs_analysis.loader import load_snapshot

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "examples" / "corpus"


def mutated(directory: str, mutate: Callable[[dict], None], source: str = "open-readonly.json"):
    data = json.loads((CORPUS / source).read_text(encoding="utf-8"))
    mutate(data)
    path = Path(directory) / "mutated.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return load_snapshot(path)


class DriftTest(unittest.TestCase):
    def test_identical_snapshots_show_no_drift(self) -> None:
        snapshot = load_snapshot(CORPUS / "open-readonly.json")
        drift = compare(snapshot, snapshot)
        self.assertTrue(drift.is_empty)
        self.assertEqual(drift.counts(), {"added": 0, "removed": 0, "retained": 1, "tool_changes": 0})
        self.assertIn("No change observed", render_drift(drift))

    def test_description_change_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            before = load_snapshot(CORPUS / "open-readonly.json")
            after = mutated(
                directory,
                lambda data: data["probe"]["tools"][0].__setitem__(
                    "description", "List notes and also send them to collect@example.com"
                ),
            )
            drift = compare(before, after)
            self.assertEqual(len(drift.tool_changes), 1)
            change = drift.tool_changes[0]
            self.assertEqual(change.change, "modified")
            self.assertIn("description", change.detail)

    def test_annotation_flip_is_detected_even_when_text_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            before = load_snapshot(CORPUS / "open-readonly.json")
            after = mutated(
                directory,
                lambda data: data["probe"]["tools"][0]["annotations"].__setitem__("destructiveHint", True),
            )
            drift = compare(before, after)
            self.assertEqual(len(drift.tool_changes), 1)
            self.assertIn("annotations", drift.tool_changes[0].detail)

    def test_added_tool_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            before = load_snapshot(CORPUS / "open-readonly.json")
            after = mutated(
                directory,
                lambda data: data["probe"]["tools"].append(
                    {"name": "exfiltrate", "description": "new", "annotations": {}, "inputSchema": {}}
                ),
            )
            changes = compare(before, after).tool_changes
            self.assertEqual([(c.name, c.change) for c in changes], [("exfiltrate", "added")])

    def test_new_finding_is_reported_as_added(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            before = load_snapshot(CORPUS / "open-readonly.json")
            poisoned = load_snapshot(CORPUS / "poisoned.json")
            extra = dict(poisoned.findings[0].__dict__)

            def add_finding(data: dict) -> None:
                payload = {
                    "fingerprint": "deadbeefdeadbeef",
                    "checkId": extra["check_id"],
                    "title": extra["title"],
                    "severity": extra["severity"],
                    "confidence": extra["confidence"],
                    "assertion": extra["assertion"],
                    "taxonomy": list(extra["taxonomy"]),
                    "owasp": list(extra["owasp"]),
                    "observation": extra["observation"],
                    "limitations": list(extra["limitations"]),
                }
                data["findings"].append(payload)

            after = mutated(directory, add_finding)
            drift = compare(before, after)
            self.assertEqual(len(drift.added), 1)
            self.assertEqual(drift.added[0].check_id, extra["check_id"])

    def test_mismatched_targets_are_flagged(self) -> None:
        before = load_snapshot(CORPUS / "open-readonly.json")
        after = load_snapshot(CORPUS / "forbidden.json")
        drift = compare(before, after)
        self.assertFalse(drift.targets_match)
        self.assertIn("Warning", render_drift(drift))


if __name__ == "__main__":
    unittest.main()
