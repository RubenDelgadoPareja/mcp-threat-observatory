import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcpobs_analysis.loader import (
    find_duplicate_targets,
    iter_snapshot_paths,
    load_corpus,
    load_index,
    load_snapshot,
)
from mcpobs_analysis.schema import SchemaError, Snapshot

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "examples" / "corpus"
SAMPLE = REPO / "examples" / "sample" / "snapshot.json"


class SchemaTest(unittest.TestCase):
    def test_null_requires_auth_is_preserved(self) -> None:
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["probe"]["auth"]["requiresAuth"] = None
        snapshot = Snapshot.from_dict(data)
        self.assertIsNone(snapshot.requires_auth)

    def test_missing_probe_is_rejected(self) -> None:
        with self.assertRaises(SchemaError):
            Snapshot.from_dict({"findings": []})

    def test_unknown_severity_is_rejected(self) -> None:
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["findings"][0]["severity"] = "catastrophic"
        with self.assertRaises(SchemaError):
            Snapshot.from_dict(data)

    def test_unknown_assertion_is_rejected(self) -> None:
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["findings"][0]["assertion"] = "guessed"
        with self.assertRaises(SchemaError):
            Snapshot.from_dict(data)

    def test_austere_record_without_findings_is_valid(self) -> None:
        data = json.loads(SAMPLE.read_text(encoding="utf-8"))
        data["findings"] = []
        self.assertEqual(Snapshot.from_dict(data).findings, ())


class LoaderTest(unittest.TestCase):
    def test_loads_the_whole_corpus(self) -> None:
        snapshots = load_corpus([CORPUS])
        self.assertEqual(len(snapshots), 9)
        self.assertEqual(len({snapshot.target for snapshot in snapshots}), 9)

    def test_file_order_is_deterministic(self) -> None:
        first = [path.name for path in iter_snapshot_paths([CORPUS])]
        second = [path.name for path in iter_snapshot_paths([CORPUS])]
        self.assertEqual(first, second)

    def test_skips_non_snapshot_json_found_by_directory_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bundle.json").write_text(json.dumps({"type": "bundle", "objects": []}), encoding="utf-8")
            (root / "snapshot.json").write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
            snapshots = load_corpus([root])
            self.assertEqual(len(snapshots), 1)

    def test_rejects_an_explicit_non_snapshot_file(self) -> None:
        with self.assertRaises(SchemaError):
            load_corpus([REPO / "examples" / "sample" / "bundle.stix.json"])

    def test_missing_path_raises(self) -> None:
        with self.assertRaises(SchemaError):
            load_corpus([REPO / "does-not-exist"])

    def test_detects_duplicate_targets(self) -> None:
        snapshot = load_snapshot(SAMPLE)
        duplicates = find_duplicate_targets([snapshot, snapshot])
        self.assertEqual(duplicates[snapshot.target], 2)

    def test_reads_the_append_only_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            index = Path(directory) / "index.jsonl"
            index.write_text('{"target":"a"}\n\n{"target":"b"}\n', encoding="utf-8")
            entries = load_index(index)
            self.assertEqual([entry["target"] for entry in entries], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
