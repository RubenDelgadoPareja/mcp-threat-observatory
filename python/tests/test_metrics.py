import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcpobs_analysis.metrics import (
    assertion_counts,
    auth_posture,
    check_matrix,
    confidence_counts,
    findings_by_check,
    rows,
    severity_counts,
    target_rows,
    write_csv,
)
from mcpobs_analysis.loader import load_corpus

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "examples" / "corpus"


class MetricsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshots = load_corpus([CORPUS])

    def test_severity_counts_add_up_to_findings(self) -> None:
        counts = severity_counts(self.snapshots)
        total = sum(counts.values())
        self.assertEqual(total, sum(len(snapshot.findings) for snapshot in self.snapshots))

    def test_every_finding_lands_in_one_confidence_bucket(self) -> None:
        counts = confidence_counts(self.snapshots)
        self.assertEqual(sum(counts.values()), sum(len(s.findings) for s in self.snapshots))

    def test_observed_and_inferred_are_both_present_in_the_corpus(self) -> None:
        counts = assertion_counts(self.snapshots)
        self.assertGreater(counts["observed"], 0)
        self.assertGreater(counts["inferred"], 0)

    def test_auth_posture_covers_every_snapshot_exactly_once(self) -> None:
        posture = auth_posture(self.snapshots)
        self.assertEqual(sum(posture.values()), len(self.snapshots))
        self.assertGreater(posture["unauthenticated"], 0)
        self.assertGreater(posture["401 challenge"], 0)
        self.assertGreater(posture["403 forbidden"], 0)

    def test_check_matrix_totals_match_per_check_counts(self) -> None:
        matrix = check_matrix(self.snapshots)
        by_check = findings_by_check(self.snapshots)
        for check_id, counts in matrix.items():
            self.assertEqual(sum(counts.values()), by_check[check_id])

    def test_rows_are_flat_and_csv_ready(self) -> None:
        data = rows(self.snapshots)
        self.assertTrue(data)
        self.assertEqual(
            set(data[0].keys()),
            {
                "target",
                "collected_at",
                "check_id",
                "severity",
                "confidence",
                "assertion",
                "owasp",
                "taxonomy",
                "fingerprint",
            },
        )

    def test_unknown_catalog_is_reported_as_unknown_not_zero(self) -> None:
        protected = [s for s in self.snapshots if s.auth_label == "401 challenge"][0]
        self.assertIsNone(protected.tools_count)
        protected_row = [r for r in target_rows([protected])][0]
        self.assertIsNone(protected_row["tools"])
        self.assertFalse(protected_row["tools_known"])

    def test_write_csv_creates_parent_directory(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "nested" / "findings.csv"
            count = write_csv(target, rows(self.snapshots))
            self.assertGreater(count, 0)
            self.assertTrue(target.exists())
            header = target.read_text(encoding="utf-8").splitlines()[0]
            self.assertIn("check_id", header)


if __name__ == "__main__":
    unittest.main()
