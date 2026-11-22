import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcpobs_analysis.cli import main

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "examples" / "corpus"
SAMPLE_BUNDLE = REPO / "examples" / "sample" / "bundle.stix.json"


def run(argv: list[str]) -> tuple[int, str]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = main(argv)
    return code, buffer.getvalue()


class CliTest(unittest.TestCase):
    def test_summarize_prints_distributions(self) -> None:
        code, output = run(["summarize", str(CORPUS)])
        self.assertEqual(code, 0)
        self.assertIn("Severity", output)
        self.assertIn("Authentication posture", output)
        self.assertIn("Findings: 19", output)
        self.assertIn("AUTH", run(["checks", str(CORPUS)])[1])

    def test_summarize_json_is_machine_readable(self) -> None:
        import json

        code, output = run(["summarize", str(CORPUS), "--json"])
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["snapshots"], 9)
        self.assertIn("severity", data)

    def test_checks_matrix(self) -> None:
        code, output = run(["checks", str(CORPUS)])
        self.assertEqual(code, 0)
        self.assertIn("RISK-001", output)
        self.assertIn("total", output)

    def test_compare_two_snapshots(self) -> None:
        code, output = run(
            [
                "compare",
                str(CORPUS / "open-readonly.json"),
                str(CORPUS / "open-readonly.json"),
            ]
        )
        self.assertEqual(code, 0)
        self.assertIn("No change observed", output)

    def test_export_writes_csv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "findings.csv"
            code, output = run(["export", str(CORPUS), "--csv", str(target)])
            self.assertEqual(code, 0)
            self.assertTrue(target.exists())
            self.assertIn("finding row(s)", output)

    def test_validate_stix_passes_on_the_committed_bundle(self) -> None:
        code, output = run(["validate-stix", str(SAMPLE_BUNDLE)])
        self.assertEqual(code, 0)
        self.assertIn("OK", output)

    def test_schema_error_exits_with_code_2(self) -> None:
        import contextlib

        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = main(["summarize", str(REPO / "missing-directory")])
        self.assertEqual(code, 2)
        self.assertIn("schema error", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
