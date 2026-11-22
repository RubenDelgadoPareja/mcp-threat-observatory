import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcpobs_analysis.stix import validate_bundle

REPO = Path(__file__).resolve().parents[2]
BUNDLE = REPO / "examples" / "sample" / "bundle.stix.json"

try:  # optional dependency, exactly like the validator
    import stix2  # type: ignore  # noqa: F401

    HAVE_STIX2 = True
except ImportError:
    HAVE_STIX2 = False


def tampered(directory: str, mutate) -> Path:
    data = json.loads(BUNDLE.read_text(encoding="utf-8"))
    mutate(data)
    path = Path(directory) / "bundle.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class StixValidationTest(unittest.TestCase):
    def test_the_committed_bundle_is_structurally_valid(self) -> None:
        result = validate_bundle(BUNDLE)
        self.assertTrue(result.ok, result.summary())
        self.assertGreater(result.objects, 0)

    def test_deep_validation_is_only_claimed_when_it_actually_ran(self) -> None:
        result = validate_bundle(BUNDLE, deep=True)
        self.assertTrue(result.ok, result.summary())
        self.assertTrue(result.deep_requested)
        if HAVE_STIX2:
            self.assertTrue(result.deep_used)
            self.assertIsNone(result.deep_note)
        else:
            self.assertFalse(result.deep_used)
            self.assertIn("stix2", result.deep_note or "")
            self.assertIn("skipped", result.summary())
            self.assertNotIn("passed with the stix2", result.summary())

    def test_detects_an_id_that_does_not_match_its_type(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = tampered(
                directory,
                lambda data: data["objects"][2].__setitem__(
                    "id", data["objects"][2]["id"].replace("infrastructure--", "vulnerability--")
                ),
            )
            result = validate_bundle(path)
            self.assertFalse(result.ok)
            self.assertTrue(any("does not match type" in issue for issue in result.issues))

    def test_detects_a_dangling_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            def mutate(data: dict) -> None:
                for obj in data["objects"]:
                    if obj["type"] == "relationship":
                        obj["target_ref"] = "vulnerability--00000000-0000-4000-8000-000000000000"
                        return

            result = validate_bundle(tampered(directory, mutate))
            self.assertFalse(result.ok)
            self.assertTrue(any("does not resolve" in issue for issue in result.issues))

    def test_detects_a_stix_2_0_confidence_field(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            def mutate(data: dict) -> None:
                for obj in data["objects"]:
                    if obj["type"] == "vulnerability":
                        obj["confidence"] = 80
                        return

            result = validate_bundle(tampered(directory, mutate))
            self.assertFalse(result.ok)
            self.assertTrue(any("confidence" in issue for issue in result.issues))

    def test_detects_a_missing_tlp_marking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = tampered(
                directory,
                lambda data: data.__setitem__(
                    "objects",
                    [obj for obj in data["objects"] if obj["type"] != "marking-definition"],
                ),
            )
            result = validate_bundle(path)
            self.assertFalse(result.ok)
            self.assertTrue(any("marking" in issue for issue in result.issues))

    def test_rejects_a_non_bundle_document(self) -> None:
        result = validate_bundle(REPO / "examples" / "sample" / "snapshot.json")
        self.assertFalse(result.ok)
        self.assertTrue(any("not a STIX bundle" in issue for issue in result.issues))


if __name__ == "__main__":
    unittest.main()
