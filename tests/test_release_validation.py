from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts import validate_release


class ReleaseValidationTests(unittest.TestCase):
    def test_schema_validator_rejects_missing_required_property(self) -> None:
        with self.assertRaises(validate_release.SchemaError):
            validate_release.validate_schema({}, {"type": "object", "required": ["schema_version"]})

    def test_release_validation_runs_against_generated_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code = validate_release.main(["--out-dir", tmp])
            self.assertEqual(code, 0)
            summary = json.loads((Path(tmp) / "release-validation.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["status"], "passed")
        self.assertGreaterEqual(len(summary["checks"]), 10)


if __name__ == "__main__":
    unittest.main()
