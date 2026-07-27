from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from scripts import validate_release

ROOT = Path(__file__).resolve().parents[1]

# Every check `run_release_validation` appends under a fixed name. Two families are data-derived
# and are therefore counted against the filesystem instead of being frozen here:
#   * "runtime policy <name>" - one per configs/policy*.json
#   * "fixture pack <name>"   - one per fixtures/terraform/packs/*/fixture.json
REQUIRED_CHECK_NAMES = frozenset(
    {
        "release metadata",
        "composite action metadata",
        "sample vulnerability intelligence",
        "sample context",
        "scoring benchmark corpus",
        "real-app benchmark snapshot expectations",
        "generated SBOM plan",
        "generated SBOM plan Markdown",
        "generated runtime policy",
        "generated scoring benchmark",
        "benchmark snapshot regression comparator",
        "generated HCL audit",
        "generated HCL audit Markdown",
        "generated source evidence pack",
        "generated security evidence pack",
        "Grype vulnerability import",
        "OSV-style vulnerability import",
        "external source evidence imports",
        "SAST/DAST security evidence import",
        "context, artifact alias, custom rule, and policy imports",
        "generated findings",
        "generated evidence graph",
        "generated baseline",
        "generated SARIF output",
        "generated diagnostics output",
        "generated PR summary Markdown",
        "generated GitHub annotations",
        "generated single-finding explanation",
        "generated PR baseline delta",
        "generated PR delta Markdown",
        "generated HTML graph report",
        "generated Terraform coverage",
        "generated Kubernetes coverage",
        "generated source coverage",
        "generated mapping report",
        "generated readiness report",
        "generated readiness report from saved inputs",
        "no-cloud Terraform plan E2E",
        "generated Semgrep starter rules",
        "generated fixture validation report",
        "generated fixture run report",
        "generated complex benchmark",
        "generated complex benchmark Markdown",
    }
)


class ReleaseValidationTests(unittest.TestCase):
    summary: dict[str, Any]
    exit_code: int

    @classmethod
    def setUpClass(cls) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cls.exit_code = validate_release.main(["--out-dir", tmp])
            cls.summary = json.loads((Path(tmp) / "release-validation.json").read_text(encoding="utf-8"))

    def test_schema_validator_rejects_missing_required_property(self) -> None:
        with self.assertRaises(validate_release.SchemaError):
            validate_release.validate_schema({}, {"type": "object", "required": ["schema_version"]})

    def test_release_validation_runs_against_generated_outputs(self) -> None:
        self.assertEqual(self.exit_code, 0)
        self.assertEqual(self.summary["status"], "passed")

        names = [check["name"] for check in self.summary["checks"]]
        policy_count = len(list((ROOT / "configs").glob("policy*.json")))
        pack_count = len(list((ROOT / "fixtures" / "terraform" / "packs").glob("*/fixture.json")))

        # No hand-written check may silently stop appending.
        self.assertEqual(REQUIRED_CHECK_NAMES - set(names), set())
        # ...and no check may silently disappear from the data-derived families either.
        self.assertEqual(len([name for name in names if name.startswith("runtime policy ")]), policy_count)
        self.assertEqual(len([name for name in names if name.startswith("fixture pack ")]), pack_count)
        self.assertGreater(policy_count, 0)
        self.assertGreater(pack_count, 0)
        # An exact total also catches deletions of names not listed above and duplicate appends.
        self.assertEqual(len(names), len(REQUIRED_CHECK_NAMES) + policy_count + pack_count)
        self.assertEqual(len(names), len(set(names)))

    def test_documented_release_check_count_matches_the_gate(self) -> None:
        quality = (ROOT / "docs" / "code_quality.md").read_text(encoding="utf-8")
        documented = re.search(r"release-check` currently covers (\d+) import/export", quality)

        self.assertIsNotNone(documented)
        assert documented is not None
        self.assertEqual(int(documented.group(1)), len(self.summary["checks"]))

    def test_required_check_names_catch_a_silently_deleted_import_check(self) -> None:
        # The auditor's mutation: make one import-verification group stop appending its check.
        # The previous `len(checks) >= 10` assertion survived that; the name set must not.
        with (
            mock.patch.object(validate_release, "_check_vulnerability_imports", lambda out_dir, checks: None),
            tempfile.TemporaryDirectory() as tmp,
        ):
            mutated = validate_release.run_release_validation(Path(tmp))

        missing = REQUIRED_CHECK_NAMES - {check["name"] for check in mutated["checks"]}
        self.assertIn("Grype vulnerability import", missing)
        self.assertIn("OSV-style vulnerability import", missing)
        self.assertGreaterEqual(len(mutated["checks"]), 10)


if __name__ == "__main__":
    unittest.main()
