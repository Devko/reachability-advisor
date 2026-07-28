# tests/test_doctor.py
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.config import CONFIG_FILENAME, load_config
from reachability_advisor.doctor import diagnose, render_text


def _repo(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


COMPLETE = """version: 1
artifacts:
  api:
    sbom: sboms/api.cdx.json
    source: src/api
evidence:
  vulnerabilities: [grype.json]
gate:
  profile: advisory
  fail_on: high
"""


class DiagnoseTests(unittest.TestCase):
    def test_reports_a_missing_sbom_file_as_a_blocker(self) -> None:
        root = _repo({CONFIG_FILENAME: COMPLETE, "grype.json": "{}"})
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertFalse(readiness.ready)
        self.assertTrue(any("sboms/api.cdx.json" in item for item in readiness.blockers))

    def test_names_the_exact_command_for_missing_evidence(self) -> None:
        root = _repo({CONFIG_FILENAME: COMPLETE, "sboms/api.cdx.json": "{}"})
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertTrue(any("grype" in item for item in readiness.next_actions))

    def test_is_ready_when_every_declared_input_exists(self) -> None:
        root = _repo(
            {
                CONFIG_FILENAME: COMPLETE,
                "sboms/api.cdx.json": "{}",
                "grype.json": "{}",
                "src/api/.keep": "",
            }
        )
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertTrue(readiness.ready, render_text(readiness))

    def test_no_config_file_names_init_as_the_next_step(self) -> None:
        # The first thing a new user hits: running `doctor` before ever running `init`.
        root = _repo({})
        readiness = diagnose(load_config(None, start=root), root)
        self.assertFalse(readiness.ready)
        self.assertTrue(any("init" in item for item in readiness.blockers))
        self.assertIn("reachability-advisor init", readiness.next_actions)

    def test_artifact_with_no_sbom_declared_anywhere_is_not_ready(self) -> None:
        # A source-only artifact (no `sbom` key at all) is exactly what `init` scaffolds
        # for a repository with a lockfile but no SBOM yet. Without a fix, `scan` would
        # immediately fail with "At least one --sbom is required" -- doctor must catch
        # that before scan does, even though every *declared* path here does exist.
        config = """version: 1
artifacts:
  api:
    source: src/api
evidence:
  vulnerabilities: [grype.json]
"""
        root = _repo({CONFIG_FILENAME: config, "src/api/.keep": "", "grype.json": "{}"})
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertFalse(readiness.ready)
        self.assertTrue(any("sbom" in item.lower() for item in readiness.blockers))
        self.assertTrue(any("syft" in item for item in readiness.next_actions))

    def test_terraform_plan_and_terraform_source_both_declared_is_a_conflict(self) -> None:
        # `config_detect.detect_repo` can legitimately set both `terraform` and
        # `terraform_source` for the same repository (a checked-in rendered plan alongside
        # a `.tf` source tree), producing a config `scan` itself refuses to run ("Choose
        # one Terraform input"). Doctor must catch that even though both declared paths
        # exist on disk.
        config = """version: 1
artifacts:
  api:
    sbom: sboms/api.cdx.json
evidence:
  vulnerabilities: [grype.json]
iac:
  terraform: tfplan.json
  terraform_source: infra
"""
        root = _repo(
            {
                CONFIG_FILENAME: config,
                "sboms/api.cdx.json": "{}",
                "grype.json": "{}",
                "tfplan.json": "{}",
                "infra/main.tf": "",
            }
        )
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertFalse(readiness.ready)
        self.assertTrue(any("only one" in item for item in readiness.blockers))

    def test_declared_terraform_source_missing_is_a_blocker(self) -> None:
        config = """version: 1
artifacts:
  api:
    sbom: sboms/api.cdx.json
evidence:
  vulnerabilities: [grype.json]
iac:
  terraform_source: infra
"""
        root = _repo({CONFIG_FILENAME: config, "sboms/api.cdx.json": "{}", "grype.json": "{}"})
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertFalse(readiness.ready)
        self.assertTrue(any("infra" in item for item in readiness.blockers))

    def test_declared_kubernetes_manifest_missing_is_a_blocker(self) -> None:
        config = """version: 1
artifacts:
  api:
    sbom: sboms/api.cdx.json
evidence:
  vulnerabilities: [grype.json]
iac:
  kubernetes: rendered
"""
        root = _repo({CONFIG_FILENAME: config, "sboms/api.cdx.json": "{}", "grype.json": "{}"})
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertFalse(readiness.ready)
        self.assertTrue(any("rendered" in item for item in readiness.blockers))

    def test_declared_sast_evidence_missing_is_a_blocker(self) -> None:
        config = """version: 1
artifacts:
  api:
    sbom: sboms/api.cdx.json
evidence:
  vulnerabilities: [grype.json]
  sast: [semgrep.json]
"""
        root = _repo({CONFIG_FILENAME: config, "sboms/api.cdx.json": "{}", "grype.json": "{}"})
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertFalse(readiness.ready)
        self.assertTrue(any("semgrep.json" in item for item in readiness.blockers))

    def test_production_profile_with_complete_evidence_is_ready(self) -> None:
        # Answers an open design question directly: doctor does not invent extra
        # requirements for `production` beyond what is declared. Scan's own quality-gate
        # thresholds (external source coverage, etc.) stay scan's job, not doctor's.
        config = COMPLETE.replace("profile: advisory", "profile: production")
        root = _repo(
            {
                CONFIG_FILENAME: config,
                "sboms/api.cdx.json": "{}",
                "grype.json": "{}",
                "src/api/.keep": "",
            }
        )
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertTrue(readiness.ready, render_text(readiness))
        self.assertFalse(any("production" in item for item in readiness.blockers))

    def test_production_profile_appends_context_when_blockers_exist(self) -> None:
        config = COMPLETE.replace("profile: advisory", "profile: production")
        root = _repo({CONFIG_FILENAME: config, "grype.json": "{}"})
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertFalse(readiness.ready)
        self.assertTrue(any("production" in item for item in readiness.blockers))


class DoctorCommandTests(unittest.TestCase):
    def test_exits_non_zero_when_not_ready(self) -> None:
        root = _repo({CONFIG_FILENAME: COMPLETE})
        self.assertEqual(
            main(["doctor", "--config", str(root / CONFIG_FILENAME), "--root", str(root)]), 1
        )

    def test_exits_zero_and_emits_json_when_ready(self) -> None:
        root = _repo(
            {
                CONFIG_FILENAME: COMPLETE,
                "sboms/api.cdx.json": "{}",
                "grype.json": "{}",
                "src/api/.keep": "",
            }
        )
        out = root / "readiness.json"
        code = main(
            [
                "doctor",
                "--config",
                str(root / CONFIG_FILENAME),
                "--root",
                str(root),
                "--json",
                str(out),
            ]
        )
        self.assertEqual(code, 0)
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(payload["ready"])
        self.assertIn("artifacts", payload)

    def test_discovers_config_from_root_not_from_cwd(self) -> None:
        # A platform team runs `doctor` across many checked-out repositories from one
        # fixed working directory (see the module docstring); discovery must follow
        # `--root`, not the process's current working directory.
        root = _repo(
            {
                CONFIG_FILENAME: COMPLETE,
                "sboms/api.cdx.json": "{}",
                "grype.json": "{}",
                "src/api/.keep": "",
            }
        )
        elsewhere = _repo({})
        old_cwd = Path.cwd()
        try:
            os.chdir(elsewhere)
            code = main(["doctor", "--root", str(root)])
        finally:
            os.chdir(old_cwd)
        self.assertEqual(code, 0)

    def test_rejects_a_root_that_is_not_a_directory(self) -> None:
        root = _repo({CONFIG_FILENAME: COMPLETE})
        not_a_dir = root / "not-a-directory"
        not_a_dir.write_text("", encoding="utf-8")
        self.assertEqual(main(["doctor", "--root", str(not_a_dir)]), 2)


if __name__ == "__main__":
    unittest.main()
