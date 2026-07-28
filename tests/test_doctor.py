# tests/test_doctor.py
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.config import CONFIG_FILENAME, load_config
from reachability_advisor.doctor import diagnose, readiness_to_dict, render_text


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


class DoctorCommandTextOutputTests(unittest.TestCase):
    """A human reads the terminal text, not the exit code -- assert it directly.

    A prior version of `cmd_doctor` could be mutated to unconditionally
    `print("gate: ready")` regardless of actual readiness, leaving the exit code correct,
    and every other doctor test still passed: none of them captured stdout. These do, and
    check that the printed text, the `--json` payload, and the exit code all agree, in both
    the ready and not-ready case -- the not-ready assertions below are exactly what that
    mutation would violate (it always prints "gate: ready", never "gate: not ready").
    """

    def test_ready_case_text_json_and_exit_code_all_agree(self) -> None:
        root = _repo(
            {
                CONFIG_FILENAME: COMPLETE,
                "sboms/api.cdx.json": "{}",
                "grype.json": "{}",
                "src/api/.keep": "",
            }
        )
        out = root / "readiness.json"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main(
                [
                    "doctor",
                    "--config", str(root / CONFIG_FILENAME),
                    "--root", str(root),
                    "--json", str(out),
                ]
            )
        text = stdout.getvalue()
        payload = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertIn("gate: ready", text)
        self.assertNotIn("gate: not ready", text)
        self.assertTrue(payload["ready"])
        self.assertEqual(code == 0, payload["ready"])

    def test_not_ready_case_text_json_and_exit_code_all_agree(self) -> None:
        # COMPLETE declares an sbom and a vulnerability report; neither is created here.
        root = _repo({CONFIG_FILENAME: COMPLETE})
        out = root / "readiness.json"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main(
                [
                    "doctor",
                    "--config", str(root / CONFIG_FILENAME),
                    "--root", str(root),
                    "--json", str(out),
                ]
            )
        text = stdout.getvalue()
        payload = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(code, 1)
        self.assertIn("gate: not ready", text)
        # "gate: ready" is not a substring of "gate: not ready" -- this is the exact
        # assertion an unconditional `print("gate: ready")` mutation fails.
        self.assertNotIn("gate: ready", text)
        self.assertIn("Blockers:", text)
        self.assertFalse(payload["ready"])
        self.assertTrue(payload["blockers"])
        self.assertEqual(code == 0, payload["ready"])


class DoctorBlockerWarningSeparationTests(unittest.TestCase):
    """`validate_paths` rates a missing declared source root a *warning*: `scan` still
    runs, falling back to weaker SBOM/package-level evidence, and exits 0. Doctor must
    report that as a warning, not a blocker, and the exit code must track blockers only --
    a repository `scan` runs cleanly against must never be reported "not ready" merely
    because its evidence is thin.
    """

    CONFIG = """version: 1
artifacts:
  api:
    sbom: sboms/api.cdx.json
    source: src/api
evidence:
  vulnerabilities: [grype.json]
"""

    def test_missing_source_root_is_a_warning_not_a_blocker(self) -> None:
        root = _repo(
            {
                CONFIG_FILENAME: self.CONFIG,
                "sboms/api.cdx.json": json.dumps(
                    {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}
                ),
                "grype.json": "{}",
                # src/api is declared but deliberately never created.
            }
        )
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)

        self.assertTrue(readiness.ready, render_text(readiness))
        self.assertEqual(readiness.blockers, [])
        self.assertTrue(any("source" in item.lower() for item in readiness.warnings), readiness.warnings)

        payload = readiness_to_dict(readiness)
        self.assertEqual(payload["blockers"], [])
        self.assertTrue(payload["warnings"])

    def test_missing_source_root_warning_matches_a_real_scan_that_succeeds(self) -> None:
        root = _repo(
            {
                CONFIG_FILENAME: self.CONFIG,
                "sboms/api.cdx.json": json.dumps(
                    {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}
                ),
                "grype.json": "{}",
            }
        )
        config_path = root / CONFIG_FILENAME
        old_cwd = Path.cwd()
        stdout = io.StringIO()
        try:
            os.chdir(root)
            with redirect_stdout(stdout):
                doctor_code = main(["doctor", "--config", str(config_path), "--root", str(root)])
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                scan_code = main(["scan", "--config", str(config_path), "--no-table"])
        finally:
            os.chdir(old_cwd)

        self.assertEqual(doctor_code, 0)
        self.assertEqual(scan_code, 0)
        self.assertIn("Warnings:", stdout.getvalue())
        self.assertNotIn("Blockers:", stdout.getvalue())
        self.assertIn("gate: ready", stdout.getvalue())


class DoctorScanAgreementMatrixTests(unittest.TestCase):
    """Doctor's `ready` verdict must agree with whether `scan` actually succeeds.

    Every row is a config shape a real repository can end up in. For every shape except
    the two this project has deliberately chosen not to detect at the `doctor`/
    `validate_paths` layer -- malformed file *content*, and a file the process cannot
    read -- `doctor.ready` must exactly predict whether `scan` exits 0. Those two shapes
    are asserted explicitly as the documented exception, not silently skipped: see
    `doctor.py`'s module docstring for why doctor stops at existence/type/size/extension
    and never opens a file to check content validity or readability.
    """

    VULN_CONFIG = """version: 1
artifacts:
  api:
    sbom: sboms/api.cdx.json
evidence:
  vulnerabilities: [grype.json]
"""

    KUBERNETES_CONFIG = """version: 1
artifacts:
  api:
    sbom: sboms/api.cdx.json
evidence:
  vulnerabilities: [grype.json]
iac:
  kubernetes: k8s.txt
"""

    VALID_SBOM = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []})

    def _diagnose_and_scan(self, root: Path, config_text: str) -> tuple[bool, int]:
        config_path = root / CONFIG_FILENAME
        config_path.write_text(config_text, encoding="utf-8")
        readiness = diagnose(load_config(config_path), root)
        old_cwd = Path.cwd()
        try:
            os.chdir(root)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                scan_code = main(["scan", "--config", str(config_path), "--no-table"])
        finally:
            os.chdir(old_cwd)
        return readiness.ready, scan_code

    def test_agreement_matrix(self) -> None:
        table: list[tuple[str, bool, int]] = []

        def record(label: str, root: Path, config_text: str) -> tuple[bool, int]:
            ready, scan_code = self._diagnose_and_scan(root, config_text)
            table.append((label, ready, scan_code))
            return ready, scan_code

        with self.subTest("valid"):
            root = _repo({"grype.json": "{}", "sboms/api.cdx.json": self.VALID_SBOM})
            ready, scan_code = record("valid", root, self.VULN_CONFIG)
            self.assertTrue(ready)
            self.assertEqual(scan_code, 0)

        with self.subTest("missing"):
            root = _repo({"grype.json": "{}"})
            ready, scan_code = record("missing", root, self.VULN_CONFIG)
            self.assertFalse(ready)
            self.assertNotEqual(scan_code, 0)

        with self.subTest("empty"):
            root = _repo({"grype.json": "{}", "sboms/api.cdx.json": ""})
            ready, scan_code = record("empty", root, self.VULN_CONFIG)
            self.assertFalse(ready)
            self.assertNotEqual(scan_code, 0)

        with self.subTest("directory_instead_of_file"):
            root = _repo({"grype.json": "{}", "sboms/api.cdx.json/.keep": ""})
            ready, scan_code = record("directory_instead_of_file", root, self.VULN_CONFIG)
            self.assertFalse(ready)
            self.assertNotEqual(scan_code, 0)

        with self.subTest("wrong_extension"):
            root = _repo(
                {
                    "grype.json": "{}",
                    "sboms/api.cdx.json": self.VALID_SBOM,
                    "k8s.txt": "not yaml or json",
                }
            )
            ready, scan_code = record("wrong_extension (kubernetes)", root, self.KUBERNETES_CONFIG)
            self.assertFalse(ready)
            self.assertNotEqual(scan_code, 0)

        with self.subTest("malformed_content"):
            root = _repo({"grype.json": "{}", "sboms/api.cdx.json": "{not valid json"})
            ready, scan_code = record("malformed_content", root, self.VULN_CONFIG)
            # Documented gap: doctor checks existence/type/size, never content validity.
            # `scan` still fails -- the safe direction holds -- doctor just cannot predict
            # it without duplicating every loader's parser (see the Minor finding this
            # answers, and doctor.py's module docstring).
            self.assertTrue(ready)
            self.assertNotEqual(scan_code, 0)

        with self.subTest("unreadable"):
            root = _repo({"grype.json": "{}", "sboms/api.cdx.json": self.VALID_SBOM})
            (root / "sboms" / "api.cdx.json").chmod(0o000)
            try:
                ready, scan_code = record("unreadable", root, self.VULN_CONFIG)
            finally:
                (root / "sboms" / "api.cdx.json").chmod(0o644)
            # Same documented gap as malformed_content. `scan` fails closed with a clear
            # message (exit 2) rather than an unhandled traceback -- see the OSError
            # handling in cli.main and tests/test_cli_outputs.py.
            self.assertTrue(ready)
            self.assertEqual(scan_code, 2)

        # Printed for a human reading test output, and pins the table shape so a change to
        # any row's agreement is a visible diff, not a silent regression.
        print("\ndoctor/scan agreement matrix:")
        for label, ready, scan_code in table:
            agree = ready == (scan_code == 0)
            print(f"  {label:32s} doctor_ready={ready!s:5s} scan_exit={scan_code}  agree={agree}")


if __name__ == "__main__":
    unittest.main()
