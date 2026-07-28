# tests/test_config_consumers.py
"""Every leaf key the config schema accepts must have a real, exercised consumer.

Final-review blocker: `gate.thresholds`, `gate.fail_on_new`, and `output.*` all validated
successfully but were never read by anything -- a config could set them to any value with
zero effect on a scan, and nothing said so. The individual wiring fixes are in
`apply_config_defaults`/`apply_compare_config_defaults` (cli.py); this file is the
structural guard the final review asked for, so a *future* schema key added without a
matching consumer fails a test immediately instead of shipping silently inert, the same
way these did.

Two layers of protection, both required:

1. `SchemaKeyCoverageTests` below asserts each schema frozenset (`ARTIFACT_KEYS`,
   `EVIDENCE_KEYS`, `IAC_KEYS`, `GATE_KEYS`, `OUTPUT_KEYS`, `TOP_LEVEL_KEYS`) equals the set
   of keys this file *claims* to cover. Add a key to the schema without updating the map
   here, and this fails -- forcing a deliberate choice: wire it for real, or write down why
   it is exempt (as `version`/`extends` are below).
2. `ConsumerBehaviorTests` actually calls `apply_config_defaults` /
   `apply_compare_config_defaults` with a distinguishing sentinel value for each key and
   asserts the value landed on the real CLI attribute a scan/compare invocation reads --
   so the coverage claim in (1) is proven true, not merely asserted.
"""

from __future__ import annotations

import argparse
import unittest
from pathlib import Path

from reachability_advisor import config_schema
from reachability_advisor.cli import (
    _OUTPUT_FORMAT_TARGETS,
    _THRESHOLD_ATTRS,
    UserFacingError,
    apply_compare_config_defaults,
    apply_config_defaults,
)
from reachability_advisor.cli_parser import build_parser
from reachability_advisor.config import LoadedConfig
from reachability_advisor.config_schema import validate_config

# -- (1) declared coverage, checked against the schema's own frozensets --------------

ARTIFACT_KEY_CONSUMERS = {
    "sbom": "scan --sbom (args.sbom)",
    "source": "scan --source-root (args.source_root)",
    "image": "scan --artifact-alias (args.artifact_alias)",
    "manifest": "scan --artifact-manifest (args.artifact_manifest)",
}
EVIDENCE_KEY_CONSUMERS = {
    "vulnerabilities": "scan --vuln-in (args.vulns)",
    "sast": "scan --sast-in (args.sast_in)",
    "dast": "scan --dast-in (args.dast_in)",
    "cspm": "scan --cspm-in (args.cspm_in)",
    "source": "scan --source-evidence-in (args.source_evidence_in)",
}
IAC_KEY_CONSUMERS = {
    "terraform": "scan --terraform-plan (args.terraform_plan)",
    "terraform_source": "scan --terraform-source (args.terraform_source)",
    "kubernetes": "scan --kubernetes-manifest (args.kubernetes_manifest)",
}
GATE_KEY_CONSUMERS = {
    "profile": "scan --analysis-profile (args.analysis_profile)",
    "fail_on": "scan --fail-on-tier (args.fail_on_tier)",
    "fail_on_new": "compare --fail-on-new-tier (args.fail_on_new_tier)",
    "thresholds": "scan --min-* (args.<threshold name>, one of _THRESHOLD_ATTRS)",
}
OUTPUT_KEY_CONSUMERS = {
    "dir": "scan --*-out (joined with a format's filename; see _OUTPUT_FORMAT_TARGETS)",
    "formats": "scan --*-out (selects which --*-out flags output.dir fills)",
}
# `version` selects the schema itself (config_schema.validate_config); `extends` is a
# resolution-time instruction consumed by config.py's resolve_layers, and is explicitly
# stripped from the merged mapping before it ever reaches validate_config (see
# merge_layers). Neither is a value a scan/compare invocation reads the way every other
# leaf key here is -- there is no "args attribute" for either to land on.
TOP_LEVEL_EXEMPT = {"version", "extends"}


class SchemaKeyCoverageTests(unittest.TestCase):
    """If this fails, a schema key was added or removed without updating the consumer map
    (or its documented exemption) above -- the whole point of this file.
    """

    def test_every_artifact_key_is_declared(self) -> None:
        self.assertEqual(config_schema.ARTIFACT_KEYS, set(ARTIFACT_KEY_CONSUMERS))

    def test_every_evidence_key_is_declared(self) -> None:
        self.assertEqual(config_schema.EVIDENCE_KEYS, set(EVIDENCE_KEY_CONSUMERS))

    def test_every_iac_key_is_declared(self) -> None:
        self.assertEqual(config_schema.IAC_KEYS, set(IAC_KEY_CONSUMERS))

    def test_every_gate_key_is_declared(self) -> None:
        self.assertEqual(config_schema.GATE_KEYS, set(GATE_KEY_CONSUMERS))

    def test_every_output_key_is_declared(self) -> None:
        self.assertEqual(config_schema.OUTPUT_KEYS, set(OUTPUT_KEY_CONSUMERS))

    def test_every_top_level_key_is_declared_or_explicitly_exempt(self) -> None:
        nested_blocks = {"artifacts", "evidence", "iac", "gate", "output"}
        self.assertEqual(config_schema.TOP_LEVEL_KEYS, nested_blocks | TOP_LEVEL_EXEMPT)

    def test_every_gate_threshold_attr_is_a_real_min_flag_on_scan(self) -> None:
        # _THRESHOLD_ATTRS (cli.py) is what apply_config_defaults actually iterates over
        # for gate.thresholds; each name in it must be a real dest on the scan subparser,
        # or filling it would silently set an attribute nothing ever reads.
        parser = build_parser()
        scan = next(
            action.choices["scan"]
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        scan_dests = {action.dest for action in scan._actions}
        self.assertTrue(_THRESHOLD_ATTRS.issubset(scan_dests), _THRESHOLD_ATTRS - scan_dests)

    def test_every_output_format_has_a_real_out_flag_on_scan(self) -> None:
        parser = build_parser()
        scan = next(
            action.choices["scan"]
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        scan_dests = {action.dest for action in scan._actions}
        for fmt in config_schema.FORMATS:
            with self.subTest(fmt=fmt):
                self.assertIn(fmt, _OUTPUT_FORMAT_TARGETS)
                attribute, _filename = _OUTPUT_FORMAT_TARGETS[fmt]
                self.assertIn(attribute, scan_dests)


# -- (2) behavioral proof: each declared consumer actually receives the value ---------


def _baseline_scan_args() -> argparse.Namespace:
    parser = build_parser()
    argv = ["scan"]
    args = parser.parse_args(argv)
    args._explicit = set()
    return args


def _baseline_compare_args() -> argparse.Namespace:
    parser = build_parser()
    argv = ["compare", "--base-findings", "b.json", "--head-findings", "h.json"]
    args = parser.parse_args(argv)
    args._explicit = set()
    return args


def _loaded(raw: dict, *, with_path: bool = True) -> LoadedConfig:
    config = validate_config({"version": 1, **raw}, "test.yml")
    return LoadedConfig(config=config, path=Path("dummy/.reachability.yml") if with_path else None)


class ConsumerBehaviorTests(unittest.TestCase):
    """One test per declared consumer above, each proving the mapping is real."""

    def test_artifacts_sbom_lands_on_args_sbom(self) -> None:
        loaded = _loaded({"artifacts": {"api": {"sbom": "s.json"}}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.sbom, ["s.json"])

    def test_artifacts_source_lands_on_args_source_root(self) -> None:
        loaded = _loaded({"artifacts": {"api": {"source": "src/api"}}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.source_root, ["api=src/api"])

    def test_artifacts_image_lands_on_args_artifact_alias(self) -> None:
        loaded = _loaded({"artifacts": {"api": {"image": "registry/api:1"}}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.artifact_alias, ["api=registry/api:1"])

    def test_artifacts_manifest_lands_on_args_artifact_manifest(self) -> None:
        loaded = _loaded({"artifacts": {"api": {"manifest": "manifest.json"}}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.artifact_manifest, ["manifest.json"])

    def test_evidence_vulnerabilities_lands_on_args_vulns(self) -> None:
        loaded = _loaded({"evidence": {"vulnerabilities": ["v.json"]}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.vulns, ["v.json"])

    def test_evidence_sast_lands_on_args_sast_in(self) -> None:
        loaded = _loaded({"evidence": {"sast": ["s.json"]}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.sast_in, ["s.json"])

    def test_evidence_dast_lands_on_args_dast_in(self) -> None:
        loaded = _loaded({"evidence": {"dast": ["d.json"]}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.dast_in, ["d.json"])

    def test_evidence_cspm_lands_on_args_cspm_in(self) -> None:
        loaded = _loaded({"evidence": {"cspm": ["c.json"]}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.cspm_in, ["c.json"])

    def test_evidence_source_lands_on_args_source_evidence_in(self) -> None:
        # The gap named explicitly in doctor.py's own module docstring before this fix:
        # "evidence.source ... accepted by the schema but not yet wired ... deliberately
        # left unchecked." It maps onto --source-evidence-in the same way sast/dast/cspm
        # map onto their own --*-in flags.
        loaded = _loaded({"evidence": {"source": ["ext.json"]}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.source_evidence_in, ["ext.json"])

    def test_iac_terraform_lands_on_args_terraform_plan(self) -> None:
        loaded = _loaded({"iac": {"terraform": "plan.json"}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.terraform_plan, "plan.json")

    def test_iac_terraform_source_lands_on_args_terraform_source(self) -> None:
        loaded = _loaded({"iac": {"terraform_source": "infra"}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.terraform_source, "infra")

    def test_iac_kubernetes_lands_on_args_kubernetes_manifest(self) -> None:
        loaded = _loaded({"iac": {"kubernetes": "k8s"}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.kubernetes_manifest, ["k8s"])

    def test_gate_profile_lands_on_args_analysis_profile(self) -> None:
        loaded = _loaded({"gate": {"profile": "production"}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.analysis_profile, "production")

    def test_gate_fail_on_lands_on_args_fail_on_tier(self) -> None:
        loaded = _loaded({"gate": {"fail_on": "medium"}})
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertEqual(result.fail_on_tier, "medium")

    def test_gate_fail_on_new_lands_on_compare_args_fail_on_new_tier(self) -> None:
        loaded = _loaded({"gate": {"fail_on_new": "high"}})
        result = apply_compare_config_defaults(_baseline_compare_args(), loaded)
        self.assertEqual(result.fail_on_new_tier, "high")

    def test_every_gate_threshold_key_lands_on_its_own_named_attribute(self) -> None:
        for attribute in sorted(_THRESHOLD_ATTRS):
            with self.subTest(attribute=attribute):
                loaded = _loaded({"gate": {"thresholds": {attribute: 0.42}}})
                result = apply_config_defaults(_baseline_scan_args(), loaded)
                self.assertEqual(getattr(result, attribute), 0.42)

    def test_every_output_format_lands_on_its_own_out_flag_under_output_dir(self) -> None:
        for fmt, (attribute, filename) in sorted(_OUTPUT_FORMAT_TARGETS.items()):
            with self.subTest(fmt=fmt):
                loaded = _loaded({"output": {"dir": "custom-out", "formats": [fmt]}})
                result = apply_config_defaults(_baseline_scan_args(), loaded)
                self.assertEqual(getattr(result, attribute), str(Path("custom-out") / filename))


class UnknownThresholdKeyRejectionTests(unittest.TestCase):
    """The other half of the structural guarantee: a threshold key that is *not* a real
    consumer (a typo, or simply made up) must be rejected loudly, not silently accepted and
    ignored. config_schema.py itself accepts any string key here (see test_config_schema.py,
    which deliberately uses placeholder names like "min_x" to test type/range validation
    independent of key semantics) -- the enforcement that a key actually corresponds to
    something scan reads belongs at the one place that knows the real flag names: here.
    """

    def test_an_unrecognized_threshold_key_is_rejected_not_silently_ignored(self) -> None:
        loaded = _loaded({"gate": {"thresholds": {"min_totally_made_up_flag": 0.5}}})
        with self.assertRaises(UserFacingError) as error:
            apply_config_defaults(_baseline_scan_args(), loaded)
        message = str(error.exception)
        self.assertIn("min_totally_made_up_flag", message)
        self.assertIn("unknown key", message)

    def test_a_typo_of_a_real_threshold_key_is_rejected(self) -> None:
        # One character off from the real "min_artifact_match_coverage".
        loaded = _loaded({"gate": {"thresholds": {"min_artifcat_match_coverage": 0.5}}})
        with self.assertRaises(UserFacingError):
            apply_config_defaults(_baseline_scan_args(), loaded)


class OutputWiringBackwardCompatibilityTests(unittest.TestCase):
    """output.dir/output.formats must only ever apply when a real config file was found --
    same rule as gate.fail_on (see apply_config_defaults's own docstring). Otherwise every
    existing no-config `scan` invocation would silently start writing files to ./outputs/
    it never wrote before.
    """

    def test_output_defaults_do_not_apply_without_a_real_config_file(self) -> None:
        loaded = _loaded({}, with_path=False)
        self.assertIsNone(loaded.path)
        self.assertEqual(loaded.config.output.dir, "outputs")  # schema default, confirmed present
        result = apply_config_defaults(_baseline_scan_args(), loaded)
        self.assertIsNone(result.out)
        self.assertIsNone(result.markdown_out)

    def test_output_dir_creates_the_directory_never_before(self) -> None:
        # Reproduces the blocker's exact repro: "output.dir: custom-out -> directory never
        # created." Once wired, --out is filled (as a relative path, joined under
        # output.dir the same way scan resolves every other relative config path: against
        # the process's working directory) and write_json_findings's own mkdir does the
        # rest -- verified end to end here, not just that the attribute was filled.
        import json
        import os
        import tempfile
        from contextlib import redirect_stderr, redirect_stdout
        from io import StringIO

        from reachability_advisor.cli import main

        root_dir = Path(__file__).resolve().parents[1]
        old_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / ".reachability.yml"
            config_path.write_text(
                "version: 1\n"
                "artifacts:\n"
                f"  audit-api:\n    sbom: {root_dir / 'samples/sboms/audit-api.cdx.json'}\n"
                "evidence:\n"
                f"  vulnerabilities: [{root_dir / 'samples/vulnerabilities.json'}]\n"
                "output:\n  dir: custom-out\n  formats: [json]\n",
                encoding="utf-8",
            )
            output_dir = Path(tmp) / "custom-out"
            self.assertFalse(output_dir.exists())
            try:
                os.chdir(tmp)
                with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                    code = main(["scan", "--no-table", "--config", str(config_path)])
            finally:
                os.chdir(old_cwd)
            self.assertIn(code, (0, 10))
            self.assertTrue(output_dir.exists())
            written = output_dir / "reachability-findings.json"
            self.assertTrue(written.is_file())
            json.loads(written.read_text(encoding="utf-8"))  # valid JSON, not just present


if __name__ == "__main__":
    unittest.main()
