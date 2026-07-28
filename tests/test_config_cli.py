# tests/test_config_cli.py
from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from reachability_advisor.cli import main

ROOT = Path(__file__).resolve().parents[1]

CONFIG = """version: 1
artifacts:
  demo-api:
    sbom: samples/sboms/audit-api.cdx.json
gate:
  fail_on: medium
  profile: production
"""


class ConfigExplainTests(unittest.TestCase):
    def test_explain_prints_each_value_and_its_layer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text(CONFIG, encoding="utf-8")
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["config", "explain", "--config", str(path)])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("gate.fail_on", output)
        self.assertIn("medium", output)
        self.assertIn(str(path), output)

    def test_explain_reports_a_malformed_config_and_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text("version: 1\ngate:\n  fial_on: high\n", encoding="utf-8")
            code = main(["config", "explain", "--config", str(path)])
        self.assertEqual(code, 2)


class ScanUsesConfigTests(unittest.TestCase):
    def test_a_cli_flag_overrides_the_config_value(self) -> None:
        from argparse import Namespace

        from reachability_advisor.cli import apply_config_defaults
        from reachability_advisor.config import load_config

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text(CONFIG, encoding="utf-8")
            loaded = load_config(path)

        explicit = Namespace(fail_on_tier="urgent", sbom=[], _explicit={"fail_on_tier"})
        self.assertEqual(apply_config_defaults(explicit, loaded).fail_on_tier, "urgent")

        implicit = Namespace(fail_on_tier=None, sbom=[], _explicit=set())
        self.assertEqual(apply_config_defaults(implicit, loaded).fail_on_tier, "medium")

    def test_equals_form_flags_count_as_explicit(self) -> None:
        # `--flag=value` must be detected as explicitly passed. If it is not, config
        # silently overrides a gate the user set on the command line.
        from reachability_advisor.cli import explicit_dests
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        for argv in (
            ["scan", "--fail-on-tier", "urgent"],
            ["scan", "--fail-on-tier=urgent"],
        ):
            with self.subTest(argv=argv):
                self.assertIn("fail_on_tier", explicit_dests(parser, argv))

    def test_unpassed_flags_are_not_reported_as_explicit(self) -> None:
        from reachability_advisor.cli import explicit_dests
        from reachability_advisor.cli_parser import build_parser

        self.assertNotIn("fail_on_tier", explicit_dests(build_parser(), ["scan", "--no-table"]))


class ApplyConfigDefaultsRegressionTests(unittest.TestCase):
    """Regressions for defects found while implementing this task's original plan.

    None of these are exercised by the plan's own tests above, so each is a case that
    would have shipped broken (or silently more dangerous) without an explicit test here.
    """

    def test_fail_on_tier_is_not_filled_when_no_config_file_was_found(self) -> None:
        # `load_config` returns this exact object when there is no .reachability.yml:
        # schema defaults (gate.fail_on == "high") with path=None. Filling fail_on_tier
        # from it unconditionally would silently turn every existing no-config `scan`
        # invocation into an enforced high-tier gate, which never happened before this
        # feature existed and would break CI for every user without a config file.
        from argparse import Namespace

        from reachability_advisor.cli import apply_config_defaults
        from reachability_advisor.config import LoadedConfig
        from reachability_advisor.config_schema import validate_config

        loaded = LoadedConfig(config=validate_config({"version": 1}, "defaults"))
        self.assertIsNone(loaded.path)
        self.assertEqual(loaded.config.gate.fail_on, "high")

        args = Namespace(fail_on_tier=None, sbom=[], _explicit=set())
        self.assertIsNone(apply_config_defaults(args, loaded).fail_on_tier)

    def test_vulnerabilities_from_config_land_on_the_vulns_attribute(self) -> None:
        # `--vuln-in` stores into dest="vulns", not "vuln_in". A fill call that targets
        # the wrong attribute name silently leaves args.vulns empty even though the
        # config declared vulnerability evidence -- the scan would then run against zero
        # vulnerabilities instead of failing loudly or using what was configured.
        from argparse import Namespace

        from reachability_advisor.cli import apply_config_defaults
        from reachability_advisor.config import load_config

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text(
                "version: 1\nevidence:\n  vulnerabilities: [vulns.json]\n", encoding="utf-8"
            )
            loaded = load_config(path)

        args = Namespace(vulns=[], sbom=[], _explicit=set())
        self.assertEqual(apply_config_defaults(args, loaded).vulns, ["vulns.json"])

    def test_kubernetes_manifest_from_config_is_a_list_not_a_bare_string(self) -> None:
        # iac.kubernetes is a single string in the schema, but --kubernetes-manifest is a
        # repeatable list flag. Assigning the bare string would make downstream code
        # iterate it character by character instead of treating it as one manifest path.
        from argparse import Namespace

        from reachability_advisor.cli import apply_config_defaults
        from reachability_advisor.config import load_config

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text("version: 1\niac:\n  kubernetes: manifests/k8s\n", encoding="utf-8")
            loaded = load_config(path)

        args = Namespace(kubernetes_manifest=[], sbom=[], _explicit=set())
        result = apply_config_defaults(args, loaded).kubernetes_manifest
        self.assertEqual(result, ["manifests/k8s"])
        self.assertIsInstance(result, list)

    def test_analysis_profile_from_config_applies_when_not_passed_on_the_cli(self) -> None:
        # --analysis-profile used to default to "advisory" in argparse itself, which made
        # args.analysis_profile truthy even when the flag was never passed. `fill` only
        # overwrites a falsy current value, so that baked-in default silently masked
        # gate.profile from ever applying.
        from argparse import Namespace

        from reachability_advisor.cli import apply_config_defaults
        from reachability_advisor.config import load_config

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text("version: 1\ngate:\n  profile: production\n", encoding="utf-8")
            loaded = load_config(path)

        args = Namespace(analysis_profile=None, sbom=[], _explicit=set())
        self.assertEqual(apply_config_defaults(args, loaded).analysis_profile, "production")

    def test_analysis_profile_from_config_applies_through_the_real_parser(self) -> None:
        # A hand-built Namespace (as above) never exercises argparse's own default
        # machinery. --analysis-profile must have no baked-in argparse default, or
        # args.analysis_profile is always truthy ("advisory") even when the flag was
        # never passed, and `fill`'s current-value check then silently refuses to ever
        # apply gate.profile from configuration.
        from reachability_advisor.cli import apply_config_defaults, explicit_dests
        from reachability_advisor.cli_parser import build_parser
        from reachability_advisor.config import load_config

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text("version: 1\ngate:\n  profile: production\n", encoding="utf-8")
            loaded = load_config(path)

        parser = build_parser()
        argv = ["scan", "--sbom", "x.json", "--vuln-in", "y.json"]
        args = parser.parse_args(argv)
        args._explicit = explicit_dests(parser, argv)
        self.assertEqual(apply_config_defaults(args, loaded).analysis_profile, "production")


class ScanEndToEndConfigTests(unittest.TestCase):
    """Real `scan` invocations against real sample data, not just the helpers directly."""

    def _config_text(self, gate_block: str) -> str:
        return (
            "version: 1\n"
            "artifacts:\n"
            f"  audit-api:\n    sbom: {ROOT / 'samples/sboms/audit-api.cdx.json'}\n"
            "evidence:\n"
            f"  vulnerabilities: [{ROOT / 'samples/vulnerabilities.json'}]\n"
            f"{gate_block}"
        )

    def test_scan_with_no_flags_uses_config_and_a_configured_gate_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text(self._config_text("gate:\n  fail_on: medium\n"), encoding="utf-8")
            code = main(["scan", "--no-table", "--config", str(path)])
        # samples/vulnerabilities.json against audit-api.cdx.json is known (see
        # ConfigExplainTests' CONFIG fixture and the manual verification run) to produce a
        # `medium` finding; a configured gate.fail_on: medium must fail the scan even
        # though no --fail-on-tier flag was passed on the command line.
        self.assertEqual(code, 10)

    def test_explicit_fail_on_tier_overrides_a_configured_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text(self._config_text("gate:\n  fail_on: medium\n"), encoding="utf-8")
            code = main(["scan", "--no-table", "--config", str(path), "--fail-on-tier=urgent"])
        self.assertEqual(code, 0)

    def test_no_config_file_present_does_not_enable_a_gate(self) -> None:
        code = main([
            "scan",
            "--no-table",
            "--sbom", str(ROOT / "samples/sboms/audit-api.cdx.json"),
            "--vuln-in", str(ROOT / "samples/vulnerabilities.json"),
        ])
        # No .reachability.yml is discoverable from this process's cwd (the repository
        # root has none), so this must behave exactly as it did before config support
        # existed: no --fail-on-tier and no --policy means no gate, regardless of tiers.
        self.assertEqual(code, 0)

    def test_scan_without_sbom_or_config_fails_closed(self) -> None:
        code = main(["scan", "--no-table"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
