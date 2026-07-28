# tests/test_config_cli.py
from __future__ import annotations

import argparse
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
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


class AbbreviatedFlagDetectionTests(unittest.TestCase):
    """argparse accepts unambiguous abbreviated long options by default
    (`allow_abbrev=True`, which this project deliberately does not disable -- that would
    change user-facing CLI behaviour and could break scripts that rely on abbreviations).
    `explicit_dests` must recognise every form argparse itself parses, or an abbreviated
    gate flag on the command line is silently overridden by configuration -- the same
    class of silent weakening this project refuses everywhere else.
    """

    def test_exact_long_form_is_detected_with_space_and_with_equals(self) -> None:
        from reachability_advisor.cli import explicit_dests
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        for argv in (
            ["scan", "--fail-on-tier", "urgent"],
            ["scan", "--fail-on-tier=urgent"],
        ):
            with self.subTest(argv=argv):
                self.assertIn("fail_on_tier", explicit_dests(parser, argv))

    def test_unambiguous_abbreviation_is_detected_with_space_and_with_equals(self) -> None:
        # --fail-on-ti is a prefix of exactly one scan option, --fail-on-tier (the others
        # sharing the --fail-on- prefix are --fail-on-mapping-warnings and
        # --fail-on-readiness-warnings, neither of which --fail-on-ti is a prefix of).
        from reachability_advisor.cli import explicit_dests
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        for argv in (
            ["scan", "--fail-on-ti", "urgent"],
            ["scan", "--fail-on-ti=urgent"],
        ):
            with self.subTest(argv=argv):
                self.assertIn("fail_on_tier", explicit_dests(parser, argv))

    def test_ambiguous_prefix_is_not_reported_and_argparse_itself_rejects_it(self) -> None:
        # --fail-on- is a prefix of --fail-on-mapping-warnings, --fail-on-readiness-
        # warnings, and --fail-on-tier all at once, so argparse itself refuses to guess
        # and exits 2 rather than parsing it as any one of them. explicit_dests must not
        # guess either: report no match, exactly as if the flag were never passed.
        from reachability_advisor.cli import explicit_dests
        from reachability_advisor.cli_parser import build_parser

        argv = ["scan", "--fail-on-", "urgent"]

        parser = build_parser()
        self.assertNotIn("fail_on_tier", explicit_dests(parser, argv))
        self.assertEqual(explicit_dests(parser, argv) & {
            "fail_on_mapping_warnings",
            "fail_on_readiness_warnings",
            "fail_on_tier",
        }, set())

        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            build_parser().parse_args(argv)
        self.assertEqual(ctx.exception.code, 2)

    def test_flag_not_passed_at_all_is_not_reported(self) -> None:
        from reachability_advisor.cli import explicit_dests
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        self.assertNotIn("fail_on_tier", explicit_dests(parser, ["scan", "--no-table"]))

    def test_repeated_flag_is_reported_once(self) -> None:
        from reachability_advisor.cli import explicit_dests
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        argv = ["scan", "--fail-on-tier", "urgent", "--fail-on-tier", "high"]
        self.assertEqual(explicit_dests(parser, argv), {"fail_on_tier"})

    def test_subcommand_flag_is_detected(self) -> None:
        # `--config` on `config explain` is an action of the nested `explain` subparser,
        # two levels below the top-level parser (top -> config -> explain). A previous
        # defect here inspected only the top-level parser's actions and found nothing for
        # any subcommand flag at all.
        from reachability_advisor.cli import explicit_dests
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        argv = ["config", "explain", "--config", "reachability.yml"]
        self.assertIn("config", explicit_dests(parser, argv))

    def test_short_options_match_exactly(self) -> None:
        # The production parser defines no short options besides the auto-added -h/
        # --help, so this exercises the general mechanism directly against a small
        # standalone parser rather than reaching into cli_parser.
        from reachability_advisor.cli import explicit_dests

        parser = argparse.ArgumentParser()
        parser.add_argument("-v", "--verbose", action="store_true")
        parser.add_argument("-x", action="store_true")

        self.assertEqual(explicit_dests(parser, ["-v"]), {"verbose"})
        self.assertEqual(explicit_dests(parser, ["-x"]), {"x"})
        # An unrelated single-dash token must not match anything.
        self.assertEqual(explicit_dests(parser, ["-z"]), set())

    def test_single_character_short_options_are_not_abbreviation_targets(self) -> None:
        # argparse *does* prefix-match single-dash multi-character option strings, such
        # as "-xray", against a shorter token like "-x" -- a separate, older argparse
        # mechanism that is not gated by `allow_abbrev` at all (verified directly against
        # argparse: `ArgumentParser(allow_abbrev=False)` still resolves "-x" to "-xray").
        # This project's parsers define no such single-dash multi-character options --
        # only single-character ones plus the auto-added -h/--help -- so resolving that
        # form is deliberately out of scope; "-x" must only ever match itself exactly.
        from reachability_advisor.cli import explicit_dests

        parser = argparse.ArgumentParser()
        parser.add_argument("-xray", action="store_true")

        self.assertEqual(explicit_dests(parser, ["-xray"]), {"xray"})
        self.assertEqual(explicit_dests(parser, ["-x"]), set())

    def test_exact_match_wins_even_when_also_a_prefix_of_a_sibling_option(self) -> None:
        # argparse checks for an exact option-string match before ever attempting prefix
        # (abbreviation) resolution (verified directly: a parser with both --fail-on-tier
        # and --fail-on-tier-extra parses "--fail-on-tier" as the former, not as
        # "ambiguous option"). So typing the full "--fail-on-tier" must resolve to
        # --fail-on-tier itself even though it is *also* a textual prefix of the sibling
        # --fail-on-tier-extra, rather than being reported ambiguous between the two.
        from reachability_advisor.cli import explicit_dests

        parser = argparse.ArgumentParser()
        parser.add_argument("--fail-on-tier")
        parser.add_argument("--fail-on-tier-extra")

        self.assertEqual(explicit_dests(parser, ["--fail-on-tier", "urgent"]), {"fail_on_tier"})

    def test_bare_double_dash_never_resolves_to_an_option(self) -> None:
        # "--" is argparse's own end-of-options marker, not an abbreviation of anything.
        # Every long option string starts with "--", so treating the bare token as a name
        # to prefix-match would make it match any single-long-option parser's one option.
        from reachability_advisor.cli import explicit_dests

        parser = argparse.ArgumentParser()
        parser.add_argument("--only", action="store_true")

        self.assertEqual(explicit_dests(parser, ["--"]), set())

    def test_help_is_never_reported_as_explicit(self) -> None:
        # -h/--help is auto-added by argparse to every parser and is excluded from
        # `_explicit`; nothing in configuration is ever named "help", but this guards the
        # exclusion itself, including through an unambiguous abbreviation of --help.
        from reachability_advisor.cli import explicit_dests
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        for argv in (["scan", "--help"], ["scan", "--hel"], ["scan", "-h"]):
            with self.subTest(argv=argv):
                self.assertNotIn("help", explicit_dests(parser, argv))

    def test_chain_closure_is_not_reopened_by_a_later_matching_token(self) -> None:
        # Once a positional token fails to match the subcommand choices available at that
        # point, no later token may re-open subcommand navigation, even if it happens to
        # spell a valid deeper subcommand name -- argparse itself would already have
        # exited with "invalid choice" before parsing got that far (verified: `config
        # bogus` alone exits 2), so this is a defensive check against explicit_dests
        # wrongly guessing dests from a deeper subparser it was never actually routed to.
        from reachability_advisor.cli import explicit_dests
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        argv = ["config", "bogus", "explain", "--config", "reachability.yml"]
        self.assertNotIn("config", explicit_dests(parser, argv))

    def test_abbreviated_cli_flag_beats_a_configured_gate_end_to_end(self) -> None:
        # The behaviour the user actually cares about: an abbreviated --fail-on-tier on
        # the command line must win over .reachability.yml's gate.fail_on, exactly like
        # the unabbreviated flag already does in
        # ScanEndToEndConfigTests.test_explicit_fail_on_tier_overrides_a_configured_gate.
        # If explicit_dests failed to recognise the abbreviation, apply_config_defaults
        # would treat fail_on_tier as unset and silently fill it from the configured
        # "medium" gate, which fails this exact scan (see
        # test_scan_with_no_flags_uses_config_and_a_configured_gate_is_enforced).
        config_text = (
            "version: 1\n"
            "artifacts:\n"
            f"  audit-api:\n    sbom: {ROOT / 'samples/sboms/audit-api.cdx.json'}\n"
            "evidence:\n"
            f"  vulnerabilities: [{ROOT / 'samples/vulnerabilities.json'}]\n"
            "gate:\n  fail_on: medium\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text(config_text, encoding="utf-8")
            code = main(["scan", "--no-table", "--config", str(path), "--fail-on-ti=urgent"])
        self.assertEqual(code, 0)


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


class ConAbbreviationBackwardCompatibilityTests(unittest.TestCase):
    """Final-review should-fix 6: before `--config` existed, `--con` was the only
    "--con*"-prefixed option on `scan`, so argparse's own abbreviation resolution
    accepted it unambiguously as `--context`. Adding `--config` made "--con" a prefix of
    *two* option strings (--context, --config), so argparse's abbreviation resolution
    alone now rejects it outright ("ambiguous option: --con could match --context,
    --config") -- a real backward-compatibility break for any existing script that relied
    on the old, unambiguous abbreviation.

    Resolution: `--con` is registered as an explicit, literal alias for `--context` (see
    cli_parser.py), not left to abbreviation resolution. argparse checks for an exact
    option-string match *before* ever attempting prefix/abbreviation resolution (pinned
    directly by `test_exact_match_wins_even_when_also_a_prefix_of_a_sibling_option` in
    `AbbreviatedFlagDetectionTests`, above), so a literal "--con" now resolves to
    --context immediately and is never even considered as a prefix of --config. This is
    also more future-proof than relying on abbreviation staying unambiguous forever: it
    stays unambiguous even if another "--con*"-prefixed flag is ever added later.
    """

    def test_bare_con_resolves_to_context_not_ambiguous(self) -> None:
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "--con", "ctx.json", "--sbom", "x.json"])
        self.assertEqual(args.context, "ctx.json")
        self.assertIsNone(args.config)

    def test_con_equals_form_also_resolves_to_context(self) -> None:
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "--con=ctx.json", "--sbom", "x.json"])
        self.assertEqual(args.context, "ctx.json")

    def test_con_is_detected_as_an_explicit_dest_for_context(self) -> None:
        # explicit_dests (cli.py) must recognise the alias too, or a `--con`-supplied
        # context on the command line would be silently treated as unset by
        # apply_config_defaults-style filling (context has no config equivalent today,
        # but this is the same mechanism relied on for every other flag).
        from reachability_advisor.cli import explicit_dests
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        self.assertIn("context", explicit_dests(parser, ["scan", "--con", "ctx.json"]))

    def test_full_context_flag_still_works_unaffected(self) -> None:
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "--context", "ctx.json", "--sbom", "x.json"])
        self.assertEqual(args.context, "ctx.json")

    def test_full_config_flag_is_unambiguous_and_unaffected_by_the_alias(self) -> None:
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "--config", "cfg.yml", "--sbom", "x.json"])
        self.assertEqual(args.config, "cfg.yml")
        self.assertIsNone(args.context)

    def test_an_unambiguous_partial_abbreviation_of_config_still_works(self) -> None:
        # "--conf" is a prefix of --config only (not of the literal "--con" alias, which
        # is an exact option string, not a prefix target) -- argparse's own abbreviation
        # resolution still applies normally to every option string that isn't a fixed
        # alias itself.
        from reachability_advisor.cli_parser import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "--conf", "cfg.yml", "--sbom", "x.json"])
        self.assertEqual(args.config, "cfg.yml")


if __name__ == "__main__":
    unittest.main()
