# tests/test_config_schema.py
from __future__ import annotations

import unittest

from reachability_advisor.config_schema import ConfigError, validate_config

MINIMAL = {
    "version": 1,
    "artifacts": {"payments-api": {"sbom": "sboms/p.cdx.json", "source": "src/p"}},
}


class ValidateConfigTests(unittest.TestCase):
    def test_accepts_a_minimal_config(self) -> None:
        config = validate_config(MINIMAL, "test.yml")
        self.assertEqual(config.artifacts["payments-api"].sbom, "sboms/p.cdx.json")
        self.assertEqual(config.gate.fail_on, "high")  # documented default

    def test_rejects_an_unknown_top_level_key(self) -> None:
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "artifcats": {}}, "test.yml")
        message = str(error.exception)
        self.assertIn("artifcats", message)
        self.assertIn("test.yml", message)

    def test_rejects_an_unknown_gate_key(self) -> None:
        # A typo'd gate key must fail loudly: silently defaulting is how a gate stops gating.
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "gate": {"fial_on": "high"}}, "test.yml")
        self.assertIn("fial_on", str(error.exception))

    def test_rejects_an_out_of_range_fail_on_tier(self) -> None:
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "gate": {"fail_on": "bad"}}, "test.yml")
        self.assertIn("fail_on", str(error.exception))

    def test_rejects_a_missing_version(self) -> None:
        with self.assertRaises(ConfigError) as error:
            validate_config({"artifacts": {}}, "test.yml")
        self.assertIn("version", str(error.exception))

    def test_rejects_an_unsupported_version(self) -> None:
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "version": 99}, "test.yml")
        self.assertIn("99", str(error.exception))

    def test_rejects_a_boolean_version(self) -> None:
        # bool is a subclass of int in Python, so `True in {1}` is True and
        # `True == 1`. Without an explicit guard, `version: true` in YAML would
        # silently validate as `version: 1` instead of being rejected as the
        # wrong type.
        with self.assertRaises(ConfigError):
            validate_config({**MINIMAL, "version": True}, "test.yml")

    def test_rejects_a_wrongly_typed_artifact_block(self) -> None:
        # Must be rejected *because* the value isn't a mapping, not by some other
        # incidental path (e.g. iterating the string's characters as "keys" and
        # coincidentally finding none of them are allowed artifact keys).
        with self.assertRaises(ConfigError) as error:
            validate_config({"version": 1, "artifacts": {"a": "not-a-mapping"}}, "test.yml")
        message = str(error.exception)
        self.assertIn("must be a mapping", message)
        self.assertIn("str", message)

    def test_rejects_an_unknown_key_in_an_artifact_block(self) -> None:
        config = {
            "version": 1,
            "artifacts": {"payments-api": {"sbom": "s.json", "extra_typo_key": "x"}},
        }
        with self.assertRaises(ConfigError) as error:
            validate_config(config, "test.yml")
        message = str(error.exception)
        self.assertIn("extra_typo_key", message)
        self.assertIn("test.yml", message)

    def test_rejects_an_unknown_evidence_key(self) -> None:
        config = {**MINIMAL, "evidence": {"vulnerabilities": ["v.json"], "bogus_evi_key": ["x"]}}
        with self.assertRaises(ConfigError) as error:
            validate_config(config, "test.yml")
        message = str(error.exception)
        self.assertIn("bogus_evi_key", message)
        self.assertIn("test.yml", message)

    def test_rejects_an_unknown_iac_key(self) -> None:
        config = {**MINIMAL, "iac": {"terraform": "infra/", "bogus_iac_key": "z"}}
        with self.assertRaises(ConfigError) as error:
            validate_config(config, "test.yml")
        message = str(error.exception)
        self.assertIn("bogus_iac_key", message)
        self.assertIn("test.yml", message)

    def test_rejects_an_unknown_output_key(self) -> None:
        config = {**MINIMAL, "output": {"dir": "out", "bogus_output_key": "z"}}
        with self.assertRaises(ConfigError) as error:
            validate_config(config, "test.yml")
        message = str(error.exception)
        self.assertIn("bogus_output_key", message)
        self.assertIn("test.yml", message)

    def test_rejects_a_float_version(self) -> None:
        # `1.0 in {1}` and `int(1.0)` both succeed, so without an explicit `int`
        # type check `version: 1.0` would silently validate as `version: 1`.
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "version": 1.0}, "test.yml")
        message = str(error.exception)
        self.assertIn("1.0", message)
        self.assertIn("test.yml", message)

    def test_rejects_an_invalid_gate_profile(self) -> None:
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "gate": {"profile": "bogus"}}, "test.yml")
        message = str(error.exception)
        self.assertIn("profile", message)
        self.assertIn("bogus", message)

    def test_rejects_an_unsupported_output_format(self) -> None:
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "output": {"formats": ["yaml"]}}, "test.yml")
        message = str(error.exception)
        self.assertIn("formats", message)
        self.assertIn("yaml", message)

    def test_rejects_non_numeric_threshold_values(self) -> None:
        # Each of these must hit the type guard, not the range check.
        for bad in ("0.8", None, [0.8], True):
            with self.subTest(bad=bad):
                config = {**MINIMAL, "gate": {"thresholds": {"min_x": bad}}}
                with self.assertRaises(ConfigError) as error:
                    validate_config(config, "test.yml")
                message = str(error.exception)
                self.assertIn("min_x", message)
                self.assertIn("must be a number", message)

    def test_rejects_a_non_string_threshold_key(self) -> None:
        # `{True: 5}` must not silently become `{"True": 5.0}`.
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "gate": {"thresholds": {True: 5}}}, "test.yml")
        message = str(error.exception)
        self.assertIn("True", message)
        self.assertIn("must be a string", message)

    def test_rejects_a_negative_threshold(self) -> None:
        # A negative threshold would make `coverage >= threshold` trivially true,
        # silently defeating the gate it is supposed to enforce.
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "gate": {"thresholds": {"min_x": -5}}}, "test.yml")
        message = str(error.exception)
        self.assertIn("min_x", message)
        self.assertIn("-5", message)

    def test_rejects_non_finite_thresholds(self) -> None:
        # NaN makes every `>=`/`<=` comparison False, silently defeating the gate.
        for bad in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(bad=bad):
                config = {**MINIMAL, "gate": {"thresholds": {"min_x": bad}}}
                with self.assertRaises(ConfigError) as error:
                    validate_config(config, "test.yml")
                self.assertIn("min_x", str(error.exception))

    def test_rejects_a_threshold_above_one(self) -> None:
        # Every gate.thresholds key corresponds to a CLI --min-* flag documented
        # as a 0..1 coverage ratio; nothing above 1.0 is ever satisfiable.
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "gate": {"thresholds": {"min_x": 1.5}}}, "test.yml")
        message = str(error.exception)
        self.assertIn("min_x", message)
        self.assertIn("1.5", message)

    def test_accepts_boundary_thresholds(self) -> None:
        config = validate_config(
            {**MINIMAL, "gate": {"thresholds": {"min_x": 0.0, "min_y": 1.0}}}, "test.yml"
        )
        self.assertEqual(config.gate.thresholds, {"min_x": 0.0, "min_y": 1.0})

    def test_rejects_an_empty_or_whitespace_output_dir(self) -> None:
        for bad in ("", "   "):
            with self.subTest(bad=repr(bad)):
                config = {**MINIMAL, "output": {"dir": bad}}
                with self.assertRaises(ConfigError) as error:
                    validate_config(config, "test.yml")
                self.assertIn("output.dir", str(error.exception))

    def test_rejects_an_empty_or_whitespace_artifact_field(self) -> None:
        for bad in ("", "   "):
            with self.subTest(bad=repr(bad)):
                config = {
                    "version": 1,
                    "artifacts": {"payments-api": {"sbom": bad}},
                }
                with self.assertRaises(ConfigError) as error:
                    validate_config(config, "test.yml")
                message = str(error.exception)
                self.assertIn("sbom", message)
                self.assertIn("non-empty string", message)


if __name__ == "__main__":
    unittest.main()
