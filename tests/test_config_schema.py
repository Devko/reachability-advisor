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


if __name__ == "__main__":
    unittest.main()
