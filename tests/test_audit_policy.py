"""Regression tests for audit findings in the `policy` group."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from typing import Any

from reachability_advisor.models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    Finding,
    Reachability,
    SourceEvidence,
    Tier,
    VulnerabilityRecord,
)
from reachability_advisor.policy import (
    ExceptionRule,
    PolicyError,
    RuntimePolicy,
    apply_exceptions,
    load_runtime_policy,
)
from reachability_advisor.scoring import ScorePolicy


def _finding() -> Finding:
    artifact = Artifact(name="payments-api")
    component = Component(name="log4j-core", version="2.14.1", purl="pkg:maven/log4j-core@2.14.1")
    vuln = VulnerabilityRecord(
        id="CVE-2021-44228", package_name="log4j-core", fixed_versions=["2.17.1"], cvss=10.0
    )
    return Finding(
        key="payments-api|log4j-core|2.14.1|CVE-2021-44228",
        artifact=artifact,
        component=component,
        vulnerability=vuln,
        source=SourceEvidence(reachability=Reachability.IMPORTED, confidence=Confidence.MEDIUM),
        context=ContextEvidence(exposure="public", confidence=Confidence.MEDIUM),
        score=95,
        tier=Tier.URGENT,
        confidence=Confidence.MEDIUM,
        rationale=[],
    )


def _write(tmp: str, payload: Any) -> Path:
    path = Path(tmp) / "policy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class UnscopedExceptionTests(unittest.TestCase):
    """Finding 1: an exception with no selector must never match every finding."""

    def test_rule_without_any_selector_does_not_apply(self) -> None:
        rule = ExceptionRule(reason="pending security review")
        self.assertFalse(rule.applies(_finding(), today=date(2026, 7, 27)))

    def test_apply_exceptions_leaves_finding_active_for_unscoped_rule(self) -> None:
        finding = _finding()
        policy = RuntimePolicy(
            score_policy=ScorePolicy(),
            exceptions=[ExceptionRule(reason="pending security review")],
        )
        apply_exceptions([finding], policy)
        self.assertEqual(finding.policy_status, "active")
        self.assertEqual(finding.rationale, [])

    def test_load_rejects_exception_with_typoed_selector_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                {
                    "schema_version": "1.0",
                    "fail_on_tier": "high",
                    "exceptions": [
                        {
                            "vulnerabilities": ["CVE-2021-44228"],
                            "package": "log4j-core",
                            "expires": "2026-12-31",
                            "reason": "waiver for log4j only",
                        }
                    ],
                },
            )
            with self.assertRaises(PolicyError) as ctx:
                load_runtime_policy(path)
        message = str(ctx.exception)
        self.assertIn("vulnerabilities", message)
        self.assertIn("package", message)

    def test_load_rejects_exception_without_selector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, {"fail_on_tier": "high", "exceptions": [{"reason": "review"}]})
            with self.assertRaises(PolicyError) as ctx:
                load_runtime_policy(path)
        self.assertIn("vulnerability", str(ctx.exception))

    def test_load_rejects_empty_string_selector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                {
                    "fail_on_tier": "high",
                    "exceptions": [{"vulnerability": "", "artifact": "app", "reason": "x"}],
                },
            )
            with self.assertRaises(PolicyError) as ctx:
                load_runtime_policy(path)
        self.assertIn("vulnerability", str(ctx.exception))

    def test_load_rejects_exception_without_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                {"fail_on_tier": "high", "exceptions": [{"vulnerability": "CVE-X"}]},
            )
            with self.assertRaises(PolicyError) as ctx:
                load_runtime_policy(path)
        self.assertIn("reason", str(ctx.exception))

    def test_scoped_exception_still_loads_and_applies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                {
                    "$schema": "../schemas/runtime-policy.schema.json",
                    "schema_version": "1.0",
                    "fail_on_tier": "medium",
                    "exceptions": [
                        {
                            "vulnerability": "CVE-2021-44228",
                            "artifact": "payments-api",
                            "component": "log4j-core",
                            "expires": "2099-01-01",
                            "reason": "accepted by owner",
                        }
                    ],
                },
            )
            policy = load_runtime_policy(path)
        self.assertEqual(policy.fail_on_tier, Tier.MEDIUM)
        finding = _finding()
        apply_exceptions([finding], policy)
        self.assertEqual(finding.policy_status, "excepted")


class ExpiresParsingTests(unittest.TestCase):
    """Findings 2 and 3: a malformed `expires` must never become a permanent waiver."""

    def test_load_rejects_non_iso_expires(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                {
                    "fail_on_tier": "high",
                    "exceptions": [
                        {
                            "vulnerability": "CVE-2021-44228",
                            "artifact": "payments-api",
                            "component": "log4j-core",
                            "expires": "01/01/2020",
                            "reason": "temporary waiver, expired long ago",
                        }
                    ],
                },
            )
            with self.assertRaises(PolicyError) as ctx:
                load_runtime_policy(path)
        message = str(ctx.exception)
        self.assertIn("01/01/2020", message)
        self.assertIn("expires", message)

    def test_load_rejects_out_of_range_expires(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                {
                    "fail_on_tier": "high",
                    "exceptions": [
                        {"vulnerability": "CVE-X", "expires": "2024-13-01", "reason": "typo"}
                    ],
                },
            )
            with self.assertRaises(PolicyError):
                load_runtime_policy(path)

    def test_load_rejects_blank_expires(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                {
                    "fail_on_tier": "high",
                    "exceptions": [{"vulnerability": "CVE-X", "expires": "", "reason": "blank"}],
                },
            )
            with self.assertRaises(PolicyError):
                load_runtime_policy(path)

    def test_load_rejects_non_string_expires(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                {
                    "fail_on_tier": "high",
                    "exceptions": [{"vulnerability": "CVE-X", "expires": 20241231, "reason": "n"}],
                },
            )
            with self.assertRaises(PolicyError):
                load_runtime_policy(path)

    def test_iso_timestamp_expires_is_parsed_and_expires(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                {
                    "fail_on_tier": "high",
                    "exceptions": [
                        {
                            "vulnerability": "CVE-2021-44228",
                            "expires": "2024-01-31T00:00:00Z",
                            "reason": "temporary",
                        }
                    ],
                },
            )
            policy = load_runtime_policy(path)
        self.assertEqual(policy.exceptions[0].expires, date(2024, 1, 31))
        finding = _finding()
        self.assertFalse(policy.exceptions[0].applies(finding, today=date(2026, 7, 27)))
        apply_exceptions([finding], policy)
        self.assertEqual(finding.policy_status, "active")

    def test_offset_timestamp_expires_is_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                {
                    "fail_on_tier": "high",
                    "exceptions": [
                        {
                            "vulnerability": "CVE-X",
                            "expires": "2030-06-01T12:00:00+02:00",
                            "reason": "temporary",
                        }
                    ],
                },
            )
            policy = load_runtime_policy(path)
        self.assertEqual(policy.exceptions[0].expires, date(2030, 6, 1))

    def test_padded_expires_is_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                {
                    "fail_on_tier": "high",
                    "exceptions": [
                        {"vulnerability": "CVE-X", "expires": " 2030-06-01 ", "reason": "t"}
                    ],
                },
            )
            policy = load_runtime_policy(path)
        self.assertEqual(policy.exceptions[0].expires, date(2030, 6, 1))

    def test_missing_expires_key_is_still_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(
                tmp,
                {
                    "fail_on_tier": "high",
                    "exceptions": [{"vulnerability": "CVE-X", "reason": "no expiry by choice"}],
                },
            )
            policy = load_runtime_policy(path)
        self.assertIsNone(policy.exceptions[0].expires)


class PolicyDocumentTests(unittest.TestCase):
    """Finding 1: the loader must not silently reinterpret a malformed document."""

    def test_load_rejects_unknown_top_level_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, {"fail_on_tier": "high", "exception": [], "exceptions": []})
            with self.assertRaises(PolicyError) as ctx:
                load_runtime_policy(path)
        self.assertIn("exception", str(ctx.exception))

    def test_load_rejects_unknown_fail_on_tier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, {"fail_on_tier": "critical", "exceptions": []})
            with self.assertRaises(PolicyError) as ctx:
                load_runtime_policy(path)
        self.assertIn("critical", str(ctx.exception))

    def test_load_rejects_non_object_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(["fail_on_tier"]), encoding="utf-8")
            with self.assertRaises(PolicyError):
                load_runtime_policy(path)

    def test_load_rejects_non_object_exception_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, {"fail_on_tier": "high", "exceptions": ["bad"]})
            with self.assertRaises(PolicyError):
                load_runtime_policy(path)

    def test_load_rejects_non_list_exceptions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, {"fail_on_tier": "high", "exceptions": {"vulnerability": "CVE-X"}})
            with self.assertRaises(PolicyError):
                load_runtime_policy(path)

    def test_policy_error_is_value_error_for_cli_exit_code(self) -> None:
        self.assertTrue(issubclass(PolicyError, ValueError))

    def test_missing_fail_on_tier_still_defaults_to_high(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, {"schema_version": "1.0", "exceptions": []})
            policy = load_runtime_policy(path)
        self.assertEqual(policy.fail_on_tier, Tier.HIGH)

    def test_fail_on_tier_is_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, {"fail_on_tier": "URGENT", "exceptions": []})
            policy = load_runtime_policy(path)
        self.assertEqual(policy.fail_on_tier, Tier.URGENT)

    def test_missing_exceptions_key_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, {"schema_version": "1.0", "fail_on_tier": "low"})
            policy = load_runtime_policy(path)
        self.assertEqual(policy.fail_on_tier, Tier.LOW)
        self.assertEqual(policy.exceptions, [])

    def test_scoped_rule_still_skips_non_matching_findings(self) -> None:
        finding = _finding()
        self.assertFalse(ExceptionRule(vulnerability="CVE-OTHER", reason="x").applies(finding))
        self.assertFalse(ExceptionRule(artifact="other-api", reason="x").applies(finding))
        self.assertFalse(ExceptionRule(component="other-lib", reason="x").applies(finding))
        self.assertTrue(ExceptionRule(vulnerability="CVE-2021-44228", reason="x").applies(finding))

    def test_no_policy_path_returns_defaults(self) -> None:
        policy = load_runtime_policy(None)
        self.assertEqual(policy.fail_on_tier, Tier.HIGH)
        self.assertEqual(policy.exceptions, [])

    def test_shipped_configs_load(self) -> None:
        root = Path(__file__).resolve().parents[1]
        configs = sorted((root / "configs").glob("policy*.json"))
        self.assertTrue(configs)
        for config in configs:
            with self.subTest(config=config.name):
                load_runtime_policy(config)


if __name__ == "__main__":
    unittest.main()
