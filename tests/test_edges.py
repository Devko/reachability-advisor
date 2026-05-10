from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.context import ContextError, _classify_policy, infer_context_from_terraform, load_context_file
from reachability_advisor.models import Artifact, Component, Confidence, ContextEvidence, Finding, Reachability, SourceEvidence, Tier, VulnerabilityRecord
from reachability_advisor.compare import write_delta, write_delta_markdown
from reachability_advisor.policy import ExceptionRule, load_runtime_policy, apply_exceptions
from reachability_advisor.purl import parse_purl
from reachability_advisor.remediation import build_remediation_groups
from reachability_advisor.sbom import SbomError, load_sbom
from reachability_advisor.scoring import ScorePolicy, fix_commands, score_finding
from reachability_advisor.source import analyze_component_source
from reachability_advisor.validators import issues_report, validate_paths
from reachability_advisor.vulnerability import VulnerabilityError, load_vulnerabilities, matching_vulnerabilities

ROOT = Path(__file__).resolve().parents[1]


class PolicyEdgeTests(unittest.TestCase):
    def _finding(self) -> Finding:
        artifact = Artifact(name="app")
        component = Component(name="lib", version="1", purl="pkg:npm/lib@1")
        vuln = VulnerabilityRecord(id="CVE-X", package_name="lib", fixed_versions=["2"], cvss=7.0)
        return Finding(
            key="app|lib|1|CVE-X",
            artifact=artifact,
            component=component,
            vulnerability=vuln,
            source=SourceEvidence(reachability=Reachability.IMPORTED, confidence=Confidence.MEDIUM),
            context=ContextEvidence(exposure="public", confidence=Confidence.MEDIUM),
            score=70,
            tier=Tier.HIGH,
            confidence=Confidence.MEDIUM,
            rationale=[],
        )

    def test_exception_rule_applies(self) -> None:
        finding = self._finding()
        rule = ExceptionRule(vulnerability="CVE-X", artifact="app", component="lib", reason="accepted")
        self.assertTrue(rule.applies(finding, today=date(2026, 1, 1)))

    def test_exception_rule_does_not_apply_after_expiry(self) -> None:
        finding = self._finding()
        rule = ExceptionRule(vulnerability="CVE-X", expires=date(2025, 1, 1))
        self.assertFalse(rule.applies(finding, today=date(2026, 1, 1)))

    def test_load_policy_with_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({"fail_on_tier": "medium", "exceptions": [{"vulnerability": "CVE-X", "artifact": "app", "component": "lib", "expires": "2099-01-01", "reason": "test"}]}), encoding="utf-8")
            policy = load_runtime_policy(path)
            self.assertEqual(policy.fail_on_tier, Tier.MEDIUM)
            finding = self._finding()
            apply_exceptions([finding], policy)
            self.assertEqual(finding.policy_status, "excepted")

    def test_load_policy_invalid_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({"fail_on_tier": "bad", "exceptions": [{"expires": "not-a-date"}, "bad"]}), encoding="utf-8")
            policy = load_runtime_policy(path)
            self.assertEqual(policy.fail_on_tier, Tier.HIGH)
            self.assertEqual(len(policy.exceptions), 1)


class ContextEdgeTests(unittest.TestCase):
    def test_context_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(ContextError):
                load_context_file(path)

    def test_context_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ContextError):
                load_context_file(path)

    def test_context_artifacts_not_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps({"artifacts": []}), encoding="utf-8")
            with self.assertRaises(ContextError):
                load_context_file(path)

    def test_policy_classifier_admin_sensitive_limited_unknown(self) -> None:
        self.assertEqual(_classify_policy(json.dumps({"Statement": {"Effect": "Allow", "Action": "*"}})), "admin")
        self.assertEqual(_classify_policy({"Statement": [{"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"]}]}), "sensitive")
        self.assertEqual(_classify_policy({"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"]}]}), "sensitive")
        self.assertEqual(_classify_policy({"Statement": [{"Effect": "Deny", "Action": ["*"]}]}), "unknown")
        self.assertEqual(_classify_policy("AdministratorAccess"), "admin")

    def test_terraform_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tf.json"
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(ContextError):
                infer_context_from_terraform(path, [])

    def test_terraform_apprunner_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tf.json"
            plan = {
                "planned_values": {
                    "root_module": {
                        "child_modules": [
                            {
                                "resources": [
                                    {
                                        "address": "aws_apprunner_service.api",
                                        "type": "aws_apprunner_service",
                                        "values": {
                                            "source_configuration": [
                                                {"image_repository": [{"image_identifier": "ghcr.io/acme/api:1"}]}
                                            ],
                                            "tags": {"Environment": "prod", "Owner": "@api"},
                                        },
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
            path.write_text(json.dumps(plan), encoding="utf-8")
            contexts = infer_context_from_terraform(path, [Artifact(name="api", reference="ghcr.io/acme/api:1")])
            self.assertEqual(contexts["api"].exposure, "public")
            self.assertEqual(contexts["api"].owner, "@api")


class ParserEdgeTests(unittest.TestCase):
    def test_parse_purl_without_slash(self) -> None:
        purl = parse_purl("pkg:npm")
        self.assertEqual(purl.ptype, "npm")  # type: ignore[union-attr]

    def test_sbom_invalid_json_and_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("{", encoding="utf-8")
            with self.assertRaises(SbomError):
                load_sbom(bad)
            arr = Path(tmp) / "arr.json"
            arr.write_text("[]", encoding="utf-8")
            with self.assertRaises(SbomError):
                load_sbom(arr)

    def test_sbom_wrong_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sbom.json"
            path.write_text(json.dumps({"bomFormat": "SPDX"}), encoding="utf-8")
            with self.assertRaises(SbomError):
                load_sbom(path)

    def test_sbom_properties_and_empty_component(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sbom.json"
            path.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"properties": [{"name": "reachability:artifact", "value": "app"}, {"name": "x", "value": None}]}}, "components": [{}, "bad", {"name": "lib", "properties": [{"name": "dependency.scope", "value": "dev"}]}]}), encoding="utf-8")
            sbom = load_sbom(path)
            self.assertEqual(sbom.artifact.name, "app")
            self.assertEqual(sbom.components[0].scope, "dev")

    def test_vulnerability_invalid_json_and_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("{", encoding="utf-8")
            with self.assertRaises(VulnerabilityError):
                load_vulnerabilities(bad)
            arr = Path(tmp) / "arr.json"
            arr.write_text("[]", encoding="utf-8")
            with self.assertRaises(VulnerabilityError):
                load_vulnerabilities(arr)

    def test_vulnerability_missing_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "v.json"
            path.write_text(json.dumps({"vulnerabilities": [{"id": "CVE-X"}]}), encoding="utf-8")
            with self.assertRaises(VulnerabilityError):
                load_vulnerabilities(path)

    def test_vulnerability_list_shape_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "v.json"
            path.write_text(json.dumps({"vulnerabilities": {}}), encoding="utf-8")
            with self.assertRaises(VulnerabilityError):
                load_vulnerabilities(path)

    def test_version_mismatch_no_match(self) -> None:
        component = Component(name="lib", version="1")
        vuln = VulnerabilityRecord(id="CVE-X", package_name="lib", affected_versions=["2"])
        self.assertEqual(matching_vulnerabilities(component, [vuln]), [])


class SourceAndScoringEdgeTests(unittest.TestCase):
    def test_python_requests_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("import requests\nrequests.get('https://example.com')\n", encoding="utf-8")
            component = Component(name="requests", purl="pkg:pypi/requests@2.0.0")
            evidence = analyze_component_source(component, root)
            self.assertEqual(evidence.reachability, Reachability.FUNCTION_REACHABLE)
            self.assertEqual(evidence.language, "python")

    def test_generic_npm_import_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.js").write_text("const leftpad = require('left-pad');\n", encoding="utf-8")
            component = Component(name="left-pad", purl="pkg:npm/left-pad@1.0.0")
            evidence = analyze_component_source(component, root)
            self.assertEqual(evidence.reachability, Reachability.IMPORTED)

    def test_nonexistent_source_root(self) -> None:
        component = Component(name="lib")
        evidence = analyze_component_source(component, Path("/definitely/missing"))
        self.assertEqual(evidence.reachability, Reachability.PACKAGE_PRESENT)

    def test_fix_commands_by_ecosystem(self) -> None:
        vuln = VulnerabilityRecord(id="CVE-X", package_name="lib", fixed_versions=["2"])
        self.assertEqual(fix_commands(Component(name="lodash", purl="pkg:npm/lodash@1"), vuln), ["npm install lodash@2"])
        self.assertEqual(fix_commands(Component(name="requests", purl="pkg:pypi/requests@1"), vuln), ["python -m pip install --upgrade requests==2"])
        self.assertIn("Maven", fix_commands(Component(name="lib", group="g", purl="pkg:maven/g/lib@1"), vuln)[0])
        self.assertEqual(fix_commands(Component(name="lib"), vuln), ["Upgrade lib to 2"])
        self.assertEqual(fix_commands(Component(name="lib"), VulnerabilityRecord(id="CVE-Y", package_name="lib")), [])

    def test_score_unknown_cvss_and_scope_guard(self) -> None:
        sbom_like = type("SbomLike", (), {"artifact": Artifact(name="app")})()
        component = Component(name="lib", version="1", scope="test")
        vuln = VulnerabilityRecord(id="CVE-X", package_name="lib", severity="weird", epss=0.5)
        source = SourceEvidence(reachability=Reachability.ATTACKER_CONTROLLED, confidence=Confidence.MEDIUM)
        context = ContextEvidence(exposure="internal", environment="staging", privilege="limited", confidence=Confidence.MEDIUM)
        finding = score_finding(sbom_like, component, vuln, source, context, ScorePolicy())
        self.assertGreater(finding.score, 0)
        self.assertIn("dependency scope", " ".join(finding.rationale))

    def test_network_iam_criticality_contributes_to_score(self) -> None:
        sbom_like = type("SbomLike", (), {"artifact": Artifact(name="app")})()
        component = Component(name="lib", version="1")
        vuln = VulnerabilityRecord(id="CVE-X", package_name="lib", severity="medium")
        source = SourceEvidence(reachability=Reachability.IMPORTED, confidence=Confidence.MEDIUM)
        base = score_finding(sbom_like, component, vuln, source, ContextEvidence(exposure="public", privilege="sensitive"), ScorePolicy())
        critical = score_finding(
            sbom_like,
            component,
            vuln,
            source,
            ContextEvidence(exposure="public", privilege="sensitive", criticality="high", iam_impacts=["data_access"], confidence=Confidence.MEDIUM),
            ScorePolicy(),
        )
        self.assertGreater(critical.score, base.score)
        self.assertIn("criticality high contributes", " ".join(critical.rationale))

    def test_high_source_confidence_is_not_downgraded_to_low(self) -> None:
        sbom_like = type("SbomLike", (), {"artifact": Artifact(name="app")})()
        finding = score_finding(
            sbom_like,
            Component(name="express", version="4.17.1", purl="pkg:npm/express@4.17.1"),
            VulnerabilityRecord(id="GHSA-X", package_name="express", cvss=6.1),
            SourceEvidence(reachability=Reachability.ATTACKER_CONTROLLED, confidence=Confidence.HIGH),
            ContextEvidence(),
            ScorePolicy(),
        )
        self.assertEqual(finding.confidence, Confidence.MEDIUM)

    def test_private_no_ingress_without_blast_radius_is_capped_below_high(self) -> None:
        sbom_like = type("SbomLike", (), {"artifact": Artifact(name="batch-worker")})()
        finding = score_finding(
            sbom_like,
            Component(name="lodash", version="4.17.20", purl="pkg:npm/lodash@4.17.20"),
            VulnerabilityRecord(id="CVE-2021-23337", package_name="lodash", cvss=7.5, epss=0.22),
            SourceEvidence(reachability=Reachability.FUNCTION_REACHABLE, confidence=Confidence.MEDIUM),
            ContextEvidence(exposure="private", environment="prod", confidence=Confidence.MEDIUM),
            ScorePolicy(),
        )
        self.assertEqual(finding.tier, Tier.MEDIUM)
        self.assertLess(finding.score, 65)
        self.assertIn("private/no-ingress", " ".join(finding.rationale))

    def test_private_known_exploited_or_attacker_controlled_can_still_be_high(self) -> None:
        sbom_like = type("SbomLike", (), {"artifact": Artifact(name="app")})()
        known_exploited = score_finding(
            sbom_like,
            Component(name="lib", version="1", purl="pkg:npm/lib@1"),
            VulnerabilityRecord(id="CVE-X", package_name="lib", cvss=7.5, known_exploited=True),
            SourceEvidence(reachability=Reachability.FUNCTION_REACHABLE, confidence=Confidence.MEDIUM),
            ContextEvidence(exposure="private", environment="prod", confidence=Confidence.MEDIUM),
            ScorePolicy(),
        )
        attacker_controlled = score_finding(
            sbom_like,
            Component(name="lib", version="1", purl="pkg:npm/lib@1"),
            VulnerabilityRecord(id="CVE-Y", package_name="lib", cvss=7.5),
            SourceEvidence(reachability=Reachability.ATTACKER_CONTROLLED, confidence=Confidence.HIGH),
            ContextEvidence(exposure="private", environment="prod", confidence=Confidence.MEDIUM),
            ScorePolicy(),
        )
        self.assertGreaterEqual(known_exploited.score, 65)
        self.assertGreaterEqual(attacker_controlled.score, 65)

    def test_remediation_groups_pick_highest_fixed_version(self) -> None:
        artifact = Artifact(name="audit-api")
        component = Component(
            name="jackson-databind",
            version="2.9.9",
            purl="pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.9",
            group="com.fasterxml.jackson.core",
        )
        findings = [
            Finding(
                key=f"audit-api|jackson-databind|2.9.9|{vuln_id}",
                artifact=artifact,
                component=component,
                vulnerability=VulnerabilityRecord(id=vuln_id, package_name="jackson-databind", fixed_versions=[fixed], cvss=8.0),
                source=SourceEvidence(reachability=Reachability.ATTACKER_CONTROLLED, confidence=Confidence.MEDIUM),
                context=ContextEvidence(exposure="public", privilege="sensitive", confidence=Confidence.MEDIUM),
                score=score,
                tier=Tier.URGENT,
                confidence=Confidence.MEDIUM,
                rationale=[],
                fix_commands=[f"Set Maven dependency com.fasterxml.jackson.core:jackson-databind to version {fixed}"],
            )
            for vuln_id, fixed, score in (
                ("GHSA-A", "2.9.10.8", 90),
                ("GHSA-B", "2.12.7.1", 95),
            )
        ]
        groups = build_remediation_groups(findings)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["vulnerability_count"], 2)
        self.assertEqual(groups[0]["suggested_version"], "2.12.7.1")
        self.assertEqual(groups[0]["suggested_fix"], "Set Maven dependency com.fasterxml.jackson.core:jackson-databind to version 2.12.7.1")


class ValidatorEdgeTests(unittest.TestCase):
    def test_validate_empty_and_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.json"
            empty.write_text("", encoding="utf-8")
            issues = validate_paths([str(empty), tmp], None, source_roots=[f"app={empty}"])
            report = issues_report(issues)
            self.assertGreaterEqual(report["summary"]["error"], 2)  # type: ignore[index]


class CliEdgeTests(unittest.TestCase):
    def test_main_bad_command_error(self) -> None:
        code = main(["scan", "--sbom", "missing", "--vulns", "missing", "--no-table"])
        self.assertEqual(code, 2)

    def test_scan_skip_validation_parse_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("{", encoding="utf-8")
            code = main(["scan", "--sbom", str(bad), "--vulns", str(ROOT / "samples/vulnerabilities.json"), "--skip-validation", "--no-table"])
            self.assertEqual(code, 2)

    def test_compare_markdown_output_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base.json"
            head = Path(tmp) / "head.json"
            md = Path(tmp) / "delta.md"
            base.write_text(json.dumps({"findings": []}), encoding="utf-8")
            head.write_text(json.dumps({"findings": []}), encoding="utf-8")
            code = main(["compare", "--base-findings", str(base), "--head-findings", str(head), "--markdown-out", str(md)])
            self.assertEqual(code, 0)
            self.assertIn("PR Delta", md.read_text(encoding="utf-8"))

    def test_explain_not_found_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.json"
            path.write_text(json.dumps({"findings": []}), encoding="utf-8")
            self.assertEqual(main(["explain", "--findings", str(path), "--key", "missing"]), 2)

    def test_write_delta_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            delta = {"summary": {"new": 0, "resolved": 0, "improved": 0, "regressed": 0, "unchanged": 0}, "new": [], "resolved": [], "improved": [], "regressed": [], "unchanged": []}
            json_path = Path(tmp) / "delta.json"
            md_path = Path(tmp) / "delta.md"
            write_delta(delta, json_path)
            write_delta_markdown(delta, md_path)
            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())


if __name__ == "__main__":
    unittest.main()
