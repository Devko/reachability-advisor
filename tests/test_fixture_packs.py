from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.fixtures import (
    FixtureError,
    discover_fixture_packs,
    evaluate_fixture_expectations,
    load_fixture_pack,
    run_fixture_pack,
    run_fixture_packs,
    validate_fixture_pack,
)
from reachability_advisor.sbom import load_sboms
from reachability_advisor.scoring import generate_findings
from reachability_advisor.source import parse_source_roots
from reachability_advisor.terraform import analyze_terraform_plan
from reachability_advisor.vulnerability import load_vulnerabilities

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "terraform"


class FixtureDiscoveryTests(unittest.TestCase):
    def test_discover_fixture_packs_from_index_in_order(self) -> None:
        paths = discover_fixture_packs(FIXTURES)
        ids = [load_fixture_pack(path).id for path in paths]
        self.assertEqual(
            ids,
            [
                "aws-ecs-fargate-service",
                "azure-container-apps",
                "gcp-cloud-run",
                "kubernetes-ingress-workload",
            ],
        )

    def test_discover_fixture_packs_without_index_falls_back_to_glob(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "packs" / "demo" / "fixture.json"
            fixture.parent.mkdir(parents=True)
            fixture.write_text('{"id":"demo","sboms":[],"plan":"tfplan.json"}', encoding="utf-8")
            paths = discover_fixture_packs(tmp)
            self.assertEqual([path.name for path in paths], ["fixture.json"])

    def test_load_fixture_pack_resolves_relative_paths(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "aws-ecs-fargate-service")
        self.assertEqual(pack.id, "aws-ecs-fargate-service")
        self.assertTrue(pack.plan.exists())
        self.assertEqual(len(pack.sboms), 1)
        self.assertIn("payments-api", pack.source_roots)
        self.assertTrue(pack.vulnerabilities.exists())

    def test_load_fixture_pack_rejects_missing_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FixtureError):
                load_fixture_pack(Path(tmp) / "missing")

    def test_load_fixture_pack_rejects_non_list_sboms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "fixture.json"
            manifest.write_text('{"id":"bad","sboms":"not-a-list"}', encoding="utf-8")
            with self.assertRaises(FixtureError):
                load_fixture_pack(manifest)

    def test_index_metadata_contains_all_pack_ids(self) -> None:
        index = json.loads((FIXTURES / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(index["schema_version"], "3.0")
        self.assertEqual({item["id"] for item in index["packs"]}, {load_fixture_pack(path).id for path in discover_fixture_packs(FIXTURES)})


class FixtureValidationTests(unittest.TestCase):
    def test_all_fixture_packs_validate_without_errors(self) -> None:
        for path in discover_fixture_packs(FIXTURES):
            with self.subTest(path=path):
                issues = validate_fixture_pack(load_fixture_pack(path))
                self.assertFalse([issue for issue in issues if issue.severity == "error"])

    def test_validate_missing_plan_reports_error(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "aws-ecs-fargate-service")
        missing = replace(pack, plan=pack.root / "missing.json")
        issues = validate_fixture_pack(missing)
        self.assertTrue(any(issue.severity == "error" and "terraform plan" in issue.message for issue in issues))

    def test_validate_missing_source_root_is_warning_not_error(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "gcp-cloud-run")
        modified = replace(pack, source_roots={"audit-api": pack.root / "missing-source"})
        issues = validate_fixture_pack(modified)
        self.assertTrue(any(issue.severity == "warning" and "source root" in issue.message for issue in issues))
        self.assertFalse(any(issue.severity == "error" for issue in issues))


class FixtureRunTests(unittest.TestCase):
    def test_run_all_fixture_packs_passes(self) -> None:
        report = run_fixture_packs(FIXTURES)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["fixture_count"], 4)
        self.assertEqual(report["failed_count"], 0)

    def test_each_fixture_has_100_percent_accounting_and_semantic_coverage(self) -> None:
        report = run_fixture_packs(FIXTURES)
        for item in report["fixtures"]:
            with self.subTest(item=item["id"]):
                summary = item["coverage_summary"]
                self.assertEqual(summary["resource_accounting_coverage"], 1.0)
                self.assertEqual(summary["semantic_classification_coverage"], 1.0)
                self.assertEqual(summary["artifact_match_coverage"], 1.0)
                self.assertEqual(summary["unsupported_or_unclassified_resources"], 0)

    def test_aws_fixture_produces_urgent_log4j_finding(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "aws-ecs-fargate-service")
        report = run_fixture_pack(pack)
        top = report["top_findings"][0]
        self.assertEqual(top["artifact"]["name"], "payments-api")
        self.assertEqual(top["component"]["name"], "log4j-core")
        self.assertEqual(top["tier"], "urgent")
        self.assertEqual(top["context"]["exposure"], "public")
        self.assertIn(top["source_reachability"]["state"], {"attacker_controlled", "function_reachable"})

    def test_azure_fixture_demotes_dev_minimist_below_lodash(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "azure-container-apps")
        report = run_fixture_pack(pack)
        lodash = next(item for item in report["findings"] if item["component"]["name"] == "lodash")
        minimist = next(item for item in report["findings"] if item["component"]["name"] == "minimist")
        self.assertGreater(lodash["score"], minimist["score"])
        self.assertEqual(lodash["tier"], "urgent")
        self.assertIn(minimist["tier"], {"low", "medium"})

    def test_gcp_fixture_marks_cloud_run_public(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "gcp-cloud-run")
        report = run_fixture_pack(pack)
        finding = report["top_findings"][0]
        self.assertEqual(finding["context"]["exposure"], "public")
        self.assertEqual(finding["context"]["privilege"], "sensitive")

    def test_kubernetes_fixture_marks_load_balancer_public_and_admin(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "kubernetes-ingress-workload")
        report = run_fixture_pack(pack)
        finding = report["top_findings"][0]
        self.assertEqual(finding["context"]["exposure"], "public")
        self.assertEqual(finding["context"]["privilege"], "admin")

    def test_run_fixture_pack_writes_per_fixture_outputs(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "gcp-cloud-run")
        with tempfile.TemporaryDirectory() as tmp:
            report = run_fixture_pack(pack, output_dir=tmp)
            self.assertEqual(report["status"], "passed")
            out = Path(tmp) / pack.id
            self.assertTrue((out / "findings.json").exists())
            self.assertTrue((out / "terraform-coverage.json").exists())
            self.assertTrue((out / "fixture-report.json").exists())

    def test_run_fixture_packs_unknown_id_raises(self) -> None:
        with self.assertRaises(FixtureError):
            run_fixture_packs(FIXTURES, only="missing")

    def test_expectation_failure_is_reported(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "aws-ecs-fargate-service")
        modified = replace(pack, expected={"min_findings": 999})
        report = run_fixture_pack(modified)
        self.assertEqual(report["status"], "failed")
        self.assertTrue(report["assertions"]["failed"])

    def test_evaluate_expectations_required_types_failure(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "aws-ecs-fargate-service")
        sboms = load_sboms([str(path) for path in pack.sboms])
        vulns = load_vulnerabilities(pack.vulnerabilities)
        sources = parse_source_roots([f"{artifact}={path}" for artifact, path in pack.source_roots.items()])
        tf = analyze_terraform_plan(pack.plan, [sbom.artifact for sbom in sboms])
        findings = generate_findings(sboms, vulns, sources, tf.contexts)
        modified = replace(pack, expected={"required_resource_types": ["missing_resource_type"]})
        assertions = evaluate_fixture_expectations(modified, findings, tf.coverage)
        self.assertTrue(assertions["failed"])


class FixtureCliTests(unittest.TestCase):
    def test_cli_fixtures_list_json(self) -> None:
        code = main(["fixtures", "list", "--root", str(FIXTURES), "--json"])
        self.assertEqual(code, 0)

    def test_cli_fixtures_validate_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "validate.json"
            code = main(["fixtures", "validate", "--root", str(FIXTURES), "--json-out", str(out)])
            self.assertEqual(code, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["failed_count"], 0)

    def test_cli_fixtures_run_one_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            code = main(["fixtures", "run", "--root", str(FIXTURES), "--fixture", "azure-container-apps", "--out", str(out), "--output-dir", str(Path(tmp) / "packs")])
            self.assertEqual(code, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["fixture_count"], 1)
            self.assertEqual(data["status"], "passed")

    def test_cli_fixtures_run_missing_id_returns_error(self) -> None:
        code = main(["fixtures", "run", "--root", str(FIXTURES), "--fixture", "missing"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()

class FixtureEdgeCoverageTests(unittest.TestCase):
    def test_fixture_issue_to_json_without_path(self) -> None:
        from reachability_advisor.fixtures import FixtureIssue, default_fixtures_root

        self.assertEqual(FixtureIssue("warning", "msg").to_json(), {"severity": "warning", "message": "msg"})
        self.assertEqual(default_fixtures_root().parts[-2:], ("fixtures", "terraform"))

    def test_discover_invalid_index_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "index.json").write_text("{", encoding="utf-8")
            with self.assertRaises(FixtureError):
                discover_fixture_packs(tmp)

    def test_discover_index_skips_bad_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "index.json").write_text(json.dumps({"packs": [{}, "bad", {"path": "packs/demo"}]}), encoding="utf-8")
            paths = discover_fixture_packs(tmp)
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0].parts[-3:], ("packs", "demo", "fixture.json"))

    def test_load_fixture_pack_invalid_json_and_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "fixture.json"
            manifest.write_text("{", encoding="utf-8")
            with self.assertRaises(FixtureError):
                load_fixture_pack(manifest)
            manifest.write_text("[]", encoding="utf-8")
            with self.assertRaises(FixtureError):
                load_fixture_pack(manifest)

    def test_load_fixture_pack_rejects_non_object_source_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "fixture.json"
            manifest.write_text(json.dumps({"id": "bad", "sboms": [], "source_roots": ["bad"]}), encoding="utf-8")
            with self.assertRaises(FixtureError):
                load_fixture_pack(manifest)

    def test_load_fixture_pack_accepts_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            absolute = Path(tmp) / "tfplan.json"
            manifest = Path(tmp) / "fixture.json"
            manifest.write_text(json.dumps({"id": "abs", "terraform_plan": str(absolute), "sboms": []}), encoding="utf-8")
            pack = load_fixture_pack(manifest)
            self.assertEqual(pack.plan, absolute)

    def test_validate_empty_id_and_no_sboms(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "aws-ecs-fargate-service")
        modified = replace(pack, id=" ", sboms=())
        issues = validate_fixture_pack(modified)
        messages = [issue.message for issue in issues]
        self.assertIn("fixture id is empty", messages)
        self.assertIn("fixture must declare at least one SBOM", messages)

    def test_validate_parse_errors_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad-sbom.json").write_text("{", encoding="utf-8")
            (root / "bad-vulns.json").write_text("{", encoding="utf-8")
            (root / "bad-plan.json").write_text("{", encoding="utf-8")
            manifest = root / "fixture.json"
            manifest.write_text(
                json.dumps({"id": "bad", "terraform_plan": "bad-plan.json", "sboms": ["bad-sbom.json"], "vulnerabilities": "bad-vulns.json", "expected": {"min_findings": 1}}),
                encoding="utf-8",
            )
            issues = validate_fixture_pack(load_fixture_pack(manifest))
            self.assertTrue(any("SBOM parse failed" in issue.message for issue in issues))
            self.assertTrue(any("vulnerability parse failed" in issue.message for issue in issues))

    def test_validate_terraform_parse_error_reported_when_sbom_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good_sbom = ROOT / "fixtures" / "terraform" / "packs" / "aws-ecs-fargate-service" / "sboms" / "payments-api.cdx.json"
            good_vulns = ROOT / "fixtures" / "terraform" / "common" / "vulnerabilities.json"
            (root / "bad-plan.json").write_text("{", encoding="utf-8")
            manifest = root / "fixture.json"
            manifest.write_text(
                json.dumps({"id": "badtf", "terraform_plan": "bad-plan.json", "sboms": [str(good_sbom)], "vulnerabilities": str(good_vulns), "expected": {"min_findings": 1}}),
                encoding="utf-8",
            )
            issues = validate_fixture_pack(load_fixture_pack(manifest))
            self.assertTrue(any("Terraform parse failed" in issue.message for issue in issues))

    def test_run_fixture_pack_validation_failure_returns_failed_report(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "aws-ecs-fargate-service")
        bad = replace(pack, plan=pack.root / "missing.json")
        report = run_fixture_pack(bad)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["error"], "fixture validation failed")

    def test_expectations_handle_missing_coverage_and_bad_tier_item(self) -> None:
        pack = replace(load_fixture_pack(FIXTURES / "packs" / "aws-ecs-fargate-service"), expected={"resource_accounting_coverage": 1.0, "must_match_artifacts": ["missing"], "min_tier_by_finding": ["bad", {"artifact": "none", "component": "none", "vulnerability": "none", "tier": "high"}]})
        assertions = evaluate_fixture_expectations(pack, [], {})
        self.assertGreaterEqual(len(assertions["failed"]), 2)

    def test_cli_fixtures_list_table_and_empty_root(self) -> None:
        self.assertEqual(main(["fixtures", "list", "--root", str(FIXTURES)]), 0)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(main(["fixtures", "list", "--root", tmp]), 0)

    def test_cli_fixtures_validate_one_and_missing(self) -> None:
        self.assertEqual(main(["fixtures", "validate", "--root", str(FIXTURES), "--fixture", "gcp-cloud-run"]), 0)
        self.assertEqual(main(["fixtures", "validate", "--root", str(FIXTURES), "--fixture", "missing"]), 2)

    def test_cli_fixtures_run_prints_report_without_out(self) -> None:
        self.assertEqual(main(["fixtures", "run", "--root", str(FIXTURES), "--fixture", "aws-ecs-fargate-service"]), 0)
