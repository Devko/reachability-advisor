from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.finding_types import CLOUD_POSTURE_FINDING
from reachability_advisor.models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    Finding,
    PostureEvidence,
    Reachability,
    SbomDocument,
    SourceEvidence,
    Tier,
    VulnerabilityRecord,
)
from reachability_advisor.posture import native_posture_records
from reachability_advisor.scoring import ScorePolicy, apply_graph_score
from reachability_advisor.security_evidence import (
    generate_security_findings,
    load_security_evidence,
)
from reachability_advisor.security_evidence_model import (
    SecurityEvidenceError,
    SecurityEvidenceRecord,
)
from reachability_advisor.security_runtime import context_for_security_record


class CspmAdapterTests(unittest.TestCase):
    def test_normalized_cspm_json_imports_posture_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cspm.json"
            path.write_text(
                json.dumps(
                    {
                        "security_evidence": [
                            {
                                "scanner_type": "cspm",
                                "tool": "checkov",
                                "rule_id": "CKV_AWS_20",
                                "weakness": "S3 bucket allows public reads",
                                "severity": "high",
                                "artifact": "api",
                                "provider": "aws",
                                "resource_id": "aws_s3_bucket.public",
                                "resource_type": "aws_s3_bucket",
                                "service": "s3",
                                "expected": "private bucket ACL",
                                "actual": "public-read ACL",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            records = load_security_evidence([path])

            self.assertEqual(records[0].scanner_type, "cspm")
            self.assertEqual(records[0].provider, "aws")
            self.assertEqual(records[0].resource_id, "aws_s3_bucket.public")

    def test_checkov_trivy_kics_and_tfsec_are_parsed_as_cspm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkov = root / "checkov.json"
            trivy = root / "trivy.json"
            kics = root / "kics.json"
            tfsec = root / "tfsec.json"
            checkov.write_text(json.dumps({"results": {"failed_checks": [{"check_id": "CKV_AWS_1", "check_name": "public bucket", "resource": "aws_s3_bucket.public", "file_path": "main.tf"}]}}), encoding="utf-8")
            trivy.write_text(json.dumps({"Results": [{"Target": "main.tf", "Misconfigurations": [{"ID": "AVD-AWS-0001", "Title": "public db", "Severity": "HIGH", "Resource": "aws_db_instance.db"}]}]}), encoding="utf-8")
            kics.write_text(json.dumps({"queries": [{"query_id": "kics-1", "query_name": "privileged container", "severity": "HIGH", "platform": "Kubernetes", "files": [{"file_name": "pod.yaml", "line": 4, "resource_name": "pod/demo"}]}]}), encoding="utf-8")
            tfsec.write_text(json.dumps({"results": [{"rule_id": "AWS001", "description": "encryption disabled", "severity": "MEDIUM", "resource": "aws_s3_bucket.logs", "location": {"filename": "main.tf", "start_line": 8}}]}), encoding="utf-8")

            records = load_security_evidence([checkov, trivy, kics, tfsec], default_scanner_type="cspm")

            self.assertEqual([record.scanner_type for record in records], ["cspm", "cspm", "cspm", "cspm"])
            self.assertEqual([record.tool for record in records], ["checkov", "trivy-config", "kics", "tfsec"])

    def test_sarif_cspm_default_preserves_location_and_resource(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trivy.sarif"
            path.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "trivy", "rules": [{"id": "AVD-KSV-0012", "properties": {"resource_id": "Deployment/web", "resource_type": "Deployment", "provider": "kubernetes"}}]}},
                                "results": [{"ruleId": "AVD-KSV-0012", "message": {"text": "privileged container"}, "level": "error", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "deploy.yaml"}, "region": {"startLine": 9}}}]}],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            records = load_security_evidence([path], default_scanner_type="cspm")

            self.assertEqual(records[0].scanner_type, "cspm")
            self.assertEqual(records[0].source.path, Path("deploy.yaml"))
            self.assertEqual(records[0].resource_id, "Deployment/web")

    def test_jsonl_accepts_normalized_records_and_reports_bad_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normalized = root / "generic.jsonl"
            invalid = root / "bad.jsonl"
            normalized.write_text(
                "\n".join(
                    [
                        "",
                        "[]",
                        json.dumps({"rule_id": "POSTURE-1", "weakness": "public storage", "resource_id": "bucket/public"}),
                    ]
                ),
                encoding="utf-8",
            )
            invalid.write_text("{not-json}", encoding="utf-8")

            records = load_security_evidence([normalized], default_scanner_type="cspm")

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].scanner_type, "cspm")
            self.assertEqual(records[0].resource_id, "bucket/public")
            with self.assertRaises(SecurityEvidenceError):
                load_security_evidence([invalid], default_scanner_type="cspm")

    def test_cspm_adapters_tolerate_sparse_scanner_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkov = root / "checkov.json"
            trivy = root / "trivy.json"
            kics = root / "kics.json"
            tfsec = root / "tfsec.json"
            checkov.write_text(json.dumps({"results": {"failed_checks": ["bad", {"check_id": "CKV_AWS_2", "file_line_range": ["7"], "resource": "aws_s3_bucket.logs"}]}}), encoding="utf-8")
            trivy.write_text(json.dumps({"Results": ["bad", {"Target": "main.tf", "Misconfigurations": ["bad", {"ID": "AVD-AWS-0002", "Title": "encryption disabled", "Severity": "UNKNOWN", "CauseMetadata": {"StartLine": {"Line": 5}}}]}]}), encoding="utf-8")
            kics.write_text(json.dumps({"queries": ["bad", {"query_id": "kics-2", "query_name": "wide ingress", "files": {"not": "a-list"}}]}), encoding="utf-8")
            tfsec.write_text(json.dumps({"results": ["bad", {"rule_id": "AWS999", "description": "legacy tfsec fallback", "impact": "warning"}]}), encoding="utf-8")

            records = load_security_evidence([checkov, trivy, kics, tfsec], default_scanner_type="cspm")

            self.assertEqual(len(records), 4)
            self.assertEqual(records[0].source.line, 7)
            self.assertEqual(records[1].source.line, 1)
            self.assertEqual(records[2].tool, "kics")
            self.assertEqual(records[3].tool, "tfsec")


class CspmGenerationAndScoringTests(unittest.TestCase):
    def test_cspm_finding_has_posture_evidence_and_does_not_set_source_or_runtime_proof(self) -> None:
        artifact = Artifact(name="api")
        record = load_security_evidence_record(
            scanner_type="cspm",
            artifact="api",
            provider="aws",
            resource_id="aws_lb.public",
            resource_type="aws_lb",
            expected="auth or WAF",
            actual="public listener without blocker",
        )

        findings, report = generate_security_findings([record], [SbomDocument(path=Path("api.cdx.json"), artifact=artifact, components=[])], {}, ScorePolicy())

        self.assertEqual(report["mapped"], 1)
        finding = findings[0]
        self.assertEqual(finding.finding_type, CLOUD_POSTURE_FINDING)
        self.assertEqual(finding.source.reachability, Reachability.PACKAGE_PRESENT)
        self.assertEqual(finding.runtime_evidence.state.value, "not_observed")
        self.assertEqual(finding.posture_evidence.resource_id, "aws_lb.public")
        self.assertTrue(any("CSPM posture evidence" in item for item in finding.evidence_summary))

    def test_unmapped_cspm_remains_visible_with_mapping_unknown(self) -> None:
        record = load_security_evidence_record(scanner_type="cspm", resource_id="aws_s3_bucket.public")

        findings, report = generate_security_findings([record], [], {}, ScorePolicy())

        self.assertEqual(len(findings), 1)
        self.assertEqual(report["unmapped"], 1)
        self.assertTrue(findings[0].artifact.name.startswith("unmapped:posture:"))
        self.assertIn("artifact or workload mapping unavailable or weak one-SBOM fallback", findings[0].unknowns)

    def test_cspm_scanner_severity_alone_does_not_become_urgent(self) -> None:
        finding = Finding(
            key="posture",
            artifact=Artifact(name="api"),
            component=Component(name="aws_s3_bucket.public", scope="posture"),
            vulnerability=VulnerabilityRecord(id="CKV_AWS_20", package_name="aws_s3_bucket", severity="critical", cvss=9.8),
            source=SourceEvidence(reachability=Reachability.PACKAGE_PRESENT, confidence=Confidence.MEDIUM),
            context=ContextEvidence(exposure="unknown", confidence=Confidence.LOW),
            score=0.0,
            tier=Tier.LOW,
            confidence=Confidence.MEDIUM,
            rationale=[],
            finding_type=CLOUD_POSTURE_FINDING,
            posture_evidence=PostureEvidence(scanner="cspm", tool="checkov", rule_id="CKV_AWS_20", resource_id="aws_s3_bucket.public", confidence=Confidence.MEDIUM),
        )

        apply_graph_score(finding)

        self.assertNotEqual(finding.tier, Tier.URGENT)
        self.assertIn("posture", finding.score_details["graph_decision"]["matched_rule"])

    def test_native_posture_records_cover_terraform_and_kubernetes(self) -> None:
        records = native_posture_records(
            {
                "resources": [
                    {
                        "address": "aws_lb.public",
                        "type": "aws_lb",
                        "provider": "aws",
                        "network_paths": [{"exposure": "public", "blockers": []}],
                    },
                    {
                        "address": "aws_iam_policy.admin",
                        "type": "aws_iam_policy",
                        "provider": "aws",
                        "values": {"Statement": [{"Action": "*", "Resource": "*"}]},
                    },
                    {
                        "address": "aws_db_instance.main",
                        "type": "aws_db_instance",
                        "provider": "aws",
                        "values": {"publicly_accessible": True, "storage_encrypted": False},
                    },
                ]
            },
            {
                "resources": [
                    {
                        "address": "Deployment/web",
                        "kind": "Deployment",
                        "values": {"spec": {"template": {"spec": {"hostNetwork": True, "containers": [{"securityContext": {"privileged": True}}]}}}},
                    },
                    {"address": "ClusterRole/admin", "kind": "ClusterRole", "values": {"rules": [{"verbs": ["*"], "resources": ["*"]}]}},
                    {"address": "Service/web", "kind": "Service", "values": {"spec": {"type": "LoadBalancer"}}},
                ]
            },
            {},
        )

        rule_ids = {record.rule_id for record in records}
        self.assertIn("RA-CSPM-PUBLIC-INGRESS-NO-BLOCKER", rule_ids)
        self.assertIn("RA-CSPM-BROAD-IAM", rule_ids)
        self.assertIn("RA-CSPM-PUBLIC-DATABASE", rule_ids)
        self.assertIn("RA-CSPM-ENCRYPTION-DISABLED", rule_ids)
        self.assertIn("RA-CSPM-K8S-PRIVILEGED-CONTAINER", rule_ids)
        self.assertIn("RA-CSPM-K8S-BROAD-RBAC", rule_ids)
        self.assertIn("RA-CSPM-K8S-PUBLIC-INGRESS-NO-AUTH", rule_ids)

    def test_native_posture_records_cover_mapping_edges_and_deduplication(self) -> None:
        terraform_row = {
            "address": "google_storage_bucket.public",
            "type": "google_storage_bucket",
            "category": "sensitive_data",
            "values": {"public": "yes"},
            "path": "bucket.tf",
            "line": "not-a-number",
        }
        records = native_posture_records(
            {
                "resources": [
                    terraform_row,
                    dict(terraform_row),
                    {
                        "address": "azurerm_network_security_group.web",
                        "type": "azurerm_network_security_group",
                        "network_paths": [{"exposure": "public", "blockers": ["waf"]}],
                    },
                    {
                        "address": "aws_iam_role.ops",
                        "type": "aws_iam_role",
                        "effective_access": [{"privilege": "admin"}],
                    },
                ]
            },
            {
                "resources": [
                    {
                        "address": "Deployment/api",
                        "kind": "Deployment",
                        "values": {
                            "spec": {
                                "template": {
                                    "spec": {
                                        "containers": [
                                            {"env": [{"name": "AWS_SECRET_ACCESS_KEY", "value": "plain"}]}
                                        ]
                                    }
                                }
                            }
                        },
                    },
                    {
                        "address": "Ingress/api",
                        "kind": "Ingress",
                        "values": {"spec": {"rules": [{"host": "api.example.test"}]}, "metadata": {"annotations": {"nginx.ingress.kubernetes.io/auth-url": "https://auth.example.test"}}},
                    },
                ]
            },
            {},
        )

        rule_ids = [record.rule_id for record in records]
        self.assertEqual(rule_ids.count("RA-CSPM-PUBLIC-SENSITIVE-DATA"), 1)
        self.assertIn("RA-CSPM-BROAD-IAM", rule_ids)
        self.assertIn("RA-CSPM-K8S-SENSITIVE-ENV", rule_ids)
        self.assertNotIn("RA-CSPM-K8S-PUBLIC-INGRESS-NO-AUTH", rule_ids)
        sensitive = next(record for record in records if record.rule_id == "RA-CSPM-PUBLIC-SENSITIVE-DATA")
        self.assertEqual(sensitive.provider, "gcp")
        self.assertEqual(sensitive.source.line, 1)

    def test_native_posture_records_flag_ingress_hosts_without_auth_hint(self) -> None:
        records = native_posture_records(
            {},
            {
                "resources": [
                    {
                        "address": "Ingress/public-api",
                        "kind": "Ingress",
                        "values": {"spec": {"rules": [{"host": "api.example.test"}]}},
                    }
                ]
            },
            {},
        )

        self.assertEqual([record.rule_id for record in records], ["RA-CSPM-K8S-PUBLIC-INGRESS-NO-AUTH"])

    def test_unknown_scanner_exposure_does_not_replace_concrete_context(self) -> None:
        record = load_security_evidence_record(
            scanner_type="dast",
            tool="zap",
            rule_id="ZAP-INFO",
            weakness="missing header",
            route="/health",
        )

        context = context_for_security_record(ContextEvidence(exposure="private"), record, "api")

        self.assertEqual(context.exposure, "private")


class CspmCliOutputTests(unittest.TestCase):
    def test_scan_cspm_flag_outputs_json_markdown_sarif_diagnostics_and_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            sbom = out / "api.cdx.json"
            vulns = out / "vulns.json"
            cspm = out / "cspm.json"
            findings_path = out / "findings.json"
            markdown_path = out / "summary.md"
            sarif_path = out / "findings.sarif"
            diagnostics_path = out / "diagnostics.json"
            html_path = out / "graph.html"
            sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "api"}}, "components": []}), encoding="utf-8")
            vulns.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
            cspm.write_text(
                json.dumps(
                    {
                        "security_evidence": [
                            {
                                "tool": "checkov",
                                "rule_id": "CKV_AWS_20",
                                "weakness": "public bucket",
                                "severity": "high",
                                "artifact": "api",
                                "provider": "aws",
                                "resource_id": "aws_s3_bucket.public",
                                "resource_type": "aws_s3_bucket",
                                "source": {"path": "main.tf", "line": 3},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            code = main([
                "scan",
                "--sbom", str(sbom),
                "--vuln-in", str(vulns),
                "--cspm-in", str(cspm),
                "--out", str(findings_path),
                "--markdown-out", str(markdown_path),
                "--sarif-out", str(sarif_path),
                "--diagnostics-out", str(diagnostics_path),
                "--html-out", str(html_path),
                "--no-table",
            ])

            self.assertEqual(code, 0)
            data = json.loads(findings_path.read_text(encoding="utf-8"))
            self.assertEqual(data["metadata"]["cloud_posture_findings"], 1)
            finding = data["findings"][0]
            self.assertEqual(finding["finding_type"], CLOUD_POSTURE_FINDING)
            self.assertEqual(finding["posture_evidence"]["resource_id"], "aws_s3_bucket.public")
            self.assertIn("Cloud posture findings", markdown_path.read_text(encoding="utf-8"))
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
            self.assertEqual(sarif["runs"][0]["results"][0]["properties"]["posture_evidence"]["resource_id"], "aws_s3_bucket.public")
            diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
            self.assertEqual(diagnostics["diagnostics"][0]["finding_type"], CLOUD_POSTURE_FINDING)
            self.assertIn("cloud_posture_finding", html_path.read_text(encoding="utf-8"))


def load_security_evidence_record(**kwargs: object):
    base = {
        "scanner_type": "cspm",
        "tool": "checkov",
        "rule_id": "CKV_AWS_20",
        "weakness": "public ingress without WAF",
        "severity": "high",
        "confidence": Confidence.MEDIUM,
    }
    base.update(kwargs)
    return SecurityEvidenceRecord(**base)


if __name__ == "__main__":
    unittest.main()
