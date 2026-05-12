from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.artifact_manifest import (
    ArtifactManifestError,
    apply_artifact_manifests,
    create_artifact_manifest_payload,
    load_artifact_manifest,
    validate_artifact_manifest,
    write_artifact_manifest,
)
from reachability_advisor.iac_render import (
    recommend_iac_render_commands,
    render_iac_render_plan_markdown,
)
from reachability_advisor.models import Artifact, SbomDocument
from reachability_advisor.readiness import load_release_readiness_inputs, release_readiness_report
from reachability_advisor.scoring_benchmark import run_scoring_benchmark
from reachability_advisor.source_evidence_pack import write_source_evidence_pack
from reachability_advisor.source_evidence_plan import (
    recommend_source_evidence_commands,
    render_source_evidence_plan_markdown,
    source_evidence_profile,
    write_source_evidence_plan_json,
)

ROOT = Path(__file__).resolve().parents[1]


class ArtifactManifestTests(unittest.TestCase):
    def test_manifest_validation_errors_are_actionable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = [
                ("bad-json.json", "{", "invalid JSON"),
                ("root-list.json", "[]", "expected a JSON object"),
                ("missing-artifacts.json", "{}", "artifacts must be a list"),
                ("bad-item.json", {"artifacts": ["bad"]}, r"artifacts\[0\] must be an object"),
                ("missing-name.json", {"artifacts": [{}]}, "missing name"),
            ]
            for filename, payload, expected in cases:
                path = root / filename
                path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
                with self.subTest(filename=filename), self.assertRaisesRegex(ArtifactManifestError, expected):
                    load_artifact_manifest(path)

    def test_manifest_applies_identity_hints_aliases_and_unmatched_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sbom_path = root / "app.cdx.json"
            sbom = SbomDocument(path=sbom_path, artifact=Artifact(name="sbom-name"), components=[])
            digest = "sha256:" + "a" * 64
            manifest = root / "artifact-manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "signature": {"issuer": "ci"},
                        "artifacts": [
                            {
                                "artifact": "pipeline-name",
                                "sbom_path": "app.cdx.json",
                                "image_ref": "ghcr.io/acme/app:1",
                                "image_digest": digest,
                                "commit": "abc123",
                                "aliases": ["app-alias"],
                                "properties": {"custom:key": "custom-value"},
                                "helm_image": "ghcr.io/acme/app:helm",
                                "kustomize_image": "ghcr.io/acme/app:kustomize",
                                "terraform_module_output_image": "ghcr.io/acme/app:terraform",
                            },
                            {
                                "name": "unmatched",
                                "registry_ref": f"ghcr.io/acme/missing@{digest}",
                                "aliases": "not-a-list",
                                "properties": "not-an-object",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = apply_artifact_manifests([sbom], [str(manifest)])

        self.assertEqual(report["entries"], 2)
        self.assertEqual(report["applied"], 1)
        self.assertEqual(report["unmatched"], ["unmatched"])
        self.assertEqual(sbom.artifact.reference, "ghcr.io/acme/app:1")
        self.assertEqual(sbom.artifact.properties["ci:image:digest"], digest)
        self.assertEqual(sbom.artifact.properties["ci:registry_ref"], f"ghcr.io/acme/app@{digest}")
        self.assertEqual(sbom.artifact.properties["github:sha:image"], "ghcr.io/acme/app:1")
        self.assertEqual(sbom.artifact.properties["ci:artifact_manifest:signed"], "true")
        self.assertEqual(sbom.artifact.properties["custom:key"], "custom-value")
        self.assertIn("ghcr.io/acme/app:terraform", sbom.artifact.properties["reachability:aliases"])

    def test_manifest_registry_ref_can_set_reference_without_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            digest = "sha256:" + "b" * 64
            sbom = SbomDocument(path=root / "bom.json", artifact=Artifact(name="app", properties={"reachability:aliases": "old"}), components=[])
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps({"artifacts": [{"name": "app", "repository_digest": f"registry.example.com/app@{digest}", "revision": "def456", "signed": True}]}),
                encoding="utf-8",
            )

            report = apply_artifact_manifests([sbom], [str(manifest)])

        self.assertEqual(report["applied"], 1)
        self.assertEqual(sbom.artifact.reference, f"registry.example.com/app@{digest}")
        self.assertEqual(sbom.artifact.properties["ci:registry_ref"], f"registry.example.com/app@{digest}")
        self.assertIn("old", sbom.artifact.properties["reachability:aliases"])

    def test_manifest_init_and_validate_reports_identity_strength(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "manifest.json"
            digest = "sha256:" + "c" * 64
            payload = create_artifact_manifest_payload(["api"], image="ghcr.io/acme/api:1", digest=digest, git_sha="abc123", sbom="api.cdx.json", signed=True)
            write_artifact_manifest(path, payload)
            report = validate_artifact_manifest(path)

        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["summary"]["strong_identity"], 1)
        self.assertEqual(report["summary"]["with_digest"], 1)
        self.assertTrue(report["artifacts"][0]["signed"])


class ReadinessTests(unittest.TestCase):
    def test_readiness_reports_blockers_warnings_and_rendering_gaps(self) -> None:
        report = release_readiness_report(
            mapping_report={
                "artifacts": [
                    {
                        "name": "api",
                        "strong_artifact_identity": False,
                        "terraform_matched": False,
                    }
                ]
            },
            source_coverage={"summary": {"critical_external_evidence_coverage": 0.25}},
            terraform_coverage={"visibility_gaps": [{"type": "opaque_module", "address": "module.api"}]},
            kubernetes_coverage={"visibility_gaps": [{"reason": "helm_template_unrendered", "path": "chart/"}]},
            findings=[{"artifact": {"name": "api"}, "context": {"network_paths": [], "effective_access": []}}],
        )

        self.assertEqual(report["status"], "blocked")
        blocker_kinds = {item["kind"] for item in report["blockers"]}
        self.assertIn("image_digest_or_exact_image_reference", blocker_kinds)
        self.assertIn("sbom_path", blocker_kinds)
        self.assertIn("deployment_workload_match", blocker_kinds)
        self.assertIn("network_path_evidence", blocker_kinds)
        self.assertIn("critical_source_coverage", blocker_kinds)
        self.assertIn("unrendered_or_opaque_iac", blocker_kinds)
        self.assertIn("unrendered_or_opaque_kubernetes", blocker_kinds)
        self.assertEqual(report["warnings"][0]["kind"], "identity_effective_access_evidence")

    def test_readiness_reports_weak_matches_and_low_confidence_paths(self) -> None:
        report = release_readiness_report(
            mapping_report={
                "artifacts": [
                    {
                        "name": "api",
                        "sbom_path": "sboms/api.cdx.json",
                        "strong_artifact_identity": True,
                        "terraform_matched": True,
                        "strong_terraform_match": False,
                        "artifact_identity": {"strongest_strength": "image_reference", "candidates": [{"strength": "image_reference"}]},
                        "mapping_warnings": ["no source root supplied for source reachability"],
                    }
                ]
            },
            source_coverage={"summary": {"critical_external_evidence_coverage": 1.0}},
            findings=[
                {
                    "artifact": {"name": "api"},
                    "context": {
                        "network_paths": [{"confidence": "low", "exposure": "public"}],
                        "effective_access": [{"decision": "allowed", "confidence": "low"}],
                    },
                }
            ],
        )

        blocker_kinds = {item["kind"] for item in report["blockers"]}
        warning_kinds = {item["kind"] for item in report["warnings"]}

        self.assertEqual(report["status"], "blocked")
        self.assertIn("strong_deployment_workload_match", blocker_kinds)
        self.assertIn("network_path_confidence", warning_kinds)
        self.assertIn("identity_effective_access_confidence", warning_kinds)
        self.assertIn("no source root supplied for source reachability", report["artifacts"][0]["warnings"])
        self.assertEqual(report["summary"]["artifacts_missing_release_identity"], 0)
        self.assertEqual(report["summary"]["artifacts_missing_workload_match"], 1)
        self.assertEqual(report["artifacts"][0]["artifact_identity_strength"], "image_reference")

    def test_readiness_accepts_effective_exposure_as_network_evidence(self) -> None:
        report = release_readiness_report(
            mapping_report={
                "artifacts": [
                    {
                        "name": "api",
                        "sbom_path": "sboms/api.cdx.json",
                        "strong_artifact_identity": True,
                        "terraform_matched": True,
                        "strong_terraform_match": True,
                        "artifact_identity": {"strongest_strength": "digest", "candidates": [{"strength": "digest"}]},
                    }
                ]
            },
            source_coverage={"summary": {"critical_external_evidence_coverage": 1.0}},
            findings=[
                {
                    "artifact": {"name": "api"},
                    "context": {
                        "effective_exposure": [{"decision": "reachable", "network": {"confidence": "high"}}],
                        "iam_capabilities": [{"action": "s3:GetObject", "confidence": "high"}],
                    },
                }
            ],
        )

        self.assertEqual(report["status"], "ready")
        self.assertFalse(report["blockers"])
        self.assertFalse(report["warnings"])

    def test_load_release_readiness_inputs_reads_files_and_rejects_bad_json_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mapping = root / "mapping.json"
            source = root / "source.json"
            findings = root / "findings.json"
            bad_mapping = root / "bad-mapping.json"
            mapping.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "name": "app",
                                "sbom_path": "bom.json",
                                "strong_artifact_identity": True,
                                "terraform_matched": True,
                                "strong_terraform_match": True,
                                "artifact_identity": {"strongest_strength": "digest", "candidates": [{"strength": "digest"}]},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            source.write_text(json.dumps({"summary": {"critical_external_evidence_coverage": 1.0}}), encoding="utf-8")
            findings.write_text(
                json.dumps({"findings": [{"artifact": {"name": "app"}, "context": {"network_paths": [{"path": "internet"}], "effective_access": [{"decision": "allowed"}]}}]}),
                encoding="utf-8",
            )
            bad_mapping.write_text("[]", encoding="utf-8")

            report = load_release_readiness_inputs(mapping=str(mapping), source_coverage=str(source), findings=str(findings))
            self.assertEqual(report["status"], "ready")
            with self.assertRaisesRegex(ValueError, "expected a JSON object"):
                load_release_readiness_inputs(mapping=str(bad_mapping), source_coverage=str(source))


class SourceEvidencePlanTests(unittest.TestCase):
    def test_source_evidence_profiles_cover_language_and_package_manager_aliases(self) -> None:
        self.assertEqual(source_evidence_profile(language="java")["name"], "java-kotlin")
        self.assertEqual(source_evidence_profile(package_manager="gradle")["name"], "java-kotlin")
        self.assertEqual(source_evidence_profile(package_manager="pnpm")["name"], "javascript-typescript")
        self.assertEqual(source_evidence_profile(package_manager="poetry")["name"], "python")
        self.assertEqual(source_evidence_profile(language="unknown")["name"], "generic")

    def test_source_evidence_commands_handle_supported_languages_and_unknowns(self) -> None:
        java = recommend_source_evidence_commands(source_root="", output_dir="", language="java")
        go = recommend_source_evidence_commands(source_root="src/go", output_dir="out", language="go")
        unknown = recommend_source_evidence_commands(source_root="src", output_dir="out", language="ruby")
        generic = recommend_source_evidence_commands()

        self.assertTrue(any("codeql/java-queries" in command.command for command in java))
        self.assertTrue(any(command.tool == "govulncheck" for command in go))
        self.assertFalse(any(command.tool == "codeql" for command in unknown))
        self.assertFalse(any(command.tool == "codeql" for command in generic))
        self.assertFalse(any(command.tool == "govulncheck" for command in generic))
        self.assertIn("reachability/semgrep-results.json", [command.output for command in java])

    def test_source_evidence_plan_markdown_uses_emitted_outputs_only(self) -> None:
        generic_markdown = render_source_evidence_plan_markdown(recommend_source_evidence_commands())
        go_markdown = render_source_evidence_plan_markdown(recommend_source_evidence_commands(language="go", output_dir="out"))

        self.assertIn("--source-evidence-in reachability/semgrep-results.json", generic_markdown)
        self.assertNotIn("codeql.sarif", generic_markdown)
        self.assertNotIn("--source-evidence-in out/codeql-db", go_markdown)
        self.assertIn("--source-evidence-in out/govulncheck.jsonl", go_markdown)
        self.assertIn("--source-evidence-in out/codeql.sarif", go_markdown)

    def test_write_source_evidence_plan_json_preserves_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "plan.json"
            write_source_evidence_plan_json(path, recommend_source_evidence_commands(language="go"))
            data = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(data["kind"], "reachability-advisor-source-evidence-plan")
        self.assertIn("go", data["profiles"])
        self.assertTrue(any(command["tool"] == "govulncheck" for command in data["commands"]))

    def test_source_evidence_pack_writes_maintained_assets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pack = write_source_evidence_pack(Path(tmp) / "pack", language="go")
            manifest = json.loads((pack.root / "source-evidence-pack.json").read_text(encoding="utf-8"))

            self.assertEqual(manifest["kind"], "reachability-advisor-source-evidence-pack")
            self.assertEqual(manifest["profile"]["name"], "go")
            self.assertTrue((pack.root / "semgrep-reachability.yml").exists())
            self.assertTrue((pack.root / "codeql" / "reachability-suite.qls").exists())
            self.assertTrue((pack.root / "govulncheck" / "reachability-govulncheck.json").exists())
            self.assertEqual(manifest["release_gate"]["critical_external_evidence_coverage"], 1.0)


class RenderedIacPlanTests(unittest.TestCase):
    def test_rendered_iac_plan_commands_cover_terraform_helm_and_kustomize(self) -> None:
        commands = recommend_iac_render_commands(
            terraform_dir="infra",
            helm_chart="charts/app",
            helm_values=["values-prod.yaml"],
            kustomize_dir="deploy/overlays/prod",
            output_dir="reachability",
        )
        markdown = render_iac_render_plan_markdown(commands)

        rendered = "\n".join(command.command for command in commands)
        self.assertIn("mkdir -p reachability", rendered)
        self.assertIn("terraform -chdir=infra plan", rendered)
        self.assertIn("terraform -chdir=infra show -json", rendered)
        self.assertIn("infra/tfplan.binary", {command.output for command in commands})
        self.assertIn("helm template app charts/app", rendered)
        self.assertIn("kustomize build deploy/overlays/prod", rendered)
        self.assertIn("--terraform-plan", markdown)


class DocumentationConsistencyTests(unittest.TestCase):
    def test_documented_test_count_matches_discovered_tests(self) -> None:
        expected = unittest.defaultTestLoader.discover(str(ROOT / "tests")).countTestCases()
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quality = (ROOT / "docs" / "code_quality.md").read_text(encoding="utf-8")
        readme_count = int(re.search(r"Ran (\d+) tests: OK", readme).group(1))  # type: ignore[union-attr]
        quality_count = int(re.search(r"Unit and workflow tests: (\d+)", quality).group(1))  # type: ignore[union-attr]

        self.assertEqual(readme_count, expected)
        self.assertEqual(quality_count, expected)

    def test_release_validation_check_count_claims_match(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quality = (ROOT / "docs" / "code_quality.md").read_text(encoding="utf-8")
        readme_count = int(re.search(r"Release import/export contract: (\d+) checks passed", readme).group(1))  # type: ignore[union-attr]
        quality_count = int(re.search(r"release-check` currently covers (\d+) import/export", quality).group(1))  # type: ignore[union-attr]

        self.assertEqual(readme_count, quality_count)


class ScoringBenchmarkEdgeTests(unittest.TestCase):
    def test_scoring_benchmark_validates_shape_and_reports_failed_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root_list = root / "list.json"
            missing_cases = root / "missing.json"
            failed_case = root / "failed.json"
            root_list.write_text("[]", encoding="utf-8")
            missing_cases.write_text("{}", encoding="utf-8")
            failed_case.write_text(
                json.dumps(
                    {
                        "cases": [
                            "ignored",
                            {
                                "id": "bad-expectation",
                                "source": {"reachability": "not-real", "confidence": "not-real"},
                                "vulnerability": {"cvss": "not-a-number", "epss": "bad"},
                                "expected_tier": "urgent",
                                "min_score": 90,
                                "max_score": "bad",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "expected a JSON object"):
                run_scoring_benchmark(root_list)
            with self.assertRaisesRegex(ValueError, "cases must be a list"):
                run_scoring_benchmark(missing_cases)
            report = run_scoring_benchmark(failed_case)

        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["case_count"], 1)
        self.assertEqual(report["failed_count"], 1)
        self.assertIn("expected tier urgent", report["results"][0]["problems"][0])


if __name__ == "__main__":
    unittest.main()
