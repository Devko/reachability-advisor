from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from reachability_advisor import scenario_view as scenario_module
from reachability_advisor.effective_exposure import (
    best_effective_exposure,
    enrich_context_map_with_effective_exposure,
    evaluate_effective_exposure,
)
from reachability_advisor.finding_types import (
    CLOUD_POSTURE_FINDING,
    DEPENDENCY_VULNERABILITY,
    DYNAMIC_RUNTIME_OBSERVATION,
)
from reachability_advisor.models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    Finding,
    Reachability,
    RuntimeEvidence,
    RuntimeEvidenceState,
    SourceEvidence,
    Tier,
    VulnerabilityRecord,
)
from reachability_advisor.sbom import SbomError, load_sbom, load_sboms
from reachability_advisor.scenario_view import build_scenario_view
from reachability_advisor.source_manifests import (
    is_manifest_file,
    manifest_dependency_evidence,
    manifest_language_for,
)
from reachability_advisor.terraform_manifest import (
    azapi_arm_category,
    classification_for_resource,
    manifest_report,
    normalized_arm_type,
    provider_for_type,
    resource_type_supported,
)


@dataclass(frozen=True)
class ManifestFixture:
    path: Path
    language: str
    text: str


class EffectiveExposureCoverageTests(unittest.TestCase):
    def test_precomputed_effective_exposure_is_copied_and_ranked(self) -> None:
        context = ContextEvidence(
            effective_exposure=[
                "bad",
                {"decision": "blocked", "exposure": "public", "confidence": "high"},
                {"decision": "reachable", "exposure": "internal", "confidence": "medium"},
            ]
        )

        records = evaluate_effective_exposure("api", context)
        records[0]["decision"] = "mutated"
        best = best_effective_exposure(context)
        enriched = enrich_context_map_with_effective_exposure({"api": ContextEvidence(exposure="internal")})

        self.assertEqual(context.effective_exposure[1]["decision"], "blocked")
        self.assertEqual(best["decision"], "reachable")
        self.assertEqual(enriched["api"].effective_exposure[0]["artifact"], "api")
        self.assertIsNone(best_effective_exposure(ContextEvidence()))


class SbomCoverageTests(unittest.TestCase):
    def test_sbom_loader_preserves_external_refs_properties_and_dependency_edges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "edge.cdx.json"
            path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {
                            "component": {
                                "name": "runtime-api",
                                "version": "1.2.3",
                                "bom-ref": "artifact-ref",
                                "properties": [
                                    {"name": "artifact:version", "value": "fallback"},
                                    {"name": "", "value": "ignored"},
                                    "bad",
                                ],
                                "externalReferences": [
                                    {"type": "distribution-intake", "url": "registry.example/runtime-api:1.2.3"},
                                    {"type": "vcs", "url": "https://example.test/repo"},
                                    {"type": "website"},
                                ],
                            }
                        },
                        "components": [
                            "bad",
                            {
                                "name": "requests",
                                "version": "2.31.0",
                                "scope": "required",
                                "properties": [{"name": "dependency.scope", "value": "optional"}],
                                "externalReferences": [
                                    {"url": "https://example.test/component-ref"},
                                    {"type": "source-distribution", "url": "https://example.test/src.tar.gz"},
                                ],
                            },
                            {"version": "missing-name"},
                        ],
                        "dependencies": [
                            "bad",
                            {"ref": ""},
                            {"ref": "artifact-ref", "dependsOn": ["pkg:requests", "pkg:requests", None, ""]},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            sbom = load_sbom(path)
            loaded = load_sboms([str(path)])

        self.assertEqual(sbom.artifact.name, "runtime-api")
        self.assertEqual(sbom.artifact.reference, "registry.example/runtime-api:1.2.3")
        self.assertEqual(sbom.artifact.properties["source"], "https://example.test/repo")
        self.assertEqual(sbom.components[0].scope, "optional")
        self.assertEqual(sbom.components[0].properties["external:ref-0"], "https://example.test/component-ref")
        self.assertEqual(sbom.dependencies, {"artifact-ref": ["pkg:requests"]})
        self.assertEqual(loaded[0].artifact.name, "runtime-api")

    def test_sbom_loader_rejects_bad_shapes_and_defaults_runtime_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad_json = root / "bad.json"
            bad_shape = root / "array.json"
            wrong_format = root / "spdx.json"
            minimal = root / "minimal.json"
            bad_json.write_text("{bad", encoding="utf-8")
            bad_shape.write_text("[]", encoding="utf-8")
            wrong_format.write_text(json.dumps({"bomFormat": "SPDX"}), encoding="utf-8")
            minimal.write_text(
                json.dumps({"components": [{"name": "runtime-lib", "properties": [{"name": "empty", "value": None}]}]}),
                encoding="utf-8",
            )

            for path in (bad_json, bad_shape, wrong_format):
                with self.subTest(path=path.name), self.assertRaises(SbomError):
                    load_sbom(path)

            sbom = load_sbom(minimal)

        self.assertEqual(sbom.artifact.name, "minimal")
        self.assertEqual(sbom.components[0].scope, "runtime")
        self.assertEqual(sbom.components[0].properties["empty"], "")


class TerraformManifestCoverageTests(unittest.TestCase):
    def test_azapi_and_provider_manifest_helpers_cover_unknowns_and_child_types(self) -> None:
        self.assertIsNone(normalized_arm_type(None))
        self.assertIsNone(normalized_arm_type("  ''  "))
        self.assertEqual(normalized_arm_type("'Microsoft.App/containerApps@2023-05-01'"), "microsoft.app/containerapps")
        self.assertEqual(azapi_arm_category("Microsoft.Storage/storageAccounts/blobServices/containers/default"), "sensitive_data")
        self.assertIsNone(azapi_arm_category("Microsoft.Unknown/things/children"))
        self.assertEqual(classification_for_resource("aws_ecs_service"), ("aws", "workload"))
        self.assertEqual(classification_for_resource("azapi_resource", {"type": "Microsoft.Unknown/things"}), ("azure", "unclassified"))
        self.assertEqual(classification_for_resource("custom_resource"), ("unknown", "unclassified"))
        self.assertTrue(resource_type_supported("aws_ecs_service"))
        self.assertFalse(resource_type_supported("azapi_resource", {"type": "Microsoft.Unknown/things"}))
        self.assertEqual(provider_for_type("aws_lb"), "aws")
        self.assertEqual(provider_for_type("azurerm_linux_web_app"), "azure")
        self.assertEqual(provider_for_type("azuread_application"), "azure")
        self.assertEqual(provider_for_type("azapi_resource"), "azure")
        self.assertEqual(provider_for_type("google_cloud_run_service"), "gcp")
        self.assertEqual(provider_for_type("kubernetes_service"), "kubernetes")
        self.assertEqual(provider_for_type("kubectl_manifest"), "kubernetes")
        self.assertEqual(provider_for_type("helm_release"), "kubernetes")
        self.assertEqual(provider_for_type("random_id"), "terraform")
        self.assertEqual(provider_for_type("null_resource"), "terraform")
        self.assertEqual(provider_for_type("docker_image"), "docker")
        self.assertEqual(provider_for_type("not_a_provider_resource"), "unknown")
        self.assertGreaterEqual(manifest_report()["provider_count"], 1)


class SourceManifestCoverageTests(unittest.TestCase):
    def test_manifest_detection_and_language_fallbacks(self) -> None:
        self.assertTrue(is_manifest_file(Path("requirements-dev.txt")))
        self.assertFalse(is_manifest_file(Path("requirements-dev.in")))
        self.assertEqual(manifest_language_for(Path("package.json")), "npm-manifest")
        self.assertEqual(manifest_language_for(Path("pyproject.toml")), "python-manifest")
        self.assertEqual(manifest_language_for(Path("pom.xml")), "jvm-manifest")
        self.assertEqual(manifest_language_for(Path("go.mod")), "go-manifest")
        self.assertEqual(manifest_language_for(Path("unknown.lock")), "manifest")

    def test_manifest_dependency_evidence_covers_ecosystem_variants(self) -> None:
        cases = [
            (
                Component(name="left-pad", purl="pkg:npm/%40scope/left-pad@1.0.0"),
                ManifestFixture(Path("package-lock.json"), "npm-manifest", '"@scope/left-pad": "1.0.0"'),
                "@scope/left-pad",
            ),
            (
                Component(name="requests", purl="pkg:pypi/requests@2.31.0"),
                ManifestFixture(Path("pyproject.toml"), "python-manifest", '[tool.poetry.group.dev.dependencies]\nrequests = "^2.31.0"\n'),
                "requests",
            ),
            (
                Component(name="urllib3", purl="pkg:pypi/urllib3@2.0.0"),
                ManifestFixture(Path("pyproject.toml"), "python-manifest", '[project]\ndependencies = ["urllib3 >=2"]\n'),
                "urllib3",
            ),
            (
                Component(name="pytest", purl="pkg:pypi/pytest@8.0.0"),
                ManifestFixture(Path("pyproject.toml"), "python-manifest", '[project.optional-dependencies]\ntest = ["pytest >=8"]\n'),
                "pytest",
            ),
            (
                Component(name="urllib3", purl="pkg:pypi/urllib3@2.0.0"),
                ManifestFixture(Path("poetry.lock"), "python-manifest", '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n'),
                "urllib3",
            ),
            (
                Component(name="log4j-core", group="org.apache.logging.log4j", purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
                ManifestFixture(Path("build.gradle"), "jvm-manifest", 'implementation module = "org.apache.logging.log4j:log4j-core"\n'),
                "org.apache.logging.log4j:log4j-core",
            ),
            (
                Component(name="jackson-databind", group="com.fasterxml.jackson.core", purl="pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0"),
                ManifestFixture(Path("pom.xml"), "jvm-manifest", "<artifactId>jackson-databind</artifactId><groupId>com.fasterxml.jackson.core</groupId>"),
                "com.fasterxml.jackson.core:jackson-databind",
            ),
            (
                Component(name="github.com/gin-gonic/gin", purl="pkg:golang/github.com/gin-gonic/gin@1.9.0"),
                ManifestFixture(Path("go.sum"), "go-manifest", "github.com/gin-gonic/gin v1.9.0 h1:hash\n"),
                "github.com/gin-gonic/gin",
            ),
        ]

        for component, manifest, expected_symbol in cases:
            with self.subTest(expected_symbol=expected_symbol):
                evidence = manifest_dependency_evidence(component, [manifest])
                self.assertIsNotNone(evidence)
                self.assertIn(expected_symbol, evidence.matched_symbols[0])

        self.assertIsNone(
            manifest_dependency_evidence(
                Component(name="unknown", purl="pkg:npm/unknown@1.0.0"),
                [ManifestFixture(Path("package.json"), "npm-manifest", '{"dependencies": {"left-pad": "1"}}')],
            )
        )
        self.assertIsNone(
            manifest_dependency_evidence(
                Component(name="left-pad", purl="pkg:npm/left-pad@1.0.0"),
                [ManifestFixture(Path("requirements.txt"), "python-manifest", "left-pad==1")],
            )
        )
        self.assertIsNone(
            manifest_dependency_evidence(
                Component(name="missing", purl="pkg:pypi/missing@1.0.0"),
                [ManifestFixture(Path("pyproject.toml"), "python-manifest", "[project]\nname = 'demo'\n")],
            )
        )


class ScenarioViewCoverageTests(unittest.TestCase):
    def test_scenario_view_groups_events_config_identity_gaps_and_blockers(self) -> None:
        network_path = {
            "id": "network:path:public",
            "assetIds": ["asset:api"],
            "label": "aws_lb.public -> kubernetes_service.api",
            "entryLabel": "Internet / attacker",
            "entrySubtitle": "direct public route",
            "provider": "aws",
            "exposure": "public",
            "confidence": "low",
            "tier": "high",
            "score": 82.4,
            "steps": ["aws_lb.public", "security_group.api", "kubernetes_service.api"],
            "blockers": [{"kind": "waf", "reason": "managed rule present"}],
        }
        findings = [
            _finding(
                key="api|log4j|CVE-1",
                finding_type=DEPENDENCY_VULNERABILITY,
                reachability=Reachability.ATTACKER_CONTROLLED,
                severity="critical",
                runtime_state=RuntimeEvidenceState.VULNERABILITY_OBSERVED,
                privilege="admin",
                iam_impacts=["secrets read"],
                effective_access=[{"identity": "task-role", "action": "secretsmanager:GetSecretValue", "decision": "allowed", "resource": "*"}],
                unknowns=["source coverage partial"],
            ),
            _finding(
                key="api|zap|40012",
                finding_type=DYNAMIC_RUNTIME_OBSERVATION,
                reachability=Reachability.PACKAGE_PRESENT,
                severity="high",
                runtime_state=RuntimeEvidenceState.UNAUTHENTICATED_OBSERVED,
            ),
            _finding(
                key="worker|checkov|CKV",
                artifact_name="worker",
                finding_type=CLOUD_POSTURE_FINDING,
                reachability=Reachability.ABSENT,
                severity="medium",
                exposure="unknown",
                privilege="unknown",
            ),
        ]

        view = build_scenario_view(
            findings,
            [network_path],
            [{"findingKey": "api|log4j|CVE-1", "severity": "critical"}],
            [{"findingKey": "api|log4j|CVE-1", "shortReason": "request reaches sink"}],
        )

        self.assertEqual(len(view["riskScenarios"]), 2)
        public = next(item for item in view["riskScenarios"] if item["assetName"] == "api")
        worker = next(item for item in view["riskScenarios"] if item["assetName"] == "worker")

        self.assertIn("Public exposed", public["title"])
        self.assertGreaterEqual(public["categoryCounts"]["events"], 1)
        self.assertGreaterEqual(public["categoryCounts"]["identity_data_access"], 1)
        self.assertGreaterEqual(public["categoryCounts"]["insecure_configuration"], 1)
        self.assertGreaterEqual(public["categoryCounts"]["visibility_gaps"], 1)
        self.assertEqual(view["attackPathGroups"][0]["routeNodes"][1]["type"], "ingress")
        self.assertEqual(worker["status"], "Open")
        self.assertIn("network path unavailable", worker["searchText"])

    def test_scenario_view_helper_decisions_remain_stable(self) -> None:
        self.assertEqual(scenario_module._asset_kind({"assetName": "bucket"}), "storage asset")
        self.assertEqual(scenario_module._asset_kind({"assetName": "aws_instance.web"}), "EC2 workload")
        self.assertEqual(scenario_module._asset_kind({"assetName": "lambda_handler"}), "Lambda function")
        self.assertEqual(scenario_module._asset_kind({"assetName": "google_cloud_run_service.api"}), "Cloud Run service")
        self.assertEqual(scenario_module._asset_kind({"assetName": "azurerm_container_app.api"}), "container app")
        self.assertEqual(scenario_module._asset_kind({"assetName": "azurerm_linux_web_app.api"}), "web app")
        self.assertEqual(scenario_module._asset_kind({"assetName": "plain"}), "workload")
        self.assertEqual(scenario_module._route_node_type("network_policy deny"), "policy")
        self.assertEqual(scenario_module._route_node_type("target_group service"), "service")
        self.assertEqual(scenario_module._route_node_type("plain hop"), "hop")
        self.assertEqual(scenario_module._entry_label("external"), "External source")
        self.assertEqual(scenario_module._entry_label("internal"), "Internal network")
        self.assertEqual(scenario_module._entry_label("private"), "No external entry")
        self.assertEqual(scenario_module._entry_label("unknown"), "Unknown entry")
        self.assertEqual(scenario_module._status_label(["excepted"]), "Excepted")
        self.assertEqual(scenario_module._status_label(["active", "excepted"]), "Mixed")
        self.assertEqual(scenario_module._max_severity(["low", "moderate", "high"]), "high")
        self.assertEqual(scenario_module._blocker_label({"type": "auth"}), "auth")
        self.assertEqual(scenario_module._blocker_detail({"detail": "requires auth"}), "requires auth")
        self.assertEqual(scenario_module._first_nonempty(["", None, "value"]), "value")
        self.assertEqual(scenario_module._provider_for_path({"label": "azurerm_lb.app"}), "Azure")
        self.assertEqual(scenario_module._provider_for_path({"label": "google_compute_forwarding_rule.app"}), "GCP")
        self.assertEqual(scenario_module._provider_for_path({"label": "kubernetes ingress"}), "Kubernetes")
        self.assertEqual(scenario_module._provider_for_path({"label": "unknown"}), "Context")
        self.assertEqual(scenario_module._network_layer({"provider": "AWS"}), "Terraform")
        self.assertEqual(scenario_module._network_layer({"provider": "Kubernetes"}), "Kubernetes")
        self.assertEqual(scenario_module._path_asset_ids({"assetIds": ["a", None, "b"]}), ["a", "b"])
        self.assertEqual(scenario_module._path_asset_ids({"assetId": "solo"}), ["solo"])
        self.assertEqual(scenario_module._path_asset_ids({}), [])
        self.assertEqual(scenario_module._path_blockers({"blockers": ["waf"]}), ["waf"])
        self.assertEqual(scenario_module._path_blockers({"blockers": "waf"}), [])


def _finding(
    *,
    key: str,
    finding_type: str,
    reachability: Reachability,
    severity: str,
    artifact_name: str = "api",
    exposure: str = "public",
    privilege: str = "privileged",
    runtime_state: RuntimeEvidenceState = RuntimeEvidenceState.NOT_OBSERVED,
    iam_impacts: list[str] | None = None,
    effective_access: list[dict[str, str]] | None = None,
    unknowns: list[str] | None = None,
) -> Finding:
    return Finding(
        key=key,
        artifact=Artifact(name=artifact_name, reference=f"registry.example/{artifact_name}:1"),
        component=Component(name="component", version="1.0.0"),
        vulnerability=VulnerabilityRecord(id=key.rsplit("|", 1)[-1], package_name="component", severity=severity, summary="summary"),
        source=SourceEvidence(reachability=reachability, reason="test source evidence"),
        context=ContextEvidence(
            exposure=exposure,
            privilege=privilege,
            iam_impacts=iam_impacts or [],
            effective_access=effective_access or [],
            evidence=["context evidence"],
        ),
        score=88.5 if severity == "critical" else 55.0,
        tier=Tier.URGENT if severity == "critical" else Tier.MEDIUM,
        confidence=Confidence.HIGH,
        rationale=["test rationale"],
        finding_type=finding_type,
        weakness={"weakness": "scanner weakness", "cwe": "CWE-79", "tool": "scanner"},
        runtime_evidence=RuntimeEvidence(state=runtime_state),
        unknowns=unknowns or [],
        evidence_summary=["finding evidence"],
    )


if __name__ == "__main__":
    unittest.main()
