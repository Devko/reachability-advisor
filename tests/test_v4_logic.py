from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.artifacts import (
    artifact_candidates,
    artifact_identity_candidates,
    artifact_identity_proof,
    artifact_match_evidence,
    best_artifact_match,
    clean_image_reference,
    normalize_image_reference,
)
from reachability_advisor.cli import main
from reachability_advisor.mapping import build_mapping_report
from reachability_advisor.models import (
    Artifact,
    Component,
    Confidence,
    Reachability,
    SbomDocument,
    VulnerabilityRecord,
)
from reachability_advisor.readiness import release_readiness_report
from reachability_advisor.sbom import load_sbom
from reachability_advisor.sbom_plan import (
    recommend_sbom_commands,
    render_sbom_plan_markdown,
    write_sbom_plan_json,
)
from reachability_advisor.source import (
    analyze_component_source,
    load_external_source_evidence,
    load_reachability_rules,
)
from reachability_advisor.source_evidence_plan import (
    recommend_source_evidence_commands,
    render_source_evidence_plan_markdown,
)
from reachability_advisor.terraform import (
    TerraformAnalyzer,
    coverage_report,
    extract_resources,
    image_matches,
)

ROOT = Path(__file__).resolve().parents[1]


def _plan(resources: list[dict]) -> dict:
    return {"planned_values": {"root_module": {"resources": resources}}}


def _resource(address: str, rtype: str, values: dict) -> dict:
    return {"address": address, "type": rtype, "name": address.rsplit(".", 1)[-1], "values": values}


class ArtifactIdentityTests(unittest.TestCase):
    def test_clean_image_reference_strips_docker_prefixes(self) -> None:
        self.assertEqual(clean_image_reference("DOCKER|ghcr.io/acme/app:1"), "ghcr.io/acme/app:1")
        self.assertEqual(clean_image_reference("docker://ghcr.io/acme/app:1"), "ghcr.io/acme/app:1")

    def test_normalize_image_reference_registry_repo_tag(self) -> None:
        image = normalize_image_reference("ghcr.io/acme/payments-api:1.2.3")
        self.assertIsNotNone(image)
        assert image is not None
        self.assertEqual(image.registry, "ghcr.io")
        self.assertEqual(image.repository, "acme/payments-api")
        self.assertEqual(image.tag, "1.2.3")
        self.assertEqual(image.repository_leaf, "payments-api")

    def test_normalize_image_reference_digest(self) -> None:
        image = normalize_image_reference("registry.example.com/a/b@sha256:" + "a" * 64)
        self.assertIsNotNone(image)
        assert image is not None
        self.assertEqual(image.digest, "sha256:" + "a" * 64)
        self.assertIn("@sha256", image.canonical)

    def test_normalize_image_reference_unresolved_terraform_expression(self) -> None:
        image = normalize_image_reference("${var.image}")
        self.assertIsNotNone(image)
        assert image is not None
        self.assertIsNone(image.repository)

    def test_artifact_candidates_include_properties_and_aliases(self) -> None:
        artifact = Artifact(name="app", properties={"container:image": "repo/app:1", "reachability:aliases": "repo/app:2,repo/app:3"})
        candidates = artifact_candidates(artifact)
        self.assertIn("repo/app:1", candidates)
        self.assertIn("repo/app:2", candidates)
        self.assertIn("app", candidates)

    def test_artifact_candidates_include_ci_helm_kustomize_and_module_hints(self) -> None:
        artifact = Artifact(
            name="checkout",
            properties={
                "github:workflow:image": "ghcr.io/acme/checkout:${{ github.sha }}",
                "helm:values:image": "registry.example.com/shop/checkout:1.2.3\nregistry.example.com/shop/checkout-canary:1.2.4",
                "kustomize:image": "registry.example.com/shop/checkout:stable",
                "terraform:module_output:image": "registry.example.com/shop/checkout:from-module",
            },
        )
        candidates = artifact_candidates(artifact)
        self.assertIn("ghcr.io/acme/checkout:${{ github.sha }}", candidates)
        self.assertIn("registry.example.com/shop/checkout:1.2.3", candidates)
        self.assertIn("registry.example.com/shop/checkout-canary:1.2.4", candidates)
        self.assertIn("registry.example.com/shop/checkout:stable", candidates)
        self.assertTrue(artifact_match_evidence(artifact, "registry.example.com/shop/checkout:from-module").matched)

    def test_artifact_candidates_include_release_pipeline_image_hints(self) -> None:
        artifact = Artifact(
            name="checkout",
            properties={
                "gha:image": "ghcr.io/acme/checkout:sha-123",
                "org.opencontainers.image.ref.name": "ghcr.io/acme/checkout:1.2.3",
                "docker:repo-digest": "ghcr.io/acme/checkout@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "skaffold:image": "ghcr.io/acme/checkout-skaffold:1",
                "jib:image": "ghcr.io/acme/checkout-jib:1",
            },
        )

        candidates = artifact_candidates(artifact)

        self.assertIn("ghcr.io/acme/checkout:sha-123", candidates)
        self.assertIn("ghcr.io/acme/checkout:1.2.3", candidates)
        self.assertIn("ghcr.io/acme/checkout@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", candidates)
        self.assertIn("ghcr.io/acme/checkout-skaffold:1", candidates)
        self.assertIn("ghcr.io/acme/checkout-jib:1", candidates)

    def test_artifact_identity_proof_preserves_candidate_source_and_strength(self) -> None:
        artifact = Artifact(
            name="checkout",
            reference="registry.example.com/shop/checkout:1.2.3",
            properties={"oci:image:ref": "registry.example.com/shop/checkout@sha256:" + "a" * 64},
        )
        candidates = artifact_identity_candidates(artifact)
        self.assertEqual(candidates[0].strength, "digest")
        self.assertEqual(candidates[0].source, "artifact.properties.oci:image:ref")
        proof = artifact_identity_proof(artifact)
        self.assertEqual(proof["strongest_strength"], "digest")
        self.assertEqual(proof["warnings"], [])

    def test_artifact_version_candidate_is_not_strong_deployment_identity(self) -> None:
        artifact = Artifact(name="checkout", version="1.2.3")

        proof = artifact_identity_proof(artifact)

        self.assertEqual(proof["strongest_strength"], "versioned_name")
        self.assertTrue(proof["warnings"])
        sbom = SbomDocument(path=Path("checkout.cdx.json"), artifact=artifact, components=[])
        report = build_mapping_report([sbom], {}, {"artifact_matches": [], "unmatched_artifacts": ["checkout"], "summary": {}})
        self.assertEqual(report["summary"]["strong_artifact_identity_coverage"], 0.0)
        self.assertEqual(report["summary"]["artifact_match_coverage"], 0.0)
        self.assertEqual(report["summary"]["mapping_warnings_count"], 3)
        self.assertIn("no strong image reference", " ".join(report["artifacts"][0]["mapping_warnings"]))

    def test_artifact_match_exact_reference_is_high(self) -> None:
        artifact = Artifact(name="payments-api", reference="ghcr.io/acme/payments-api:1.2.3")
        match = artifact_match_evidence(artifact, "ghcr.io/acme/payments-api:1.2.3")
        self.assertTrue(match.matched)
        self.assertEqual(match.method, "exact-reference")
        self.assertEqual(match.confidence, "high")

    def test_artifact_match_digest_beats_tag(self) -> None:
        digest = "sha256:" + "b" * 64
        artifact = Artifact(name="app", reference=f"repo/app:old@{digest}")
        match = artifact_match_evidence(artifact, f"repo/app:new@{digest}")
        self.assertTrue(match.matched)
        self.assertEqual(match.method, "digest")

    def test_artifact_match_repository_with_different_tag_is_medium(self) -> None:
        artifact = Artifact(name="payments-api", reference="ghcr.io/acme/payments-api:1.2.3")
        match = artifact_match_evidence(artifact, "ghcr.io/acme/payments-api:latest")
        self.assertTrue(match.matched)
        self.assertEqual(match.method, "repository")
        self.assertEqual(match.confidence, "medium")

    def test_artifact_match_does_not_use_substring_false_positive(self) -> None:
        artifact = Artifact(name="api")
        match = artifact_match_evidence(artifact, "ghcr.io/acme/payments-api:1")
        self.assertFalse(match.matched)

    def test_best_artifact_match_picks_strongest_match(self) -> None:
        a1 = Artifact(name="api")
        a2 = Artifact(name="payments-api", reference="ghcr.io/acme/payments-api:1")
        artifact, match = best_artifact_match([a1, a2], "ghcr.io/acme/payments-api:1")
        self.assertEqual(artifact, a2)
        self.assertEqual(match.method, "exact-reference")

    def test_terraform_image_matches_uses_conservative_artifact_logic(self) -> None:
        self.assertFalse(image_matches(Artifact(name="api"), "ghcr.io/acme/payments-api:1"))
        self.assertTrue(image_matches(Artifact(name="payments-api"), "ghcr.io/acme/payments-api:1"))


class SbomMetadataTests(unittest.TestCase):
    def test_sbom_loader_reads_top_level_and_component_external_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.cdx.json"
            path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {
                            "component": {
                                "name": "app",
                                "externalReferences": [{"type": "distribution", "url": "ghcr.io/acme/app:1"}],
                            }
                        },
                        "components": [
                            {
                                "name": "lib",
                                "version": "1",
                                "externalReferences": [{"type": "vcs", "url": "https://example.invalid/repo"}],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            sbom = load_sbom(path)
        self.assertEqual(sbom.artifact.reference, "ghcr.io/acme/app:1")
        self.assertEqual(sbom.artifact.properties["external:distribution"], "ghcr.io/acme/app:1")
        self.assertEqual(sbom.components[0].properties["source"], "https://example.invalid/repo")

    def test_sbom_loader_uses_top_level_properties_as_artifact_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.cdx.json"
            path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "properties": [{"name": "artifact:name", "value": "from-props"}, {"name": "oci:image:ref", "value": "repo/from-props:1"}],
                        "components": [],
                    }
                ),
                encoding="utf-8",
            )
            sbom = load_sbom(path)
        self.assertEqual(sbom.artifact.name, "from-props")
        self.assertEqual(sbom.artifact.reference, "repo/from-props:1")

    def test_sbom_loader_preserves_component_scope_property(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.cdx.json"
            path.write_text(
                json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "pytest", "properties": [{"name": "dependency.scope", "value": "dev"}]}]}),
                encoding="utf-8",
            )
            sbom = load_sbom(path)
        self.assertEqual(sbom.components[0].scope, "dev")


class SourceReachabilityV4Tests(unittest.TestCase):
    def _log4j_component(self) -> Component:
        return Component(name="log4j-core", group="org.apache.logging.log4j", version="2.14.1", purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")

    def _log4j_vuln(self) -> VulnerabilityRecord:
        return VulnerabilityRecord(id="CVE-2021-44228", package_name="log4j-core")

    def test_same_file_import_function_and_entrypoint_is_attacker_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Controller.java").write_text(
                "import org.apache.logging.log4j.LogManager;\n@PostMapping(\"/x\")\nclass C { void f(@RequestBody String b){ LogManager.getLogger(C.class).info(b); }}",
                encoding="utf-8",
            )
            evidence = analyze_component_source(self._log4j_component(), root, self._log4j_vuln())
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertIn("vulnerability-specific", evidence.reason)

    def test_entrypoint_in_different_file_does_not_become_attacker_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "LoggerUse.java").write_text("import org.apache.logging.log4j.LogManager; class C { void f(String b){ LogManager.getLogger(C.class).info(b); }}", encoding="utf-8")
            (root / "Controller.java").write_text("@PostMapping(\"/x\") class Controller { }", encoding="utf-8")
            evidence = analyze_component_source(self._log4j_component(), root, self._log4j_vuln())
        self.assertEqual(evidence.reachability, Reachability.FUNCTION_REACHABLE)
        self.assertIn("elsewhere", evidence.reason)

    def test_unrelated_entrypoint_in_same_file_does_not_become_attacker_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Controller.java").write_text(
                "import org.apache.logging.log4j.LogManager;\n"
                "class C {\n"
                "  void logInternal(String value){ LogManager.getLogger(C.class).info(value); }\n"
                "  @PostMapping(\"/x\") void route(@RequestBody String body){ String ignored = body; }\n"
                "}\n",
                encoding="utf-8",
            )
            evidence = analyze_component_source(self._log4j_component(), root, self._log4j_vuln())
        self.assertEqual(evidence.reachability, Reachability.FUNCTION_REACHABLE)

    def test_import_and_function_in_different_files_is_low_confidence_function_reachable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Import.java").write_text("import org.apache.logging.log4j.LogManager; class I {}", encoding="utf-8")
            (root / "Use.java").write_text("class U { void f(){ LogManager.getLogger(U.class); }}", encoding="utf-8")
            evidence = analyze_component_source(self._log4j_component(), root, self._log4j_vuln())
        self.assertEqual(evidence.reachability, Reachability.FUNCTION_REACHABLE)
        self.assertEqual(evidence.confidence.value, "low")

    def test_go_generic_import_detection(self) -> None:
        component = Component(name="pkg", purl="pkg:golang/github.com/acme/pkg@1.0.0")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.go").write_text('package main\nimport "github.com/acme/pkg"\nfunc main(){}', encoding="utf-8")
            evidence = analyze_component_source(component, root)
        self.assertEqual(evidence.reachability, Reachability.IMPORTED)
        self.assertEqual(evidence.language, "go")

    def test_unknown_due_to_no_rule_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text("console.log('no package usage here');\n", encoding="utf-8")
            evidence = analyze_component_source(Component(name="left-pad", purl="pkg:npm/left-pad@1.0.0"), root)
        self.assertEqual(evidence.reachability, Reachability.UNKNOWN_DUE_TO_NO_RULE)
        self.assertIn("no package-specific source rule", evidence.reason)

    def test_python_cross_file_handler_to_sink_is_attacker_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api.py").write_text(
                "from fastapi import FastAPI, Request\n"
                "from client import fetch_report\n\n"
                "app = FastAPI()\n"
                "@app.get('/report')\n"
                "async def report(request: Request):\n"
                "    return fetch_report(request.query_params['url'])\n",
                encoding="utf-8",
            )
            (root / "client.py").write_text(
                "import requests\n\n"
                "def fetch_report(url):\n"
                "    return requests.get(url, timeout=2).text\n",
                encoding="utf-8",
            )
            evidence = analyze_component_source(Component(name="requests", purl="pkg:pypi/requests@2.19.0"), root)
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertIn("direct source call path", evidence.reason)
        self.assertTrue(any(symbol.startswith("call_path:") for symbol in evidence.matched_symbols))

    def test_python_multi_hop_handler_to_sink_is_attacker_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api.py").write_text(
                "from fastapi import FastAPI, Request\nfrom service import load\n"
                "app = FastAPI()\n@app.get('/report')\nasync def report(request: Request):\n    return load(request.query_params['url'])\n",
                encoding="utf-8",
            )
            (root / "service.py").write_text("from client import fetch_report\n\ndef load(url):\n    return fetch_report(url)\n", encoding="utf-8")
            (root / "client.py").write_text("import requests\n\ndef fetch_report(url):\n    return requests.get(url, timeout=2).text\n", encoding="utf-8")
            evidence = analyze_component_source(Component(name="requests", purl="pkg:pypi/requests@2.19.0"), root)
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertIn("report->load->fetch_report", " ".join(evidence.matched_symbols))

    def test_javascript_route_to_local_sink_is_attacker_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text(
                "const axios = require('axios');\n"
                "function fetchUrl(url) { return axios.get(url); }\n"
                "function showReport(req, res) { return fetchUrl(req.query.url); }\n"
                "app.get('/report', showReport);\n",
                encoding="utf-8",
            )
            evidence = analyze_component_source(Component(name="axios", purl="pkg:npm/axios@1.6.0"), root)
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertIn("direct source call path", evidence.reason)

    def test_typescript_class_method_route_to_local_sink_is_attacker_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "controller.ts").write_text(
                "import { fetchUrl } from './sink';\n"
                "class ReportController {\n"
                "  @Get(':url')\n"
                "  async show(@Param('url') url: string) { return fetchUrl(url); }\n"
                "}\n",
                encoding="utf-8",
            )
            (root / "sink.ts").write_text(
                "import axios from 'axios';\n"
                "export function fetchUrl(url: string) { return axios.get(url); }\n",
                encoding="utf-8",
            )
            evidence = analyze_component_source(Component(name="axios", purl="pkg:npm/axios@1.6.0"), root)
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertIn("show->fetchUrl", " ".join(evidence.matched_symbols))

    def test_node_request_generated_client_is_function_reachable_without_entrypoint_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "client.ts").write_text(
                "import localVarRequest = require('request');\n"
                "export class OrdersApi {\n"
                "  public async createOrder(orderRequest: Order) {\n"
                "    const localVarRequestOptions = { body: orderRequest };\n"
                "    return localVarRequest(localVarRequestOptions, () => undefined);\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
            evidence = analyze_component_source(Component(name="request", purl="pkg:npm/request@2.88.2"), root)
        self.assertEqual(evidence.reachability, Reachability.FUNCTION_REACHABLE)
        self.assertIn("request HTTP client", evidence.reason)

    def test_expanded_builtin_rules_cover_common_risk_families(self) -> None:
        cases = [
            (
                Component(name="pyyaml", purl="pkg:pypi/pyyaml@5.3"),
                "api.py",
                "import yaml\nfrom fastapi import FastAPI, Request\napp = FastAPI()\n@app.post('/yaml')\nasync def parse(request: Request):\n    return yaml.load(await request.body())\n",
            ),
            (
                Component(name="jsonwebtoken", purl="pkg:npm/jsonwebtoken@8.5.0"),
                "auth.js",
                "const jwt = require('jsonwebtoken');\nfunction auth(req) { return jwt.verify(req.headers.authorization, 'secret'); }\n",
            ),
            (
                Component(name="snakeyaml", purl="pkg:maven/org.yaml/snakeyaml@1.26"),
                "YamlController.java",
                "import org.yaml.snakeyaml.Yaml;\nclass C { @PostMapping(\"/yaml\") Object parse(@RequestBody String body) { return new Yaml().load(body); }}\n",
            ),
        ]
        for component, filename, source in cases:
            with self.subTest(component=component.name):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / filename).write_text(source, encoding="utf-8")
                    evidence = analyze_component_source(component, root)
                self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)

    def test_source_scanner_ignores_node_modules(self) -> None:
        component = Component(name="lodash", purl="pkg:npm/lodash@4.17.20")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nm = root / "node_modules" / "lodash"
            nm.mkdir(parents=True)
            (nm / "index.js").write_text("const _ = require('lodash'); _.merge({}, {});", encoding="utf-8")
            evidence = analyze_component_source(component, root)
        self.assertEqual(evidence.reachability, Reachability.PACKAGE_PRESENT)

    def test_dependency_graph_parent_import_marks_transitive_component_reachable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("import parentpkg\nparentpkg.run()\n", encoding="utf-8")
            artifact = Artifact(name="app", bom_ref="app-ref")
            parent = Component(name="parentpkg", purl="pkg:pypi/parentpkg@1.0.0", bom_ref="parent-ref")
            child = Component(name="childlib", purl="pkg:pypi/childlib@1.0.0", bom_ref="child-ref")
            sbom = SbomDocument(path=root / "bom.json", artifact=artifact, components=[parent, child], dependencies={"app-ref": ["parent-ref"], "parent-ref": ["child-ref"]})
            evidence = analyze_component_source(child, root, sbom=sbom)
        self.assertEqual(evidence.reachability, Reachability.DEPENDENCY_REACHABLE)
        self.assertEqual(evidence.dependency_path, ["app", "parentpkg", "childlib"])

    def test_package_manager_manifests_add_weak_dependency_evidence(self) -> None:
        cases = [
            (
                Component(name="left-pad", purl="pkg:npm/left-pad@1.0.0"),
                "pnpm-lock.yaml",
                "lockfileVersion: '9.0'\npackages:\n  left-pad@1.0.0:\n    resolution: {}\n",
                "pnpm-lock.yaml",
            ),
            (
                Component(name="react", purl="pkg:npm/react@18.2.0"),
                "yarn.lock",
                '"react@npm:^18.2.0":\n  version: 18.2.0\n',
                "yarn.lock",
            ),
            (
                Component(name="requests", purl="pkg:pypi/requests@2.31.0"),
                "pyproject.toml",
                '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.31.0"\n',
                "pyproject.toml",
            ),
            (
                Component(name="httpx", purl="pkg:pypi/httpx@0.27.0"),
                "pyproject.toml",
                '[project]\ndependencies = ["httpx>=0.27.0"]\n',
                "pyproject.toml",
            ),
            (
                Component(name="urllib3", purl="pkg:pypi/urllib3@2.2.0"),
                "poetry.lock",
                '[[package]]\nname = "urllib3"\nversion = "2.2.0"\n',
                "poetry.lock",
            ),
            (
                Component(name="log4j-core", group="org.apache.logging.log4j", purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
                "build.gradle",
                'dependencies { implementation("org.apache.logging.log4j:log4j-core:2.14.1") }\n',
                "build.gradle",
            ),
            (
                Component(name="gin", purl="pkg:golang/github.com/gin-gonic/gin@1.9.0"),
                "go.mod",
                "module example.com/app\n\nrequire github.com/gin-gonic/gin v1.9.0\n",
                "go.mod",
            ),
        ]
        for component, filename, contents, expected_manifest in cases:
            with self.subTest(filename=filename):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / filename).write_text(contents, encoding="utf-8")
                    evidence = analyze_component_source(component, root)
                self.assertEqual(evidence.reachability, Reachability.DEPENDENCY_REACHABLE)
                self.assertEqual(evidence.confidence.value, "low")
                self.assertIn("package-manager manifest", evidence.reason)
                self.assertTrue(any(symbol.startswith(f"manifest:{expected_manifest}:") for symbol in evidence.matched_symbols))
                self.assertEqual(evidence.locations[0].path.name, expected_manifest)

    def test_manifest_matching_avoids_cross_ecosystem_and_project_name_false_positives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"dependencies": {"requests": "2.31.0"}}\n', encoding="utf-8")
            evidence = analyze_component_source(Component(name="requests", purl="pkg:pypi/requests@2.31.0"), root)
        self.assertEqual(evidence.reachability, Reachability.PACKAGE_PRESENT)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text('[project]\nname = "requests"\nversion = "0.1.0"\n', encoding="utf-8")
            evidence = analyze_component_source(Component(name="requests", purl="pkg:pypi/requests@2.31.0"), root)
        self.assertEqual(evidence.reachability, Reachability.PACKAGE_PRESENT)

    def test_custom_rule_file_can_define_vulnerability_specific_sink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules.json"
            rules.write_text(
                json.dumps(
                    {
                        "rules": [
                            {
                                "ecosystem": "npm",
                                "package": "left-pad",
                                "vulnerabilities": ["GHSA-leftpad"],
                                "import_patterns": ["require\\(['\\\"]left-pad['\\\"]\\)"],
                                "function_patterns": ["leftPad\\s*\\("],
                                "attacker_patterns": ["event\\.body"],
                                "description": "left-pad demo rule",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (root / "handler.js").write_text("const leftPad = require('left-pad'); exports.handler = e => leftPad(e.event.body, 2);", encoding="utf-8")
            custom = load_reachability_rules(rules)
            evidence = analyze_component_source(Component(name="left-pad", purl="pkg:npm/left-pad@1.0.0"), root, VulnerabilityRecord(id="GHSA-leftpad", package_name="left-pad"), custom)
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertIn("vulnerability-specific", evidence.reason)

    def test_custom_rule_file_validation_rejects_missing_import_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(json.dumps({"rules": [{"ecosystem": "npm", "package": "x"}]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_reachability_rules(path)

    def test_custom_rule_file_validation_rejects_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(json.dumps([]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_reachability_rules(path)


class MappingAndSbomPlanTests(unittest.TestCase):
    def test_sbom_plan_recommends_image_and_ecosystem_commands(self) -> None:
        commands = recommend_sbom_commands("payments-api", source_root=".", image="ghcr.io/acme/payments-api:1", ecosystem="maven")
        tools = {command.tool for command in commands}
        self.assertIn("syft", tools)
        self.assertIn("trivy", tools)
        self.assertIn("cyclonedx-maven-plugin", tools)

    def test_sbom_plan_markdown_contains_metadata_guidance(self) -> None:
        commands = recommend_sbom_commands("notifier", image="ghcr.io/acme/notifier:1", ecosystem="npm")
        markdown = render_sbom_plan_markdown("notifier", commands)
        self.assertIn("npm sbom", markdown)
        self.assertIn("Recommended SBOM metadata", markdown)

    def test_write_sbom_plan_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.json"
            commands = recommend_sbom_commands("app", ecosystem="python")
            write_sbom_plan_json(path, "app", commands)
            data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["artifact"], "app")
        self.assertTrue(data["commands"])

    def test_cli_sbom_plan_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_json = Path(tmp) / "sbom-plan.json"
            out_md = Path(tmp) / "sbom-plan.md"
            code = main(["sbom-plan", "--artifact", "app", "--image", "repo/app:1", "--ecosystem", "npm", "--out-json", str(out_json), "--out-md", str(out_md)])
            self.assertEqual(code, 0)
            self.assertTrue(out_json.exists())
            self.assertIn("npm sbom", out_md.read_text(encoding="utf-8"))

    def test_source_evidence_plan_recommends_external_analyzer_handoff(self) -> None:
        commands = recommend_source_evidence_commands(source_root="src", output_dir="reachability", language="go")
        markdown = render_source_evidence_plan_markdown(commands)

        self.assertTrue(any(command.tool == "semgrep" for command in commands))
        self.assertTrue(any(command.tool == "codeql" and "codeql/go-queries" in command.command for command in commands))
        self.assertTrue(any(command.tool == "govulncheck" for command in commands))
        self.assertIn("--source-evidence-in reachability/semgrep-results.json", markdown)

    def test_cli_source_evidence_plan_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_json = Path(tmp) / "source-plan.json"
            out_md = Path(tmp) / "source-plan.md"
            code = main([
                "source-evidence-plan",
                "--source-root", "src",
                "--language", "python",
                "--out-json", str(out_json),
                "--out-md", str(out_md),
            ])
            self.assertEqual(code, 0)
            self.assertIn("reachability-advisor-source-evidence-plan", out_json.read_text(encoding="utf-8"))
            self.assertIn("codeql/python-queries", out_md.read_text(encoding="utf-8"))

    def test_mapping_report_shows_source_and_terraform_matches(self) -> None:
        sbom = load_sbom(ROOT / "samples/sboms/payments-api.cdx.json")
        plan = json.loads((ROOT / "samples/tfplan-multicloud.json").read_text(encoding="utf-8"))
        analysis = TerraformAnalyzer(plan, [sbom.artifact]).analyze()
        report = build_mapping_report([sbom], {"payments-api": ROOT / "samples/source/payments-api"}, analysis.coverage)
        self.assertEqual(report["summary"]["artifact_count"], 1)
        self.assertTrue(report["artifacts"][0]["terraform_matched"])
        self.assertFalse(report["artifacts"][0]["mapping_warnings"])

    def test_artifact_manifest_supplies_release_identity_and_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sbom = root / "bom.json"
            vulns = root / "vulns.json"
            manifest = root / "artifact-manifest.json"
            plan_path = root / "tfplan.json"
            mapping = root / "mapping.json"
            readiness = root / "readiness.json"
            source_coverage = root / "source-coverage.json"
            readiness_from_inputs = root / "readiness-from-inputs.json"
            digest = "sha256:" + "a" * 64
            sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "app"}}, "components": []}), encoding="utf-8")
            vulns.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
            manifest.write_text(
                json.dumps(
                    {
                        "signed": True,
                        "artifacts": [
                            {
                                "name": "app",
                                "sbom": "bom.json",
                                "image": "repo/app:1",
                                "digest": digest,
                                "git_sha": "abc123",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            plan_path.write_text(
                json.dumps(
                    {
                        "planned_values": {
                            "root_module": {
                                "resources": [
                                    {
                                        "address": "aws_lambda_function.app",
                                        "type": "aws_lambda_function",
                                        "name": "app",
                                        "values": {"function_name": "app", "image_uri": f"repo/app@{digest}"},
                                    }
                                ]
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            code = main(
                [
                    "scan",
                    "--sbom",
                    str(sbom),
                    "--vulns",
                    str(vulns),
                    "--terraform-plan",
                    str(plan_path),
                    "--artifact-manifest",
                    str(manifest),
                    "--mapping-out",
                    str(mapping),
                    "--source-coverage-out",
                    str(source_coverage),
                    "--readiness-out",
                    str(readiness),
                    "--no-table",
                ]
            )

            self.assertEqual(code, 0)
            mapping_report = json.loads(mapping.read_text(encoding="utf-8"))
            self.assertEqual(mapping_report["artifact_manifest"]["applied"], 1)
            self.assertTrue(mapping_report["artifacts"][0]["strong_artifact_identity"])
            self.assertTrue(mapping_report["artifacts"][0]["terraform_matched"])
            self.assertEqual(json.loads(readiness.read_text(encoding="utf-8"))["status"], "ready")
            self.assertEqual(
                main(
                    [
                        "evidence-profile",
                        "--mapping",
                        str(mapping),
                        "--source-coverage",
                        str(source_coverage),
                        "--out",
                        str(readiness_from_inputs),
                        "--fail-on-blockers",
                    ]
                ),
                0,
            )
            self.assertEqual(json.loads(readiness_from_inputs.read_text(encoding="utf-8"))["status"], "ready")

    def test_readiness_blocks_zero_critical_external_coverage(self) -> None:
        report = release_readiness_report(
            mapping_report={"artifacts": [], "summary": {}},
            source_coverage={"summary": {"critical_external_evidence_coverage": 0.0}},
        )

        self.assertEqual(report["status"], "blocked")
        self.assertTrue(any(blocker["kind"] == "critical_source_coverage" for blocker in report["blockers"]))

    def test_scan_writes_source_coverage_and_accepts_external_source_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sbom = root / "bom.json"
            vulns = root / "vulns.json"
            source = root / "src"
            source.mkdir()
            out = root / "findings.json"
            coverage = root / "source-coverage.json"
            evidence = root / "source-evidence.json"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "metadata": {"component": {"name": "app"}},
                        "components": [{"name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0"}],
                    }
                ),
                encoding="utf-8",
            )
            vulns.write_text(json.dumps({"vulnerabilities": [{"id": "GHSA-leftpad", "package": {"name": "left-pad"}}]}), encoding="utf-8")
            (source / "index.js").write_text("console.log('no source match');\n", encoding="utf-8")
            evidence.write_text(
                json.dumps(
                    {
                        "evidence": [
                            {
                                "artifact": "app",
                                "component": "left-pad",
                                "vulnerability": "GHSA-leftpad",
                                "state": "attacker_controlled",
                                "confidence": "high",
                                "reason": "semgrep taint trace",
                                "tool": "semgrep",
                                "locations": [{"path": str(source / "index.js"), "line": 1}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            code = main(
                [
                    "scan",
                    "--sbom",
                    str(sbom),
                    "--vulns",
                    str(vulns),
                    "--source-root",
                    f"app={source}",
                    "--source-evidence-in",
                    str(evidence),
                    "--out",
                    str(out),
                    "--source-coverage-out",
                    str(coverage),
                    "--no-table",
                ]
            )
            self.assertEqual(code, 0)
            findings = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(findings["findings"][0]["source_reachability"]["state"], "attacker_controlled")
            self.assertEqual(findings["findings"][0]["source_reachability"]["evidence_source"], "semgrep")
            report = json.loads(coverage.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["external_evidence_records"], 1)

    def test_external_source_evidence_purl_requires_component_purl_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source-evidence.json"
            path.write_text(
                json.dumps(
                    {
                        "evidence": [
                            {
                                "purl": "pkg:npm/left-pad@1.0.0",
                                "state": "attacker_controlled",
                                "confidence": "high",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            store = load_external_source_evidence([path])
        vuln = VulnerabilityRecord(id="GHSA-leftpad", package_name="left-pad")
        self.assertIsNone(store.best_for("app", Component(name="left-pad"), vuln))
        self.assertIsNotNone(store.best_for("app", Component(name="left-pad", purl="pkg:npm/left-pad@1.0.0"), vuln))

    def test_external_source_evidence_ranks_selector_and_provider_strength(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source-evidence.json"
            path.write_text(
                json.dumps(
                    [
                        {"component": "axios", "state": "function_reachable", "confidence": "high", "source": "semgrep"},
                        {"component": "axios", "state": "function_reachable", "confidence": "high", "source": "CodeQL"},
                        {"purl": "pkg:npm/axios@1.0.0", "state": "function_reachable", "confidence": "high", "source": "semgrep"},
                    ]
                ),
                encoding="utf-8",
            )
            store = load_external_source_evidence([path])

        evidence = store.best_for("web", Component(name="axios", purl="pkg:npm/axios@1.0.0"), VulnerabilityRecord(id="GHSA-axios", package_name="axios"))
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.evidence_source, "semgrep")
        component_only = store.best_for("web", Component(name="axios"), VulnerabilityRecord(id="GHSA-axios", package_name="axios"))
        self.assertIsNotNone(component_only)
        assert component_only is not None
        self.assertEqual(component_only.evidence_source, "CodeQL")
        self.assertEqual(store.provider_counts(), {"CodeQL": 1, "semgrep": 2})

    def test_external_source_evidence_reports_unmatchable_selectors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source-evidence.json"
            path.write_text(
                json.dumps(
                    [
                        {"artifact": "api", "state": "attacker_controlled", "confidence": "high", "source": "semgrep"},
                        {"state": "function_reachable", "confidence": "medium", "source": "custom"},
                    ]
                ),
                encoding="utf-8",
            )
            store = load_external_source_evidence([path])

        self.assertIsNone(store.best_for("api", Component(name="axios"), VulnerabilityRecord(id="GHSA-axios", package_name="axios")))
        self.assertEqual(store.selector_diagnostics()["artifact_only_records"], 1)
        self.assertEqual(store.selector_diagnostics()["unscoped_records"], 1)
        self.assertEqual(store.records[0].evidence.diagnostics[0]["code"], "external_selector_artifact_only")
        self.assertEqual(store.records[1].evidence.diagnostics[0]["code"], "external_selector_missing")

    def test_semgrep_source_evidence_preserves_purl_selector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "semgrep.json"
            path.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "reachability.test",
                                "path": "src/index.js",
                                "start": {"line": 1, "col": 1},
                                "extra": {
                                    "message": "taint trace",
                                    "metadata": {
                                        "reachability_advisor": {
                                            "purl": "pkg:npm/left-pad@1.0.0",
                                            "state": "attacker_controlled",
                                            "confidence": "high",
                                        }
                                    },
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            store = load_external_source_evidence([path])
        vuln = VulnerabilityRecord(id="GHSA-other", package_name="left-pad")
        evidence = store.best_for("app", Component(name="left-pad", purl="pkg:npm/left-pad@1.0.0"), vuln)
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.evidence_source, "semgrep")

    def test_semgrep_dataflow_trace_becomes_attacker_controlled_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "semgrep-trace.json"
            path.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "reachability.npm.axios.attacker_controlled",
                                "path": "src/app.js",
                                "start": {"line": 7, "col": 3},
                                "extra": {
                                    "message": "tainted URL reaches axios.get",
                                    "metadata": {
                                        "package": "axios",
                                        "vulnerability": "GHSA-axios",
                                    },
                                    "metavars": {"$URL": {"abstract_content": "req.query.url"}},
                                    "dataflow_trace": {
                                        "taint_source": [
                                            {
                                                "location": {"path": "src/app.js", "start": {"line": 3, "col": 15}},
                                                "content": "req.query.url",
                                            }
                                        ],
                                        "taint_sink": [
                                            {
                                                "location": {"path": "src/app.js", "start": {"line": 7, "col": 3}},
                                                "content": "axios.get(url)",
                                            }
                                        ],
                                    },
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            store = load_external_source_evidence([path])

        evidence = store.best_for("web", Component(name="axios"), VulnerabilityRecord(id="GHSA-axios", package_name="axios"))
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertEqual(evidence.confidence, Confidence.HIGH)
        self.assertEqual(evidence.language, "javascript")
        self.assertEqual(evidence.evidence_source, "semgrep")
        self.assertIn("Semgrep dataflow trace", evidence.reason)
        self.assertEqual([location.line for location in evidence.locations], [3, 7])
        self.assertIn("$URL:req.query.url", evidence.matched_symbols)
        self.assertEqual(evidence.diagnostics[0]["code"], "semgrep_dataflow_trace")

    def test_codeql_codeflow_uses_package_selector_without_rule_id_vulnerability_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "codeql.sarif"
            path.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {
                                    "driver": {
                                        "name": "CodeQL",
                                        "rules": [
                                            {
                                                "id": "js/request-forgery",
                                                "properties": {
                                                    "reachability_advisor": {
                                                        "package": "axios",
                                                        "language": "javascript",
                                                    },
                                                    "precision": "high",
                                                },
                                            }
                                        ],
                                    }
                                },
                                "results": [
                                    {
                                        "ruleId": "js/request-forgery",
                                        "message": {"text": "request URL reaches HTTP client"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "src/app.js"},
                                                    "region": {"startLine": 12, "startColumn": 9},
                                                }
                                            }
                                        ],
                                        "codeFlows": [
                                            {
                                                "threadFlows": [
                                                    {
                                                        "locations": [
                                                            {
                                                                "location": {
                                                                    "message": {"text": "user controlled URL"},
                                                                    "physicalLocation": {
                                                                        "artifactLocation": {"uri": "src/app.js"},
                                                                        "region": {"startLine": 4, "startColumn": 19},
                                                                    },
                                                                }
                                                            },
                                                            {
                                                                "location": {
                                                                    "message": {"text": "HTTP sink"},
                                                                    "physicalLocation": {
                                                                        "artifactLocation": {"uri": "src/client.js"},
                                                                        "region": {"startLine": 8, "startColumn": 5},
                                                                    },
                                                                }
                                                            },
                                                        ]
                                                    }
                                                ]
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            store = load_external_source_evidence([path])

        evidence = store.best_for("web", Component(name="axios"), VulnerabilityRecord(id="GHSA-other", package_name="axios"))
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertEqual(evidence.confidence, Confidence.HIGH)
        self.assertEqual(evidence.evidence_source, "CodeQL")
        self.assertIn("CodeQL data-flow path", evidence.reason)
        self.assertEqual(evidence.locations[0].path, Path("src/app.js"))
        self.assertEqual(evidence.locations[-1].path, Path("src/client.js"))
        self.assertEqual([location.line for location in evidence.locations], [12, 4, 8])
        self.assertIn("js/request-forgery", evidence.matched_symbols)
        self.assertEqual(evidence.diagnostics[0]["code"], "codeql_code_flow")

    def test_semgrep_adapter_handles_rule_package_and_direct_trace_locations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "semgrep-native.json"
            path.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "reachability.npm.lodash.function_reachable",
                                "path": "src/util.ts",
                                "start": {"line": 2, "col": 4},
                                "extra": {"message": "lodash usage"},
                            },
                            {
                                "check_id": "custom.requests.trace",
                                "path": "app.py",
                                "start": {"line": 6, "col": 1},
                                "extra": {
                                    "metadata": {"purl": "pkg:pypi/requests@2.19.0"},
                                    "dataflow_trace": {
                                        "taint_source": [
                                            {"path": "app.py", "start": {"line": 1, "column": 2}, "message": "request arg"},
                                            {"location": {"start": {"line": 2}}},
                                        ],
                                        "taint_sink": [{"path": "app.py", "line": 6, "column": 1, "content": "requests.get(url)"}],
                                    },
                                },
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            store = load_external_source_evidence([path])

        lodash = store.best_for("web", Component(name="lodash"), VulnerabilityRecord(id="GHSA-lodash", package_name="lodash"))
        self.assertIsNotNone(lodash)
        assert lodash is not None
        self.assertEqual(lodash.reachability, Reachability.FUNCTION_REACHABLE)
        self.assertEqual(lodash.confidence, Confidence.MEDIUM)
        self.assertEqual(lodash.language, "javascript")
        self.assertNotIn("dataflow trace", lodash.reason)
        self.assertEqual(lodash.diagnostics[0]["code"], "semgrep_result")

        requests = store.best_for(
            "api",
            Component(name="requests", purl="pkg:pypi/requests@2.19.0"),
            VulnerabilityRecord(id="GHSA-requests", package_name="requests"),
        )
        self.assertIsNotNone(requests)
        assert requests is not None
        self.assertEqual(requests.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertEqual([location.line for location in requests.locations], [1, 6])

    def test_sarif_adapter_handles_related_locations_and_vulnerability_rule_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "generic.sarif"
            path.write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "tool": {
                                    "driver": {
                                        "name": "custom-sarif",
                                        "rules": [
                                            "bad",
                                            {
                                                "id": "GHSA-custom",
                                                "properties": {
                                                    "queryName": "custom-query",
                                                    "source_symbol": "req.query",
                                                    "sink_symbol": "leftPad",
                                                },
                                            },
                                        ],
                                    }
                                },
                                "results": [
                                    {
                                        "ruleId": "GHSA-custom",
                                        "message": {"text": "left-pad is reachable"},
                                        "properties": {"package": "left-pad"},
                                        "locations": [
                                            "bad",
                                            {
                                                "message": {"text": "primary"},
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "src/index.js"},
                                                    "region": {"startLine": 10, "startColumn": 3},
                                                },
                                            },
                                        ],
                                        "relatedLocations": [
                                            "bad",
                                            {"physicalLocation": {"region": {"startLine": 1}}},
                                            {
                                                "message": {"text": "helper"},
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "src/helper.js"},
                                                    "region": {"startLine": 2, "startColumn": 1},
                                                },
                                            },
                                        ],
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            store = load_external_source_evidence([path])

        evidence = store.best_for("web", Component(name="left-pad"), VulnerabilityRecord(id="GHSA-custom", package_name="left-pad"))
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence.reachability, Reachability.FUNCTION_REACHABLE)
        self.assertEqual(evidence.confidence, Confidence.MEDIUM)
        self.assertEqual(evidence.evidence_source, "custom-sarif")
        self.assertEqual([location.path for location in evidence.locations], [Path("src/index.js"), Path("src/helper.js")])
        self.assertIn("queryName:custom-query", evidence.matched_symbols)
        self.assertIn("source_symbol:req.query", evidence.matched_symbols)
        self.assertEqual(evidence.diagnostics[0]["code"], "sarif_result")

    def test_external_source_evidence_imports_supported_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plain = root / "plain.json"
            findings = root / "findings.json"
            sarif = root / "results.sarif"
            govuln = root / "govuln.jsonl"
            plain.write_text(
                json.dumps(
                    [
                        {
                            "package": "left-pad",
                            "vulnerability_id": "GHSA-leftpad",
                            "state": "invalid-state",
                            "confidence": "invalid-confidence",
                            "source": "plain-tool",
                            "locations": [
                                "bad",
                                {},
                                {"uri": "src/index.js", "startLine": 3, "startColumn": 4, "snippet": "leftPad(value)"},
                            ],
                            "matched_symbols": ["leftPad"],
                            "dependency_path": ["app", "left-pad"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            findings.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "artifact": {"name": "api"},
                                "component": {"name": "requests", "purl": "pkg:pypi/requests@2.19.0"},
                                "vulnerability": {"id": "GHSA-requests"},
                                "source_reachability": {
                                    "state": "imported",
                                    "confidence": "high",
                                    "language": "python",
                                    "reason": "imported evidence",
                                    "matched_symbols": ["requests"],
                                    "dependency_path": ["api", "requests"],
                                    "evidence_source": "reachability-advisor",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            sarif.write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "tool": {"driver": {"name": "CodeQL"}},
                                "results": [
                                    {
                                        "ruleId": "GHSA-axios",
                                        "message": {"text": "axios sink"},
                                        "properties": {
                                            "component": "axios",
                                            "purl": "pkg:npm/axios@1.6.0",
                                            "reachability": "attacker_controlled",
                                            "confidence": "high",
                                        },
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "src/app.js"},
                                                    "region": {"startLine": 9, "startColumn": 2},
                                                }
                                            }
                                        ],
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            govuln.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "finding": {
                                    "osv": "GO-2024-0001",
                                    "trace": [
                                        "bad",
                                        {
                                            "module": "example.com/mod",
                                            "position": {"filename": "main.go", "line": 7, "column": 3},
                                        },
                                    ],
                                }
                            }
                        ),
                        json.dumps({"finding": {"trace": []}}),
                    ]
                ),
                encoding="utf-8",
            )
            store = load_external_source_evidence([plain, findings, sarif, govuln])

        self.assertEqual(len(store.records), 4)
        leftpad = store.best_for("app", Component(name="left-pad"), VulnerabilityRecord(id="GHSA-leftpad", package_name="left-pad"))
        self.assertIsNotNone(leftpad)
        assert leftpad is not None
        self.assertEqual(leftpad.reachability, Reachability.FUNCTION_REACHABLE)
        self.assertEqual(leftpad.confidence.value, "medium")
        self.assertEqual(leftpad.locations[0].path, Path("src/index.js"))
        self.assertEqual(leftpad.dependency_path, ["app", "left-pad"])

        requests = store.best_for("api", Component(name="requests", purl="pkg:pypi/requests@2.19.0"), VulnerabilityRecord(id="GHSA-requests", package_name="requests"))
        self.assertIsNotNone(requests)
        assert requests is not None
        self.assertEqual(requests.reachability, Reachability.IMPORTED)

        axios = store.best_for("web", Component(name="axios", purl="pkg:npm/axios@1.6.0"), VulnerabilityRecord(id="GHSA-axios", package_name="axios"))
        self.assertIsNotNone(axios)
        assert axios is not None
        self.assertEqual(axios.evidence_source, "CodeQL")
        self.assertEqual(axios.locations[0].path, Path("src/app.js"))

        govuln = store.best_for("go-api", Component(name="example.com/mod"), VulnerabilityRecord(id="GO-2024-0001", package_name="example.com/mod"))
        self.assertIsNotNone(govuln)
        assert govuln is not None
        self.assertEqual(govuln.evidence_source, "govulncheck")
        self.assertEqual(govuln.locations[0].line, 7)

    def test_export_semgrep_rules_command_writes_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "rules.yml"
            code = main(["export-semgrep-rules", "--out", str(out)])
            text = out.read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertIn("reachability.npm.axios", text)
        self.assertIn("reachability_advisor", text)

    def test_mapping_report_warns_when_no_strong_artifact_reference(self) -> None:
        sbom = load_sbom(ROOT / "samples/sboms/payments-api.cdx.json")
        sbom.artifact.reference = None
        sbom.artifact.version = None
        sbom.artifact.properties.clear()
        report = build_mapping_report([sbom], {}, {"artifact_matches": [], "unmatched_artifacts": ["payments-api"], "summary": {}})
        warnings = report["artifacts"][0]["mapping_warnings"]
        self.assertGreaterEqual(len(warnings), 3)

    def test_cli_scan_writes_mapping_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mapping = Path(tmp) / "mapping.json"
            code = main([
                "scan",
                "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                "--vulns", str(ROOT / "samples/vulnerabilities.json"),
                "--source-root", f"payments-api={ROOT / 'samples/source/payments-api'}",
                "--terraform-plan", str(ROOT / "samples/tfplan-multicloud.json"),
                "--mapping-out", str(mapping),
                "--no-table",
            ])
            self.assertEqual(code, 0)
            data = json.loads(mapping.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], "4.0")
        self.assertEqual(data["summary"]["artifacts_with_terraform_matches"], 1)

    def test_cli_artifact_alias_enables_terraform_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sbom = tmp_path / "service.cdx.json"
            sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "service"}}, "components": [{"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}]}), encoding="utf-8")
            vulns = tmp_path / "vulns.json"
            vulns.write_text(json.dumps({"vulnerabilities": [{"id": "GHSA-lodash", "package": {"name": "lodash"}, "affected_versions": ["4.17.20"], "severity": "high"}]}), encoding="utf-8")
            tfplan = tmp_path / "tfplan.json"
            tfplan.write_text(json.dumps(_plan([_resource("aws_lambda_function.fn", "aws_lambda_function", {"function_name": "fn", "image_uri": "ghcr.io/acme/alias-app:1"})])), encoding="utf-8")
            mapping = tmp_path / "mapping.json"
            code = main([
                "scan", "--sbom", str(sbom), "--vulns", str(vulns), "--terraform-plan", str(tfplan),
                "--artifact-alias", "service=ghcr.io/acme/alias-app:1", "--mapping-out", str(mapping), "--no-table",
            ])
            self.assertEqual(code, 0)
            data = json.loads(mapping.read_text(encoding="utf-8"))
        self.assertEqual(data["summary"]["artifacts_with_terraform_matches"], 1)

    def test_cli_artifact_alias_rejects_unknown_artifact(self) -> None:
        code = main([
            "scan",
            "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
            "--vulns", str(ROOT / "samples/vulnerabilities.json"),
            "--artifact-alias", "missing=repo/missing:1",
            "--no-table",
        ])
        self.assertEqual(code, 2)


class TerraformMappingEvidenceTests(unittest.TestCase):
    def test_terraform_coverage_match_rows_include_method_and_score(self) -> None:
        artifact = Artifact(name="app", reference="repo/app:1")
        resources = [_resource("aws_lambda_function.fn", "aws_lambda_function", {"image_uri": "repo/app:1", "function_name": "fn"})]
        analysis = TerraformAnalyzer(_plan(resources), [artifact]).analyze()
        match = analysis.coverage["artifact_matches"][0]
        self.assertEqual(match["match_method"], "exact-reference")
        self.assertEqual(match["match_score"], 100)

    def test_terraform_coverage_reports_unmatched_artifact_after_conservative_match(self) -> None:
        artifact = Artifact(name="api")
        resources = [_resource("aws_lambda_function.fn", "aws_lambda_function", {"image_uri": "repo/payments-api:1", "function_name": "fn"})]
        analysis = TerraformAnalyzer(_plan(resources), [artifact]).analyze()
        self.assertEqual(analysis.coverage["unmatched_artifacts"], ["api"])

    def test_coverage_report_accepts_empty_artifact_list(self) -> None:
        resources = extract_resources(_plan([_resource("custom_resource.x", "custom_resource", {})]))
        report = coverage_report(resources, [], [])
        self.assertEqual(report["summary"]["artifact_match_coverage"], 1.0)
        self.assertEqual(len(report["visibility_gaps"]), 1)

    def test_artifact_alias_appears_in_mapping_candidates(self) -> None:
        artifact = Artifact(name="app", properties={"reachability:aliases": "repo/app:1"})
        resources = [_resource("aws_lambda_function.fn", "aws_lambda_function", {"image_uri": "repo/app:1"})]
        analysis = TerraformAnalyzer(_plan(resources), [artifact]).analyze()
        self.assertEqual(analysis.coverage["artifact_matches"][0]["match_method"], "exact-reference")


if __name__ == "__main__":
    unittest.main()

class AdditionalCoverageV4Tests(unittest.TestCase):
    def test_normalize_none_and_tagless_canonical(self) -> None:
        self.assertIsNone(normalize_image_reference(None))
        image = normalize_image_reference("busybox")
        self.assertIsNotNone(image)
        assert image is not None
        self.assertEqual(image.repository_leaf, "busybox")
        self.assertEqual(image.canonical, "busybox")

    def test_artifact_match_to_json_for_empty_target(self) -> None:
        match = artifact_match_evidence(Artifact(name="app"), None)
        data = match.to_json()
        self.assertFalse(data["matched"])
        self.assertIn("empty", data["reasons"][0])

    def test_best_artifact_match_with_no_artifacts(self) -> None:
        artifact, match = best_artifact_match([], "repo/app:1")
        self.assertIsNone(artifact)
        self.assertFalse(match.matched)

    def test_artifact_name_exact_token_match(self) -> None:
        match = artifact_match_evidence(Artifact(name="app"), "app")
        self.assertTrue(match.matched)
        self.assertIn(match.method, {"repository", "repository-leaf", "name", "artifact-name", "exact-reference"})

    def test_artifact_name_match_can_be_disabled(self) -> None:
        match = artifact_match_evidence(Artifact(name="app"), "app", allow_name_only=False)
        self.assertTrue(match.matched)  # exact reference remains valid even when loose name matching is disabled
        other = artifact_match_evidence(Artifact(name="app"), "repo/other-app:1", allow_name_only=False)
        self.assertFalse(other.matched)

    def test_load_reachability_rules_none_returns_empty_tuple(self) -> None:
        self.assertEqual(load_reachability_rules(None), ())

    def test_custom_rule_rejects_non_object_rule_item(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(json.dumps({"rules": ["bad"]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_reachability_rules(path)

    def test_parse_source_roots_rejects_empty_artifact_name(self) -> None:
        from reachability_advisor.source import parse_source_roots

        with self.assertRaises(ValueError):
            parse_source_roots(["=src"])

    def test_source_root_that_does_not_exist_is_package_present(self) -> None:
        evidence = analyze_component_source(Component(name="lodash", purl="pkg:npm/lodash@1"), Path("/definitely/missing/path"))
        self.assertEqual(evidence.reachability, Reachability.PACKAGE_PRESENT)

    def test_custom_package_rule_without_vulnerability_id_applies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules.json"
            rules.write_text(json.dumps({"rules": [{"ecosystem": "npm", "package": "demo", "import_patterns": ["require\\(['\\\"]demo['\\\"]\\)"]}]}), encoding="utf-8")
            (root / "index.js").write_text("const demo = require('demo');", encoding="utf-8")
            evidence = analyze_component_source(Component(name="demo", purl="pkg:npm/demo@1"), root, custom_rules=load_reachability_rules(rules))
        self.assertEqual(evidence.reachability, Reachability.IMPORTED)

    def test_sbom_ignores_malformed_property_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.cdx.json"
            path.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "x", "properties": ["bad", {"name": "owner", "value": "team"}]}}, "components": []}), encoding="utf-8")
            sbom = load_sbom(path)
        self.assertEqual(sbom.artifact.properties["owner"], "team")

    def test_sbom_ignores_external_reference_without_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.cdx.json"
            path.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "x", "externalReferences": [{"type": "distribution"}]}}, "components": []}), encoding="utf-8")
            sbom = load_sbom(path)
        self.assertNotIn("external:distribution", sbom.artifact.properties)

    def test_cli_sbom_plan_prints_when_no_output_paths(self) -> None:
        code = main(["sbom-plan", "--artifact", "app", "--ecosystem", "python"])
        self.assertEqual(code, 0)

    def test_cli_artifact_alias_rejects_bad_syntax(self) -> None:
        code = main([
            "scan", "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"), "--vulns", str(ROOT / "samples/vulnerabilities.json"), "--artifact-alias", "bad", "--no-table"
        ])
        self.assertEqual(code, 2)

    def test_cli_artifact_alias_rejects_empty_reference(self) -> None:
        code = main([
            "scan", "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"), "--vulns", str(ROOT / "samples/vulnerabilities.json"), "--artifact-alias", "payments-api=", "--no-table"
        ])
        self.assertEqual(code, 2)
