from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.context import infer_context_from_terraform, load_context_file
from reachability_advisor.models import Component, Confidence, Reachability, Tier
from reachability_advisor.outputs import (
    explain_finding,
    render_table,
    write_annotations,
    write_diagnostics,
    write_json_findings,
    write_markdown_report,
    write_sarif,
)
from reachability_advisor.purl import ecosystem_from_component, package_match, parse_purl
from reachability_advisor.sbom import load_sbom, load_sboms
from reachability_advisor.scoring import generate_findings, tier_for_score
from reachability_advisor.source import analyze_component_source, parse_source_roots
from reachability_advisor.validators import has_errors, validate_paths
from reachability_advisor.vulnerability import (
    VulnerabilityError,
    load_vulnerabilities,
    matching_vulnerabilities,
)

ROOT = Path(__file__).resolve().parents[1]


class PurlTests(unittest.TestCase):
    def test_parse_maven_purl(self) -> None:
        purl = parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        self.assertIsNotNone(purl)
        assert purl is not None
        self.assertEqual(purl.ptype, "maven")
        self.assertEqual(purl.namespace, "org.apache.logging.log4j")
        self.assertEqual(purl.name, "log4j-core")
        self.assertEqual(purl.version, "2.14.1")

    def test_parse_npm_scoped_purl(self) -> None:
        purl = parse_purl("pkg:npm/%40scope/name@1.0.0")
        self.assertIsNotNone(purl)
        assert purl is not None
        self.assertEqual(purl.namespace, "@scope")
        self.assertEqual(purl.name, "name")

    def test_invalid_purl_returns_none(self) -> None:
        self.assertIsNone(parse_purl("not-a-purl"))

    def test_package_match_by_name(self) -> None:
        self.assertTrue(package_match("lodash", "pkg:npm/lodash@4.17.20", "lodash", "pkg:npm/lodash"))

    def test_package_mismatch_namespace(self) -> None:
        self.assertFalse(package_match("log4j-core", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "log4j-core", "pkg:maven/com.example/log4j-core"))

    def test_ecosystem_from_component(self) -> None:
        self.assertEqual(ecosystem_from_component("pkg:pypi/requests@2.0.0", "requests"), "pypi")
        self.assertEqual(ecosystem_from_component(None, "@scope/pkg"), "npm")


class SbomAndVulnTests(unittest.TestCase):
    def test_load_payment_sbom(self) -> None:
        sbom = load_sbom(ROOT / "samples/sboms/payments-api.cdx.json")
        self.assertEqual(sbom.artifact.name, "payments-api")
        self.assertEqual(len(sbom.components), 2)
        self.assertEqual(sbom.components[0].scope, "runtime")

    def test_load_multiple_sboms(self) -> None:
        sboms = load_sboms([str(ROOT / "samples/sboms/payments-api.cdx.json"), str(ROOT / "samples/sboms/notifier.cdx.json")])
        self.assertEqual([s.artifact.name for s in sboms], ["payments-api", "notifier"])

    def test_load_vulnerabilities(self) -> None:
        vulns = load_vulnerabilities(ROOT / "samples/vulnerabilities.json")
        self.assertEqual(len(vulns), 7)
        self.assertTrue(any(v.known_exploited for v in vulns))

    def test_matching_vulnerabilities_filters_version(self) -> None:
        sbom = load_sbom(ROOT / "samples/sboms/payments-api.cdx.json")
        vulns = load_vulnerabilities(ROOT / "samples/vulnerabilities.json")
        matches = matching_vulnerabilities(sbom.components[0], vulns)
        self.assertEqual([m.id for m in matches], ["CVE-2021-44228"])

    def test_matching_vulnerabilities_filters_artifact_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scoped.json"
            path.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "id": "CVE-SCOPED",
                                "artifact": "checkout",
                                "package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.20"},
                                "affected_versions": ["4.17.20"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            vulns = load_vulnerabilities(path)
        component = Component(name="lodash", version="4.17.20", purl="pkg:npm/lodash@4.17.20")
        self.assertEqual([match.id for match in matching_vulnerabilities(component, vulns, "checkout")], ["CVE-SCOPED"])
        self.assertEqual(matching_vulnerabilities(component, vulns, "ui"), [])
        self.assertEqual([match.id for match in matching_vulnerabilities(component, vulns)], ["CVE-SCOPED"])

    def test_osv_style_parser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "osv.json"
            path.write_text(json.dumps({"results": [{"packages": [{"package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.20", "version": "4.17.20"}, "vulnerabilities": [{"id": "GHSA-test", "summary": "sample", "fixed_versions": ["4.17.21"]}]}]}]}), encoding="utf-8")
            vulns = load_vulnerabilities(path)
            self.assertEqual(vulns[0].id, "GHSA-test")
            self.assertEqual(vulns[0].package_name, "lodash")

    def test_grype_style_parser_matches_sbom_component(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grype.json"
            path.write_text(
                json.dumps(
                    {
                        "matches": [
                            {
                                "vulnerability": {
                                    "id": "GHSA-35jh-r3h4-6jhm",
                                    "severity": "High",
                                    "description": "Prototype pollution in lodash.",
                                    "urls": ["https://github.com/advisories/GHSA-35jh-r3h4-6jhm"],
                                    "cvss": [{"version": "3.1", "metrics": {"baseScore": 7.4}}],
                                    "epss": [{"cve": "CVE-2021-23337", "epss": 0.22}],
                                    "fix": {"versions": ["4.17.21"], "state": "fixed"},
                                },
                                "artifact": {
                                    "name": "lodash",
                                    "version": "4.17.20",
                                    "type": "npm",
                                    "purl": "pkg:npm/lodash@4.17.20",
                                },
                                "relatedVulnerabilities": [{"id": "CVE-2021-23337"}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            vulns = load_vulnerabilities(path)
            self.assertEqual(len(vulns), 1)
            self.assertEqual(vulns[0].id, "GHSA-35jh-r3h4-6jhm")
            self.assertEqual(vulns[0].aliases, ["CVE-2021-23337"])
            self.assertEqual(vulns[0].package_name, "lodash")
            self.assertEqual(vulns[0].package_purl, "pkg:npm/lodash@4.17.20")
            self.assertEqual(vulns[0].affected_versions, ["4.17.20"])
            self.assertEqual(vulns[0].severity, "high")
            self.assertEqual(vulns[0].cvss, 7.4)
            self.assertEqual(vulns[0].epss, 0.22)
            self.assertEqual(vulns[0].fixed_versions, ["4.17.21"])
            sbom = load_sbom(ROOT / "samples/sboms/notifier.cdx.json")
            matches = matching_vulnerabilities(sbom.components[0], vulns)
            self.assertEqual([match.id for match in matches], ["GHSA-35jh-r3h4-6jhm"])

    def test_grype_parser_preserves_artifact_scope_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grype-scoped.json"
            path.write_text(
                json.dumps(
                    {
                        "matches": [
                            {
                                "reachability_advisor": {"artifact": "checkout"},
                                "vulnerability": {"id": "CVE-SCOPED-GRYPE", "severity": "High"},
                                "artifact": {"name": "request", "version": "2.88.2", "purl": "pkg:npm/request@2.88.2"},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            vulns = load_vulnerabilities(path)
        component = Component(name="request", version="2.88.2", purl="pkg:npm/request@2.88.2")
        self.assertEqual(vulns[0].artifact_name, "checkout")
        self.assertEqual([match.id for match in matching_vulnerabilities(component, vulns, "checkout")], ["CVE-SCOPED-GRYPE"])
        self.assertEqual(matching_vulnerabilities(component, vulns, "orders"), [])


    def test_grype_parser_handles_edge_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grype-edge.json"
            path.write_text(
                json.dumps(
                    {
                        "matches": [
                            "not an object",
                            {"vulnerability": {"id": "SKIP"}, "artifact": {}},
                            {
                                "vulnerability": {
                                    "id": "CVE-EDGE",
                                    "packageName": "left-pad",
                                    "severity": "Medium",
                                    "aliases": ["CVE-EDGE", "CVE-ALIAS", "CVE-ALIAS", " "],
                                    "cvss": [4.0, {"score": "5.5"}, {"metrics": {"baseScore": "6.6"}}],
                                    "epss": {"percentage": "0.31"},
                                    "knownExploited": "known",
                                    "fix": {"version": "1.3.0"},
                                    "references": {"href": "https://example.test/ref"},
                                    "advisories": [{"url": "https://example.test/advisory"}, "https://example.test/advisory"],
                                    "dataSource": "https://example.test/source",
                                },
                                "artifact": {"version": "1.2.0", "purl": "pkg:npm/left-pad@1.2.0"},
                                "relatedVulnerabilities": ["CVE-RELATED", {"value": "GHSA-RELATED"}],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            vulns = load_vulnerabilities(path)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].package_name, "left-pad")
        self.assertEqual(vulns[0].aliases, ["CVE-ALIAS", "CVE-RELATED", "GHSA-RELATED"])
        self.assertEqual(vulns[0].cvss, 6.6)
        self.assertEqual(vulns[0].epss, 0.31)
        self.assertTrue(vulns[0].known_exploited)
        self.assertEqual(vulns[0].fixed_versions, ["1.3.0"])
        self.assertEqual(vulns[0].references, ["https://example.test/ref", "https://example.test/advisory", "https://example.test/source"])

    def test_grype_parser_rejects_non_list_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad-grype.json"
            path.write_text(json.dumps({"matches": {}}), encoding="utf-8")
            with self.assertRaises(VulnerabilityError):
                load_vulnerabilities(path)

    def test_osv_parser_handles_severity_and_bad_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "osv-edge.json"
            path.write_text(
                json.dumps(
                    {
                        "results": [
                            "bad result",
                            {
                                "packages": [
                                    "bad package",
                                    {
                                        "package": {"name": "requests", "purl": "pkg:pypi/requests@2.19.0", "version": "2.19.0"},
                                        "vulnerabilities": [
                                            "bad vuln",
                                            {
                                                "id": "PYSEC-EDGE",
                                                "severity": [{"type": "CVSS_V3", "score": "7.1"}],
                                                "summary": "edge",
                                                "references": ["https://example.test/osv"],
                                            },
                                        ],
                                    },
                                ]
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            vulns = load_vulnerabilities(path)
        self.assertEqual(vulns[0].id, "PYSEC-EDGE")
        self.assertEqual(vulns[0].severity, "cvss_v3")
        self.assertEqual(vulns[0].cvss, 7.1)


class SourceTests(unittest.TestCase):
    def test_parse_source_roots(self) -> None:
        roots = parse_source_roots([f"payments-api={ROOT / 'samples/source/payments-api'}"])
        self.assertIn("payments-api", roots)

    def test_parse_source_roots_rejects_bad_syntax(self) -> None:
        with self.assertRaises(ValueError):
            parse_source_roots(["bad"])

    def test_log4j_attacker_controlled(self) -> None:
        sbom = load_sbom(ROOT / "samples/sboms/payments-api.cdx.json")
        evidence = analyze_component_source(sbom.components[0], ROOT / "samples/source/payments-api")
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertEqual(evidence.confidence, Confidence.MEDIUM)
        self.assertTrue(evidence.locations)

    def test_lodash_attacker_controlled(self) -> None:
        sbom = load_sbom(ROOT / "samples/sboms/notifier.cdx.json")
        evidence = analyze_component_source(sbom.components[0], ROOT / "samples/source/notifier")
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)

    def test_express_attacker_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text(
                "const express = require('express');\n"
                "const app = express();\n"
                "app.get('/items/:id', (req, res) => res.json({ id: req.params.id }));\n",
                encoding="utf-8",
            )
            component = Component(name="express", purl="pkg:npm/express@4.17.1")
            evidence = analyze_component_source(component, root)
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertIn("Express", evidence.reason)

    def test_chainlit_attacker_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "chat.py").write_text(
                "import chainlit as cl\n\n"
                "@cl.on_message\n"
                "async def on_message(message: cl.Message):\n"
                "    await cl.Message(content=message.content).send()\n",
                encoding="utf-8",
            )
            component = Component(name="chainlit", purl="pkg:pypi/chainlit@1.0.200")
            evidence = analyze_component_source(component, root)
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertEqual(evidence.language, "python")

    def test_fastapi_attacker_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api.py").write_text(
                "from fastapi import FastAPI, Request\n"
                "app = FastAPI()\n\n"
                "@app.post('/items')\n"
                "async def create_item(request: Request):\n"
                "    return await request.json()\n",
                encoding="utf-8",
            )
            component = Component(name="fastapi", purl="pkg:pypi/fastapi@0.100.1")
            evidence = analyze_component_source(component, root)
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)

    def test_spring_web_attacker_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Controller.java").write_text(
                "import org.springframework.web.bind.annotation.*;\n"
                "@RestController\n"
                "class ProductsController {\n"
                "  @PostMapping(\"/products\")\n"
                "  String create(@RequestBody String body) { return body; }\n"
                "}\n",
                encoding="utf-8",
            )
            component = Component(name="spring-web", purl="pkg:maven/org.springframework/spring-web@6.0.0")
            evidence = analyze_component_source(component, root)
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)

    def test_nestjs_platform_express_attacker_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "checkout.controller.ts").write_text(
                "import { Body, Controller, Post } from '@nestjs/common';\n"
                "@Controller('checkout')\n"
                "export class CheckoutController {\n"
                "  @Post()\n"
                "  create(@Body() order: unknown) { return order; }\n"
                "}\n",
                encoding="utf-8",
            )
            component = Component(name="@nestjs/platform-express", purl="pkg:npm/%40nestjs/platform-express@11.1.3")
            evidence = analyze_component_source(component, root)
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)

    def test_no_source_root_is_low_confidence(self) -> None:
        sbom = load_sbom(ROOT / "samples/sboms/notifier.cdx.json")
        evidence = analyze_component_source(sbom.components[0], None)
        self.assertEqual(evidence.reachability, Reachability.PACKAGE_PRESENT)
        self.assertEqual(evidence.confidence, Confidence.LOW)

    def test_unknown_source_usage_package_present(self) -> None:
        sbom = load_sbom(ROOT / "samples/sboms/payments-api.cdx.json")
        evidence = analyze_component_source(sbom.components[1], ROOT / "samples/source/payments-api")
        self.assertEqual(evidence.reachability, Reachability.PACKAGE_PRESENT)


class ContextTests(unittest.TestCase):
    def test_load_context_file(self) -> None:
        contexts = load_context_file(ROOT / "samples/context.json")
        self.assertEqual(contexts["payments-api"].exposure, "public")
        self.assertEqual(contexts["payments-api"].confidence, Confidence.HIGH)

    def test_infer_context_from_terraform(self) -> None:
        sboms = load_sboms([str(ROOT / "samples/sboms/payments-api.cdx.json"), str(ROOT / "samples/sboms/notifier.cdx.json")])
        contexts = infer_context_from_terraform(ROOT / "samples/tfplan-lite.json", [sbom.artifact for sbom in sboms])
        self.assertIn("payments-api", contexts)
        self.assertIn("notifier", contexts)
        self.assertEqual(contexts["payments-api"].exposure, "public")
        self.assertEqual(contexts["notifier"].exposure, "public")

    def test_missing_context_returns_empty(self) -> None:
        self.assertEqual(load_context_file(None), {})
        self.assertEqual(infer_context_from_terraform(None, []), {})


class ScoringTests(unittest.TestCase):
    def _findings(self):
        sboms = load_sboms([str(ROOT / "samples/sboms/payments-api.cdx.json"), str(ROOT / "samples/sboms/notifier.cdx.json")])
        vulns = load_vulnerabilities(ROOT / "samples/vulnerabilities.json")
        roots = parse_source_roots([f"payments-api={ROOT / 'samples/source/payments-api'}", f"notifier={ROOT / 'samples/source/notifier'}"])
        contexts = load_context_file(ROOT / "samples/context.json")
        return generate_findings(sboms, vulns, roots, contexts)

    def test_generate_findings_sorted(self) -> None:
        findings = self._findings()
        self.assertGreaterEqual(len(findings), 4)
        self.assertEqual(findings[0].vulnerability.id, "CVE-2021-44228")
        self.assertGreaterEqual(findings[0].score, findings[1].score)

    def test_log4j_is_urgent(self) -> None:
        finding = self._findings()[0]
        self.assertEqual(finding.tier, Tier.URGENT)
        self.assertIn("known exploited", " ".join(finding.rationale))

    def test_test_scope_minimist_demoted(self) -> None:
        findings = self._findings()
        minimist = next(f for f in findings if f.component.name == "minimist")
        self.assertIn(minimist.tier, {Tier.LOW, Tier.INFORMATIONAL, Tier.MEDIUM})
        self.assertLess(minimist.score, 65)

    def test_tier_thresholds(self) -> None:
        self.assertEqual(tier_for_score(90), Tier.URGENT)
        self.assertEqual(tier_for_score(70), Tier.HIGH)
        self.assertEqual(tier_for_score(45), Tier.MEDIUM)
        self.assertEqual(tier_for_score(25), Tier.LOW)
        self.assertEqual(tier_for_score(1), Tier.INFORMATIONAL)

    def test_render_table(self) -> None:
        table = render_table(self._findings())
        self.assertIn("Priority", table)
        self.assertIn("payments-api", table)

    def test_output_writers_and_explain_paths(self) -> None:
        findings = self._findings()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            json_path = root / "findings.json"
            sarif_path = root / "findings.sarif"
            diagnostics_path = root / "diagnostics.json"
            markdown_path = root / "summary.md"
            annotations_path = root / "annotations.txt"
            empty_markdown_path = root / "empty.md"
            empty_annotations_path = root / "empty-annotations.txt"

            write_json_findings(findings, json_path, metadata={"sbom_count": 2})
            data = json.loads(json_path.read_text(encoding="utf-8"))
            explained = explain_finding(data, key=findings[0].key)
            write_sarif(findings, sarif_path)
            write_diagnostics(findings, diagnostics_path)
            write_markdown_report(findings, markdown_path, max_findings=2)
            write_markdown_report([], empty_markdown_path)
            write_annotations(findings, annotations_path, min_tier=Tier.LOW, max_findings=2)
            write_annotations([], empty_annotations_path)

            self.assertIn(findings[0].vulnerability.id, explained)
            self.assertIn("runs", sarif_path.read_text(encoding="utf-8"))
            self.assertIn("diagnostics", diagnostics_path.read_text(encoding="utf-8"))
            self.assertIn("Remediation queue", markdown_path.read_text(encoding="utf-8"))
            self.assertIn("No matching dependency vulnerabilities or imported scanner findings", empty_markdown_path.read_text(encoding="utf-8"))
            self.assertTrue(annotations_path.read_text(encoding="utf-8").startswith("::"))
            self.assertEqual(empty_annotations_path.read_text(encoding="utf-8"), "")


class ValidationTests(unittest.TestCase):
    def test_validate_good_paths(self) -> None:
        issues = validate_paths([str(ROOT / "samples/sboms/payments-api.cdx.json")], str(ROOT / "samples/vulnerabilities.json"), source_roots=[f"payments-api={ROOT / 'samples/source/payments-api'}"])
        self.assertFalse(has_errors(issues))

    def test_validate_bad_path(self) -> None:
        issues = validate_paths(["missing.json"], None)
        self.assertTrue(has_errors(issues))

    def test_validate_bad_source_syntax(self) -> None:
        issues = validate_paths([str(ROOT / "samples/sboms/payments-api.cdx.json")], None, source_roots=["bad"])
        self.assertTrue(has_errors(issues))


if __name__ == "__main__":
    unittest.main()
