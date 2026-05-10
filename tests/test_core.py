from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.context import infer_context_from_terraform, load_context_file
from reachability_advisor.models import Confidence, Reachability, Tier
from reachability_advisor.outputs import render_table
from reachability_advisor.purl import ecosystem_from_component, package_match, parse_purl
from reachability_advisor.sbom import load_sbom, load_sboms
from reachability_advisor.scoring import generate_findings, tier_for_score
from reachability_advisor.source import analyze_component_source, parse_source_roots
from reachability_advisor.validators import has_errors, validate_paths
from reachability_advisor.vulnerability import load_vulnerabilities, matching_vulnerabilities

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
        self.assertEqual(len(vulns), 6)
        self.assertTrue(any(v.known_exploited for v in vulns))

    def test_matching_vulnerabilities_filters_version(self) -> None:
        sbom = load_sbom(ROOT / "samples/sboms/payments-api.cdx.json")
        vulns = load_vulnerabilities(ROOT / "samples/vulnerabilities.json")
        matches = matching_vulnerabilities(sbom.components[0], vulns)
        self.assertEqual([m.id for m in matches], ["CVE-2021-44228"])

    def test_osv_style_parser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "osv.json"
            path.write_text(json.dumps({"results": [{"packages": [{"package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.20", "version": "4.17.20"}, "vulnerabilities": [{"id": "GHSA-test", "summary": "sample", "fixed_versions": ["4.17.21"]}]}]}]}), encoding="utf-8")
            vulns = load_vulnerabilities(path)
            self.assertEqual(vulns[0].id, "GHSA-test")
            self.assertEqual(vulns[0].package_name, "lodash")


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
        self.assertIn("Tier", table)
        self.assertIn("payments-api", table)


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
