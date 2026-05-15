from __future__ import annotations

import unittest
from pathlib import Path

from reachability_advisor.security_evidence import load_security_evidence
from reachability_advisor.vulnerability import load_vulnerabilities

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "scanner_adapters"


class ScannerAdapterVariantTests(unittest.TestCase):
    def test_vulnerability_adapters_keep_good_records_from_partial_reports(self) -> None:
        grype = load_vulnerabilities(FIXTURES / "grype-partial.json")
        osv = load_vulnerabilities(FIXTURES / "osv-partial.json")

        self.assertEqual(len(grype), 1)
        self.assertEqual(grype[0].id, "CVE-2021-44228")
        self.assertEqual(grype[0].package_name, "log4j-core")
        self.assertEqual(grype[0].cvss, 10.0)
        self.assertEqual(grype[0].fixed_versions, ["2.17.1"])

        self.assertEqual(len(osv), 1)
        self.assertEqual(osv[0].id, "GHSA-35jh-r3h4-6jhm")
        self.assertEqual(osv[0].package_name, "lodash")
        self.assertEqual(osv[0].severity, "high")
        self.assertEqual(osv[0].cvss, 7.2)
        self.assertEqual(osv[0].fixed_versions, ["4.17.21"])

    def test_security_adapters_tolerate_real_world_partial_reports(self) -> None:
        records = load_security_evidence(
            [
                FIXTURES / "semgrep-partial.json",
                FIXTURES / "codeql-partial.sarif",
                FIXTURES / "zap-partial.json",
                FIXTURES / "nuclei-partial.jsonl",
                FIXTURES / "checkov-partial.json",
                FIXTURES / "trivy-partial.json",
                FIXTURES / "kics-partial.json",
                FIXTURES / "tfsec-partial.json",
            ],
        )

        self.assertEqual(len(records), 8)
        by_tool = {record.tool: record for record in records}

        self.assertEqual(by_tool["semgrep"].source.line, 1)
        self.assertEqual(by_tool["semgrep"].source.column, 1)
        self.assertEqual(by_tool["semgrep"].cwe, "CWE-79")

        self.assertEqual(by_tool["CodeQL"].message, "String SARIF messages appear in some tools")
        self.assertEqual(by_tool["CodeQL"].source.line, 1)
        self.assertEqual(by_tool["CodeQL"].dataflow, "SARIF codeFlows present")

        self.assertEqual(by_tool["zap"].rule_id, "40012")
        self.assertEqual(by_tool["zap"].cwe, "CWE-79")
        self.assertEqual(by_tool["zap"].parameter, "q")

        self.assertEqual(by_tool["nuclei"].parameter, "q=test")
        self.assertIn("https://nuclei.projectdiscovery.io", by_tool["nuclei"].references)

        self.assertEqual(by_tool["checkov"].rule_id, "1001")
        self.assertEqual(by_tool["checkov"].source.line, 7)

        self.assertEqual(by_tool["trivy-config"].source.line, 9)
        self.assertEqual(by_tool["trivy-config"].resource_id, "Deployment/web")

        self.assertEqual(by_tool["kics"].rule_id, "991")
        self.assertEqual(by_tool["kics"].source.line, 1)

        self.assertEqual(by_tool["tfsec"].source.line, 1)
        self.assertIn("https://aquasecurity.github.io/tfsec/", by_tool["tfsec"].references)


if __name__ == "__main__":
    unittest.main()
