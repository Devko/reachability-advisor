from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts import run_complex_app_validation, validate_release

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"


def _load_schema(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


class SchemaContractTests(unittest.TestCase):
    def test_static_repository_documents_match_schemas(self) -> None:
        documents = [
            (ROOT / "samples" / "vulnerabilities.json", "vulnerability-intelligence.schema.json"),
            (ROOT / "samples" / "context.json", "context.schema.json"),
            (ROOT / "configs" / "policy.example.json", "runtime-policy.schema.json"),
        ]
        documents.extend(
            (fixture, "fixture-pack.schema.json")
            for fixture in sorted((ROOT / "fixtures" / "terraform" / "packs").glob("*/fixture.json"))
        )

        for document, schema_name in documents:
            with self.subTest(document=str(document.relative_to(ROOT)), schema=schema_name):
                validate_release.validate_json_file(document, SCHEMAS / schema_name)

    def test_complex_benchmark_schema_accepts_runner_snapshot(self) -> None:
        benchmark = run_complex_app_validation._benchmark_snapshot(
            {
                "schema_version": "1.0",
                "generated_at": "2026-05-11T00:00:00+00:00",
                "corpus": "external_corpus/complex_app_cases.json",
                "case_count": 1,
                "passed_count": 1,
                "failed_count": 0,
                "skipped_count": 0,
                "cases": [
                    {
                        "id": "contract-case",
                        "status": "passed",
                        "metrics": {
                            "sbom_count": 2,
                            "vulnerability_matches": 4,
                            "finding_count": 3,
                            "remediation_count": 2,
                            "services_with_findings": 2,
                            "terraform_resources": 6,
                            "terraform_artifacts_matched": 1,
                            "terraform_artifact_match_coverage": 0.5,
                            "mapping_warnings": 1,
                            "tier_counts": {"medium": 2, "high": 1},
                            "remediation_tier_counts": {"medium": 1, "high": 1},
                            "source_reachability_counts": {"import_observed": 2, "no_rule": 1},
                            "exposure_counts": {"internal": 2, "public": 1},
                            "privilege_counts": {"limited": 1, "sensitive": 1},
                        },
                        "expectations": [{"status": "passed"}, {"status": "failed"}],
                    }
                ],
            }
        )

        validate_release.validate_schema(benchmark, _load_schema("complex-benchmark.schema.json"))
        self.assertEqual(benchmark["aggregate"]["terraform_artifacts_matched"], 1)
        self.assertEqual(benchmark["cases"][0]["expectations_failed"], 1)


if __name__ == "__main__":
    unittest.main()
