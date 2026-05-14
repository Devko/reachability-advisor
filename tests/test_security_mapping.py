from __future__ import annotations

import unittest

from reachability_advisor.models import Artifact, Confidence, ContextEvidence
from reachability_advisor.security_evidence_model import SecurityEvidenceRecord
from reachability_advisor.security_mapping import (
    map_security_evidence_record,
    unmapped_runtime_artifact,
)


class SecurityEvidenceMappingTests(unittest.TestCase):
    def test_dast_url_maps_to_context_host_with_high_confidence(self) -> None:
        artifact = Artifact(name="web-api")
        context = ContextEvidence(
            network_paths=[
                {
                    "source": "kubernetes",
                    "entry_kind": "ingress",
                    "steps": ["shop.example.test", "/search"],
                }
            ]
        )
        record = SecurityEvidenceRecord(scanner_type="dast", tool="zap", rule_id="xss", weakness="xss", url="https://shop.example.test/search?q=x")

        decision = map_security_evidence_record(record, [artifact], {"web-api": context})

        self.assertEqual(decision.artifact, artifact)
        self.assertEqual(decision.confidence, Confidence.HIGH)
        self.assertEqual(decision.reason, "DAST URL matched deployment context host or path")

    def test_one_sbom_fallback_is_low_confidence(self) -> None:
        artifact = Artifact(name="api")
        record = SecurityEvidenceRecord(scanner_type="dast", tool="zap", rule_id="xss", weakness="xss", url="https://unknown.example.test/search")

        decision = map_security_evidence_record(record, [artifact], {})

        self.assertEqual(decision.artifact, artifact)
        self.assertEqual(decision.confidence, Confidence.LOW)
        self.assertEqual(decision.reason, "weak one-SBOM fallback")

    def test_unmapped_runtime_artifact_is_explicit(self) -> None:
        record = SecurityEvidenceRecord(scanner_type="dast", tool="zap", rule_id="xss", weakness="xss", url="https://unknown.example.test/search")

        artifact = unmapped_runtime_artifact(record)

        self.assertEqual(artifact.name, "unmapped:unknown_example_test")
        self.assertEqual(artifact.properties["mapping:confidence"], "unknown")


if __name__ == "__main__":
    unittest.main()
