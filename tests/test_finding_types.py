from __future__ import annotations

import unittest

from reachability_advisor.finding_types import (
    canonical_finding_type,
    count_canonical_types,
    finding_kind,
    is_dependency_finding,
    is_dynamic_finding,
    is_security_finding,
    is_static_finding,
)


class FindingTypeTests(unittest.TestCase):
    def test_unknown_future_types_are_preserved(self) -> None:
        self.assertEqual(canonical_finding_type("custom_finding"), "custom_finding")
        self.assertEqual(finding_kind("custom_finding"), "security_finding")

    def test_counts_are_canonicalized(self) -> None:
        counts = count_canonical_types(["static_code_weakness", "dynamic_runtime_observation"])

        self.assertEqual(counts["static_code_weakness"], 1)
        self.assertEqual(counts["dynamic_runtime_observation"], 1)

    def test_canonical_security_types(self) -> None:
        self.assertTrue(is_static_finding("static_code_weakness"))
        self.assertTrue(is_dynamic_finding("dynamic_runtime_observation"))
        self.assertTrue(is_security_finding("static_code_weakness"))
        self.assertFalse(is_dependency_finding("static_code_weakness"))
        self.assertEqual(finding_kind("static_code_weakness"), "static_code_weakness")


if __name__ == "__main__":
    unittest.main()
