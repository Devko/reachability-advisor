"""Regression tests for audited defects in the visual report renderer."""

from __future__ import annotations

import json
import re
import unittest
from typing import Any

from reachability_advisor.attack_path_view import _finding_type_label, build_attack_paths
from reachability_advisor.finding_types import CANONICAL_FINDING_TYPES
from reachability_advisor.models import (
    Artifact,
    Component,
    Confidence,
    ContextEvidence,
    Finding,
    Reachability,
    SourceEvidence,
    Tier,
    VulnerabilityRecord,
)
from reachability_advisor.scenario_view import (
    _append_category_item,
    _new_scenario,
    build_scenario_view,
)
from reachability_advisor.visual import _visual_payload, render_html_report
from reachability_advisor.visual_layout import UniqueIndex
from reachability_advisor.visual_template import HTML_TEMPLATE

REPORT_DATA = re.compile(r'<script id="report-data" type="application/json">(.*?)</script>', re.DOTALL)


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-standard JSON token: {value}")


def strict_report_payload(html: str) -> dict[str, Any]:
    """Parse the embedded payload exactly the way the report's ``JSON.parse`` call does."""

    match = REPORT_DATA.search(html)
    assert match is not None, "report-data script block missing"
    payload = json.loads(match.group(1), parse_constant=_reject_constant)
    assert isinstance(payload, dict)
    return payload


def audit_finding(
    asset: str = "api",
    component: str = "demo",
    vulnerability: str = "CVE-DEMO",
    *,
    cvss: float | None = 8.0,
    epss: float | None = 0.1,
    score: float = 80.0,
    finding_type: str = "dependency_vulnerability",
    weakness: dict[str, Any] | None = None,
    exposure: str = "unknown",
) -> Finding:
    return Finding(
        key=f"{asset}|{component}|1.0|{vulnerability}",
        artifact=Artifact(name=asset, reference=f"repo/{asset}:1.0"),
        component=Component(name=component, version="1.0", purl=f"pkg:npm/{component}@1.0"),
        vulnerability=VulnerabilityRecord(
            id=vulnerability,
            package_name=component,
            severity="high",
            cvss=cvss,
            epss=epss,
            summary="demo vulnerability",
        ),
        source=SourceEvidence(reachability=Reachability.PACKAGE_PRESENT, confidence=Confidence.LOW, reason="test evidence"),
        context=ContextEvidence(
            environment="prod",
            exposure=exposure,
            privilege="limited",
            criticality="high",
            owner="@team",
            confidence=Confidence.LOW,
        ),
        score=score,
        tier=Tier.HIGH,
        confidence=Confidence.LOW,
        rationale=["test rationale"],
        finding_type=finding_type,
        weakness=weakness or {},
    )


def findings_sharing_one_network_path(assets: int, per_asset: int) -> list[Finding]:
    """Build findings with no IaC evidence, so every asset collapses onto one shared path."""

    return [
        audit_finding(asset=f"svc{asset}", component=f"pkg{index:04d}", vulnerability=f"CVE-{asset:03d}-{index:04d}")
        for asset in range(assets)
        for index in range(per_asset)
    ]


class NonFiniteNumberTests(unittest.TestCase):
    """Finding 1: a non-finite number must not turn the whole report into a blank page."""

    def test_embedded_payload_stays_strict_json_for_non_finite_numbers(self) -> None:
        finding = audit_finding(cvss=float("nan"), epss=float("inf"), score=float("-inf"))

        payload = strict_report_payload(render_html_report([finding]))

        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(len(payload["attackPaths"]), 1)
        self.assertEqual(len(payload["vulnerabilities"]), 1)

    def test_non_finite_numbers_render_as_unknown_and_never_as_zero(self) -> None:
        finding = audit_finding(cvss=float("nan"), epss=float("inf"), score=float("nan"))

        payload = strict_report_payload(render_html_report([finding]))

        self.assertIsNone(payload["vulnerabilities"][0]["cvss"])
        self.assertIsNone(payload["findings"][0]["vulnerability"]["cvss"])
        self.assertIsNone(payload["findings"][0]["vulnerability"]["epss"])
        self.assertIsNone(payload["attackPaths"][0]["advisory"]["cvss"])
        self.assertIsNone(payload["attackPaths"][0]["score"])

    def test_a_non_finite_value_smuggled_past_ingest_still_renders_the_report(self) -> None:
        """The renderer must be defensive on its own, not only when ingest sanitized first."""

        graph = {"vulnerabilities": [{"id": "CVE-DEMO", "intelligence": {"cvss": {"value": float("nan"), "source": "local"}}}]}

        payload = strict_report_payload(render_html_report([audit_finding()], evidence_graph=graph))

        self.assertIsNone(payload["evidenceGraph"]["vulnerabilities"][0]["intelligence"]["cvss"]["value"])
        self.assertEqual(len(payload["findings"]), 1)

    def test_finite_numbers_are_left_untouched(self) -> None:
        payload = strict_report_payload(render_html_report([audit_finding(cvss=8.0, epss=0.25, score=80.0)]))

        self.assertEqual(payload["vulnerabilities"][0]["cvss"], 8.0)
        self.assertEqual(payload["attackPaths"][0]["advisory"]["epss"], 0.25)
        self.assertEqual(payload["attackPaths"][0]["score"], 80.0)


class AttackPathPayloadSizeTests(unittest.TestCase):
    """Findings 2 and 3: attack paths must not embed the shared path's fan-out lists."""

    def test_raw_evidence_network_path_drops_the_shared_fan_out_lists(self) -> None:
        payload = _visual_payload(findings_sharing_one_network_path(assets=2, per_asset=3))

        self.assertEqual(len(payload["networkPaths"]), 1, "test needs one shared fallback path")
        for attack_path in payload["attackPaths"]:
            raw_path = attack_path["rawEvidence"]["network_path"]
            self.assertNotIn("findingKeys", raw_path)
            self.assertNotIn("assetIds", raw_path)
            self.assertNotIn("assetNames", raw_path)
            self.assertNotIn("sourcePathIds", raw_path)
            self.assertEqual(raw_path["id"], payload["networkPaths"][0]["id"])
            self.assertEqual(raw_path["label"], payload["networkPaths"][0]["label"])
            self.assertEqual(raw_path["findingCount"], 6)
            self.assertEqual(raw_path["assetCount"], 2)

    def test_raw_evidence_does_not_leak_finding_keys_of_other_assets(self) -> None:
        payload = _visual_payload(findings_sharing_one_network_path(assets=2, per_asset=1))
        own_key = "svc0|pkg0000|1.0|CVE-000-0000"
        other_key = "svc1|pkg0000|1.0|CVE-001-0000"

        attack_path = next(item for item in payload["attackPaths"] if item["findingKey"] == own_key)

        self.assertNotIn(other_key, json.dumps(attack_path))

    def test_attack_path_size_is_independent_of_the_finding_count(self) -> None:
        small = _visual_payload(findings_sharing_one_network_path(assets=1, per_asset=30))
        large = _visual_payload(findings_sharing_one_network_path(assets=1, per_asset=60))

        largest_small = max(len(json.dumps(item)) for item in small["attackPaths"])
        largest_large = max(len(json.dumps(item)) for item in large["attackPaths"])

        self.assertLess(largest_large - largest_small, 200)

    def test_report_size_grows_linearly_with_the_finding_count(self) -> None:
        """Doubling the findings must roughly double the report, not quadruple it."""

        small = len(render_html_report(findings_sharing_one_network_path(assets=4, per_asset=75))) - len(HTML_TEMPLATE)
        large = len(render_html_report(findings_sharing_one_network_path(assets=4, per_asset=150))) - len(HTML_TEMPLATE)

        self.assertLess(large, 2.2 * small, f"report grew {large / small:.2f}x for 2x the findings")

    def test_shared_network_path_still_carries_the_full_fan_out_lists(self) -> None:
        findings = findings_sharing_one_network_path(assets=2, per_asset=2)

        payload = _visual_payload(findings)

        shared = payload["networkPaths"][0]
        self.assertEqual(sorted(shared["findingKeys"]), sorted(finding.key for finding in findings))
        self.assertEqual(sorted(shared["assetIds"]), ["asset:svc0", "asset:svc1"])
        self.assertEqual(sorted(shared["assetNames"]), ["svc0", "svc1"])
        self.assertEqual(shared["assetCount"], 2)

    def test_attack_paths_without_a_network_path_keep_an_empty_raw_evidence_path(self) -> None:
        attack_paths = build_attack_paths([audit_finding()], [], [], [])

        self.assertEqual(attack_paths[0]["rawEvidence"]["network_path"], {})


class ScenarioCategoryDedupTests(unittest.TestCase):
    """Finding 5: category de-duplication must not rescan the items already collected."""

    class _ExplodingItem(dict[str, Any]):
        def get(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("category de-duplication rescanned the existing items")

    def _scenario(self) -> dict[str, Any]:
        return _new_scenario("scenario:test", "asset:api", audit_finding(), None)

    def test_appending_a_category_item_does_not_scan_existing_items(self) -> None:
        scenario = self._scenario()
        category = scenario["categories"]["vulnerabilities"]
        category["items"].append(self._ExplodingItem())
        unique = UniqueIndex()

        _append_category_item(scenario, "vulnerabilities", {"key": "k1", "findingKey": "f1", "label": "one"}, unique)
        _append_category_item(scenario, "vulnerabilities", {"key": "k2", "findingKey": "f2", "label": "two"}, unique)

        self.assertEqual([item.get("key") for item in category["items"][1:]], ["k1", "k2"])

    def test_category_items_and_finding_keys_are_still_de_duplicated(self) -> None:
        scenario = self._scenario()
        category = scenario["categories"]["vulnerabilities"]
        unique = UniqueIndex()
        item = {"key": "k1", "findingKey": "f1", "label": "one"}

        _append_category_item(scenario, "vulnerabilities", item, unique)
        _append_category_item(scenario, "vulnerabilities", dict(item), unique)
        _append_category_item(scenario, "vulnerabilities", {"findingKey": "f1", "label": "two"}, unique)

        self.assertEqual(len(category["items"]), 2)
        self.assertEqual(category["findingKeys"], ["f1"])

    def test_scenario_view_output_stays_json_serializable(self) -> None:
        findings = findings_sharing_one_network_path(assets=2, per_asset=2)
        payload = _visual_payload(findings)

        view = build_scenario_view(findings, payload["networkPaths"], payload["vulnerabilities"], payload["attackPaths"])

        rendered = json.loads(json.dumps(view))
        scenario = rendered["riskScenarios"][0]
        self.assertEqual(scenario["categoryCounts"]["vulnerabilities"], 2)
        self.assertEqual(len(scenario["categoryList"][0]["items"]), 2)
        self.assertEqual(len(scenario["findingKeys"]), 2)


class UniqueIndexTests(unittest.TestCase):
    """The shared de-duplication index behind the linear payload assembly."""

    def test_append_preserves_order_and_skips_empty_values(self) -> None:
        unique = UniqueIndex()
        items: list[Any] = []

        for value in ["b", "a", "b", None, "", [], {}, "c"]:
            unique.append(items, value)

        self.assertEqual(items, ["b", "a", "c"])

    def test_append_de_duplicates_unhashable_values(self) -> None:
        unique = UniqueIndex()
        items: list[Any] = []

        unique.append(items, {"reason": "blocked"})
        unique.append(items, {"reason": "blocked"})
        unique.append(items, {"reason": "other"})

        self.assertEqual(items, [{"reason": "blocked"}, {"reason": "other"}])

    def test_membership_is_tracked_per_list(self) -> None:
        unique = UniqueIndex()
        first: list[Any] = []
        second: list[Any] = []

        unique.append(first, "a")
        unique.append(second, "a")

        self.assertEqual((first, second), (["a"], ["a"]))

    def test_append_keyed_never_drops_an_item_without_a_key(self) -> None:
        unique = UniqueIndex()
        items: list[Any] = []

        unique.append_keyed(items, "", {"label": "one"})
        unique.append_keyed(items, "", {"label": "two"})
        unique.append_keyed(items, "k", {"label": "three"})
        unique.append_keyed(items, "k", {"label": "four"})

        self.assertEqual([item["label"] for item in items], ["one", "two", "three"])


class FindingTypeLabelTests(unittest.TestCase):
    """Finding 4: cloud posture findings must not be labelled a static code weakness."""

    def _template_label_map(self) -> dict[str, str]:
        match = re.search(r"function findingTypeLabel\(value\) \{(.*?)\n\}", HTML_TEMPLATE, re.DOTALL)
        self.assertIsNotNone(match, "findingTypeLabel helper missing from the report template")
        body = match.group(1) if match else ""
        return dict(re.findall(r"(\w+): \"([a-z ]+)\",", body))

    def test_details_panel_labels_every_canonical_finding_type(self) -> None:
        labels = self._template_label_map()

        self.assertEqual(set(labels), CANONICAL_FINDING_TYPES)
        for finding_type, label in labels.items():
            self.assertEqual(label, _finding_type_label(finding_type))
        self.assertEqual(labels["cloud_posture_finding"], "cloud posture finding")

    def test_details_panel_uses_the_label_helper_instead_of_a_two_branch_ternary(self) -> None:
        self.assertIn('"finding type": findingTypeLabel(datum.findingType),', HTML_TEMPLATE)
        self.assertNotIn('isSecurityFinding(datum.findingType) ? "static code weakness"', HTML_TEMPLATE)

    def test_cwe_row_is_omitted_only_for_findings_that_have_no_cwe_concept(self) -> None:
        self.assertIn(
            'CWE: datum.weakness?.cwe || (isStaticFinding(datum.findingType) || isRuntimeFinding(datum.findingType) ? "unknown" : undefined),',
            HTML_TEMPLATE,
        )
        self.assertNotIn('CWE: isSecurityFinding(datum.findingType) ? (datum.weakness?.cwe || "unknown") : undefined', HTML_TEMPLATE)

    def test_a_real_cspm_finding_is_labelled_a_posture_finding_by_the_template(self) -> None:
        finding = audit_finding(
            component="aws_s3_bucket.public",
            vulnerability="CKV_AWS_20",
            finding_type="cloud_posture_finding",
            weakness={"weakness": "S3 bucket allows public reads", "tool": "checkov", "scanner_type": "cspm", "cwe": None},
        )
        payload = strict_report_payload(render_html_report([finding]))
        node = payload["vulnerabilities"][0]

        rendered_label = self._template_label_map()[node["findingType"]]

        self.assertEqual(rendered_label, "cloud posture finding")
        self.assertEqual(payload["attackPaths"][0]["findingTypeLabel"], rendered_label)
        self.assertIsNone(node["weakness"]["cwe"])


if __name__ == "__main__":
    unittest.main()
