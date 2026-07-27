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


class EvidenceStateInvariantTests(unittest.TestCase):
    """The product invariant: absence of evidence may never render as a positive claim.

    The redesign introduced a positive vocabulary ("proven", "confirmed by evidence",
    "N of M links proven") and defaulted every step that was not explicitly flagged to
    it, so a finding with ``exposure="unknown"``, no network path and a populated
    ``unknowns`` list rendered three links as proven in the confirmed hue. Measured in
    the page before the fix: 88 proven / 21 unknown across the 12 default-visible rows;
    after: 73 / 36, and the audited finding's verdict moved from "7 of 10 links proven"
    to "4 of 10".
    """

    def test_a_chain_node_is_only_proven_when_it_names_an_evidence_layer(self) -> None:
        body = re.search(r"function chainNodeState\(node\) \{(.*?)\n\}", HTML_TEMPLATE, re.DOTALL)
        self.assertIsNotNone(body)
        source = body.group(1) if body else ""

        self.assertIn("hasCollectedEvidence(node) ? \"proven\" : \"unknown\"", source)
        # The old default: everything not explicitly flagged claimed proof.
        self.assertNotIn('  return "proven";', source)

    def test_a_chain_edge_is_only_proven_when_it_names_an_evidence_layer(self) -> None:
        body = re.search(r"function chainEdgeState\(edge\) \{(.*?)\n\}", HTML_TEMPLATE, re.DOTALL)
        self.assertIsNotNone(body)
        source = body.group(1) if body else ""

        self.assertIn("hasCollectedEvidence(edge) ? \"proven\" : \"unknown\"", source)
        self.assertNotIn('edge.unknown ? "unknown" : "proven"', source)

    def test_the_context_fallback_layer_is_not_an_evidence_claim(self) -> None:
        # "Context" is what the builder writes when nothing was collected for a step.
        body = re.search(r"function hasCollectedEvidence\(item\) \{(.*?)\n\}", HTML_TEMPLATE, re.DOTALL)
        self.assertIsNotNone(body)
        source = body.group(1) if body else ""

        self.assertIn("CONTEXT_EVIDENCE_LAYER", source)
        self.assertIn('const CONTEXT_EVIDENCE_LAYER = "context";', HTML_TEMPLATE)

    def test_an_edge_name_never_starts_from_a_positive_state(self) -> None:
        body = re.search(r"function edgeMarkState\(edge\) \{(.*?)\n\}", HTML_TEMPLATE, re.DOTALL)
        self.assertIsNotNone(body)
        source = body.group(1) if body else ""

        self.assertTrue(source.rstrip().endswith('return "unknown";'), source)
        self.assertNotIn('let state = "confirmed by evidence";', HTML_TEMPLATE)

    def test_the_state_line_never_falls_back_to_the_word_proven(self) -> None:
        self.assertIn('stateEl.textContent = state === "proven" ? node.evidenceLayer : state;', HTML_TEMPLATE)
        self.assertNotIn('node.evidenceLayer || "proven"', HTML_TEMPLATE)

    def test_only_links_with_a_proven_node_and_edge_count_toward_the_verdict(self) -> None:
        self.assertIn('if (nodeState === "proven" && edgeState === "proven") provenLinks += 1;', HTML_TEMPLATE)

    def test_an_unmapped_artifact_does_not_claim_the_sbom_layer(self) -> None:
        finding = audit_finding(asset="unmapped:posture:aws_s3_bucket_public", finding_type="cloud_posture_finding")
        path = build_attack_paths([finding], [], [], [])[0]
        artifact = next(node for node in path["nodes"] if node["type"] == "artifact")
        edge = next(edge for edge in path["edges"] if edge["type"] == "workload_artifact")

        self.assertEqual(artifact["evidenceLayer"], "Context")
        self.assertEqual(artifact["state"], "unknown")
        self.assertTrue(edge["unknown"])

    def test_a_mapped_artifact_still_claims_the_sbom_layer(self) -> None:
        path = build_attack_paths([audit_finding(asset="payments-api")], [], [], [])[0]
        artifact = next(node for node in path["nodes"] if node["type"] == "artifact")
        edge = next(edge for edge in path["edges"] if edge["type"] == "workload_artifact")

        self.assertEqual(artifact["evidenceLayer"], "SBOM")
        self.assertEqual(artifact["state"], "normal")
        self.assertFalse(edge["unknown"])


class GraphMarkEncodingTests(unittest.TestCase):
    """Hue encodes evidence state. Severity is a width and a labelled chip, never a hue.

    Three audits found this independently. Measured in the page before the fix, light
    theme: Attack Paths 6 of 24 edges on --sev-medium-ink; Architecture 27 of 27 edges
    on --sev-urgent/high/medium-ink; Evidence Paths 24 of 32. Those hues appear nowhere
    in the five-state legend rendered directly above them, and --sev-high-ink vs
    --sev-medium-ink measures CIE dE 2.7 under deuteranopia against a stated bar of 12.
    After: every edge in every view strokes from one of the five legend tokens, and the
    worst hue-bearing pair measures dE 25.7 under deuteranopia.
    """

    CSS = HTML_TEMPLATE.split("<style>", 1)[1].split("</style>", 1)[0]

    def test_no_edge_rule_strokes_from_a_severity_token(self) -> None:
        offenders = [
            line.strip()
            for line in self.CSS.splitlines()
            if line.lstrip().startswith(".edge") and "--sev-" in line
        ]

        self.assertEqual(offenders, [])

    def test_no_graph_node_plate_is_filled_from_a_severity_token(self) -> None:
        offenders = [
            line.strip()
            for line in self.CSS.splitlines()
            if ".attack-graph-circle" in line and "--sev-" in line
        ]

        self.assertEqual(offenders, [])

    def test_every_state_the_legend_names_has_a_stroke_rule(self) -> None:
        for state in ("confirmed", "blocked", "internal", "structural", "unknown"):
            self.assertIn(f".edge.state-{state} {{", self.CSS)

    def test_the_two_neutral_states_are_separated_by_texture_not_by_hue(self) -> None:
        # --mark-unknown is deliberately near-neutral, so its dash is what carries it.
        self.assertIn("stroke-dasharray", css_declaration(self.CSS, ".edge.state-unknown"))
        self.assertNotIn("stroke-dasharray", css_declaration(self.CSS, ".edge.state-structural"))
        self.assertIn("stroke-dasharray", css_declaration(self.CSS, ".edge.state-blocked"))

    def test_the_entry_edge_no_longer_borrows_the_unknown_dash(self) -> None:
        # A known public entry rendered dashed grey, which the legend maps to
        # "unknown, evidence missing".
        self.assertNotIn(".edge.entry { stroke-dasharray", self.CSS)

    def test_the_spoken_states_and_the_legend_describe_the_same_five_things(self) -> None:
        legend = dict(re.findall(r'<i class="swatch swatch-(\w+)" aria-hidden="true"></i>([^<]+)</span>', HTML_TEMPLATE))
        spoken = dict(re.findall(r'(\w+): "([^"]+)"', HTML_TEMPLATE.split("MARK_STATE_TEXT = {", 1)[1].split("};", 1)[0]))

        self.assertEqual(set(legend), set(spoken))
        self.assertEqual(set(legend), {"confirmed", "blocked", "internal", "structural", "unknown"})
        # The caption is a label and the accessible name is a sentence, so they
        # share the word that distinguishes the state rather than the phrasing.
        for state, keyword in (
            ("confirmed", "confirmed"),
            ("blocked", "blocked by a control"),
            ("internal", "internal pivot"),
            ("structural", "structural step"),
            ("unknown", "unknown, evidence missing"),
        ):
            self.assertIn(keyword, legend[state])
            self.assertIn(keyword, spoken[state])


class GraphEdgeAccessibilityTests(unittest.TestCase):
    """Architecture and Evidence Paths drew 27 and 32 edges with no name and no tab stop."""

    def test_every_edge_builder_takes_and_applies_an_accessible_name(self) -> None:
        for builder in ("architectureEdgePath", "edgePath", "fanEdgePath"):
            signature = re.search(rf"function {builder}\(([^)]*)\)", HTML_TEMPLATE)
            self.assertIsNotNone(signature, builder)
            self.assertIn("accessibleName", signature.group(1) if signature else "")

    def test_the_named_edge_helper_makes_the_path_reachable_and_announced(self) -> None:
        body = re.search(r"function namedEdge\((.*?)\n\}", HTML_TEMPLATE, re.DOTALL)
        self.assertIsNotNone(body)
        source = body.group(1) if body else ""

        self.assertIn('path.setAttribute("tabindex", "0")', source)
        self.assertIn('path.setAttribute("aria-label", accessibleName)', source)


class RiskBoardSemanticsTests(unittest.TestCase):
    """Spec section 6 makes this list the graph's text equivalent, so its roles matter.

    Measured before: 0 table/row/columnheader/cell elements, 12 role=button rows each
    containing a focusable link, and both numeric columns announced as bare digits
    inside one 281-character run-on name. After: 1 table, 13 rows, 7 identified column
    headers, 84 described cells, 0 nested interactive controls.
    """

    def test_the_board_is_a_table_with_identified_column_headers(self) -> None:
        self.assertIn('board.setAttribute("role", "table")', HTML_TEMPLATE)
        self.assertIn('cell.setAttribute("role", "columnheader")', HTML_TEMPLATE)
        self.assertIn('cell.id = `riskCol${index}`;', HTML_TEMPLATE)

    def test_every_body_cell_points_at_its_column_header(self) -> None:
        body = re.search(r"function riskCell\(columnIndex, className\) \{(.*?)\n\}", HTML_TEMPLATE, re.DOTALL)
        self.assertIsNotNone(body)
        source = body.group(1) if body else ""

        self.assertIn('cell.setAttribute("role", "cell")', source)
        self.assertIn('cell.setAttribute("aria-describedby", `riskCol${columnIndex}`)', source)

    def test_the_numeric_cells_carry_their_column_name_in_the_accessible_name(self) -> None:
        self.assertIn('visuallyHidden("findings: ")', HTML_TEMPLATE)
        self.assertIn('visuallyHidden("in-use finding', HTML_TEMPLATE)

    def test_the_row_is_not_a_button_wrapping_a_link(self) -> None:
        row = re.search(r"function renderRiskRow\(scenario, layout\) \{(.*?)\n  const severity", HTML_TEMPLATE, re.DOTALL)
        self.assertIsNotNone(row)
        source = row.group(1) if row else ""

        self.assertIn('row.setAttribute("role", "row")', source)
        self.assertNotIn('row.setAttribute("role", "button")', HTML_TEMPLATE)

    def test_the_selected_row_exposes_its_selection(self) -> None:
        self.assertIn('row.setAttribute("aria-current", "true")', HTML_TEMPLATE)
        self.assertIn('.risk-row[aria-current="true"]', HTML_TEMPLATE)

    def test_each_attack_path_link_is_named_for_its_own_scenario(self) -> None:
        self.assertIn('`Open attack path for ${scenario.title || "risk scenario"}`', HTML_TEMPLATE)


class RightRailLayoutTests(unittest.TestCase):
    """#riskListRegion measured 0 visible pixels at 1366x768 and 1280x800, in every view.

    It is the only text equivalent of the SVG in the Architecture and Evidence views,
    and the document skip link points at it. After the fix it measures 140 visible
    pixels at 1366x768 with all 12 items reachable by scrolling.
    """

    CSS = HTML_TEMPLATE.split("<style>", 1)[1].split("</style>", 1)[0]

    def test_neither_content_row_of_the_rail_is_sized_from_the_viewport(self) -> None:
        rows = re.search(r"grid-template-rows: (auto minmax[^;]*);", css_declaration(self.CSS, ".right-panel"))
        self.assertIsNotNone(rows)
        declaration = rows.group(1) if rows else ""

        self.assertNotIn("vh", declaration)
        # Both tracks are proportional with a floor, so neither can starve the other.
        self.assertEqual(declaration.count("minmax"), 2)
        self.assertIn("fr", declaration)

    def test_the_risk_list_can_take_focus_from_the_skip_link(self) -> None:
        self.assertIn('id="riskListRegion" tabindex="-1"', HTML_TEMPLATE)

    def test_the_skip_link_follows_the_list_that_is_actually_rendered(self) -> None:
        # In the Attack view the rail list is display:none and the strip is the list.
        body = re.search(r"function updateSkipLinkTarget\(\) \{(.*?)\n\}", HTML_TEMPLATE, re.DOTALL)
        self.assertIsNotNone(body)
        source = body.group(1) if body else ""

        self.assertIn('link.setAttribute("href", "#attackRiskSidebar")', source)
        self.assertIn('link.setAttribute("href", "#riskListRegion")', source)
        self.assertIn("sidebar.tabIndex = -1", source)


class IdentifierTypographyTests(unittest.TestCase):
    """The mono rule reached 1 of 32 rendered identifiers; it now reaches 40 of 40.

    isIdentifierText() rejects any string containing whitespace, so the rule only ever
    fired when an identifier was the entire string -- which is almost never true in the
    detail rail, the risk-list subtitles or the evidence category lists.
    """

    def test_a_text_run_splitter_exists_and_wraps_tokens_in_mono(self) -> None:
        body = re.search(r"function identifierRuns\(value\) \{(.*?)\n\}", HTML_TEMPLATE, re.DOTALL)
        self.assertIsNotNone(body)
        source = body.group(1) if body else ""

        self.assertIn('span.className = "mono"', source)
        self.assertIn("isIdentifierText(token)", source)

    def test_the_surfaces_the_audit_measured_all_route_through_it(self) -> None:
        for call in (
            "title.appendChild(identifierRuns(item.label",
            "detail.appendChild(identifierRuns([item.detail",
            "button.appendChild(identifierRuns(item.label",
            "meta.appendChild(identifierRuns(",
            "item.appendChild(identifierRuns(value))",
        ):
            self.assertIn(call, HTML_TEMPLATE)

    def test_two_prose_words_joined_by_a_slash_are_not_an_identifier(self) -> None:
        self.assertIn("if (/^[A-Za-z]+\\/[A-Za-z]+$/.test(raw)) return false;", HTML_TEMPLATE)


class LabelTruncationTests(unittest.TestCase):
    """Distinct evidence rendered as byte-identical chips: 6 ambiguous groups, now 3."""

    def test_an_identifier_keeps_its_last_segment_when_it_is_shortened(self) -> None:
        # "aws_ecs_task_definition…" was four different task definitions.
        self.assertIn("const tail = last > 0 ? raw.slice(last) : \"\";", HTML_TEMPLATE)
        self.assertIn('return `${raw.slice(0, budget - tail.length - 1).replace(/[._:-]+$/, "")}…${tail}`;', HTML_TEMPLATE)

    def test_a_prose_string_keeps_a_trailing_identifier(self) -> None:
        self.assertIn("if (words.length > 2 && isIdentifierText(tail) && tail.length + 4 <= budget) {", HTML_TEMPLATE)


class PrintPaginationTests(unittest.TestCase):
    """A width-only print fit let a 1802px shell span 2.5 sheets, sliced through nodes."""

    def test_the_print_fit_is_computed_on_both_axes(self) -> None:
        self.assertIn("const PRINT_CONTENT_HEIGHT_PX = 680;", HTML_TEMPLATE)
        self.assertIn(
            "const scale = Math.min(1, PRINT_CONTENT_PX / width, PRINT_CONTENT_HEIGHT_PX / height);",
            HTML_TEMPLATE,
        )

    def test_the_withdrawal_note_names_the_axis_that_did_not_fit(self) -> None:
        self.assertIn("points tall", HTML_TEMPLATE)
        self.assertIn("points wide", HTML_TEMPLATE)


class ChainOverflowTests(unittest.TestCase):
    """The break scrolled off screen on a resize and the fade cue never updated."""

    def test_the_chain_is_observed_for_resize_alongside_the_graph(self) -> None:
        body = re.search(r"function setupViewportRefit\(\) \{(.*?)\n\}", HTML_TEMPLATE, re.DOTALL)
        self.assertIsNotNone(body)
        source = body.group(1) if body else ""

        self.assertIn("scrollChainToBreak()", source)
        self.assertIn("observer.observe(chainTrack)", source)

    def test_the_track_opens_at_the_entry_link_and_scrolls_only_to_the_break(self) -> None:
        self.assertIn("chainTrack.scrollLeft = 0;\nscrollChainToBreak();", HTML_TEMPLATE.replace("  ", ""))


class ShellMinificationTests(unittest.TestCase):
    """The shell's authoring prose shipped to every reader: ~42 KB per report."""

    def test_the_rendered_shell_drops_comments_without_dropping_declarations(self) -> None:
        from reachability_advisor.visual import _report_shell

        shell = _report_shell()

        self.assertLess(len(shell), len(HTML_TEMPLATE))
        # Nothing load bearing may go with them.
        for token in ("__REPORT_DATA__", ".edge.state-unknown", "function chainNodeState(node)", "</style>"):
            self.assertIn(token, shell)

    def test_no_line_of_the_rendered_shell_is_a_comment(self) -> None:
        from reachability_advisor.visual import _report_shell

        stray = [line for line in _report_shell().splitlines() if line.startswith(("//", "/*"))]

        self.assertEqual(stray, [])

    def test_the_report_still_parses_as_one_html_document_with_its_payload(self) -> None:
        html = render_html_report([audit_finding()])

        self.assertTrue(html.startswith("<!doctype html>"))
        self.assertEqual(html.count('<script id="report-data"'), 1)
        self.assertIn("</html>", html)
        strict_report_payload(html)


def css_declaration(css: str, selector: str) -> str:
    match = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css)
    return match.group(1) if match else ""


if __name__ == "__main__":
    unittest.main()
