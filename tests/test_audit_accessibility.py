"""Regression tests for the report's accessibility, print and responsive contract.

Every assertion here corresponds to a defect measured in the rendered page, so the
comments name the measurement rather than restating the rule. These are template
assertions: they cannot prove the rendered contrast, but they do stop the specific
declaration that caused each failure from coming back unnoticed.
"""

from __future__ import annotations

import re
import unittest

from reachability_advisor.visual_template import HTML_TEMPLATE

# The style block, isolated so markup and script text cannot satisfy a CSS assertion.
STYLE = re.search(r"<style>(.*?)</style>", HTML_TEMPLATE, re.DOTALL)
CSS = STYLE.group(1) if STYLE else ""
BODY = HTML_TEMPLATE.split("</style>", 1)[1] if "</style>" in HTML_TEMPLATE else HTML_TEMPLATE
MARKUP = BODY.split('<script id="report-data"', 1)[0]


def css_block(selector: str) -> str:
    """Return the declaration block for an exact top-level selector."""

    match = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", CSS)
    return match.group(1) if match else ""


class FocusVisibleTests(unittest.TestCase):
    """46 buttons shipped with no focus style at all."""

    def test_a_global_focus_visible_ring_exists_at_the_specified_width_and_offset(self) -> None:
        block = css_block(":focus-visible")

        self.assertIn("outline: 2px solid var(--focus)", block)
        self.assertIn("outline-offset: 2px", block)

    def test_nothing_removes_an_outline_without_replacing_it(self) -> None:
        # `outline: none` / `outline: 0` anywhere would silently reopen the hole.
        stripped = re.findall(r"outline:\s*(?:none|0)\b", CSS)

        self.assertEqual(stripped, [])


class AccessibleNameTests(unittest.TestCase):
    """Seven inputs and selects shipped with no accessible name."""

    def test_every_input_and_select_in_the_shell_has_a_name(self) -> None:
        controls = re.findall(r"<(?:input|select)\b[^>]*>", MARKUP)
        self.assertGreaterEqual(len(controls), 7, "control set shrank; update this test deliberately")

        unnamed = [
            control
            for control in controls
            # A checkbox is named by the <label class="check"> that wraps it.
            if "aria-label=" not in control and 'type="checkbox"' not in control
        ]

        self.assertEqual(unnamed, [])

    def test_a_placeholder_is_never_the_only_name(self) -> None:
        for control in re.findall(r"<input\b[^>]*placeholder=[^>]*>", MARKUP):
            self.assertIn("aria-label=", control)


class GraphSemanticsTests(unittest.TestCase):
    """role="img" pruned 52 focusable descendants out of the accessibility tree."""

    def test_the_graph_is_a_group_so_its_nodes_and_edges_stay_in_the_tree(self) -> None:
        graph = re.search(r'<div id="graph"[^>]*>', MARKUP)
        self.assertIsNotNone(graph)
        attributes = graph.group(0) if graph else ""

        self.assertIn('role="group"', attributes)
        self.assertNotIn('role="img"', attributes)
        self.assertIn("aria-label=", attributes)
        self.assertIn('aria-describedby="graphAlt"', attributes)

    def test_the_graph_description_points_at_the_text_equivalent(self) -> None:
        description = re.search(r'<p id="graphAlt"[^>]*>(.*?)</p>', MARKUP, re.DOTALL)
        self.assertIsNotNone(description)
        text = (description.group(1) if description else "").lower()

        self.assertIn("risk list", text)
        self.assertIn("skip link", text)

    def test_the_skip_link_reaches_the_region_the_description_promises(self) -> None:
        self.assertIn('href="#riskListRegion"', MARKUP)
        self.assertIn('id="riskListRegion"', MARKUP)

    def test_every_focusable_edge_is_given_a_name_carrying_its_evidence_state(self) -> None:
        # The edge is a tab stop; an unnamed one says nothing about a broken chain.
        self.assertIn('path.setAttribute("aria-label", edgeAccessibleName(edgeDatum));', HTML_TEMPLATE)
        for state in ("unknown, evidence missing", "blocked by a control", "confirmed by evidence"):
            self.assertIn(state, HTML_TEMPLATE)


class ReducedMotionTests(unittest.TestCase):
    def test_transitions_and_animations_are_disabled_on_request(self) -> None:
        block = re.search(
            r"@media \(prefers-reduced-motion: reduce\) \{(.*?)\n\}\n", CSS, re.DOTALL
        )
        self.assertIsNotNone(block)
        text = block.group(1) if block else ""

        for declaration in ("animation-duration", "transition-duration", "animation-iteration-count"):
            self.assertIn(declaration, text)
            self.assertIn("!important", text)


class ContrastRegressionTests(unittest.TestCase):
    """Each of these declarations measured below its WCAG floor in the page."""

    def test_the_entry_card_body_subtitle_is_not_painted_on_the_wrong_plate(self) -> None:
        # Unscoped, this rule put --surface-sunken text on --surface: 1.12:1 light,
        # 1.03:1 dark, i.e. invisible body text.
        self.assertIn(".entry-card .top .sub { color: var(--surface-sunken); }", CSS)
        self.assertNotIn(".entry-card .sub { color: var(--surface-sunken); }", CSS)

    def test_dimmed_graph_nodes_do_not_fade_their_own_text(self) -> None:
        # A blanket opacity of .38 measured 2.46:1 on the label and 1.78:1 on the
        # subtitle. Moving the opacity onto the circle was not enough: the circle
        # holds a 13px/700 identifier glyph, so compositing plate and glyph
        # together dropped the glyph to 2.77-3.11:1 against its own plate in the
        # default on-load state. Nothing that contains text may carry an opacity.
        self.assertNotIn(".attack-graph-node.dimmed { opacity:", CSS)
        circle = css_block(".attack-graph-node.dimmed .attack-graph-circle")
        self.assertNotIn("opacity", circle)
        # It recedes by losing its saturation and its elevation instead.
        self.assertIn("saturate(", circle)
        self.assertIn("box-shadow: none", circle)
        self.assertIn("var(--ink-muted)", css_block(".attack-graph-node.dimmed .attack-graph-label"))

    def test_dimmed_edges_recede_by_width_rather_than_by_disappearing(self) -> None:
        for selector in (".edge.attack-graph-edge.dimmed", ".edge.attack-path.dimmed"):
            block = css_block(selector)
            opacity = re.search(r"opacity:\s*\.(\d+)", block)
            self.assertIsNotNone(opacity, f"{selector} lost its opacity declaration")
            # .75 is the point where the weakest mark hue still measures 3.13:1.
            self.assertGreaterEqual(int((opacity.group(1) if opacity else "0").ljust(2, "0")), 75)

    def test_an_unknown_edge_is_never_quieter_than_a_proven_one(self) -> None:
        # The product may not let absent evidence read as absent risk. The rule
        # moved from `.edge.attack-graph-edge.unknown, .edge.attack-path.unknown`
        # to the shared `.edge.state-unknown` when every view's edges were
        # repainted by evidence state; the contract it asserts is unchanged.
        unknown = css_block(".edge.state-unknown")
        self.assertIn("stroke-dasharray", unknown)
        opacity = re.search(r"opacity:\s*\.(\d+)", unknown)
        self.assertIsNotNone(opacity)
        self.assertGreaterEqual(int((opacity.group(1) if opacity else "0").ljust(2, "0")), 85)


class ResponsiveTests(unittest.TestCase):
    """The evidence view scrolled the page sideways at 390 and 360."""

    def test_the_detail_rail_caps_its_column_instead_of_taking_min_content(self) -> None:
        # An implicit auto track took the 413px min-content of a file-path list.
        self.assertIn("grid-template-columns: minmax(0, 1fr);", css_block(".right-panel"))

    def test_list_items_may_break_a_path_that_cannot_fit(self) -> None:
        self.assertIn("overflow-wrap: break-word", css_block("li"))

    def test_no_rule_reintroduces_mid_word_wrapping_on_a_graph_label(self) -> None:
        # Stage 2's bug: `anywhere` split identifiers mid-token.
        for selector in (".attack-graph-label", ".attack-graph-sub", ".chain-name"):
            self.assertNotIn("anywhere", css_block(selector))


class PrintTests(unittest.TestCase):
    """The printed graph was cropped to a 640px frame with no sign of the rest."""

    def test_print_forces_the_light_canvas_and_drops_elevation(self) -> None:
        self.assertIn("--canvas: #FFFFFF", CSS)
        self.assertIn("--shadow-1: none", CSS)

    def test_print_hides_the_filter_bar_and_the_theme_toggle(self) -> None:
        self.assertIn(".controls, .header-actions, .legend, .skip-link { display: none !important; }", CSS)

    def test_print_stacks_the_panes(self) -> None:
        self.assertIn(".layout, .layout.with-left-sidebar, .pane-canvas { display: block !important; }", CSS)

    def test_the_printed_graph_is_scaled_to_the_sheet_rather_than_clipped(self) -> None:
        self.assertIn("zoom: var(--print-scale, 1)", CSS)
        self.assertIn("#graph { position: relative; height: auto; overflow: visible; }", CSS)
        # A fixed frame height is what cropped it.
        self.assertNotIn("#graph { position: relative; height: 640px; }", CSS)

    def test_a_graph_too_wide_to_print_legibly_is_named_rather_than_shrunk(self) -> None:
        self.assertIn('graphShell.dataset.printFit = fits ? "whole" : "oversized";', HTML_TEMPLATE)
        self.assertIn('.graph-shell[data-print-fit="oversized"] #graph { display: none; }', CSS)
        self.assertIn('id="printGraphNote"', MARKUP)

    def test_the_legibility_floor_for_print_is_derived_not_guessed(self) -> None:
        self.assertIn("const PRINT_MIN_TEXT_PX = 9;", HTML_TEMPLATE)
        self.assertIn(
            "const PRINT_MIN_SCALE = PRINT_MIN_TEXT_PX / GRAPH_BASE_TEXT_PX;", HTML_TEMPLATE
        )

    def test_a_portrait_sheet_withdraws_the_diagram_instead_of_cropping_it(self) -> None:
        self.assertIn("@media print and (max-width: 860px)", CSS)
        self.assertIn(".graph-shell .print-portrait-note { display: block; }", CSS)

    def test_the_notes_never_appear_on_screen(self) -> None:
        self.assertIn(".print-graph-note, .print-portrait-note { display: none; }", CSS)


class GraphFocusTests(unittest.TestCase):
    """Focus scrolled the pan container 52px and could land off screen."""

    def test_focus_inside_the_graph_pans_the_surface_and_zeroes_the_stray_scroll(self) -> None:
        self.assertIn('graph.addEventListener("focusin", event => panFocusIntoView(event.target));', HTML_TEMPLATE)
        self.assertIn('graph.addEventListener("scroll", resetGraphScroll);', HTML_TEMPLATE)
        self.assertIn("function resetGraphScroll()", HTML_TEMPLATE)
        self.assertIn("function panFocusIntoView(target)", HTML_TEMPLATE)


class SelfContainedTests(unittest.TestCase):
    """The report must never reach the network, whatever else changes."""

    def test_no_remote_asset_or_request_is_referenced(self) -> None:
        for token in ("http://", "https://", "//cdn", "fetch(", "XMLHttpRequest", "@import"):
            if token in ("http://", "https://"):
                # The SVG namespace is a declaration, not a fetch.
                remotes = [
                    ref
                    for ref in re.findall(re.escape(token) + r"[^\"'\s)]*", HTML_TEMPLATE)
                    if not ref.startswith("http://www.w3.org/")
                ]
                self.assertEqual(remotes, [], f"remote reference via {token}")
            else:
                self.assertNotIn(token, HTML_TEMPLATE)


if __name__ == "__main__":
    unittest.main()
