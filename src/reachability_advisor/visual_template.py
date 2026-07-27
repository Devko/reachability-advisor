"""Static HTML shell for the interactive report renderer."""

from __future__ import annotations

HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Reachability Advisor Evidence Report</title>
<script>
/* Runs before the first paint so a pinned theme never flashes the other one.
   Storage is denied on some file:// origins; auto theme still applies there. */
(function () {
  try {
    var mode = window.localStorage.getItem("ra-theme");
    if (mode === "light" || mode === "dark") {
      document.documentElement.setAttribute("data-theme", mode);
    }
  } catch (error) {}
})();
</script>
<style>
/* === 1. Tokens ===========================================================
   Light is the base. Dark applies via prefers-color-scheme unless the reader
   pinned light, and via [data-theme="dark"] when the reader pinned dark, so an
   explicit choice wins in both directions. The two dark blocks are deliberate
   duplicates: a media query cannot join a selector list. Keep them in sync. */
:root {
  color-scheme: light;
  /* surfaces + ink */
  --surface: #FFFFFF; --surface-raised: #F7F9FB; --surface-sunken: #EFF3F7;
  --border: #DCE3EC; --border-strong: #C3CDDB;
  --ink: #10151C; --ink-muted: #55607A;
  --ink-faint: #7C8699; /* 3.7:1 on --surface: large text and non-text marks only */
  --focus: #1B6FA8;
  /* graph marks: hue = evidence state, texture = confidence */
  --mark-confirmed: #B42318; --mark-blocked: #1B6FA8; --mark-internal: #6941C6; --mark-unknown: #5F6B7A;
  /* The soft tints are the lightest step of each mark hue. Three of them land on
     the same value as a severity tint because both are the 50-step of the same
     hue family; that collision is in the tint, never in the ink or the mark. */
  --mark-confirmed-soft: #FEF3F2; --mark-blocked-soft: #EFF8FF; --mark-internal-soft: #F4F0FE; --mark-unknown-soft: #F2F4F7;
  --on-mark: #FFFFFF;
  /* severity: tint + ink + the severity word, never colour alone */
  --sev-urgent-bg: #FEF3F2; --sev-urgent-ink: #912018; --sev-urgent-border: #FECDCA;
  --sev-high-bg: #FFF4ED; --sev-high-ink: #9C2A10; --sev-high-border: #FDDCAB;
  --sev-medium-bg: #FFFAEB; --sev-medium-ink: #7A5A0A; --sev-medium-border: #FEDF89;
  --sev-low-bg: #EFF8FF; --sev-low-ink: #16537E; --sev-low-border: #B2DDFF;
  --sev-info-bg: #F2F4F7; --sev-info-ink: #40495A; --sev-info-border: #D0D5DD;
  /* canvas + elevation: a border and a hairline shadow, never a heavy drop */
  --canvas: #F7F9FB; --canvas-line: rgba(99, 116, 139, .13); --overlay: rgba(255, 255, 255, .88);
  --shadow-1: 0 1px 2px rgba(16, 21, 28, .06); --shadow-2: 0 2px 6px rgba(16, 21, 28, .09);
  /* type */
  --font-ui: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --text-2xs: .6875rem; --text-xs: .75rem; --text-sm: .8125rem; --text-base: .875rem;
  --text-lg: 1.25rem; --text-xl: 1.75rem;
  --tracking-heading: -0.011em;
  /* space, radius, layout */
  --s1: 4px; --s2: 8px; --s3: 12px; --s4: 16px; --s5: 24px; --s6: 32px; --s7: 48px;
  --r-sm: 4px; --r-md: 6px; --r-lg: 10px; --r-full: 999px;
  --list-w: 360px; --rail-w: 400px;
}
/* Both dark blocks are scoped to `screen`, so print falls back to the base
   light palette without restating a single token. */
@media screen and (prefers-color-scheme: dark) {
  /* dark 1 of 2: the reader has not pinned light */
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --surface: #0E1116; --surface-raised: #161B23; --surface-sunken: #0A0D11;
    --border: #262E3A; --border-strong: #38424F;
    --ink: #E6EAF2; --ink-muted: #98A2B3; --ink-faint: #6C7789;
    --focus: #7DD3FC;
    --mark-confirmed: #F87171; --mark-blocked: #7DD3FC; --mark-internal: #A855F7; --mark-unknown: #98A2B3;
    --mark-confirmed-soft: #2B1614; --mark-blocked-soft: #0F1E2B; --mark-internal-soft: #1E1630; --mark-unknown-soft: #1A1F28;
    --on-mark: #0E1116;
    --sev-urgent-bg: #2B1614; --sev-urgent-ink: #FDA29B; --sev-urgent-border: #5C2A24;
    --sev-high-bg: #2A1A12; --sev-high-ink: #FDBA8C; --sev-high-border: #5A3320;
    --sev-medium-bg: #241D0E; --sev-medium-ink: #F5CE7A; --sev-medium-border: #4C3D19;
    --sev-low-bg: #0F1E2B; --sev-low-ink: #9CD5FA; --sev-low-border: #22415A;
    --sev-info-bg: #1A1F28; --sev-info-ink: #BFC7D4; --sev-info-border: #333C49;
    --canvas: #0A0D11; --canvas-line: rgba(148, 163, 184, .10); --overlay: rgba(22, 27, 35, .88);
    --shadow-1: 0 1px 2px rgba(0, 0, 0, .4); --shadow-2: 0 2px 6px rgba(0, 0, 0, .5);
  }
}
@media screen {
/* dark 2 of 2: the reader pinned dark */
:root[data-theme="dark"] {
  color-scheme: dark;
  --surface: #0E1116; --surface-raised: #161B23; --surface-sunken: #0A0D11;
  --border: #262E3A; --border-strong: #38424F;
  --ink: #E6EAF2; --ink-muted: #98A2B3; --ink-faint: #6C7789;
  --focus: #7DD3FC;
  --mark-confirmed: #F87171; --mark-blocked: #7DD3FC; --mark-internal: #A855F7; --mark-unknown: #98A2B3;
  --mark-confirmed-soft: #2B1614; --mark-blocked-soft: #0F1E2B; --mark-internal-soft: #1E1630; --mark-unknown-soft: #1A1F28;
  --on-mark: #0E1116;
  --sev-urgent-bg: #2B1614; --sev-urgent-ink: #FDA29B; --sev-urgent-border: #5C2A24;
  --sev-high-bg: #2A1A12; --sev-high-ink: #FDBA8C; --sev-high-border: #5A3320;
  --sev-medium-bg: #241D0E; --sev-medium-ink: #F5CE7A; --sev-medium-border: #4C3D19;
  --sev-low-bg: #0F1E2B; --sev-low-ink: #9CD5FA; --sev-low-border: #22415A;
  --sev-info-bg: #1A1F28; --sev-info-ink: #BFC7D4; --sev-info-border: #333C49;
  --canvas: #0A0D11; --canvas-line: rgba(148, 163, 184, .10); --overlay: rgba(22, 27, 35, .88);
  --shadow-1: 0 1px 2px rgba(0, 0, 0, .4); --shadow-2: 0 2px 6px rgba(0, 0, 0, .5);
}
}

/* === 2. Base ============================================================= */
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; min-height: 100vh; display: flex; flex-direction: column;
  font-family: var(--font-ui); font-size: var(--text-base); font-weight: 400; line-height: 1.5;
  color: var(--ink); background: var(--surface-sunken); text-rendering: optimizeLegibility;
}
h1, h2, h3 { margin: 0; font-weight: 600; line-height: 1.25; letter-spacing: var(--tracking-heading); }
p { margin: 0; }
/* Every machine identifier is mono: CVE ids, purls, resource addresses, paths.
   Mono runs large, so identifiers are set at .9375em of their context. */
.mono, code, kbd, pre { font-family: var(--font-mono); font-weight: 500; font-size: .9375em; letter-spacing: 0; }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
.visually-hidden {
  position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0;
  overflow: hidden; clip: rect(0 0 0 0); clip-path: inset(50%); white-space: nowrap; border: 0;
}
.skip-link {
  position: absolute; left: var(--s3); top: -60px; z-index: 20;
  padding: var(--s2) var(--s3); border: 1px solid var(--border-strong); border-radius: var(--r-md);
  background: var(--surface); color: var(--ink);
  font-size: var(--text-sm); font-weight: 600; text-decoration: none; transition: top .12s ease;
}
.skip-link:focus { top: var(--s3); }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: .001ms !important; animation-delay: 0ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: .001ms !important; scroll-behavior: auto !important;
  }
}

/* === 3. Controls =========================================================
   Resting borders are --ink-faint, not --border-strong. A control whose fill
   matches the page has nothing but its border to identify it, and
   --border-strong measured 1.61:1 on --surface against the 3:1 floor for a
   non-text mark; --ink-faint is 3.67:1 in light and 4.18:1 in dark. */
.btn {
  display: inline-flex; align-items: center; gap: var(--s2); min-height: 32px; padding: 0 var(--s3);
  border: 1px solid var(--ink-faint); border-radius: var(--r-md);
  background: var(--surface); color: var(--ink);
  font: inherit; font-size: var(--text-sm); font-weight: 600; white-space: nowrap; cursor: pointer;
  transition: background-color .12s ease, border-color .12s ease;
}
.btn:hover { background: var(--surface-sunken); }
.btn-quiet {
  display: inline-flex; align-items: center; min-height: 28px; padding: 0 var(--s2);
  border: 1px solid transparent; border-radius: var(--r-sm); background: transparent; color: var(--ink-muted);
  font: inherit; font-size: var(--text-xs); font-weight: 500; white-space: nowrap; cursor: pointer;
}
.btn-quiet:hover { border-color: var(--border); background: var(--surface-sunken); color: var(--ink); }
input[type="search"], input[type="text"], select {
  min-height: 32px; min-width: 0; padding: 0 var(--s2);
  border: 1px solid var(--ink-faint); border-radius: var(--r-md);
  background: var(--surface); color: var(--ink); font: inherit; font-size: var(--text-sm);
}
input::placeholder { color: var(--ink-muted); }
label.check {
  display: inline-flex; align-items: center; gap: var(--s2);
  color: var(--ink-muted); font-size: var(--text-xs); white-space: nowrap; cursor: pointer;
}
label.check input { width: 15px; height: 15px; margin: 0; accent-color: var(--focus); }

/* === 4. Shell: header, summary, controls ================================= */
.app-header {
  flex: 0 0 auto; display: flex; align-items: flex-start; justify-content: space-between;
  flex-wrap: wrap; gap: var(--s3) var(--s5); padding: var(--s4) var(--s5) var(--s3);
  background: var(--surface); border-bottom: 1px solid var(--border);
}
.app-title { font-size: var(--text-xl); }
.provenance {
  margin-top: var(--s1); color: var(--ink-muted);
  font-family: var(--font-mono); font-size: var(--text-xs); overflow-wrap: anywhere;
}
.header-actions { display: flex; align-items: center; flex-wrap: wrap; gap: var(--s2); }
.theme-glyph {
  width: 12px; height: 12px; border: 1px solid var(--ink-muted); border-radius: var(--r-full);
  background: linear-gradient(to right, var(--ink) 0 50%, transparent 50% 100%);
}
#themeToggle[data-theme="light"] .theme-glyph { background: transparent; }
#themeToggle[data-theme="dark"] .theme-glyph { background: var(--ink); }
/* The summary is severity weighted. A non-zero urgent or high count is the
   number a reader acts on, so it is a tinted plate at --text-xl. Scope counts
   are plain. Coverage counts are recessive, and a coverage zero is marked as
   "not scanned" rather than left to read as an all-clear. */
.summary {
  flex: 0 0 auto; display: flex; flex-wrap: wrap; align-items: stretch; gap: var(--s2) var(--s4);
  padding: var(--s3) var(--s5); background: var(--surface); border-bottom: 1px solid var(--border);
}
.stat-group { display: flex; flex-wrap: wrap; align-items: stretch; gap: var(--s2) var(--s4); }
.stat-group + .stat-group { padding-left: var(--s4); border-left: 1px solid var(--border); }
.stat { display: inline-flex; align-items: baseline; gap: var(--s2); }
.stat-value {
  font-family: var(--font-mono); font-variant-numeric: tabular-nums;
  font-size: var(--text-base); font-weight: 600; color: var(--ink);
}
.stat-label { font-size: var(--text-xs); color: var(--ink-muted); }
.stat.is-prominent {
  align-items: center; gap: var(--s2); padding: var(--s1) var(--s3);
  border: 1px solid var(--sev-info-border); border-radius: var(--r-md); background: var(--sev-info-bg);
}
.stat.is-prominent .stat-value { font-size: var(--text-xl); line-height: 1.1; }
.stat.is-prominent .stat-label { font-size: var(--text-base); font-weight: 600; color: var(--ink); }
.stat.tone-urgent.is-prominent {
  border-color: var(--sev-urgent-border); background: var(--sev-urgent-bg);
}
.stat.tone-urgent.is-prominent .stat-value,
.stat.tone-urgent.is-prominent .stat-label { color: var(--sev-urgent-ink); }
.stat.tone-high.is-prominent { border-color: var(--sev-high-border); background: var(--sev-high-bg); }
.stat.tone-high.is-prominent .stat-value,
.stat.tone-high.is-prominent .stat-label { color: var(--sev-high-ink); }
.stat.is-zero .stat-value, .stat.tone-quiet .stat-value {
  font-size: var(--text-xs); font-weight: 500; color: var(--ink-muted);
}
.stat.is-zero .stat-label, .stat.tone-quiet .stat-label { font-size: var(--text-2xs); }
/* A zero scanner count is absence of evidence, so it takes the unknown texture. */
.stat.is-unscanned .stat-value {
  color: var(--mark-unknown); border-bottom: 1px dashed var(--mark-unknown); cursor: help;
}
.stat.is-unscanned .stat-label { color: var(--mark-unknown); cursor: help; }
.controls {
  flex: 0 0 auto; display: flex; align-items: flex-start; flex-wrap: wrap; gap: var(--s2) var(--s4);
  padding: var(--s3) var(--s5); background: var(--surface); border-bottom: 1px solid var(--border);
}
/* A real segmented control: one row, equal heights, single-line labels sized to
   fit, and an active state that is filled rather than faintly outlined. */
.view-tabs {
  display: inline-flex; flex: 0 0 auto; align-items: stretch; gap: 2px; padding: 3px;
  border: 1px solid var(--border-strong); border-radius: var(--r-md); background: var(--surface-sunken);
}
.view-tabs button {
  display: inline-flex; align-items: center; justify-content: center;
  min-height: 30px; padding: 0 var(--s3); border: 1px solid transparent; border-radius: var(--r-sm);
  background: transparent; color: var(--ink-muted);
  font: inherit; font-size: var(--text-sm); font-weight: 600; line-height: 1;
  letter-spacing: var(--tracking-heading); white-space: nowrap; cursor: pointer;
}
.view-tabs button:hover { color: var(--ink); background: var(--surface); }
.view-tabs button.active {
  background: var(--ink); border-color: var(--ink); color: var(--surface); box-shadow: var(--shadow-1);
}
.view-tabs button.active:hover { background: var(--ink); color: var(--surface); }
.filters { flex: 1 1 520px; min-width: 0; }
.filters-toggle {
  display: none; align-items: center; gap: var(--s2); width: max-content; min-height: 32px;
  padding: 0 var(--s3); border: 1px solid var(--ink-faint); border-radius: var(--r-md);
  background: var(--surface); color: var(--ink);
  font-size: var(--text-sm); font-weight: 600; list-style: none; cursor: pointer;
}
.filters-toggle::-webkit-details-marker { display: none; }
.filter-bar { display: flex; flex-wrap: wrap; align-items: center; gap: var(--s2); min-width: 0; }
.filter-bar #search { flex: 1 1 220px; min-width: 150px; max-width: 420px; }
.filter-bar select { flex: 0 1 auto; max-width: 100%; }
.filter-actions { display: inline-flex; align-items: center; gap: var(--s1); margin-left: auto; }

/* === 5. Two-pane body ====================================================
   At two-pane widths the report is an app shell: the viewport is the frame and
   each pane scrolls inside it. Below that it goes back to document flow so the
   stacked panes can grow. */
@media (min-width: 1280px) {
  body { height: 100vh; overflow: hidden; }
}
.layout { flex: 1 1 auto; min-height: 0; display: grid; grid-template-columns: minmax(0, 1fr); }
.layout.with-left-sidebar { grid-template-columns: var(--list-w) minmax(0, 1fr); }
.left-panel {
  display: none; min-width: 0; min-height: 0;
  border-right: 1px solid var(--border); background: var(--surface);
}
.layout.with-left-sidebar .left-panel { display: grid; grid-template-rows: minmax(0, 1fr); }
.pane-canvas {
  min-width: 0; min-height: 0; display: grid;
  grid-template-columns: minmax(0, 1fr) var(--rail-w);
  grid-template-rows: max-content minmax(0, 1fr);
}
.evidence-chain { grid-column: 1 / -1; }
.graph-shell {
  position: relative; min-width: 0; min-height: 0; overflow: hidden;
  background:
    linear-gradient(var(--canvas-line) 1px, transparent 1px),
    linear-gradient(90deg, var(--canvas-line) 1px, transparent 1px),
    var(--canvas);
  background-size: 36px 36px, 36px 36px, 100% 100%;
}
#graph { position: absolute; inset: 0; overflow: hidden; cursor: grab; user-select: none; }
#graph.dragging { cursor: grabbing; }
/* Nothing inside the zoom surface may be based on a size that survives the fit
   scale below 11px, so the two smallest steps are lifted to --text-sm here. The
   fit floor (MIN_FIT_SCALE in the script) is 11 / 13 and is derived from this. */
#surface {
  position: absolute; left: 0; top: 0; transform-origin: 0 0;
  --text-2xs: var(--text-sm); --text-xs: var(--text-sm);
}
/* The risk view is a table, not a graph: it renders outside the zoom surface at
   1:1 and scrolls, so its text is never optically shrunk. */
.board { position: absolute; inset: 0; display: none; overflow: auto; padding: var(--s4); }
.graph-shell.board-mode .board { display: block; }
.graph-shell.board-mode #graph, .graph-shell.board-mode .graph-scale { display: none; }
.graph-scale {
  position: absolute; right: var(--s3); bottom: var(--s3); z-index: 3; padding: 2px var(--s2);
  max-width: min(440px, calc(100% - var(--s5))); text-align: right;
  border: 1px solid var(--border); border-radius: var(--r-lg);
  background: var(--overlay); color: var(--ink-muted);
  font-family: var(--font-mono); font-size: var(--text-2xs); font-variant-numeric: tabular-nums;
  line-height: 1.4; pointer-events: none;
}
#edges { position: absolute; left: 0; top: 0; overflow: visible; pointer-events: none; }
#edges marker path { fill: var(--ink-faint); }
#cards { position: absolute; left: 0; top: 0; }
/* The explicit column is load bearing. An implicit `auto` track takes the
   max of its items' min-content, and a detail pane full of absolute file paths
   has a min-content of 413px, so at 390 the whole page scrolled sideways.
   minmax(0, 1fr) removes that floor; `li` below is what lets the path break. */
/* Both content rows are fr tracks with a floor, never a viewport height. At
   `auto minmax(180px, 42vh) minmax(0, 1fr)` the legend plus a 42vh detail row
   consumed the whole panel at every laptop height: the risk list measured 0
   visible pixels at 1366x768 and 1280x800, and it is the ONLY text equivalent
   of the graph in the Architecture and Evidence views -- which is also what the
   document skip link points at. Proportional tracks with 120px/140px floors
   give both a share at every height, and each one scrolls inside its own box. */
.right-panel {
  min-width: 0; min-height: 0; overflow: hidden; display: grid;
  grid-template-columns: minmax(0, 1fr);
  grid-template-rows: auto minmax(120px, 1.2fr) minmax(140px, 1fr);
  border-left: 1px solid var(--border); background: var(--surface);
}
.layout.with-left-sidebar .right-panel { grid-template-rows: auto minmax(0, 1fr); }
.layout.with-left-sidebar .finding-list { display: none; }

/* === 6. Chips ============================================================ */
.chips { display: flex; flex-wrap: wrap; gap: var(--s1); min-width: 0; max-width: 100%; }
.top > .chips { max-width: 178px; justify-content: flex-end; }
/* inline-block, not inline-flex: text-overflow does not apply to flex content,
   which is how "network exposure: public" came to be cut without an ellipsis. */
.chip {
  display: inline-block; min-height: 20px; padding: 2px var(--s2); line-height: 16px;
  border: 1px solid var(--sev-info-border); border-radius: var(--r-full);
  background: var(--sev-info-bg); color: var(--sev-info-ink);
  font-size: var(--text-2xs); font-variant-numeric: tabular-nums;
  white-space: nowrap; min-width: 0; flex: 0 1 auto;
  max-width: 100%; overflow: hidden; text-overflow: ellipsis;
}
/* Severity is a tinted chip carrying the severity word, never a bare dot. */
.chip.urgent { background: var(--sev-urgent-bg); color: var(--sev-urgent-ink); border-color: var(--sev-urgent-border); }
.chip.high { background: var(--sev-high-bg); color: var(--sev-high-ink); border-color: var(--sev-high-border); }
.chip.medium { background: var(--sev-medium-bg); color: var(--sev-medium-ink); border-color: var(--sev-medium-border); }
.chip.low { background: var(--sev-low-bg); color: var(--sev-low-ink); border-color: var(--sev-low-border); }
.chip.informational { background: var(--sev-info-bg); color: var(--sev-info-ink); border-color: var(--sev-info-border); }
.chip.request-controlled-path { background: var(--mark-confirmed-soft); color: var(--mark-confirmed); border-color: var(--mark-confirmed); }
.chip.reachable-vulnerable-api, .chip.import-observed, .chip.reachable-through-dependency-graph {
  background: var(--sev-medium-bg); color: var(--sev-medium-ink); border-color: var(--sev-medium-border);
}
/* No evidence: near-neutral and dashed, so it can never read as benign. */
.chip.sbom-only, .chip.no-source-rule, .chip.absent-from-scanned-source {
  background: var(--mark-unknown-soft); color: var(--mark-unknown);
  border-color: var(--border-strong); border-style: dashed;
}
.chip.score, .chip.count, .chip.paths {
  background: var(--surface-sunken); color: var(--ink-muted);
  border-color: var(--border); font-family: var(--font-mono);
}

/* === 7. Graph cards ====================================================== */
.card {
  position: absolute; display: flex; flex-direction: column; overflow: hidden; cursor: pointer;
  border: 1px solid var(--border); border-left: 6px solid var(--sev-info-ink); border-radius: var(--r-lg);
  background: var(--surface); box-shadow: var(--shadow-2); contain: layout paint;
}
.card.selected { outline: 2px solid var(--focus); outline-offset: 2px; }
/* minmax(120px, 1fr), not minmax(0, 1fr): the chips column is max-content, so a
   zero floor lets it starve the label down to "aws_ecs_ta / sk_defini...". */
.card .top {
  display: grid; grid-template-columns: minmax(120px, 1fr) max-content; align-items: flex-start;
  gap: var(--s3); padding: var(--s3) var(--s3) var(--s2); min-width: 0;
}
.asset-card .top { background: var(--surface-raised); border-bottom: 1px solid var(--border); }
.entry-card { border-left-color: var(--ink); }
.entry-card .top { background: var(--ink); color: var(--surface); }
/* Scoped to .top on purpose: only the header sits on the ink plate. Unscoped,
   this also paints the body subtitle --surface-sunken on --surface, which
   measured 1.12:1 in light and 1.03:1 in dark, i.e. invisible. */
.entry-card .top .sub { color: var(--surface-sunken); }
.entry-card .body { padding-top: var(--s2); }
.path-card { border-left-color: var(--ink-muted); }
.path-card .top { background: var(--surface-sunken); border-bottom: 1px solid var(--border); }
/* These two cards carry a resource address as their subtitle, so the chips give
   the label column back the width it needs to hold one on a line. */
.path-card .top > .chips, .entry-card .top > .chips { max-width: 122px; }
.title {
  min-width: 0; overflow: hidden; font-size: var(--text-base); font-weight: 600;
  line-height: 1.3; letter-spacing: var(--tracking-heading);
}
/* break-word, not anywhere: a token only breaks when it cannot fit a line on
   its own, so identifiers stay whole wherever there is room for them. */
.title-main {
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;
  overflow: hidden; overflow-wrap: break-word; word-break: normal;
}
.sub {
  margin-top: var(--s1); color: var(--ink-muted); font-size: var(--text-xs); line-height: 1.35;
  overflow-wrap: break-word; word-break: normal;
}
.body { padding: 0 var(--s3) var(--s3); min-height: 0; overflow: hidden; flex: 1; }
.row {
  display: grid; grid-template-columns: 92px minmax(0, 1fr); gap: var(--s2); margin-top: var(--s1);
  font-size: var(--text-xs); line-height: 1.35; min-width: 0;
}
.row .label { color: var(--ink-muted); overflow: hidden; text-overflow: ellipsis; }
.card.urgent { border-left-color: var(--sev-urgent-ink); }
.card.high { border-left-color: var(--sev-high-ink); }
.card.medium { border-left-color: var(--sev-medium-ink); }
.card.low { border-left-color: var(--sev-low-ink); }
.card.informational { border-left-color: var(--sev-info-ink); }
.zone-panel {
  position: absolute; overflow: hidden; cursor: pointer;
  border: 1px solid var(--border-strong); border-radius: var(--r-lg);
  background: var(--overlay); box-shadow: var(--shadow-1);
}
.zone-panel.selected { outline: 2px solid var(--focus); outline-offset: 2px; }
.zone-head {
  padding: var(--s3) var(--s3) var(--s2);
  border-bottom: 1px solid var(--border); background: var(--surface-raised);
}
.zone-title { font-size: var(--text-base); font-weight: 600; letter-spacing: var(--tracking-heading); }
.zone-sub { margin-top: var(--s1); color: var(--ink-muted); font-size: var(--text-xs); line-height: 1.35; }
.architecture-hop {
  border-left-color: var(--ink-muted); border-radius: var(--r-full);
  box-shadow: var(--shadow-2); overflow: visible;
}
/* The title track takes what the name needs before the chips take anything. At
   `minmax(96px, 1fr) max-content` the chips held a fixed 150px and the node's
   own name was the first thing spent on ellipsis: "Unknown entry" rendered as
   "Unknown…" beside two chips that were themselves clipped to "Conte…" and
   "5 asse…", which carry nothing. Now a 292px pill fits all three. */
.architecture-hop .top {
  grid-template-columns: minmax(96px, max-content) minmax(64px, max-content);
  padding: var(--s2) var(--s3);
  background: var(--surface-raised); border-bottom: 0;
}
.architecture-hop .body { display: none; }
.architecture-hop .title-main { -webkit-line-clamp: 1; }
.architecture-hop .sub { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
/* A hop pill is one line tall: chips ellipsize side by side rather than wrap
   onto a second row that the pill has no room to show. */
.architecture-hop .top > .chips { flex-wrap: nowrap; max-width: 100%; }
/* Order of sacrifice inside the pill: the title first (it never gives), then
   the provider, and the count last. A count clipped to "5 asse…" carries no
   information at all, while the provider is also named on the asset cards this
   hop feeds and on the zone around it. */
.architecture-hop .top > .chips > .chip:last-child { flex: 0 0 auto; }
.architecture-hop[data-hop-kind="entry"] { border-left-color: var(--ink); background: var(--ink); color: var(--surface); }
.architecture-hop[data-hop-kind="entry"] .top { background: var(--ink); }
.architecture-hop[data-hop-kind="entry"] .top .sub { color: var(--surface-sunken); }
/* The same unknown vocabulary the chain and the attack graph use. Without it a
   pill named "Unknown entry" took the most confident fill in the palette --
   --ink, solid, identical to "Internet / attacker" -- and the signature
   encoding read as half applied across the three boards. The last two rules
   have to restate the entry colours because [data-hop-kind="entry"] above is
   equally specific and would otherwise win on source order. */
.architecture-hop[data-node-state="unknown"],
.architecture-hop[data-node-state="unknown"][data-hop-kind="entry"] {
  border: 1px dashed var(--mark-unknown); border-left: 6px dashed var(--mark-unknown);
  background: var(--mark-unknown-soft); color: var(--mark-unknown);
}
.architecture-hop[data-node-state="unknown"] .top,
.architecture-hop[data-node-state="unknown"][data-hop-kind="entry"] .top {
  background: transparent; color: var(--mark-unknown);
}
.architecture-hop[data-node-state="unknown"] .top .sub,
.architecture-hop[data-node-state="unknown"][data-hop-kind="entry"] .top .sub { color: var(--mark-unknown); }
.architecture-hop[data-node-state="blocked"] { border-left-color: var(--mark-blocked); }
.architecture-asset { border-left-width: 6px; }
.architecture-asset .top {
  grid-template-columns: minmax(0, 1fr); gap: var(--s2);
  background: var(--surface); border-bottom: 1px solid var(--border);
}
.architecture-asset .top > .chips { max-width: 100%; justify-content: flex-start; }
.architecture-asset .title-main { -webkit-line-clamp: 2; }
.architecture-asset .body { padding-top: var(--s2); }
.vuln-card .title { font-size: var(--text-base); }
.vuln-card .top > .chips { max-width: 158px; }
.vuln-card .sub, .path-card .sub, .entry-card .sub {
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
}
.vuln-card .body { padding-top: 0; }
.asset-card .body { padding-top: var(--s2); }
.path-card .body .sub, .vuln-card .body .sub {
  display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden;
}
.lane-label {
  position: absolute; height: 28px; padding: var(--s1) var(--s3); pointer-events: none;
  border: 1px solid var(--border); border-radius: var(--r-full);
  background: var(--overlay); color: var(--ink-muted);
  font-size: var(--text-xs); font-weight: 600; box-shadow: var(--shadow-1);
}

/* === 8. Attack view: risk list and graph nodes =========================== */
.attack-risk-sidebar {
  min-width: 0; height: 100%; overflow: auto; padding: var(--s3); background: var(--surface);
}
.attack-risk-sidebar-title {
  display: flex; justify-content: space-between; align-items: baseline; gap: var(--s2);
  padding: 0 0 var(--s3); color: var(--ink);
  font-size: var(--text-base); font-weight: 600; letter-spacing: var(--tracking-heading);
}
.attack-risk-sidebar-list { display: grid; gap: var(--s2); }
.attack-risk-sidebar-card {
  width: 100%; height: auto; min-height: 0; padding: var(--s2) var(--s3); text-align: left;
  border: 1px solid var(--border); border-left: 5px solid var(--sev-info-ink); border-radius: var(--r-md);
  background: var(--surface); color: var(--ink);
  font: inherit; cursor: pointer; overflow: visible; box-shadow: var(--shadow-1);
}
.attack-risk-sidebar-card:hover, .attack-risk-sidebar-card.selected {
  border-color: var(--border-strong); background: var(--surface-raised);
}
.attack-risk-sidebar-card.urgent { border-left-color: var(--sev-urgent-ink); }
.attack-risk-sidebar-card.high { border-left-color: var(--sev-high-ink); }
.attack-risk-sidebar-card.medium { border-left-color: var(--sev-medium-ink); }
.attack-risk-sidebar-card.low { border-left-color: var(--sev-low-ink); }
.attack-risk-sidebar-card.informational { border-left-color: var(--sev-info-ink); }
.attack-risk-sidebar-card .risk-title {
  color: var(--ink); font-size: var(--text-sm); font-weight: 600; line-height: 1.3;
  letter-spacing: var(--tracking-heading); overflow-wrap: anywhere;
}
.attack-risk-sidebar-card .risk-meta {
  margin-top: var(--s1); color: var(--ink-muted);
  font-size: var(--text-2xs); line-height: 1.35; overflow-wrap: anywhere;
}
.attack-risk-sidebar-card .chips { margin-top: var(--s2); }
.attack-graph-node {
  position: absolute; display: grid; grid-template-rows: max-content max-content max-content;
  justify-items: center; align-content: start; gap: var(--s1); min-width: 0; text-align: center;
  border: 0; padding: 0; background: transparent; color: var(--ink); cursor: pointer;
  transition: opacity .16s ease, transform .16s ease;
}
.attack-graph-node.draggable { cursor: grab; }
.attack-graph-node.dragging { cursor: grabbing; z-index: 12; }
.attack-graph-node:hover { transform: translateY(-2px); }
.attack-graph-node.selected .attack-graph-circle,
.attack-graph-node:focus-visible .attack-graph-circle { outline: 2px solid var(--focus); outline-offset: 3px; }
/* De-emphasis must not be achieved with opacity on anything that contains text.
   The blanket opacity of .38 pushed 21 of 30 dimmed labels below legibility;
   moving to .75 on the circle alone was still wrong, because the circle holds a
   13px/700 identifier glyph, and compositing plate and glyph together dropped
   that glyph to 2.77-3.11:1 against its own plate in the default on-load state.
   The plate keeps its full alpha and its hue -- greying a proven node would make
   it read as unknown, the one thing this report may never do. What recedes is
   everything around the glyph: the label loses its plate and drops to muted ink
   (6.1:1 on the canvas), the subtitle is withdrawn, the elevation goes flat, and
   the plate loses its saturation. `saturate` is built on the luma coefficients,
   so it moves the plate toward its own grey without moving its luminance, and
   the glyph is white, which has no saturation to lose: measured after the
   change, the weakest glyph-on-plate pair is 6.15:1 where it was 2.77:1. */
.attack-graph-node.dimmed .attack-graph-circle {
  box-shadow: none; filter: saturate(.55);
}
.attack-graph-node.dimmed .attack-graph-label {
  background: transparent; color: var(--ink-muted); font-weight: 500;
}
.attack-graph-node.dimmed .attack-graph-sub { visibility: hidden; }
.attack-graph-circle {
  position: relative; width: 58px; height: 58px; display: grid; place-items: center;
  border: 3px solid var(--surface); border-radius: var(--r-full);
  background: var(--ink-muted); color: var(--on-mark); box-shadow: var(--shadow-2);
  font-size: var(--text-sm); font-weight: 700; transition: box-shadow .16s ease, transform .16s ease;
}
.attack-graph-node[data-node-type="entry"] .attack-graph-circle {
  width: 78px; height: 78px; background: var(--ink); color: var(--surface); font-size: var(--text-base);
}
.attack-graph-node[data-node-type="lateral"] .attack-graph-circle {
  width: 78px; height: 78px; background: var(--mark-internal); font-size: var(--text-base);
}
.attack-graph-node[data-node-type="identity"] .attack-graph-circle,
.attack-graph-node[data-node-type="data"] .attack-graph-circle { background: var(--mark-internal); }
.attack-graph-node[data-node-type="ingress"] .attack-graph-circle,
.attack-graph-node[data-node-type="vulnerability"] .attack-graph-circle,
.attack-graph-node[data-node-type="weakness"] .attack-graph-circle { background: var(--mark-confirmed); }
/* A finding plate used to be tinted by tier, which put --sev-medium-ink and
   --sev-low-ink on a mark and made priority a hue. The plate now says what the
   evidence says; the priority is on the chip beside it, in words. */
.attack-graph-node[data-node-type="finding"] .attack-graph-circle { background: var(--mark-confirmed); }
/* Unknown is near-neutral and always dashed: the absence of evidence is not a
   fourth confident category, and it must never read as benign. */
.attack-graph-node[data-node-type="unknown"] .attack-graph-circle,
.attack-graph-node[data-node-state="unknown"] .attack-graph-circle {
  background: var(--mark-unknown-soft); color: var(--mark-unknown);
  border-color: var(--mark-unknown); border-style: dashed;
}
.attack-graph-node[data-node-state="blocked"] .attack-graph-circle {
  background: var(--mark-blocked); border-color: var(--mark-blocked); border-style: double;
}
.attack-graph-badge {
  position: absolute; right: -5px; top: -6px; min-width: 22px; height: 22px; padding: 0 var(--s1);
  display: grid; place-items: center; border: 2px solid var(--surface); border-radius: var(--r-full);
  background: var(--mark-confirmed); color: var(--on-mark);
  font-size: var(--text-2xs); font-weight: 700; line-height: 1;
}
.attack-graph-toggle {
  position: absolute; left: -5px; top: -6px; width: 22px; height: 22px;
  display: grid; place-items: center; border: 2px solid var(--border-strong); border-radius: var(--r-full);
  background: var(--surface); color: var(--ink);
  font-size: var(--text-xs); font-weight: 700; line-height: 1;
}
/* Labels are shortened at a separator boundary in the script, never mid-token,
   so wrapping is left at its default: `anywhere` is what produced
   "aws_ecs_task_def / inition.payment". The untruncated value stays on title. */
.attack-graph-label {
  width: 168px; padding: 2px var(--s2); border-radius: var(--r-md);
  background: var(--overlay); color: var(--ink);
  font-size: var(--text-sm); font-weight: 600; line-height: 1.25;
  overflow-wrap: normal; word-break: normal; hyphens: none;
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
}
.attack-graph-label.mono { letter-spacing: -0.01em; }
.attack-graph-sub {
  width: 168px; color: var(--ink-muted); font-size: var(--text-2xs); line-height: 1.3;
  overflow-wrap: normal; word-break: normal; display: -webkit-box; -webkit-line-clamp: 2;
  -webkit-box-orient: vertical; overflow: hidden;
}

/* === 9. Edges: hue carries state, dash pattern carries confidence ========
   Every edge in every view is stroked from one of the five state classes
   below, and from nothing else. Severity used to be wired straight into the
   stroke (.edge.urgent/.high/.medium/.low), which put four warm hues on the
   canvas that the legend does not name and that collapse under deuteranopia:
   --sev-high-ink vs --sev-medium-ink measured CIE dE 2.7 there, and
   --mark-confirmed vs --sev-medium-ink 3.6, against a stated bar of 12. It is
   the exact failure the palette work was commissioned to remove. Priority now
   rides on stroke width and on the labelled chips, which is where it reads. */
.edge {
  fill: none; stroke: var(--ink-faint); stroke-width: 2; opacity: .85;
  stroke-linecap: round; stroke-linejoin: round; marker-end: url(#edge-arrow);
}
.edge.network { stroke-width: 2.6; }
.edge.vulnerability { opacity: .75; }
/* .75, not .55: at .55 an architecture edge measured 2.4-2.97:1 on the canvas,
   under the 3:1 floor for a non-text mark. .75 puts the weakest at 3.45:1. */
.edge.architecture { opacity: .75; stroke-width: 2.1; }
.edge.urgent { stroke-width: 3; }
.edge.high { stroke-width: 2.6; }
.edge.attack-path { stroke-width: 2.4; opacity: .9; }
.edge.attack-graph-edge {
  stroke-width: 2.4; opacity: .85;
  marker-end: url(#edge-arrow); stroke-linecap: round;
}
.edge[tabindex] { pointer-events: stroke; cursor: pointer; }
/* The five states, in the order the legend lists them. Each one is a hue AND a
   texture, so the graph survives greyscale, print and colour-vision deficiency:
   nothing here is carried by hue alone. */
.edge.state-confirmed { stroke: var(--mark-confirmed); }
.edge.state-internal { stroke: var(--mark-internal); }
.edge.state-structural { stroke: var(--ink-muted); }
.edge.state-blocked { stroke: var(--mark-blocked); stroke-dasharray: 2 6; }
/* Full strength, and dashed. An unknown edge used to be drawn at .7 (2.85:1),
   quieter than the proven edges around it -- exactly the reading this report
   exists to prevent. The dash pattern is what says "we do not know"; the
   opacity says nothing. */
.edge.state-unknown { stroke: var(--mark-unknown); stroke-dasharray: 7 6; opacity: .85; }
.edge.active { opacity: 1; stroke-width: 3.4; }
.edge.attack-graph-edge.selected, .edge.attack-path.selected {
  stroke-width: 3.1; opacity: 1; animation: pulse-edge 1.8s ease-in-out infinite;
}
.edge:hover, .edge:focus-visible { stroke-width: 4; opacity: 1; }
/* A dimmed edge recedes by weight, not by vanishing. At opacity .2 it measured
   1.3:1 -- selecting a node erased the rest of the graph, which reads as "there
   are no other paths". Width does the de-emphasis now; opacity holds the 3:1
   floor (weakest hue 3.13:1) because a dimmed edge is still clickable. */
.edge.attack-graph-edge.dimmed { opacity: .75; stroke-width: 1.3; }
.edge.attack-path.dimmed { opacity: .75; stroke-width: 1.5; }
@keyframes pulse-edge { 0%, 100% { opacity: .72; } 50% { opacity: 1; } }

/* === 9b. The evidence chain =============================================
   Hue is state, texture is confidence, and neither is load bearing on its
   own: every link also carries its state as a word, a fill and a dash
   pattern, so the chain survives greyscale, print and CVD. */
.evidence-chain {
  min-width: 0; padding: var(--s2) var(--s5) var(--s1);
  background: var(--surface); border-bottom: 1px solid var(--border);
}
.chain-head {
  display: flex; flex-wrap: wrap; align-items: baseline; gap: var(--s1) var(--s3);
}
.chain-title {
  font-size: var(--text-xs); font-weight: 700; color: var(--ink-muted);
  text-transform: uppercase; letter-spacing: .06em;
}
.chain-verdict { font-size: var(--text-base); font-weight: 600; overflow-wrap: anywhere; }
.chain-verdict .chain-verdict-mark {
  font-family: var(--font-mono); font-size: .9375em; font-weight: 500;
}
.chain-verdict.is-broken { color: var(--mark-unknown); }
.chain-verdict.is-blocked { color: var(--mark-blocked); }
.chain-verdict.is-proven { color: var(--mark-confirmed); }
/* The 5px of top padding is the focus ring's room. The track hides vertical
   overflow and cannot scroll vertically, so with the links flush against its
   top edge a focused link's 2px ring at 3px offset was cut off along its whole
   top edge and rendered as a three-sided U. */
.chain-track {
  display: flex; align-items: flex-start; gap: 0; margin: 0; padding: 5px 0 var(--s1);
  overflow-x: auto; overflow-y: hidden; list-style: none; scrollbar-width: thin;
}
.chain-track::-webkit-scrollbar { height: 8px; }
.chain-track::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: var(--r-full); }
/* currentColor is used purely for its alpha: a mask carries no hue. */
.chain-track.fade-start {
  -webkit-mask-image: linear-gradient(90deg, transparent 0, currentColor 30px);
  mask-image: linear-gradient(90deg, transparent 0, currentColor 30px);
}
.chain-track.fade-end {
  -webkit-mask-image: linear-gradient(90deg, currentColor calc(100% - 30px), transparent 100%);
  mask-image: linear-gradient(90deg, currentColor calc(100% - 30px), transparent 100%);
}
.chain-track.fade-start.fade-end {
  -webkit-mask-image: linear-gradient(90deg, transparent 0, currentColor 30px,
    currentColor calc(100% - 30px), transparent 100%);
  mask-image: linear-gradient(90deg, transparent 0, currentColor 30px,
    currentColor calc(100% - 30px), transparent 100%);
}
.chain-link {
  position: relative; flex: 0 0 auto; width: 164px; display: grid; gap: 3px;
  justify-items: center; padding: 0; text-align: center;
  border: 0; background: transparent; color: inherit; font: inherit; cursor: pointer;
  /* Same mapping as the graph, so the chain and the graph read as one system:
     structural steps stay neutral, confirmed hue is reserved for the steps that
     are the reachability claim, and the IAM pair is the internal pivot. */
  --chain-hue: var(--ink-muted);
  --chain-ink: var(--on-mark);
  animation: chain-in .28s ease both;
}
.chain-link.is-static { animation: none; }
.chain-link[data-chain-role="entry"] { --chain-hue: var(--ink); --chain-ink: var(--surface); }
.chain-link[data-chain-role="network"],
.chain-link[data-chain-role="finding"],
.chain-link[data-chain-role="posture"] { --chain-hue: var(--mark-confirmed); }
.chain-link[data-chain-role="identity"],
.chain-link[data-chain-role="data"],
.chain-link[data-chain-role="pivot"] { --chain-hue: var(--mark-internal); }
.chain-link[data-chain-state="blocked"] { --chain-hue: var(--mark-blocked); }
.chain-link[data-chain-state="unknown"] {
  --chain-hue: var(--mark-unknown);
  --chain-ink: var(--mark-unknown);
}
.chain-role {
  font-size: var(--text-2xs); font-weight: 700; color: var(--ink-muted);
  text-transform: uppercase; letter-spacing: .05em; white-space: nowrap;
}
.chain-mark {
  display: grid; place-items: center; width: 40px; height: 40px;
  border: 2px solid var(--chain-hue); border-radius: var(--r-md);
  background: var(--chain-hue); color: var(--chain-ink);
  font-size: var(--text-sm); font-weight: 700; line-height: 1;
}
/* Outlined + dashed + near-neutral: an unknown link can never read as proven. */
.chain-link[data-chain-state="unknown"] .chain-mark {
  background: var(--mark-unknown-soft); border-style: dashed;
}
.chain-link[data-chain-state="blocked"] .chain-mark {
  background: var(--mark-blocked-soft); border-style: double; border-width: 4px;
  color: var(--mark-blocked);
}
.chain-name {
  max-width: 100%; font-size: var(--text-xs); font-weight: 600; line-height: 1.3;
  overflow-wrap: break-word; word-break: normal; hyphens: none;
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
}
.chain-name.mono { font-family: var(--font-mono); font-weight: 500; font-size: var(--text-2xs); }
.chain-state {
  font-size: var(--text-2xs); font-weight: 600; color: var(--ink-muted); white-space: nowrap;
}
.chain-link[data-chain-state="unknown"] .chain-state { color: var(--mark-unknown); }
.chain-link[data-chain-state="blocked"] .chain-state { color: var(--mark-blocked); }
.chain-link:hover .chain-mark, .chain-link.is-active .chain-mark { box-shadow: var(--shadow-2); }
.chain-link:focus-visible { outline: 2px solid var(--focus); outline-offset: 3px; border-radius: var(--r-sm); }
.chain-edge {
  position: relative; flex: 0 0 42px; align-self: flex-start; height: 40px;
  margin-top: 17px; color: var(--mark-confirmed);
}
.chain-edge[data-chain-state="unknown"] { color: var(--mark-unknown); }
.chain-edge[data-chain-state="blocked"] { color: var(--mark-blocked); }
.chain-edge-line { position: absolute; left: 0; right: 9px; top: 12px; height: 2px; background: currentColor; }
/* Dash pattern, not opacity, is what says "we do not know". */
.chain-edge[data-chain-state="unknown"] .chain-edge-line {
  background: repeating-linear-gradient(90deg, currentColor 0 5px, transparent 5px 10px);
}
.chain-edge-cap {
  position: absolute; right: 0; top: 8px; width: 0; height: 0;
  border-left: 9px solid currentColor;
  border-top: 5px solid transparent; border-bottom: 5px solid transparent;
}
/* A blocked edge ends in a stop bar, never an arrow. */
.chain-edge[data-chain-state="blocked"] .chain-edge-cap {
  border: 0; right: 1px; top: 5px; width: 3px; height: 16px; background: currentColor;
}
.chain-edge-label {
  position: absolute; left: -8px; right: -8px; top: 20px;
  font-size: var(--text-2xs); line-height: 1.2; color: var(--ink-muted); text-align: center;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.chain-edge[data-chain-state="unknown"] .chain-edge-label { color: var(--mark-unknown); font-weight: 600; }
.chain-edge[data-chain-state="blocked"] .chain-edge-label { color: var(--mark-blocked); font-weight: 600; }
.chain-note {
  min-height: 20px; font-size: var(--text-xs); line-height: 1.45; color: var(--ink-muted);
  overflow-wrap: anywhere;
}
.chain-note .chain-note-kind {
  font-weight: 700; text-transform: uppercase; letter-spacing: .05em; font-size: var(--text-2xs);
}
.chain-note.is-unknown { color: var(--mark-unknown); }
.chain-note.is-blocked { color: var(--mark-blocked); }
.chain-empty { margin-top: var(--s2); font-size: var(--text-sm); color: var(--ink-muted); }
@keyframes chain-in { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }

/* === 10. Risk board ======================================================
   Laid out in fr units so it fills the pane at any width and only falls back
   to its own horizontal scroll below --board-min. */
.risk-board {
  /* The CONTEXT track is sized to hold "network exposure: unknown" whole. At
     minmax(148px) it ellipsised to "network exposure: unk…" at every width from
     1440 down, and the word it cut is the one the product exists to surface. */
  --board-cols: minmax(92px, .6fr) minmax(200px, 2.2fr) minmax(148px, 1fr)
                56px 64px minmax(182px, 1fr) 132px;
  --board-min: 946px;
  position: relative; width: 100%; min-width: var(--board-min); overflow: hidden;
  border: 1px solid var(--border); border-radius: var(--r-lg);
  background: var(--surface); box-shadow: var(--shadow-1);
}
.risk-board-head {
  position: sticky; top: 0; z-index: 2;
  display: grid; grid-template-columns: var(--board-cols); gap: var(--s3);
  padding: var(--s2) var(--s3); border-bottom: 1px solid var(--border);
  background: var(--surface-raised); color: var(--ink-muted);
  font-size: var(--text-2xs); font-weight: 700; text-transform: uppercase; letter-spacing: .04em;
}
.risk-row {
  display: grid; grid-template-columns: var(--board-cols); gap: var(--s3);
  align-items: center; min-height: 72px; padding: var(--s2) var(--s3);
  border-bottom: 1px solid var(--border); cursor: pointer;
}
.risk-row:last-child { border-bottom: 0; }
.risk-row:hover, .risk-row[aria-current="true"] { background: var(--surface-raised); }
.risk-row[aria-current="true"] { box-shadow: inset 4px 0 0 var(--focus); }
.risk-cell { min-width: 0; font-size: var(--text-xs); }
.risk-cell.num { font-family: var(--font-mono); font-variant-numeric: tabular-nums; }
/* The row is a table row, so the activation lives on the scenario title rather
   than on the container: a role=button row swallowed the "Open attack path"
   link into a 281-character accessible name and nested one interactive control
   inside another, which ARIA forbids. */
.risk-title-button {
  display: block; width: 100%; padding: 0; text-align: left;
  border: 0; background: transparent; color: inherit; font: inherit; cursor: pointer;
}
.risk-severity { display: inline-flex; align-items: center; gap: var(--s2); font-weight: 600; }
.risk-dot { width: 10px; height: 10px; border-radius: var(--r-full); background: var(--sev-info-ink); }
.risk-dot.urgent { background: var(--sev-urgent-ink); }
.risk-dot.high { background: var(--sev-high-ink); }
.risk-dot.medium { background: var(--sev-medium-ink); }
.risk-dot.low { background: var(--sev-low-ink); }
.risk-title {
  font-size: var(--text-sm); font-weight: 600; line-height: 1.3;
  letter-spacing: var(--tracking-heading); overflow-wrap: anywhere;
}
.risk-meta {
  margin-top: var(--s1); color: var(--ink-muted);
  font-size: var(--text-xs); line-height: 1.35; overflow-wrap: break-word; word-break: normal;
}
.risk-path-link {
  display: inline-flex; align-items: center; justify-content: center; padding: var(--s1) var(--s2);
  border: 1px solid var(--border-strong); border-radius: var(--r-md);
  background: var(--surface); color: var(--ink);
  font: inherit; font-size: var(--text-xs); font-weight: 600;
  text-decoration: none; white-space: nowrap; cursor: pointer;
}
.risk-path-link:hover { border-color: var(--focus); background: var(--surface-sunken); }
.risk-board .chips { flex-wrap: wrap; }

/* === 11. Detail rail ===================================================== */
.legend {
  display: flex; flex-wrap: wrap; gap: var(--s2) var(--s3); padding: var(--s3);
  border-bottom: 1px solid var(--border); background: var(--surface-raised);
}
.legend span { display: inline-flex; align-items: center; gap: var(--s2); font-size: var(--text-2xs); color: var(--ink-muted); }
.swatch { width: 18px; height: 0; border-top: 3px solid var(--ink-faint); }
.swatch-confirmed { border-top-color: var(--mark-confirmed); }
.swatch-blocked { border-top: 5px double var(--mark-blocked); }
.swatch-internal { border-top-color: var(--mark-internal); }
.swatch-structural { border-top-color: var(--ink-muted); }
.swatch-unknown { border-top: 3px dashed var(--mark-unknown); }
.details, .finding-list { padding: var(--s3); overflow: auto; min-height: 0; }
.details { border-bottom: 1px solid var(--border); }
.details h2, .finding-list h2 { margin: 0 0 var(--s2); font-size: var(--text-base); overflow-wrap: anywhere; }
.empty { color: var(--ink-muted); font-size: var(--text-sm); line-height: 1.5; }
.kv {
  display: grid; grid-template-columns: 116px minmax(0, 1fr); gap: var(--s1) var(--s2);
  margin: var(--s2) 0; font-size: var(--text-xs); line-height: 1.5;
}
.kv div:nth-child(odd) { color: var(--ink-muted); }
.kv div:nth-child(even) { overflow-wrap: anywhere; }
.item {
  padding: var(--s3); margin-bottom: var(--s2); cursor: pointer;
  border: 1px solid var(--ink-faint); border-radius: var(--r-md); background: var(--surface-raised);
}
.item:hover { border-color: var(--focus); }
.item-title {
  display: grid; grid-template-columns: minmax(0, 1fr) max-content; gap: var(--s2); min-width: 0;
  font-size: var(--text-sm); font-weight: 600; overflow-wrap: anywhere;
}
.item-meta {
  margin-top: var(--s1); color: var(--ink-muted);
  font-size: var(--text-xs); line-height: 1.4; overflow-wrap: anywhere;
}
ul { margin: var(--s1) 0 0 17px; padding: 0; min-width: 0; }
/* break-word, not anywhere: list items carry absolute paths and purls, and an
   unbroken one must be allowed to break rather than push the pane wider. */
li { margin: var(--s1) 0; font-size: var(--text-xs); overflow-wrap: break-word; }
.category-panels { display: grid; gap: var(--s2); margin-top: var(--s2); }
.category-panel {
  border: 1px solid var(--border); border-radius: var(--r-md);
  background: var(--surface-raised); overflow: hidden;
}
.category-panel summary { padding: var(--s2) var(--s3); font-size: var(--text-sm); font-weight: 600; cursor: pointer; }
.category-panel-body { padding: 0 var(--s3) var(--s3); }
.category-item {
  padding: var(--s2) 0; border-top: 1px solid var(--border);
  font-size: var(--text-xs); line-height: 1.45;
}
.category-item-title { font-weight: 600; overflow-wrap: anywhere; }
.category-item-detail { margin-top: 2px; color: var(--ink-muted); overflow-wrap: anywhere; }
.raw-evidence {
  margin-top: var(--s3); border: 1px solid var(--border); border-radius: var(--r-md);
  background: var(--surface-raised); overflow: hidden;
}
.raw-evidence summary { padding: var(--s2) var(--s3); font-size: var(--text-sm); font-weight: 600; cursor: pointer; }
.raw-evidence pre {
  margin: 0; padding: var(--s3); max-height: 280px; overflow: auto;
  border-top: 1px solid var(--border); font-size: var(--text-2xs); white-space: pre-wrap;
}
.detail-action-list { list-style: none; padding-left: 0; }
.detail-action-list li { margin: var(--s1) 0; }
.detail-link-button {
  width: 100%; padding: var(--s2) var(--s3); text-align: left;
  border: 1px solid var(--ink-faint); border-radius: var(--r-md);
  background: var(--surface-raised); color: var(--ink);
  font: inherit; font-size: var(--text-sm); cursor: pointer; overflow-wrap: anywhere;
}
.detail-link-button:hover { border-color: var(--focus); background: var(--surface-sunken); }

/* === 12. Responsive: no horizontal page scroll at or above 360px ========= */
@media (max-width: 1279px) {
  .layout, .layout.with-left-sidebar {
    grid-template-columns: minmax(0, 1fr); grid-auto-rows: max-content minmax(0, 1fr);
  }
  .left-panel { border-right: 0; border-bottom: 1px solid var(--border); }
  .layout.with-left-sidebar .left-panel { grid-template-rows: auto; }
  .attack-risk-sidebar { height: auto; max-height: 30vh; }
  /* One vertical scroller below 1280, and that is the page. The row used to be
     pinned to 55vh, so in the board views #board kept its own scrollbar inside a
     document that also scrolled: two bars 15px apart at 1024x768, and a wheel
     over the table could not move the page past it. The graph keeps a fixed
     frame -- it pans by transform and never scrolls -- and the table flows. */
  .pane-canvas {
    grid-template-columns: minmax(0, 1fr);
    grid-template-rows: max-content max-content minmax(0, 1fr);
  }
  .graph-shell { min-height: 380px; height: 55vh; }
  .graph-shell.board-mode { height: auto; min-height: 0; }
  .graph-shell.board-mode .board { position: static; overflow: visible; }
  .right-panel {
    border-left: 0; border-top: 1px solid var(--border);
    overflow: visible; grid-template-rows: auto auto auto;
  }
  .details, .finding-list { overflow: visible; }
}
@media (max-width: 767px) {
  .app-header, .summary, .controls { padding-left: var(--s4); padding-right: var(--s4); }
  .app-title { font-size: var(--text-lg); }
  .filters-toggle { display: inline-flex; }
  /* Two rows of two, still equal height and still one line per label. */
  .view-tabs { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); width: 100%; }
  .view-tabs button { padding: 0 var(--s2); overflow: hidden; text-overflow: ellipsis; }
  .filters[open] .filter-bar { margin-top: var(--s2); }
  .filter-actions { margin-left: 0; }
  .filter-bar #search { max-width: 100%; }
  .graph-shell { height: 60vh; }
  /* Single column: the strip is the page's own first section, not a 253px
     window onto eight screens of primary content. */
  .attack-risk-sidebar { max-height: none; overflow: visible; }
  .evidence-chain { padding-left: var(--s4); padding-right: var(--s4); }
  .board { padding: var(--s2); }
  .stat-group + .stat-group { padding-left: 0; border-left: 0; }
}

/* === 13. Print: light tokens, panes stacked, chrome hidden ===============
   The dark palettes are screen-only, so print already renders on the light
   tokens whatever the reader pinned. Only the canvas and elevation change. */
/* Both notes only ever render on paper; on screen the graph itself is there. */
.print-graph-note, .print-portrait-note { display: none; }
@media print {
  :root { --canvas: #FFFFFF; --shadow-1: none; --shadow-2: none; }
  /* Landscape because the report is wide: the risk board is seven columns and
     portrait cropped 94px off it, and the evidence chain is a horizontal track. */
  @page { size: landscape; margin: 10mm; }
  body { display: block; height: auto; overflow: visible; background: var(--surface); }
  .controls, .header-actions, .legend, .skip-link { display: none !important; }
  .layout, .layout.with-left-sidebar, .pane-canvas { display: block !important; }
  .left-panel { display: block !important; border: 0; }
  .attack-risk-sidebar { height: auto; max-height: none; overflow: visible; }
  /* The graph is fitted to the sheet, not cropped to a fixed frame. A 640px
     frame clipped a 2075px surface and printed roughly a third of the attack
     graph with no indication that the rest existed -- on an artifact whose
     whole claim is that it does not hide paths. Height is auto so the fitted
     graph sets its own, and --print-scale (written by applyTransform, derived
     from the narrower of A4 and US Letter at this @page margin) scales it. */
  .graph-shell {
    position: static; height: auto; background: var(--surface);
    border: 1px solid var(--border); break-inside: avoid;
  }
  #graph { position: relative; height: auto; overflow: visible; }
  /* zoom, not transform: zoom is taken into account by layout, so the graph
     frame collapses onto the fitted size instead of reserving the unscaled
     height and printing a page of white below it. */
  #surface {
    position: relative; transform: none !important; zoom: var(--print-scale, 1);
  }
  .graph-scale { display: none !important; }
  .graph-shell.board-mode { height: auto; }
  /* A surface too big to fit the sheet at a readable size is not shrunk into
     illegibility and not cropped: it is withdrawn and named. The chain and the
     risk list, both of which print complete at 1:1, carry the same items.
     "Too big" is both axes. Height used to be unguarded, so a 1802px fitted
     shell spanned two and a half landscape sheets and `break-inside: avoid`
     could not hold it: the page break fell through the middle of a node and
     through the x-height of four labels. */
  .graph-shell[data-print-fit="oversized"] { border: 0; }
  .graph-shell[data-print-fit="oversized"] #graph { display: none; }
  .graph-shell[data-print-fit="oversized"] .print-graph-note,
  .print-portrait-note {
    padding: var(--s3);
    border: 1px dashed var(--border-strong); border-radius: var(--r-md);
    background: var(--surface-raised); color: var(--ink-muted);
    font-size: var(--text-sm); line-height: 1.5; break-inside: avoid;
  }
  .graph-shell[data-print-fit="oversized"] .print-graph-note { display: block; }
  .board { position: static; overflow: visible; padding: 0; }
  .risk-board { min-width: 0; box-shadow: none; }
  .risk-board-head { position: static; }
  /* The chain is audit evidence: it prints in full, wrapped, never scrolled. */
  .evidence-chain { break-inside: avoid; border-bottom: 0; }
  .chain-track { overflow: visible; flex-wrap: wrap; row-gap: var(--s3); }
  .chain-link, .chain-edge { break-inside: avoid; }
  .right-panel { display: block; border: 0; overflow: visible; }
  .layout.with-left-sidebar .finding-list { display: block; }
  .details, .finding-list { overflow: visible; }
  .card, .item, .risk-row, .attack-risk-sidebar-card { break-inside: avoid; }
  .raw-evidence pre { max-height: none; }
}
/* --print-scale is computed for the landscape sheet @page asks for. A reader
   who overrides the dialog to portrait would get a graph 274pt wider than the
   page, and print crops without saying so -- so on a narrow sheet the diagram
   is withdrawn and named instead, and the risk table gives up its comfortable
   column minimums rather than losing a column off the edge. */
@media print and (max-width: 860px) {
  .graph-shell { border: 0; }
  .graph-shell #graph { display: none !important; }
  .graph-shell .print-graph-note { display: none !important; }
  .graph-shell .print-portrait-note { display: block; }
  /* The last track is sized to the "Open attack path" control rather than to
     the header above it: at 84px the control hung 35pt off the sheet. */
  .risk-board {
    --board-cols: minmax(60px, .6fr) minmax(140px, 2.4fr) minmax(96px, 1fr)
                  38px 44px minmax(96px, 1fr) 122px;
  }
  .risk-board-head, .risk-row { gap: var(--s2); padding: var(--s2); }
}
</style>
</head>
<body>
<a class="skip-link" href="#riskListRegion">Skip to the risk list</a>
<header class="app-header">
  <div class="app-id">
    <h1 class="app-title">Reachability Advisor Evidence Report</h1>
    <p class="provenance" id="generated"></p>
  </div>
  <div class="header-actions">
    <button id="themeToggle" class="btn" type="button" data-theme="auto" aria-label="Theme: auto">
      <span class="theme-glyph" aria-hidden="true"></span><span id="themeLabel">Auto</span>
    </button>
    <button id="exportData" class="btn" type="button" title="Download the report data as JSON">Export JSON</button>
    <button id="printReport" class="btn" type="button" title="Print the report or save it as a PDF">Print</button>
  </div>
</header>
<section class="summary" id="stats" aria-label="Report summary"></section>
<section class="controls">
  <div class="view-tabs" role="group" aria-label="Report view">
    <button id="attackTab" type="button" data-view="attack" aria-pressed="false">Attack Paths</button>
    <button id="architectureTab" type="button" data-view="architecture" aria-pressed="false">Architecture</button>
    <button id="evidenceTab" type="button" data-view="evidence" aria-pressed="false">Evidence Paths</button>
    <button id="riskTab" type="button" class="active" data-view="risk" aria-pressed="true">Risk</button>
  </div>
  <details class="filters" id="filters" open>
    <summary class="filters-toggle">Filters</summary>
    <div class="filter-bar" role="group" aria-label="Filters">
      <input id="search" type="search" aria-label="Search findings" placeholder="Search asset, component, CVE, scanner rule, IAM/RBAC, network, owner">
      <select id="tier" aria-label="Minimum priority">
        <option value="informational">All priorities</option>
        <option value="urgent">Urgent only</option>
        <option value="high">High or urgent</option>
        <option value="medium">Medium or higher</option>
        <option value="low">Low or higher</option>
      </select>
      <select id="exposure" aria-label="Network exposure">
        <option value="">All exposures</option>
      </select>
      <select id="findingType" aria-label="Finding type">
        <option value="">All finding types</option>
        <option value="dependency_vulnerability">Dependency vulnerabilities</option>
        <option value="static_code_weakness">Static scanner findings (SAST)</option>
        <option value="dynamic_runtime_observation">Runtime scanner findings (DAST)</option>
        <option value="cloud_posture_finding">Cloud posture findings (CSPM)</option>
        <option value="correlated_security_finding">Correlated security findings</option>
      </select>
      <select id="confidence" aria-label="Evidence confidence">
        <option value="">All confidence</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select id="evidenceLayer" aria-label="Evidence layer">
        <option value="">All evidence layers</option>
      </select>
      <select id="topLimit" aria-label="Result limit">
        <option value="50">Top 50</option>
        <option value="100">Top 100</option>
        <option value="">All findings</option>
      </select>
      <label class="check"><input id="highestPerAsset" type="checkbox" checked> highest risk per asset</label>
      <label class="check"><input id="activeOnly" type="checkbox" checked> hide excepted findings</label>
      <span class="filter-actions">
        <button id="fit" class="btn-quiet" type="button" title="Fit the current graph into the visible area">Fit</button>
        <button id="reset" class="btn-quiet" type="button" title="Reset graph zoom and pan">Reset</button>
      </span>
    </div>
  </details>
</section>
<main class="layout" id="layout">
  <aside class="left-panel" id="leftPanel" aria-label="Risk list">
    <div id="riskSidebar"></div>
  </aside>
  <div class="pane-canvas">
    <section class="evidence-chain" id="evidenceChain" aria-labelledby="chainTitle">
      <div class="chain-head">
        <h2 class="chain-title" id="chainTitle">Evidence chain</h2>
        <p class="chain-verdict" id="chainVerdict"></p>
      </div>
      <div class="chain-track" id="chainTrack" aria-describedby="chainHelp"></div>
      <p class="chain-note" id="chainNote"></p>
      <p class="visually-hidden" id="chainHelp">Each link names one evidence step. A link is proven, blocked by a control, or unknown. Unknown links are dashed and outlined, and name the evidence that is missing.</p>
    </section>
    <section class="graph-shell" id="graphShell">
      <!-- group, not img. role="img" makes the subtree a presentational leaf, so
           the 28 node buttons and 24 edges inside were tab stops that no screen
           reader could see: 52 stops announcing one image label. A group keeps
           the label and leaves its children in the tree. -->
      <div id="graph" role="group" aria-label="Attack path graph" aria-describedby="graphAlt">
        <div id="surface">
          <!-- Chromium maps a bare svg to an unnamed img node. It is a container
               for the edges, which name themselves, so it is a labelled group. -->
          <svg id="edges" role="group" aria-label="Graph connections"></svg>
          <div id="cards"></div>
        </div>
      </div>
      <div class="board" id="board" tabindex="0" role="region" aria-label="Risk scenario table"></div>
      <p class="print-graph-note" id="printGraphNote"></p>
      <p class="print-portrait-note">This diagram is omitted because the sheet is portrait and the graph is wider than it. Print landscape to include it. The evidence chain above and the risk list below carry the same items, complete, as text.</p>
      <output class="graph-scale" id="graphScale" aria-live="off"></output>
      <!-- Fit's outcome, announced on activation only. The scale readout beside
           it is aria-live="off" on purpose: a live region that fires on every
           wheel tick is noise, and it is updated by panning as well as by Fit. -->
      <p class="visually-hidden" id="fitStatus" role="status" aria-live="polite"></p>
      <p id="graphAlt" class="visually-hidden">Nodes and edges in this graph are reachable with Tab, and each one names its evidence state. The same items are also listed as text, with their evidence state and priority, in the risk list: use the skip link at the top of the report to jump straight to it.</p>
    </section>
    <aside class="right-panel" aria-label="Detail panel">
      <div class="legend" aria-label="Graph legend">
        <span><i class="swatch swatch-confirmed" aria-hidden="true"></i>confirmed path</span>
        <span><i class="swatch swatch-blocked" aria-hidden="true"></i>blocked by a control</span>
        <span><i class="swatch swatch-internal" aria-hidden="true"></i>internal pivot</span>
        <span><i class="swatch swatch-structural" aria-hidden="true"></i>structural step, no state claim</span>
        <span><i class="swatch swatch-unknown" aria-hidden="true"></i>unknown, evidence missing</span>
      </div>
      <section class="details" id="details" aria-label="Selected item"></section>
      <section class="finding-list" id="riskListRegion" tabindex="-1" aria-labelledby="visibleListTitle">
        <h2 id="visibleListTitle">Visible Risk Scenarios</h2>
        <div id="findingList"></div>
      </section>
    </aside>
  </div>
</main>
<script id="report-data" type="application/json">__REPORT_DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById("report-data").textContent);
const tierRank = {informational: 0, low: 1, medium: 2, high: 3, urgent: 4};
const exposureRank = {unknown: 0, isolated: 1, private: 1, internal: 2, external: 3, public: 4};
const assetById = new Map((DATA.assets || []).map(asset => [asset.id, asset]));
const vulnerabilityByFindingKey = new Map((DATA.vulnerabilities || []).map(vuln => [vuln.findingKey, vuln]));
const attackPathByFindingKey = new Map((DATA.attackPaths || []).map(path => [path.findingKey, path]));
const scenarioById = new Map((DATA.riskScenarios || []).map(scenario => [scenario.id, scenario]));
const attackPathGroupById = new Map((DATA.attackPathGroups || []).map(group => [group.id, group]));
const attackSurfaceById = new Map((DATA.attackSurfaces || []).map(surface => [surface.id, surface]));
const scenarioByFindingKey = new Map();
for (const scenario of DATA.riskScenarios || []) {
  for (const findingKey of scenario.findingKeys || []) {
    if (!scenarioByFindingKey.has(findingKey)) scenarioByFindingKey.set(findingKey, scenario);
  }
}
const vulnerabilitiesByAssetId = new Map();
for (const vuln of DATA.vulnerabilities || []) {
  if (!vulnerabilitiesByAssetId.has(vuln.assetId)) vulnerabilitiesByAssetId.set(vuln.assetId, []);
  vulnerabilitiesByAssetId.get(vuln.assetId).push(vuln);
}
const networkPathsByAssetId = new Map();
for (const path of DATA.networkPaths || []) {
  for (const assetId of pathAssetIds(path)) {
    if (!networkPathsByAssetId.has(assetId)) networkPathsByAssetId.set(assetId, []);
    networkPathsByAssetId.get(assetId).push(path);
  }
}
for (const paths of networkPathsByAssetId.values()) {
  paths.sort((a, b) => ((exposureRank[b.exposure] ?? 0) - (exposureRank[a.exposure] ?? 0)) || ((tierRank[b.tier] ?? 0) - (tierRank[a.tier] ?? 0)) || ((b.score || 0) - (a.score || 0)));
}
const entryWidth = 210;
const entryHeight = 96;
// Kept in step with CARD_LAYOUT in visual_layout.py, which is the Python mirror
// of these numbers; change one and change the other.
const pathWidth = 340;
const pathHeight = 152;
const assetWidth = 410;
const assetHeight = 292;
const vulnWidth = 500;
const vulnHeight = 112;
const rowGap = 64;
const vulnGap = 16;
const entryX = 56;
const pathX = 318;
const assetX = 712;
const vulnX = 1182;
const laneY = 28;
const firstRowY = 78;
const archZoneWidth = 360;
const archZoneGap = 22;
const archItemGap = 14;
const archMarginX = 46;
const archMarginY = 58;
const archZoneHeader = 74;
// Hops, entries and assets share one width inside a zone: they line up, and at
// 292px the label keeps its room once the chips have taken theirs.
const archHopWidth = 292;
const archHopHeight = 68;
const archEntryWidth = 292;
const archEntryHeight = 92;
const archAssetWidth = 292;
const archAssetHeight = 152;
const attackEntryX = 58;
const attackPathX = 338;
const attackAssetX = 742;
const attackRiskX = 1110;
const attackLaneY = 70;
const attackFirstRowY = 120;
const attackEntryWidth = 226;
const attackEntryHeight = 94;
const attackPathWidth = 342;
const attackPathHeight = 132;
const attackAssetWidth = 306;
const attackAssetHeight = 142;
const attackRiskWidth = 330;
const attackRiskHeight = 110;
const attackAssetGap = 14;
const attackRowGap = 42;
const graph = document.getElementById("graph");
const graphShell = document.getElementById("graphShell");
const graphScale = document.getElementById("graphScale");
const fitStatus = document.getElementById("fitStatus");
const printNote = document.getElementById("printGraphNote");
const board = document.getElementById("board");
const chainTrack = document.getElementById("chainTrack");
const chainVerdict = document.getElementById("chainVerdict");
const chainNote = document.getElementById("chainNote");
const layoutRoot = document.getElementById("layout");
const riskSidebar = document.getElementById("riskSidebar");
const surface = document.getElementById("surface");
const edgesSvg = document.getElementById("edges");
const cards = document.getElementById("cards");
const details = document.getElementById("details");
const search = document.getElementById("search");
const tier = document.getElementById("tier");
const exposure = document.getElementById("exposure");
const findingType = document.getElementById("findingType");
const confidence = document.getElementById("confidence");
const evidenceLayer = document.getElementById("evidenceLayer");
const topLimit = document.getElementById("topLimit");
const highestPerAsset = document.getElementById("highestPerAsset");
const activeOnly = document.getElementById("activeOnly");
const viewTabs = [...document.querySelectorAll(".view-tabs button")];
let viewMode = "risk";
let selected = null;
let transform = {x: 30, y: 30, scale: 1};
let drag = null;
let nodeDrag = null;
let suppressNodeClickId = null;
const nodePositionOverrides = new Map();
const expandedGraphNodes = new Set();
let surfaceBounds = {width: 1000, height: 700};

// Spec floor: nothing in the report may render below 11px, graph labels included.
// #surface lifts its two smallest steps to --text-sm, so 13px is the smallest base
// size inside the zoom surface and 11/13 is the smallest fit scale that keeps it
// legible. Content taller or wider than that is panned, never shrunk past the floor.
const MIN_GRAPH_TEXT_PX = 11;
const GRAPH_BASE_TEXT_PX = 13;
const MIN_FIT_SCALE = MIN_GRAPH_TEXT_PX / GRAPH_BASE_TEXT_PX;
const MAX_FIT_SCALE = 1.2;
const FIT_PADDING = 24;
// Print targets a landscape sheet, which the stylesheet asks for: the risk board
// is seven columns wide and portrait cropped 94px off it. Content width at the
// 10mm @page margin is 1047px on A4 landscape and 980px on US Letter landscape,
// so 960 clears either. Content height at the same margin is 718px on A4
// landscape and 691px on US Letter landscape, so 680 clears either; a diagram
// that will not fit that box whole is withdrawn and named rather than sliced
// through its nodes by a page break the stylesheet cannot suppress.
const PRINT_CONTENT_PX = 960;
const PRINT_CONTENT_HEIGHT_PX = 680;
// Below this the diagram stops being a diagram. 9px is ~6.75pt, about the floor
// for a printed mono identifier. A view whose graph cannot be drawn whole at or
// above it is not printed shrunk and not printed cropped: it is replaced by a
// statement of what was left out. Silently printing 30% of an attack graph is
// the same failure as calling an unproven path safe.
const PRINT_MIN_TEXT_PX = 9;
const PRINT_MIN_SCALE = PRINT_MIN_TEXT_PX / GRAPH_BASE_TEXT_PX;
// Budgets are the character counts that fit the fixed label boxes: two lines for
// the whole string, one line for the longest single token, since a box can wrap
// between words but never inside one.
const GRAPH_LABEL_BUDGET = 44;
const GRAPH_LABEL_TOKEN = 23;
const GRAPH_SUBTITLE_BUDGET = 48;
const GRAPH_SUBTITLE_TOKEN = 26;
const CHAIN_NAME_BUDGET = 24;
const CHIP_TEXT_BUDGET = 42;
const CHIP_TOKEN_BUDGET = 30;
const CARD_TITLE_BUDGET = 68;
const CARD_SUB_BUDGET = 96;
const CARD_TOKEN_BUDGET = 26;
const boardViews = new Set(["risk", "findings"]);
// Reader-facing names for the views, used where a sentence has to name one.
const VIEW_TITLES = {
  attack: "attack paths",
  architecture: "architecture",
  evidence: "evidence paths",
  risk: "risk",
};

/* === The evidence-state model ============================================
   One rule, used by every mark in every view. A step is only claimed as proven
   when the data names the evidence layer it was collected from; "Context" is
   the builder's fallback for a step nothing was collected for, so it is the
   absence of evidence, not a weak form of it. Everything unnamed defaults to
   unknown, never the other way round: a positive claim the data does not
   support is worse than no claim at all, and "missing evidence is never
   treated as safe" is the one thing this report may not get wrong.

   The five states are exactly the five the legend prints, and each one is a hue
   AND a texture. Severity never enters here: it rides on stroke width and on
   the labelled chips, because the four severity hues are not separable under
   deuteranopia and the legend does not name them. */
const CONTEXT_EVIDENCE_LAYER = "context";
const MARK_STATE_TEXT = {
  confirmed: "confirmed by evidence",
  blocked: "blocked by a control",
  internal: "internal pivot",
  structural: "structural step, no state claim",
  unknown: "unknown, evidence missing for this step",
};

function hasCollectedEvidence(item) {
  const layer = String((item && item.evidenceLayer) || "").trim().toLowerCase();
  return Boolean(layer) && layer !== CONTEXT_EVIDENCE_LAYER;
}

// A node on a route: its own recorded state first, then the evidence test.
function nodeMarkState(node) {
  if (!node) return "unknown";
  if (node.state === "blocked") return "blocked";
  if (node.state === "unknown" || node.type === "unknown") return "unknown";
  return hasCollectedEvidence(node) ? "confirmed" : "unknown";
}

// A network route -- an attack-path group, a network path or an architecture
// hop. All three carry the same exposure/pathType/blockers vocabulary.
function routeMarkState(route) {
  if (!route) return "unknown";
  if ((route.blockers || []).length) return "blocked";
  const exposure = String(route.exposure || "unknown").toLowerCase();
  const pathType = String(route.pathType || "").toLowerCase();
  if (exposure === "unknown" || pathType === "unresolved") return "unknown";
  // No ingress was observed into this route: the boundary is what stops it, and
  // a stop is what the blocked mark and its end-cap say.
  if (pathType === "no_observed_ingress" || exposure === "private" || exposure === "isolated") return "blocked";
  if (exposure === "internal" || route.surfaceMode === "lateral") return "internal";
  return "confirmed";
}

// One step along a route. A step is never stronger than the node it arrives at.
function stepMarkState(node, route) {
  const state = nodeMarkState(node);
  return state === "confirmed" ? routeMarkState(route) : state;
}

// A finding's own reachability. "SBOM only", "no source rule" and "absent from
// the scanned source" are all statements that source usage was NOT observed, so
// the mark that carries them is the unknown one.
const UNPROVEN_REACHABILITY = new Set(["package_present", "unknown_due_to_no_rule", "absent", "unknown", ""]);

function findingMarkState(finding) {
  if (!finding) return "unknown";
  return UNPROVEN_REACHABILITY.has(String(finding.reachability || "").toLowerCase()) ? "unknown" : "confirmed";
}

const THEME_KEY = "ra-theme";
const THEME_ORDER = ["auto", "light", "dark"];
const THEME_LABEL = {auto: "Auto", light: "Light", dark: "Dark"};
const THEME_HINT = {auto: "follows your system setting", light: "always light", dark: "always dark"};
let themeMode = "auto";

function readStoredTheme() {
  try {
    const stored = window.localStorage.getItem(THEME_KEY);
    return THEME_ORDER.includes(stored) ? stored : "auto";
  } catch (error) {
    return "auto";
  }
}

function storeTheme(mode) {
  try {
    window.localStorage.setItem(THEME_KEY, mode);
  } catch (error) {
    /* storage is denied on some file:// origins; the theme still applies for this session */
  }
}

function applyTheme(mode) {
  themeMode = THEME_ORDER.includes(mode) ? mode : "auto";
  if (themeMode === "auto") {
    document.documentElement.removeAttribute("data-theme");
  } else {
    document.documentElement.setAttribute("data-theme", themeMode);
  }
  const toggle = document.getElementById("themeToggle");
  const next = THEME_ORDER[(THEME_ORDER.indexOf(themeMode) + 1) % THEME_ORDER.length];
  toggle.dataset.theme = themeMode;
  document.getElementById("themeLabel").textContent = THEME_LABEL[themeMode];
  toggle.setAttribute("aria-label", `Theme: ${THEME_LABEL[themeMode]}, ${THEME_HINT[themeMode]}. Activate for ${THEME_LABEL[next]}.`);
  toggle.title = `Theme: ${THEME_LABEL[themeMode]} (${THEME_HINT[themeMode]})`;
}

function setupTheme() {
  applyTheme(readStoredTheme());
  document.getElementById("themeToggle").addEventListener("click", () => {
    const next = THEME_ORDER[(THEME_ORDER.indexOf(themeMode) + 1) % THEME_ORDER.length];
    applyTheme(next);
    storeTheme(next);
  });
}

function setupHeaderActions() {
  document.getElementById("printReport").addEventListener("click", () => window.print());
  // The print sheet gives the graph a fixed frame; refit so it lands inside it.
  window.addEventListener("beforeprint", fitGraph);
  document.getElementById("exportData").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(DATA, null, 2)], {type: "application/json"});
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "reachability-report.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  });
}

function setupFilterDisclosure() {
  const filters = document.getElementById("filters");
  const wide = window.matchMedia("(min-width: 768px)");
  const sync = () => { filters.open = wide.matches; };
  sync();
  if (wide.addEventListener) wide.addEventListener("change", sync);
}

function init() {
  document.getElementById("generated").textContent = `${DATA.metadata.tool} ${DATA.metadata.version} generated ${DATA.metadata.generated_at}`;
  setupTheme();
  setupHeaderActions();
  setupFilterDisclosure();
  setupViewportRefit();
  chainTrack.addEventListener("scroll", updateChainOverflow, {passive: true});
  renderStats();
  for (const item of Object.keys(DATA.stats.exposures || {}).sort()) {
    const option = document.createElement("option");
    option.value = item;
    option.textContent = item;
    exposure.appendChild(option);
  }
  const layers = new Set((DATA.attackPaths || []).flatMap(path => path.evidenceLayers || []));
  for (const item of [...layers].sort()) {
    const option = document.createElement("option");
    option.value = item;
    option.textContent = item;
    evidenceLayer.appendChild(option);
  }
  for (const control of [search, tier, exposure, findingType, confidence, evidenceLayer, topLimit, highestPerAsset, activeOnly]) {
    control.addEventListener("input", render);
    control.addEventListener("change", render);
  }
  // The readout is aria-live="off" while panning, which is right: a live region
  // that fires on every wheel tick is noise. It is switched on for the moment
  // after Fit is pressed, because that is the one activation whose whole
  // outcome may be "nothing moved, and here is why".
  const fitButton = document.getElementById("fit");
  fitButton.addEventListener("click", () => {
    fitGraph();
    const message = fitOutcomeMessage();
    fitButton.title = message;
    if (!fitStatus) return;
    // Re-announced through empty so an unchanged outcome still reaches a screen
    // reader: when the fit is clamped, "nothing moved" is the whole report.
    fitStatus.textContent = "";
    window.requestAnimationFrame(() => { fitStatus.textContent = message; });
  });
  for (const tab of viewTabs) {
    tab.addEventListener("click", () => {
      viewMode = tab.dataset.view || "architecture";
      selected = null;
      render();
      window.setTimeout(fitGraph, 0);
    });
  }
  document.getElementById("reset").addEventListener("click", () => {
    transform = {x: 30, y: 30, scale: 1};
    applyTransform();
  });
  graph.addEventListener("wheel", onWheel, {passive: false});
  graph.addEventListener("mousedown", onMouseDown);
  graph.addEventListener("focusin", event => panFocusIntoView(event.target));
  graph.addEventListener("scroll", resetGraphScroll);
  window.addEventListener("mousemove", onMouseMove);
  window.addEventListener("mouseup", onMouseUp);
  render();
  window.setTimeout(fitGraph, 0);
}

// The summary row is severity weighted: a non-zero urgent or high count is what
// a reader acts on, so it is loud. A zero is context, not an alert, and the
// scanner-coverage counts stay recessive whatever their value.
function renderStats() {
  const stats = document.getElementById("stats");
  const s = DATA.stats;
  const types = s.finding_types || {};
  const unscanned = "no findings of this type were ingested. That is scanner coverage, not an all-clear.";
  const groups = [
    [
      {label: "urgent", value: s.tiers.urgent || 0, tone: "urgent"},
      {label: "high", value: s.tiers.high || 0, tone: "high"},
    ],
    [
      {label: "findings", value: s.finding_count || 0, tone: "neutral"},
      {label: "assets", value: s.artifact_count || 0, tone: "neutral"},
      {label: "components", value: s.component_count || 0, tone: "neutral"},
    ],
    [
      {label: "static", value: types.static_code_weakness || 0, tone: "quiet", hint: unscanned},
      {label: "runtime", value: types.dynamic_runtime_observation || 0, tone: "quiet", hint: unscanned},
      {label: "posture", value: types.cloud_posture_finding || 0, tone: "quiet", hint: unscanned},
    ],
  ];
  stats.replaceChildren(...groups.map(items => {
    const group = document.createElement("div");
    group.className = "stat-group";
    group.append(...items.map(item => {
      const cell = document.createElement("div");
      const prominent = (item.tone === "urgent" || item.tone === "high") && item.value > 0;
      const unknownCoverage = item.hint && item.value === 0;
      cell.className = `stat tone-${item.tone}${prominent ? " is-prominent" : ""}${item.value === 0 ? " is-zero" : ""}${unknownCoverage ? " is-unscanned" : ""}`;
      const value = document.createElement("span");
      value.className = "stat-value";
      value.textContent = String(item.value);
      const label = document.createElement("span");
      label.className = "stat-label";
      label.textContent = item.label;
      if (unknownCoverage) cell.title = `${item.label}: ${item.hint}`;
      cell.append(value, label);
      return cell;
    }));
    return group;
  }));
}

// "Clear a filter" is the wrong instruction when the report has no findings at
// all: the two cases are different claims and they get different sentences.
function emptyListMessage(kind) {
  return DATA.findings.length
    ? `No ${kind} match the current filters. Clear one or more filters to see more results.`
    : `This report contains no ${kind}. See the detail panel for what was scanned and what was absent.`;
}

function emptyListElement(kind) {
  const empty = document.createElement("div");
  empty.className = "empty";
  empty.textContent = emptyListMessage(kind);
  return empty;
}

// What was scanned, stated plainly. A report with nothing to show must say what
// it looked at, because "no findings" and "no inputs" are not the same claim.
function coverageSummary() {
  const meta = DATA.metadata || {};
  const scanned = [
    ["SBOM documents", meta.sbom_count],
    ["vulnerability records", meta.vulnerability_records],
    ["Terraform resources", meta.terraform_resources],
    ["Kubernetes resources", meta.kubernetes_resources],
    ["source files", meta.source_files],
    ["scanner evidence records", meta.security_evidence_records],
    ["external source evidence records", meta.external_source_evidence_records],
  ];
  return {
    present: scanned.filter(entry => Number(entry[1]) > 0).map(entry => `${entry[1]} ${entry[0]}`),
    absent: scanned.filter(entry => !Number(entry[1])).map(entry => entry[0]),
    profile: meta.analysis_profile || "unknown",
  };
}

function findingText(finding) {
  return JSON.stringify(finding).toLowerCase();
}

function canonicalFindingType(value) {
  return value;
}

function isSecurityFinding(value) {
  return canonicalFindingType(value) === "static_code_weakness" || canonicalFindingType(value) === "dynamic_runtime_observation" || canonicalFindingType(value) === "cloud_posture_finding";
}

function isRuntimeFinding(value) {
  return canonicalFindingType(value) === "dynamic_runtime_observation";
}

function isStaticFinding(value) {
  return canonicalFindingType(value) === "static_code_weakness";
}

// Mirrors attack_path_view._finding_type_label, including its passthrough for unknown
// future types: a ternary chain silently files anything it does not know into the wrong
// bucket, which is how cloud posture findings came to be labelled a code weakness.
function findingTypeLabel(value) {
  const canonical = canonicalFindingType(value);
  const labels = {
    dependency_vulnerability: "dependency vulnerability",
    static_code_weakness: "static code weakness",
    dynamic_runtime_observation: "dynamic runtime observation",
    correlated_security_finding: "correlated security finding",
    cloud_posture_finding: "cloud posture finding",
  };
  return labels[canonical] || String(canonical).replace(/_/g, " ");
}

function assetText(asset) {
  return JSON.stringify(asset).toLowerCase();
}

function attackPathText(path) {
  return path ? JSON.stringify(path).toLowerCase() : "";
}

function scenarioText(scenario) {
  return (scenario.searchText || JSON.stringify(scenario)).toLowerCase();
}

function scenarioMatchesFindingType(scenario, typeFilter) {
  if (!typeFilter) return true;
  return (scenario.findingTypes || []).map(canonicalFindingType).includes(typeFilter);
}

function scenarioMatchesEvidenceLayer(scenario, layerFilter) {
  if (!layerFilter) return true;
  for (const findingKey of scenario.findingKeys || []) {
    if (((attackPathByFindingKey.get(findingKey) || {}).evidenceLayers || []).includes(layerFilter)) return true;
  }
  return false;
}

function visibleRiskScenarios() {
  const query = search.value.trim().toLowerCase();
  const minTier = tierRank[tier.value] ?? 0;
  const exposureFilter = exposure.value;
  const typeFilter = findingType.value;
  const confidenceFilter = confidence.value;
  const layerFilter = evidenceLayer.value;
  const limit = topLimit.value ? Number(topLimit.value) : 0;
  let rows = (DATA.riskScenarios || [])
    .filter(s => (tierRank[s.tier] ?? 0) >= minTier)
    .filter(s => !activeOnly.checked || s.status !== "Excepted")
    .filter(s => !exposureFilter || (s.exposure || "unknown") === exposureFilter)
    .filter(s => scenarioMatchesFindingType(s, typeFilter))
    .filter(s => !confidenceFilter || (s.confidence || "low") === confidenceFilter)
    .filter(s => scenarioMatchesEvidenceLayer(s, layerFilter))
    .filter(s => !query || scenarioText(s).includes(query))
    .sort((a, b) => (tierRank[b.tier] - tierRank[a.tier]) || ((b.score || 0) - (a.score || 0)) || String(a.title || "").localeCompare(String(b.title || "")));
  return limit ? rows.slice(0, limit) : rows;
}

function visibleFindings() {
  const query = search.value.trim().toLowerCase();
  const minTier = tierRank[tier.value] ?? 0;
  const exposureFilter = exposure.value;
  const typeFilter = findingType.value;
  const confidenceFilter = confidence.value;
  const layerFilter = evidenceLayer.value;
  const limit = topLimit.value ? Number(topLimit.value) : 0;
  const attackPathByKey = new Map((DATA.attackPaths || []).map(path => [path.findingKey, path]));
  let rows = DATA.findings
    .filter(f => (tierRank[f.tier] ?? 0) >= minTier)
    .filter(f => !activeOnly.checked || f.policy_status !== "excepted")
    .filter(f => !exposureFilter || ((f.context || {}).exposure || "unknown") === exposureFilter)
    .filter(f => !typeFilter || canonicalFindingType(f.finding_type) === typeFilter)
    .filter(f => !confidenceFilter || (f.confidence || "low") === confidenceFilter)
    .filter(f => !layerFilter || ((attackPathByKey.get(f.key) || {}).evidenceLayers || []).includes(layerFilter))
    .filter(f => !query || findingText(f).includes(query) || assetText(assetForFinding(f)).includes(query) || attackPathText(attackPathByKey.get(f.key)).includes(query))
    .sort((a, b) => (tierRank[b.tier] - tierRank[a.tier]) || (b.score - a.score));
  if (highestPerAsset.checked) {
    const seenAssets = new Set();
    rows = rows.filter(finding => {
      const assetName = (finding.artifact || {}).name || "unknown";
      if (seenAssets.has(assetName)) return false;
      seenAssets.add(assetName);
      return true;
    });
  }
  return limit ? rows.slice(0, limit) : rows;
}

function assetForFinding(finding) {
  const assetId = `asset:${finding.artifact.name}`;
  return assetById.get(assetId) || {};
}

function render() {
  for (const tab of viewTabs) {
    const active = (tab.dataset.view || "architecture") === viewMode;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-pressed", String(active));
  }
  layoutRoot.classList.toggle("with-left-sidebar", viewMode === "attack");
  const riskScenarios = visibleRiskScenarios();
  const visibleScenarioIds = new Set(riskScenarios.map(scenario => scenario.id));
  const visibleGroupIds = new Set((DATA.attackPathGroups || []).filter(group => (group.scenarioIds || []).some(id => visibleScenarioIds.has(id))).map(group => group.id));
  const visibleSurfaceIds = new Set((DATA.attackPathGroups || []).filter(group => visibleGroupIds.has(group.id)).map(group => group.surfaceId).filter(Boolean));
  const findings = visibleFindings();
  const visibleKeys = new Set(findings.map(finding => finding.key));
  const visibleVulns = findings.map(finding => vulnerabilityByFindingKey.get(finding.key)).filter(Boolean);
  const visibleAssetIds = new Set(visibleVulns.map(vuln => vuln.assetId));
  const visibleAssets = DATA.assets.filter(asset => visibleAssetIds.has(asset.id));
  const visibleNetworkPaths = uniqueById(visibleAssets.map(asset => primaryNetworkPath(asset)).filter(Boolean));
  const visibleEntries = uniqueEntries(visibleNetworkPaths);
  const visibleNetworkIds = new Set(visibleNetworkPaths.flatMap(path => [path.id, entryNodeId(path)]));
  // Stale selections are dropped, then a default is chosen, before anything is
  // laid out: the board row highlight and the evidence chain both read `selected`
  // while they render, so resolving it afterwards left them one frame behind.
  const selectedAssetIds = new Set(pathAssetIds(selected || {}));
  if (selected && (selected.scenarioKind === "scenario" || selected.attackKind === "scenario") && !visibleScenarioIds.has(selected.id)) {
    selected = null;
  }
  if (selected && selected.attackKind === "group" && !visibleGroupIds.has(selected.id)) {
    selected = null;
  }
  if (selected && selected.attackKind === "surface" && !visibleSurfaceIds.has(selected.id)) {
    selected = null;
  }
  if (selected && (selected.attackKind === "graphNode" || selected.attackKind === "graphEdge") && selected.path && !visibleGroupIds.has(selected.path.id)) {
    selected = null;
  }
  if (selected && !selected.attackKind && !selected.architectureKind && !visibleAssetIds.has(selected.id) && !visibleKeys.has(selected.findingKey) && !visibleNetworkIds.has(selected.id) && !visibleAssetIds.has(selected.assetId) && ![...selectedAssetIds].some(assetId => visibleAssetIds.has(assetId))) {
    selected = null;
  }
  ensureDefaultSelection(riskScenarios, visibleVulns);
  graphShell.classList.toggle("board-mode", boardViews.has(viewMode));
  if (viewMode === "attack") {
    const layout = layoutAttackPaths(visibleScenarioIds);
    edgesSvg.replaceChildren(renderEdgeDefs(), ...renderAttackPathEdges(layout));
    riskSidebar.replaceChildren(renderAttackRiskSidebar(riskScenarios));
    cards.replaceChildren(...layout.graphNodes.map(node => renderAttackGraphNode(node.datum, node.position)));
  } else if (viewMode === "evidence") {
    riskSidebar.replaceChildren();
    const layout = layoutCards(visibleAssets, visibleVulns, visibleNetworkPaths);
    edgesSvg.replaceChildren(renderEdgeDefs(), ...renderEdges(visibleVulns, visibleNetworkPaths, layout));
    cards.replaceChildren(
      ...renderLaneLabels(),
      ...visibleEntries.map(entry => renderEntryCard(entry, layout.entries.get(entry.id))),
      ...visibleNetworkPaths.map(path => renderNetworkPathCard(path, layout.networkPaths.get(path.id))),
      ...visibleAssets.map(asset => renderAssetCard(asset, layout.assets.get(asset.id))),
      ...visibleVulns.map(vuln => renderVulnerabilityCard(vuln, layout.vulnerabilities.get(vuln.id)))
    );
  } else if (boardViews.has(viewMode)) {
    riskSidebar.replaceChildren();
    const layout = layoutRiskScenarios(riskScenarios);
    edgesSvg.replaceChildren(renderEdgeDefs());
    cards.replaceChildren();
    board.replaceChildren(renderRiskBoard(riskScenarios, layout));
  } else {
    riskSidebar.replaceChildren();
    const layout = layoutArchitecture(visibleAssetIds, visibleKeys);
    edgesSvg.replaceChildren(renderEdgeDefs(), ...renderArchitectureEdges(layout));
    cards.replaceChildren(
      ...layout.zones.map(zone => renderArchitectureZone(zone.datum, zone.position)),
      ...layout.hops.map(hop => renderArchitectureHop(hop.datum, hop.position)),
      ...layout.assets.map(asset => renderArchitectureAsset(asset.datum, asset.position))
    );
  }
  edgesSvg.setAttribute("width", surfaceBounds.width);
  edgesSvg.setAttribute("height", surfaceBounds.height);
  surface.style.width = `${surfaceBounds.width}px`;
  surface.style.height = `${surfaceBounds.height}px`;

  if (viewMode === "risk" || viewMode === "attack") {
    renderScenarioList(riskScenarios);
  } else {
    renderFindingList(findings);
  }
  renderEvidenceChain(selected);
  renderDetails(selected);
  updateSkipLinkTarget();
  titleClippedChips();
  applyTransform();
}

// A chip the fixed-width pill cut has no other way to give its value back.
// shortenLabel only knows about the strings it shortened itself, so anything CSS
// ellipsised afterwards -- "network exposure: unk…" was the one that mattered --
// would otherwise be unrecoverable on hover, on focus and in print.
function titleClippedChips() {
  for (const chip of [...cards.querySelectorAll(".chip"), ...board.querySelectorAll(".chip")]) {
    if (chip.title) continue;
    if (chip.scrollWidth > chip.clientWidth + 0.5) chip.title = chip.textContent;
  }
}

// The skip link is the documented route to the graph's text equivalent, so it
// has to point at whichever list is actually on screen: in the Attack view the
// right-rail list is display:none and the strip in the left sidebar is the list,
// so a fixed href sent the reader to a hidden element.
function updateSkipLinkTarget() {
  const link = document.querySelector(".skip-link");
  if (!link) return;
  const sidebar = riskSidebar && riskSidebar.querySelector(".attack-risk-sidebar");
  if (viewMode === "attack" && sidebar) {
    sidebar.id = "attackRiskSidebar";
    sidebar.tabIndex = -1;
    link.setAttribute("href", "#attackRiskSidebar");
  } else {
    link.setAttribute("href", "#riskListRegion");
  }
}

// On load the reader should land on the risk that matters, not on instructions.
// Every view gets a default: the top scenario where scenarios drive the view, the
// top finding where findings do, and the scenario's asset in the architecture view.
function ensureDefaultSelection(scenarios, vulnerabilities) {
  if (selected) return;
  const topScenario = scenarios.length
    ? {...scenarios[0], scenarioKind: "scenario", attackKind: "scenario"}
    : null;
  if (viewMode === "evidence") {
    selected = vulnerabilities[0] || topScenario;
    return;
  }
  if (viewMode === "architecture" && topScenario) {
    selected = assetById.get(topScenario.assetId) || topScenario;
    return;
  }
  selected = topScenario || vulnerabilities[0] || null;
}

function layoutAttackPaths(visibleScenarioIds) {
  const attackGroups = (DATA.attackPathGroups || [])
    .map(group => ({
      ...group,
      assets: (group.assets || []).filter(asset => visibleScenarioIds.has(asset.id)).map(asset => scenarioById.get(asset.id) || asset),
    }))
    .filter(group => group.assets.length)
    .sort((a, b) => (tierRank[b.tier] - tierRank[a.tier]) || ((b.score || 0) - (a.score || 0)) || String(a.title || "").localeCompare(String(b.title || "")));
  const attackSurfaces = groupAttackSurfaces(attackGroups);
  if (selected && selected.attackKind === "group" && !attackGroups.some(path => path.id === selected.id)) {
    selected = null;
  }
  if (selected && selected.attackKind === "surface" && !attackSurfaces.some(surface => surface.id === selected.id)) {
    selected = null;
  }
  const selectedGroupId = selected?.attackKind === "group"
    ? selected.id
    : selected?.attackKind === "scenario"
      ? selected.attackPathGroupId
      : selected?.attackKind === "node" || selected?.attackKind === "graphNode" || selected?.attackKind === "graphEdge"
        ? selected.path?.id
        : null;
  if (selected && selected.attackKind === "node" && selectedGroupId && !attackGroups.some(path => path.id === selectedGroupId)) {
    selected = null;
  }
  const selectedSurfaceId = selected?.attackKind === "surface"
    ? selected.id
    : selectedGroupId
      ? (attackGroups.find(path => path.id === selectedGroupId) || {}).surfaceId
      : null;
  const selectedSurface = selectedSurfaceId
    ? attackSurfaces.find(surface => surface.id === selectedSurfaceId) || attackSurfaces[0]
    : attackSurfaces[0];
  const selectedRouteGroups = selectedSurface ? selectedSurface.groups || [] : [];

  const positions = new Map();

  const overviewLimit = 14;
  let overviewPaths = uniqueById([...selectedRouteGroups, ...attackGroups]).slice(0, overviewLimit);
  if (!overviewPaths.length) {
    overviewPaths = attackGroups.slice(0, overviewLimit);
  }
  overviewPaths = uniqueById(overviewPaths);

  const graphNodes = [];
  const graphNodeById = new Map();
  const graphEdges = [];
  const graphStartX = 92;
  const entryX = graphStartX;
  const hopStartX = graphStartX + 190;
  const hopGapX = 155;
  const branchGapY = 132;
  const surfaceGapY = 90;
  const nodeSize = 86;
  const entrySize = 106;
  const groupsBySurface = new Map();
  for (const path of overviewPaths) {
    const key = path.surfaceId || "surface:unknown";
    if (!groupsBySurface.has(key)) groupsBySurface.set(key, []);
    groupsBySurface.get(key).push(path);
  }
  const visibleSurfaces = attackSurfaces.filter(surface => groupsBySurface.has(surface.id));
  let currentY = 46;
  const surfaceBlocks = [];
  for (const surface of visibleSurfaces) {
    const groups = groupsBySurface.get(surface.id) || [];
    let branchOffset = 66;
    const branches = groups.map((path, index) => {
      const height = attackBranchHeight(path);
      const branch = {path, index, y: currentY + branchOffset, height};
      branchOffset += height;
      return branch;
    });
    const surfaceHeight = Math.max(190, branchOffset + 36);
    surfaceBlocks.push({
      surface,
      groups,
      branches,
      height: surfaceHeight,
      y: currentY,
      centerY: currentY + surfaceHeight / 2,
    });
    currentY += surfaceHeight + surfaceGapY;
  }
  const outsideBlocks = surfaceBlocks.filter(block => block.surface.surfaceMode === "outside");
  const internetRootId = "attack-entry:internet";
  if (outsideBlocks.length) {
    const outsideRows = outsideBlocks.flatMap(block => block.branches.map(branch => ({path: branch.path, y: branch.y})));
    const rootY = average(outsideRows.map(row => row.y));
    const selectedOutside = selected && selected.attackKind === "surface" && outsideBlocks.some(block => block.surface.id === selected.id);
    const rootScore = Math.max(...outsideBlocks.map(block => Number(block.surface.score || 0)));
    const rootTier = outsideBlocks.reduce((tierValue, block) => strongerTier(tierValue, block.surface.tier), "informational");
    const rootDatum = {
      id: internetRootId,
      attackKind: "graphNode",
      graphKind: "entryRoot",
      graphType: "entry",
      type: "entry",
      label: "Internet / attacker",
      subtitle: "shared outside entry",
      badge: String(outsideRows.length),
      routeCount: outsideRows.length,
      surfaceIds: outsideBlocks.map(block => block.surface.id),
      surfaceTitles: outsideBlocks.map(block => block.surface.title),
      tier: rootTier,
      score: rootScore,
      selected: Boolean(selectedOutside || (selected && selected.id === internetRootId)),
      dimmed: Boolean(selected && selected.attackKind === "surface" && !selectedOutside),
    };
    positions.set(internetRootId, {x: entryX, y: rootY - entrySize / 2, width: entrySize, height: entrySize});
    graphNodes.push({datum: rootDatum, position: positions.get(internetRootId)});
    graphNodeById.set(internetRootId, rootDatum);
  }
  for (const block of surfaceBlocks) {
    const surface = block.surface;
    const groups = block.groups;
    const outsideSurface = surface.surfaceMode === "outside";
    const surfaceNodeId = outsideSurface ? internetRootId : `${surface.id}:graph-entry`;
    const surfaceSelected = selected?.attackKind === "surface" && selected.id === surface.id;
    if (!outsideSurface) {
      positions.set(surfaceNodeId, {x: entryX, y: block.centerY - entrySize / 2, width: entrySize, height: entrySize});
      const surfaceDatum = {
        ...surface,
        id: surfaceNodeId,
        sourceId: surface.id,
        attackKind: "surface",
        graphKind: "entry",
        graphType: surface.surfaceMode === "lateral" ? "lateral" : "entry",
        label: surface.surfaceMode === "lateral" ? "Internal pivot" : surface.entryLabel || "Internet / attacker",
        subtitle: surface.surfaceModeLabel || surface.exposure || "",
        badge: surface.routeCount ? String(surface.routeCount) : "",
        selected: surfaceSelected,
      };
      graphNodes.push({datum: surfaceDatum, position: positions.get(surfaceNodeId)});
      graphNodeById.set(surfaceNodeId, surfaceDatum);
    }
    groups.forEach((path, groupIndex) => {
      const pathSelected = selectedGroupId ? selectedGroupId === path.id : surfaceSelected;
      const dimmed = selectedGroupId ? selectedGroupId !== path.id : selected && selected.attackKind === "surface" ? selected.id !== surface.id : false;
      const routeNodes = compactRouteNodes(graphRouteNodes(path, surface));
      const branch = block.branches[groupIndex] || {y: block.y + 64 + groupIndex * branchGapY};
      const branchY = branch.y;
      let previousNodeId = surfaceNodeId;
      if (!routeNodes.length) {
        const routeId = `${path.id}:graph-route`;
        positions.set(routeId, {x: hopStartX, y: branchY - nodeSize / 2, width: nodeSize, height: nodeSize});
        const routeDatum = attackGraphNodeDatum(routeId, "ingress", path.pathLabel || path.title || "Network route", path.pathType || path.provider || "", path, pathSelected, dimmed);
        graphNodes.push({datum: routeDatum, position: positions.get(routeId)});
        graphNodeById.set(routeId, routeDatum);
        graphEdges.push(attackGraphEdge(surfaceNodeId, routeId, path, pathSelected, dimmed, routeMarkState(path), "Entry to network route"));
        previousNodeId = routeId;
      }
      let previousState = routeMarkState(path);
      routeNodes.forEach((node, nodeIndex) => {
        const viewNodeId = `${path.id}:graph-node:${node.id}`;
        const position = {x: hopStartX + nodeIndex * hopGapX, y: branchY - nodeSize / 2, width: nodeSize, height: nodeSize};
        positions.set(viewNodeId, position);
        const nodeDatum = {
          ...attackGraphNodeDatum(viewNodeId, node.type || "unknown", node.label || node.type || "Node", node.subtitle || node.evidenceLayer || "", path, pathSelected, dimmed),
          rawNodeId: node.id,
          state: node.state || "normal",
          evidenceLayer: node.evidenceLayer,
          confidence: node.confidence,
        };
        graphNodes.push({datum: nodeDatum, position});
        graphNodeById.set(viewNodeId, nodeDatum);
        previousState = stepMarkState(node, path);
        graphEdges.push(attackGraphEdge(previousNodeId, viewNodeId, path, pathSelected, dimmed, previousState, `${path.pathType || "route"} step`));
        previousNodeId = viewNodeId;
      });
      const assetId = `${path.id}:graph-assets`;
      const assetNames = (path.assets || []).map(asset => asset.assetName || asset.title || asset.id).filter(Boolean);
      const assetLabel = assetNames.length === 1 ? assetNames[0] : `${path.assetCount || assetNames.length || 0} assets`;
      const assetX = hopStartX + Math.max(routeNodes.length, 1) * hopGapX + 40;
      positions.set(assetId, {x: assetX, y: branchY - nodeSize / 2, width: nodeSize, height: nodeSize});
      const assetDatum = {
        ...attackGraphNodeDatum(assetId, "workload", assetLabel, path.provider || path.exposure || "", path, pathSelected, dimmed),
        badge: path.assetCount ? String(path.assetCount) : "",
      };
      graphNodes.push({datum: assetDatum, position: positions.get(assetId)});
      graphNodeById.set(assetId, assetDatum);
      graphEdges.push(attackGraphEdge(previousNodeId, assetId, path, pathSelected, dimmed, previousState, "Route reaches workload"));
      const issueId = `${path.id}:graph-findings`;
      positions.set(issueId, {x: assetX + 170, y: branchY - nodeSize / 2, width: nodeSize, height: nodeSize});
      const findingsExpanded = expandedGraphNodes.has(issueId);
      const issueDatum = {
        ...attackGraphNodeDatum(issueId, "vulnerability", `${path.findingCount || 0} findings`, findingsExpanded ? "expanded finding list" : "click to expand finding list", path, pathSelected, dimmed),
        badge: path.findingCount ? String(path.findingCount) : "",
        graphKind: "findingGroup",
        expandable: true,
        expanded: findingsExpanded,
        findingKeys: path.findingKeys || [],
      };
      graphNodes.push({datum: issueDatum, position: positions.get(issueId)});
      graphNodeById.set(issueId, issueDatum);
      // Containment, not reachability: a workload holding findings is structure,
      // and the legend has a word for a step that makes no state claim.
      graphEdges.push(attackGraphEdge(assetId, issueId, path, pathSelected, dimmed, "structural", "Workload has linked findings"));
      if (findingsExpanded) {
        const linkedFindings = (path.findingKeys || []).map(key => vulnerabilityByFindingKey.get(key)).filter(Boolean);
        linkedFindings.forEach((finding, findingIndex) => {
          const findingId = `${issueId}:finding:${findingIndex}:${slug(finding.findingKey || finding.label || "finding")}`;
          const findingY = branchY - ((linkedFindings.length - 1) * 74) / 2 + findingIndex * 74;
          positions.set(findingId, {x: assetX + 340, y: findingY - nodeSize / 2, width: nodeSize, height: nodeSize});
          const findingDatum = {
            id: findingId,
            attackKind: "graphNode",
            graphKind: "finding",
            graphType: "finding",
            type: "finding",
            label: finding.label || finding.findingKey || "Finding",
            subtitle: compactComponent(finding.component, finding.componentVersion),
            path,
            finding,
            findingKey: finding.findingKey,
            tier: finding.tier || path.tier,
            score: finding.score || path.score,
            selected: Boolean(selected && selected.findingKey === finding.findingKey),
            dimmed: Boolean(dimmed),
          };
          graphNodes.push({datum: findingDatum, position: positions.get(findingId)});
          graphNodeById.set(findingId, findingDatum);
          graphEdges.push(attackGraphEdge(issueId, findingId, {...path, tier: findingDatum.tier, score: findingDatum.score}, pathSelected, dimmed, "structural", "Finding detail"));
        });
      }
    });
  }

  for (const item of graphNodes) {
    const override = nodePositionOverrides.get(item.datum.id);
    if (!override) continue;
    item.position = {...item.position, x: override.x, y: override.y};
    positions.set(item.datum.id, item.position);
  }
  const summary = attackSummary(attackSurfaces, attackGroups);
  summary.shown = overviewPaths.length;
  const maxY = Math.max(840, ...[...positions.values()].map(position => position.y + position.height + 70));
  const maxX = Math.max(1260, ...[...positions.values()].map(position => position.x + position.width + 90));
  surfaceBounds = {width: maxX, height: maxY, maxVulnCount: 0};
  return {graphNodes, graphNodeById, edges: graphEdges, positions, selectedSurface, summary};
}

function attackBranchHeight(path) {
  const issueId = `${path.id}:graph-findings`;
  if (!expandedGraphNodes.has(issueId)) return 132;
  const findingCount = (path.findingKeys || []).map(key => vulnerabilityByFindingKey.get(key)).filter(Boolean).length;
  return Math.max(132, findingCount * 82 + 58);
}

function attackGraphNodeDatum(id, type, label, subtitle, path, selectedNode, dimmed) {
  return {
    id,
    attackKind: "graphNode",
    graphKind: "route",
    graphType: type,
    type,
    label,
    subtitle,
    path,
    tier: path.tier,
    score: path.score,
    selected: Boolean(selectedNode),
    dimmed: Boolean(dimmed),
  };
}

function attackGraphEdge(from, to, path, selectedEdge, dimmed, state, label) {
  return {
    id: `${from}->${to}`,
    from,
    to,
    graph: true,
    attackKind: "graphEdge",
    label: label || "Attack route transition",
    tier: path.tier,
    score: path.score,
    path,
    selected: Boolean(selectedEdge),
    dimmed: Boolean(dimmed),
    markState: state,
    // Kept as flags because the detail panel and the selection code read them.
    unknown: state === "unknown",
    blocker: state === "blocked",
    lateral: state === "internal",
  };
}

function graphRouteNodes(path, surface) {
  const nodes = [...(path.routeNodes || [])];
  if (!nodes.length) return nodes;
  const firstNode = nodes[0] || {};
  const firstLabel = String(firstNode.label || "").toLowerCase();
  const entryLabel = String(surface?.entryLabel || path.entryLabel || "").toLowerCase();
  const isEntryNode = firstNode.type === "entry" || firstLabel === entryLabel || firstLabel.includes("internet / attacker") || firstLabel.includes("internal pivot");
  return isEntryNode ? nodes.slice(1) : nodes;
}

function compactRouteNodes(nodes) {
  if (nodes.length <= 6) return nodes;
  const picked = [nodes[0], ...nodes.slice(1, 5), nodes[nodes.length - 1]];
  return uniqueById(picked);
}

function groupAttackSurfaces(groups) {
  const surfaces = new Map();
  for (const group of groups) {
    const surfaceId = group.surfaceId || `attack-surface:${slug([group.surfaceMode, group.entryLabel, group.exposure, group.provider].join("-"))}`;
    const base = attackSurfaceById.get(surfaceId) || {};
    if (!surfaces.has(surfaceId)) {
      surfaces.set(surfaceId, {
        ...base,
        id: surfaceId,
        attackKind: "surface",
        title: base.title || surfaceTitleForGroup(group),
        summary: base.summary || "",
        surfaceMode: base.surfaceMode || group.surfaceMode || surfaceModeForGroup(group),
        surfaceModeLabel: base.surfaceModeLabel || group.surfaceModeLabel || surfaceModeLabel(surfaceModeForGroup(group)),
        entryLabel: base.entryLabel || group.entryLabel || "Unknown entry",
        entrySubtitle: base.entrySubtitle || group.entrySubtitle || "",
        provider: base.provider || group.provider || "Context",
        exposure: base.exposure || group.exposure || "unknown",
        confidence: base.confidence || group.confidence || "low",
        tier: "informational",
        score: 0,
        groups: [],
        groupIds: [],
        assetIds: [],
        assetNames: [],
        findingKeys: [],
        scenarioIds: [],
        categoryCounts: {},
      });
    }
    const surface = surfaces.get(surfaceId);
    surface.tier = strongerTier(surface.tier, group.tier);
    surface.score = Math.max(Number(surface.score || 0), Number(group.score || 0));
    surface.confidence = strongerConfidence(surface.confidence, group.confidence);
    surface.groups.push(group);
    pushUnique(surface.groupIds, group.id);
    for (const assetId of group.assetIds || []) pushUnique(surface.assetIds, assetId);
    for (const assetName of group.assetNames || []) pushUnique(surface.assetNames, assetName);
    for (const findingKey of group.findingKeys || []) pushUnique(surface.findingKeys, findingKey);
    for (const scenarioId of group.scenarioIds || []) pushUnique(surface.scenarioIds, scenarioId);
    for (const [categoryId, count] of Object.entries(group.categoryCounts || {})) {
      surface.categoryCounts[categoryId] = Number(surface.categoryCounts[categoryId] || 0) + Number(count || 0);
    }
  }
  const values = [...surfaces.values()];
  for (const surface of values) {
    surface.routeCount = surface.groups.length;
    surface.assetCount = surface.assetIds.length;
    surface.findingCount = surface.findingKeys.length;
    surface.categorySummary = (DATA.issueCategories || [])
      .filter(category => surface.categoryCounts[category.id])
      .map(category => ({...category, count: surface.categoryCounts[category.id]}));
    surface.summary = surface.summary || `${surface.routeCount} ${surface.surfaceModeLabel || "entry"} route option(s) reach ${surface.assetCount} asset(s) with ${surface.findingCount} linked finding(s).`;
  }
  return values.sort((a, b) => (tierRank[b.tier] - tierRank[a.tier]) || ((b.score || 0) - (a.score || 0)) || (surfaceModeRank(b.surfaceMode) - surfaceModeRank(a.surfaceMode)) || String(a.title || "").localeCompare(String(b.title || "")));
}

function surfaceModeForGroup(group) {
  const exposureValue = String(group.exposure || "unknown").toLowerCase();
  const entry = String(group.entryLabel || "").toLowerCase();
  if (["public", "external"].includes(exposureValue) || entry.includes("internet") || entry.includes("attacker")) return "outside";
  if (exposureValue === "internal" || entry.includes("internal") || entry.includes("pivot")) return "lateral";
  if (["private", "isolated"].includes(exposureValue)) return "private";
  return "unknown";
}

function surfaceModeLabel(mode) {
  return {
    outside: "outside entry",
    lateral: "lateral movement",
    private: "private/no external entry",
    unknown: "unresolved entry",
  }[mode] || "unresolved entry";
}

function surfaceModeRank(mode) {
  return {outside: 4, lateral: 3, private: 2, unknown: 1}[mode] || 1;
}

function surfaceTitleForGroup(group) {
  const mode = surfaceModeForGroup(group);
  if (mode === "outside") return `Outside entry options through ${group.entryLabel || "unknown entry"} (${group.provider || "Context"})`;
  if (mode === "lateral") return `Lateral movement options through ${group.entryLabel || "unknown entry"} (${group.provider || "Context"})`;
  if (mode === "private") return `Private assets without external entry (${group.provider || "Context"})`;
  return `Unresolved entry options (${group.provider || "Context"})`;
}

function strongerConfidence(first, second) {
  const rank = {low: 0, medium: 1, high: 2};
  return (rank[first || "low"] || 0) >= (rank[second || "low"] || 0) ? first || "low" : second || "low";
}

function pushUnique(values, value) {
  if (value && !values.includes(value)) values.push(value);
}

function attackSummary(surfaces, groups) {
  return {
    id: "attack:summary",
    attackKind: "summary",
    surfaceCount: surfaces.length,
    routeCount: groups.length,
    pathCount: groups.length,
    urgent: groups.filter(path => path.tier === "urgent").length,
    high: groups.filter(path => path.tier === "high").length,
    public: groups.filter(path => ["public", "external"].includes(path.exposure)).length,
    lateral: groups.filter(path => path.surfaceMode === "lateral" || path.exposure === "internal").length,
    runtime: groups.reduce((total, path) => total + Number((path.categoryCounts || {}).events || 0), 0),
    unknowns: groups.reduce((total, path) => total + Number((path.categoryCounts || {}).visibility_gaps || 0), 0),
  };
}

function slug(value) {
  return String(value || "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "unknown";
}

function layoutArchitecture(visibleAssetIds, visibleKeys) {
  const arch = DATA.architecture || {zones: [], hops: [], assets: [], edges: []};
  const archAssets = (arch.assets || [])
    .filter(asset => visibleAssetIds.has(asset.id))
    .sort((a, b) => (tierRank[b.tier] - tierRank[a.tier]) || ((b.score || 0) - (a.score || 0)) || String(a.name || "").localeCompare(String(b.name || "")));
  const visibleAssetSet = new Set(archAssets.map(asset => asset.id));
  const archHops = (arch.hops || [])
    .filter(hop => (hop.assetIds || []).some(assetId => visibleAssetSet.has(assetId)) || (hop.pathIds || []).some(pathId => (arch.edges || []).some(edge => edge.pathId === pathId && visibleAssetSet.has(edge.target))))
    .sort((a, b) => String(a.label || "").localeCompare(String(b.label || "")));
  const visibleHopSet = new Set(archHops.map(hop => hop.id));
  const zonePositions = new Map();
  const hopPositions = new Map();
  const assetPositions = new Map();
  const zoneModels = [];
  const hopModels = [];
  const assetModels = [];
  const zoneContent = new Map();
  for (const zone of arch.zones || []) {
    zoneContent.set(zone.id, {
      hops: archHops.filter(hop => hop.zoneId === zone.id),
      assets: archAssets.filter(asset => asset.zoneId === zone.id),
    });
  }
  const visibleZones = [...(arch.zones || [])]
    .filter(zone => {
      const content = zoneContent.get(zone.id) || {hops: [], assets: []};
      return content.hops.length || content.assets.length;
    })
    .sort((a, b) => (a.order || 0) - (b.order || 0));
  const zoneCount = Math.max(visibleZones.length, 1);
  const maxItems = Math.max(1, ...visibleZones.map(zone => {
    const content = zoneContent.get(zone.id) || {hops: [], assets: []};
    return content.hops.length + content.assets.length;
  }));
  const zoneHeight = Math.max(520, archZoneHeader + 54 + maxItems * (archAssetHeight + archItemGap));

  visibleZones.forEach((zone, zoneIndex) => {
    const x = archMarginX + zoneIndex * (archZoneWidth + archZoneGap);
    const content = zoneContent.get(zone.id) || {hops: [], assets: []};
    const zoneHops = content.hops
      .sort((a, b) => (tierRank[b.tier] - tierRank[a.tier]) || ((b.score || 0) - (a.score || 0)) || String(a.label || "").localeCompare(String(b.label || "")));
    const zoneAssets = content.assets;
    let y = archMarginY + archZoneHeader + 24;
    for (const hop of zoneHops) {
      const entry = hop.kind === "entry";
      const width = entry ? archEntryWidth : archHopWidth;
      const height = entry ? archEntryHeight : archHopHeight;
      const position = {
        x: architectureNodeX(zone.id, x, width),
        y,
        width,
        height,
      };
      hopPositions.set(hop.id, position);
      hopModels.push({datum: {...hop, architectureKind: "hop"}, position});
      y += height + archItemGap;
    }
    if (zoneHops.length && zoneAssets.length) {
      y += 16;
    }
    for (const asset of zoneAssets) {
      const baseAsset = assetById.get(asset.id) || asset;
      const position = {x: x + 34, y, width: archAssetWidth, height: archAssetHeight};
      assetPositions.set(asset.id, position);
      assetModels.push({datum: {...baseAsset, architecture: asset}, position});
      y += archAssetHeight + archItemGap;
    }
    const position = {x, y: archMarginY, width: archZoneWidth, height: zoneHeight};
    zonePositions.set(zone.id, position);
    zoneModels.push({
      datum: {
        ...zone,
        architectureKind: "zone",
        assetIds: zoneAssets.map(asset => asset.id),
        hopIds: zoneHops.map(hop => hop.id),
      },
      position,
    });
  });

  surfaceBounds = {
    width: Math.max(980, archMarginX * 2 + zoneCount * archZoneWidth + (zoneCount - 1) * archZoneGap),
    height: Math.max(620, archMarginY + zoneHeight + 60),
    maxVulnCount: 0,
  };
  return {zones: zoneModels, hops: hopModels, assets: assetModels, positions: new Map([...zonePositions, ...hopPositions, ...assetPositions]), visibleHopSet, visibleAssetSet, visibleKeys};
}

function architectureNodeX(zoneId, zoneX, width) {
  if (zoneId === "zone:internet-external") {
    return zoneX + Math.max(24, (archZoneWidth - width) / 2);
  }
  if (zoneId === "zone:edge-ingress") {
    return zoneX + Math.max(24, (archZoneWidth - width) / 2);
  }
  return zoneX + Math.max(30, (archZoneWidth - width) / 2);
}

function layoutFindings(vulnerabilities) {
  const positions = new Map();
  const columns = 3;
  const gap = 16;
  vulnerabilities.forEach((vuln, index) => {
    const col = index % columns;
    const row = Math.floor(index / columns);
    positions.set(vuln.id, {
      x: 56 + col * (360 + gap),
      y: 72 + row * (132 + gap),
      width: 360,
      height: 132,
    });
  });
  surfaceBounds = {
    width: Math.max(980, 56 + columns * 360 + (columns - 1) * gap + 56),
    height: Math.max(620, 72 + Math.ceil(vulnerabilities.length / columns) * (132 + gap) + 80),
    maxVulnCount: vulnerabilities.length,
  };
  return positions;
}

// The board is a table rendered outside the zoom surface at 1:1, so it has no
// surface geometry of its own; the surface is collapsed to keep the empty SVG
// from claiming a scroll area behind it.
function layoutRiskScenarios(scenarios) {
  surfaceBounds = {width: 1, height: 1, maxVulnCount: scenarios.length};
  return {rowHeight: 72};
}

// Spec section 6 makes this list the graph's text equivalent, which makes its
// structure load bearing rather than cosmetic. It used to be seven unlabelled
// divs per row inside one role=button, so the two numeric columns were
// announced as bare digits in a 281-character run-on name and nothing said
// which was "Findings" and which was "In-use findings".
const RISK_BOARD_COLUMNS = ["Priority", "Risk scenario", "Evidence categories", "Findings", "In-use findings", "Context", "Attack path"];

function renderRiskBoard(scenarios, layout) {
  const board = document.createElement("div");
  board.className = "risk-board";
  board.setAttribute("role", "table");
  board.setAttribute("aria-label", `Risk scenarios, ${scenarios.length} rows`);
  board.setAttribute("aria-colcount", String(RISK_BOARD_COLUMNS.length));
  const header = document.createElement("div");
  header.className = "risk-board-head";
  header.setAttribute("role", "row");
  RISK_BOARD_COLUMNS.forEach((label, index) => {
    const cell = document.createElement("div");
    cell.setAttribute("role", "columnheader");
    cell.id = `riskCol${index}`;
    cell.textContent = label;
    header.appendChild(cell);
  });
  board.appendChild(header);
  if (!scenarios.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.style.padding = "18px";
    empty.textContent = emptyListMessage("risk scenarios");
    board.appendChild(empty);
    return board;
  }
  for (const scenario of scenarios) {
    board.appendChild(renderRiskRow(scenario, layout));
  }
  return board;
}

function riskCell(columnIndex, className) {
  const cell = document.createElement("div");
  cell.className = className || "risk-cell";
  cell.setAttribute("role", "cell");
  cell.setAttribute("aria-describedby", `riskCol${columnIndex}`);
  return cell;
}

function openScenarioAttackPath(scenario) {
  viewMode = "attack";
  selected = {...scenario, scenarioKind: "scenario", attackKind: "scenario"};
  render();
  window.setTimeout(fitGraph, 0);
}

function renderRiskRow(scenario, layout) {
  const isSelected = Boolean(selected && selected.id === scenario.id);
  const row = document.createElement("div");
  row.className = "risk-row";
  row.setAttribute("role", "row");
  // Styled selection has to be announced selection. The view switcher already
  // exposes aria-pressed; a selected row exposed nothing at all, so a screen
  // reader user could not tell which risk the detail canvas was showing.
  if (isSelected) row.setAttribute("aria-current", "true");
  row.style.minHeight = `${layout.rowHeight}px`;
  // A mouse convenience only, and deliberately not a role: clicking anywhere in
  // the row still selects it, but the row is not announced as a control and
  // does not absorb the name of the link inside it.
  row.addEventListener("click", event => {
    if (event.target.closest("a, button")) return;
    selected = {...scenario, scenarioKind: "scenario", attackKind: "scenario"};
    render();
  });

  const severity = riskCell(0);
  const severityWrap = document.createElement("span");
  severityWrap.className = "risk-severity";
  const dot = document.createElement("span");
  dot.className = `risk-dot ${scenario.tier || "informational"}`;
  dot.setAttribute("aria-hidden", "true");
  const severityText = document.createElement("span");
  severityText.textContent = scenario.priorityLabel || priorityText(scenario.tier);
  severityWrap.append(dot, severityText);
  severity.appendChild(severityWrap);

  const risk = riskCell(1);
  // The activation lives here, not on the row: role=button takes presentational
  // children, so a row-level button swallowed the "Open attack path" link.
  const title = document.createElement("button");
  title.type = "button";
  title.className = "risk-title-button risk-title";
  title.textContent = scenario.title || "Risk scenario";
  if (isSelected) title.setAttribute("aria-current", "true");
  title.addEventListener("click", event => {
    event.stopPropagation();
    selected = {...scenario, scenarioKind: "scenario", attackKind: "scenario"};
    render();
  });
  const meta = document.createElement("div");
  meta.className = "risk-meta";
  meta.append(
    identifierSpan(scenario.assetName || "unknown asset", 34, 32),
    text(" | entry: "),
    text(scenario.entryLabel || "unknown entry"),
    text(" -> path: "),
    identifierSpan(scenario.pathLabel || "network path", 64, 32)
  );
  risk.append(title, meta);

  const categories = riskCell(2);
  categories.append(categoryChips(scenario.categorySummary || []));

  // The digit is the whole visible cell, so the column name travels with it for
  // anyone reading the row as one run of speech.
  const total = riskCell(3, "risk-cell num");
  total.append(visuallyHidden("findings: "), text(String(scenario.totalFindings || 0)));

  const inUse = riskCell(4, "risk-cell num");
  inUse.append(visuallyHidden("in-use findings: "), text(String(scenario.inUseCount || 0)));

  const context = riskCell(5);
  context.append(chips([exposureChip(scenario.exposure), scenario.provider, countChip((scenario.categoryCounts || {}).identity_data_access || 0, "IAM")], 3));

  const pathCell = riskCell(6);
  const attackPathLink = document.createElement("a");
  attackPathLink.className = "risk-path-link";
  attackPathLink.href = `#attack-path-${scenario.attackPathGroupId || scenario.id}`;
  attackPathLink.textContent = "Open attack path";
  // Twelve links all named "Open attack path" are twelve identical tab stops.
  attackPathLink.setAttribute("aria-label", `Open attack path for ${scenario.title || "risk scenario"}`);
  attackPathLink.title = `Show the attack path for ${scenario.title || "risk scenario"}`;
  attackPathLink.addEventListener("click", event => {
    event.preventDefault();
    event.stopPropagation();
    openScenarioAttackPath(scenario);
  });
  pathCell.appendChild(attackPathLink);

  row.append(severity, risk, categories, total, inUse, context, pathCell);
  return row;
}

function visuallyHidden(value) {
  const span = document.createElement("span");
  span.className = "visually-hidden";
  span.textContent = value;
  return span;
}

function layoutCards(assets, vulnerabilities, networkPaths) {
  const entryPositions = new Map();
  const networkPathPositions = new Map();
  const assetPositions = new Map();
  const vulnerabilityPositions = new Map();
  const visibleVulnerabilitiesByAssetId = new Map();
  for (const vuln of vulnerabilities) {
    if (!visibleVulnerabilitiesByAssetId.has(vuln.assetId)) visibleVulnerabilitiesByAssetId.set(vuln.assetId, []);
    visibleVulnerabilitiesByAssetId.get(vuln.assetId).push(vuln);
  }
  let y = firstRowY;
  let maxVulnCount = 0;
  for (const asset of assets) {
    const assetVulns = (visibleVulnerabilitiesByAssetId.get(asset.id) || [])
      .sort((a, b) => (tierRank[b.tier] - tierRank[a.tier]) || (b.score - a.score) || a.label.localeCompare(b.label));
    maxVulnCount = Math.max(maxVulnCount, assetVulns.length);
    const rowHeight = Math.max(assetHeight, pathHeight, assetVulns.length * (vulnHeight + vulnGap) - vulnGap);
    const assetY = y + Math.max(0, (rowHeight - assetHeight) / 2);
    assetPositions.set(asset.id, {x: assetX, y: assetY, width: assetWidth, height: assetHeight});
    assetVulns.forEach((vuln, index) => {
      vulnerabilityPositions.set(vuln.id, {x: vulnX, y: y + index * (vulnHeight + vulnGap), width: vulnWidth, height: vulnHeight});
    });
    y += rowHeight + rowGap;
  }
  const entryPathIds = new Map();
  for (const networkPath of networkPaths) {
    const connectedAssets = pathAssetIds(networkPath).map(assetId => assetPositions.get(assetId)).filter(Boolean);
    if (!connectedAssets.length) continue;
    const centerY = average(connectedAssets.map(asset => asset.y + asset.height / 2));
    networkPathPositions.set(networkPath.id, {x: pathX, y: Math.max(0, centerY - pathHeight / 2), width: pathWidth, height: pathHeight});
    const entryId = entryNodeId(networkPath);
    if (!entryPathIds.has(entryId)) entryPathIds.set(entryId, []);
    entryPathIds.get(entryId).push(networkPath.id);
  }
  for (const [entryId, pathIds] of entryPathIds.entries()) {
    const pathCenters = pathIds.map(pathId => networkPathPositions.get(pathId)).filter(Boolean).map(path => path.y + path.height / 2);
    if (!pathCenters.length) continue;
    const centerY = average(pathCenters);
    entryPositions.set(entryId, {x: entryX, y: Math.max(0, centerY - entryHeight / 2), width: entryWidth, height: entryHeight});
  }
  surfaceBounds = {
    width: Math.max(980, vulnX + vulnWidth + 80),
    height: Math.max(620, y + 40),
    maxVulnCount,
  };
  return {entries: entryPositions, networkPaths: networkPathPositions, assets: assetPositions, vulnerabilities: vulnerabilityPositions};
}

function renderLaneLabels() {
  return [
    laneLabel("Entry", entryX, laneY, entryWidth),
    laneLabel("Network path", pathX, laneY, pathWidth),
    laneLabel("Asset", assetX, laneY, assetWidth),
    laneLabel("Findings", vulnX, laneY, vulnWidth),
  ];
}

function laneLabel(value, x, y, width) {
  const label = document.createElement("div");
  label.className = "lane-label";
  label.style.left = `${x}px`;
  label.style.top = `${y}px`;
  label.style.width = `${width}px`;
  label.textContent = value;
  return label;
}

function average(values) {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
}

function renderEdgeDefs() {
  const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
  const marker = document.createElementNS("http://www.w3.org/2000/svg", "marker");
  marker.setAttribute("id", "edge-arrow");
  marker.setAttribute("viewBox", "0 0 10 10");
  marker.setAttribute("refX", "8");
  marker.setAttribute("refY", "5");
  marker.setAttribute("markerWidth", "6");
  marker.setAttribute("markerHeight", "6");
  marker.setAttribute("orient", "auto-start-reverse");
  const arrow = document.createElementNS("http://www.w3.org/2000/svg", "path");
  arrow.setAttribute("d", "M 0 0 L 10 5 L 0 10 z");
  // The fill is themed from CSS (#edges marker path) so it follows the tokens.
  marker.appendChild(arrow);
  defs.appendChild(marker);
  return defs;
}

function renderEdges(vulnerabilities, networkPaths, layout) {
  const paths = [];
  for (const pathNode of networkPaths) {
    const entry = layout.entries.get(entryNodeId(pathNode));
    const path = layout.networkPaths.get(pathNode.id);
    if (!entry || !path) continue;
    const state = routeMarkState(pathNode);
    const entryLabel = pathNode.entryLabel || "entry";
    const pathLabel = pathNode.label || "network path";
    // The entry edge used to be dashed grey whatever its state, which read as
    // "unknown, evidence missing" for a known public route. Dashed is reserved.
    paths.push(edgePath(
      entry.x + entry.width, entry.y + entry.height / 2, path.x, path.y + path.height / 2,
      `edge network state-${state} ${pathNode.tier || "informational"}`,
      entryNodeId(pathNode), pathNode.id,
      `Network route: ${entryLabel} to ${pathLabel}. ${MARK_STATE_TEXT[state]}. Priority ${pathNode.tier || "informational"}.`
    ));
    for (const assetId of pathAssetIds(pathNode)) {
      const asset = layout.assets.get(assetId);
      if (!asset) continue;
      const assetName = (assetById.get(assetId) || {}).name || assetId;
      paths.push(edgePath(
        path.x + path.width, path.y + path.height / 2, asset.x, asset.y + asset.height / 2,
        `edge network state-${state} ${pathNode.tier || "informational"}`,
        pathNode.id, assetId,
        `Network route: ${pathLabel} reaches ${assetName}. ${MARK_STATE_TEXT[state]}. Priority ${pathNode.tier || "informational"}.`
      ));
    }
  }
  for (const vuln of vulnerabilities) {
    const asset = layout.assets.get(vuln.assetId);
    const target = layout.vulnerabilities.get(vuln.id);
    if (!asset || !target) continue;
    const x1 = asset.x + asset.width;
    const y1 = asset.y + asset.height / 2;
    const x2 = target.x;
    const y2 = target.y + target.height / 2;
    const busX = x1 + 44;
    const state = findingMarkState(vuln);
    const assetName = (assetById.get(vuln.assetId) || {}).name || vuln.assetId;
    paths.push(fanEdgePath(
      x1, y1, busX, x2, y2,
      `edge vulnerability state-${state} ${vuln.tier || "informational"}`,
      vuln.assetId, vuln.id,
      `Finding on ${assetName}: ${vuln.label || vuln.findingKey || "finding"}. ${MARK_STATE_TEXT[state]}. Priority ${vuln.tier || "informational"}.`
    ));
  }
  return paths;
}

function renderArchitectureEdges(layout) {
  const paths = [];
  const arch = DATA.architecture || {edges: []};
  const pathById = new Map((DATA.networkPaths || []).map(item => [item.id, item]));
  const hopById = new Map((arch.hops || []).map(item => [item.id, item]));
  const nodeName = id => (hopById.get(id) || {}).label || (assetById.get(id) || {}).name || id;
  const seen = new Set();
  for (const edge of arch.edges || []) {
    if (!layout.visibleHopSet.has(edge.source) && !layout.visibleAssetSet.has(edge.source)) continue;
    if (!layout.visibleHopSet.has(edge.target) && !layout.visibleAssetSet.has(edge.target)) continue;
    const edgeKey = `${edge.source}->${edge.target}`;
    if (seen.has(edgeKey)) continue;
    seen.add(edgeKey);
    const source = layout.positions.get(edge.source);
    const target = layout.positions.get(edge.target);
    if (!source || !target) continue;
    // The route this edge was drawn from is what it may claim, so its state
    // comes from the network path -- never from the tier, which is a priority.
    const state = routeMarkState(pathById.get(edge.pathId) || hopById.get(edge.source));
    paths.push(architectureEdgePath(
      source, target,
      `edge network architecture state-${state} ${edge.tier || "informational"}`,
      edge.source, edge.target,
      `Route step: ${nodeName(edge.source)} to ${nodeName(edge.target)}. ${MARK_STATE_TEXT[state]}. Priority ${edge.tier || "informational"}.`
    ));
  }
  return paths;
}

function renderAttackPathEdges(layout) {
  const paths = [];
  for (const edge of layout.edges || []) {
    const sourceId = edge.from || edge.source;
    const targetId = edge.to || edge.target;
    const source = layout.positions.get(sourceId);
    const target = layout.positions.get(targetId);
    if (!source || !target) continue;
    const selectedEdge = edge.selected || (selected && selected.attackKind === "graphEdge" && selected.id === edge.id);
    const edgeDatum = {
      ...edge,
      fromNode: layout.graphNodeById?.get(sourceId),
      toNode: layout.graphNodeById?.get(targetId),
    };
    const className = `edge ${edge.graph ? "attack-graph-edge" : "attack-path"} ${edge.tier || "informational"} state-${edgeMarkState(edge)}${selectedEdge ? " selected" : ""}${edge.dimmed ? " dimmed" : ""}`;
    if (edge.graph) {
      paths.push(attackGraphEdgePath(source, target, className, sourceId, targetId, edgeDatum));
    } else {
      paths.push(edgePath(source.x + source.width, source.y + source.height / 2, target.x, target.y + target.height / 2, className, sourceId, targetId));
    }
  }
  return paths;
}

// The state an already-built edge datum carries. Nothing is inferred as
// confirmed here: an edge that was never given a state is one nothing is known
// about, and it says so.
function edgeMarkState(edge) {
  if (!edge) return "unknown";
  if (edge.markState) return edge.markState;
  if (edge.blocker) return "blocked";
  if (edge.unknown) return "unknown";
  if (edge.lateral) return "internal";
  return "unknown";
}

// An edge is a tab stop, so it needs a name, and the name has to carry the one
// thing the stroke carries visually: whether this step is proven, blocked or
// unknown. Silence here would let a broken chain sound like a whole one.
function edgeAccessibleName(edgeDatum) {
  const from = String(edgeDatum.fromNode?.label || "").trim();
  const to = String(edgeDatum.toNode?.label || "").trim();
  const step = from && to ? `${from} to ${to}` : String(edgeDatum.label || "attack route transition");
  const state = MARK_STATE_TEXT[edgeMarkState(edgeDatum)];
  return `Attack step: ${step}. ${state}. Priority ${edgeDatum.tier || "informational"}.`;
}

function attackGraphEdgePath(source, target, className, sourceId, targetId, edgeDatum) {
  const x1 = source.x + source.width / 2;
  const y1 = source.y + source.height / 2;
  const x2 = target.x + target.width / 2;
  const y2 = target.y + target.height / 2;
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("class", className);
  path.dataset.edgeSource = sourceId;
  path.dataset.edgeTarget = targetId;
  const distance = Math.max(80, Math.abs(x2 - x1));
  const curve = Math.min(180, distance * .48);
  path.setAttribute("d", `M ${x1} ${y1} C ${x1 + curve} ${y1}, ${x2 - curve} ${y2}, ${x2} ${y2}`);
  path.setAttribute("role", "button");
  path.setAttribute("tabindex", "0");
  path.setAttribute("aria-label", edgeAccessibleName(edgeDatum));
  path.addEventListener("mousedown", event => event.stopPropagation());
  path.addEventListener("click", event => {
    event.stopPropagation();
    selected = selected && selected.attackKind === "graphEdge" && selected.id === edgeDatum.id ? null : edgeDatum;
    render();
  });
  path.addEventListener("keydown", event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    event.stopPropagation();
    selected = selected && selected.attackKind === "graphEdge" && selected.id === edgeDatum.id ? null : edgeDatum;
    render();
  });
  markActiveEdge(path, sourceId, targetId);
  return path;
}

// Every edge in every view is a named tab stop. The Architecture and Evidence
// boards used to draw 27 and 32 edges with no accessible name and no keyboard
// reach at all, which left their whole encoding available to sighted mouse
// users only -- and the graph is what those two views are.
function namedEdge(path, sourceId, targetId, accessibleName) {
  path.dataset.edgeSource = sourceId;
  path.dataset.edgeTarget = targetId;
  if (accessibleName) {
    path.setAttribute("role", "img");
    path.setAttribute("tabindex", "0");
    path.setAttribute("aria-label", accessibleName);
  }
  markActiveEdge(path, sourceId, targetId);
  return path;
}

function architectureEdgePath(source, target, className, sourceId, targetId, accessibleName) {
  const x1 = source.x + source.width;
  const y1 = source.y + source.height / 2;
  const x2 = target.x;
  const y2 = target.y + target.height / 2;
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("class", className);
  const midX = x1 + Math.max(34, (x2 - x1) / 2);
  path.setAttribute("d", `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`);
  return namedEdge(path, sourceId, targetId, accessibleName);
}

function edgePath(x1, y1, x2, y2, className, sourceId, targetId, accessibleName) {
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("class", className);
  path.setAttribute("d", `M ${x1} ${y1} C ${x1 + 42} ${y1}, ${x2 - 42} ${y2}, ${x2} ${y2}`);
  return namedEdge(path, sourceId, targetId, accessibleName);
}

function fanEdgePath(x1, y1, busX, x2, y2, className, sourceId, targetId, accessibleName) {
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("class", className);
  path.setAttribute("d", `M ${x1} ${y1} C ${busX} ${y1}, ${busX} ${y2}, ${x2} ${y2}`);
  return namedEdge(path, sourceId, targetId, accessibleName);
}

function markActiveEdge(path, sourceId, targetId) {
  if (!selected) return;
  const selectedIds = new Set([selected.id, selected.assetId, selected.findingKey, selected.from, selected.to].filter(Boolean));
  for (const assetId of pathAssetIds(selected)) selectedIds.add(assetId);
  for (const pathId of selected.linkedPathIds || []) selectedIds.add(pathId);
  for (const pathId of selected.pathIds || []) selectedIds.add(pathId);
  for (const assetId of selected.assetIds || []) selectedIds.add(assetId);
  for (const scenarioId of selected.scenarioIds || []) selectedIds.add(scenarioId);
  if (selectedIds.has(sourceId) || selectedIds.has(targetId)) {
    path.classList.add("active");
  }
}

function primaryNetworkPath(asset) {
  const paths = networkPathsForAsset(asset.id);
  return paths.length ? paths[0] : null;
}

function networkPathsForAsset(assetId) {
  return networkPathsByAssetId.get(assetId) || [];
}

function pathAssetIds(path) {
  if (!path || typeof path !== "object") return [];
  if (Array.isArray(path.assetIds) && path.assetIds.length) return path.assetIds.filter(Boolean);
  return path.assetId ? [path.assetId] : [];
}

function entryNodeId(path) {
  return path.entryNodeId || `${path.id}:entry`;
}

function uniqueById(items) {
  const seen = new Set();
  return items.filter(item => {
    if (!item || !item.id || seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
}

function uniqueEntries(paths) {
  const entries = new Map();
  for (const path of paths) {
    const id = entryNodeId(path);
    if (!entries.has(id)) {
      entries.set(id, {
        ...path,
        id,
        networkKind: "entry",
        assetIds: [],
        linkedPathIds: [],
      });
    }
    const entry = entries.get(id);
    if (!entry.linkedPathIds.includes(path.id)) entry.linkedPathIds.push(path.id);
    for (const assetId of pathAssetIds(path)) {
      if (!entry.assetIds.includes(assetId)) entry.assetIds.push(assetId);
    }
    entry.score = Math.max(Number(entry.score || 0), Number(path.score || 0));
    entry.tier = strongerTier(entry.tier, path.tier);
  }
  return [...entries.values()];
}

function renderArchitectureZone(zone, position) {
  const panel = document.createElement("div");
  panel.className = `zone-panel${selected && selected.id === zone.id ? " selected" : ""}`;
  panel.dataset.nodeId = zone.id;
  panel.style.left = `${position.x}px`;
  panel.style.top = `${position.y}px`;
  panel.style.width = `${position.width}px`;
  panel.style.height = `${position.height}px`;
  panel.addEventListener("mousedown", event => event.stopPropagation());
  panel.addEventListener("click", event => {
    event.stopPropagation();
    selected = zone;
    render();
  });
  const head = document.createElement("div");
  head.className = "zone-head";
  const title = document.createElement("div");
  title.className = "zone-title";
  title.textContent = zone.label;
  const sub = document.createElement("div");
  sub.className = "zone-sub";
  const assetCount = (zone.assetIds || []).length;
  const hopCount = (zone.hopIds || []).length;
  sub.textContent = `${assetCount} ${assetCount === 1 ? "asset" : "assets"} | ${hopCount} ${hopCount === 1 ? "hop" : "hops"}`;
  head.append(title, sub);
  panel.append(head);
  return panel;
}

function renderArchitectureHop(hop, position) {
  const card = createCard("architecture-hop", hop.tier || "informational", position, hop);
  card.dataset.hopKind = hop.kind || "hop";
  // The same state the chain and the attack graph read, so an "Unknown entry"
  // pill can never take the confident fill that "Internet / attacker" takes.
  const state = routeMarkState(hop);
  card.dataset.nodeState = state === "unknown" ? "unknown" : state === "blocked" ? "blocked" : "normal";
  card.append(
    // The subtitle sits in the same fixed-width pill as the chips, so the word
    // is kept short: the dashed border and the near-neutral fill say the rest.
    cardTop(hop.label || "Network hop", [tag(hop.provider || "Context", "count"), countChip((hop.assetIds || []).length, "assets")], state === "unknown" ? "unknown route" : hop.kind || hop.confidence || "")
  );
  return card;
}

function renderArchitectureAsset(asset, position) {
  const arch = asset.architecture || {};
  const counts = arch.findingTypeCounts || {};
  const card = createCard("architecture-asset", asset.tier, position, asset);
  card.append(
    cardTop(asset.name, [
      priorityChip(asset.tier),
      scoreChip(asset.score, "max"),
      countChip(asset.findingKeys.length, "findings"),
      counts.dynamic_runtime_observation ? countChip(counts.dynamic_runtime_observation, "runtime findings") : null,
      counts.static_code_weakness ? countChip(counts.static_code_weakness, "static findings") : null,
      counts.cloud_posture_finding ? countChip(counts.cloud_posture_finding, "posture findings") : null,
      counts.dependency_vulnerability ? countChip(counts.dependency_vulnerability, "deps") : null,
    ], `${arch.provider || "Context"} | ${asset.owner || "unknown owner"}`),
    assetBody(asset)
  );
  return card;
}

function renderAttackRiskSidebar(scenarios) {
  const sidebar = document.createElement("aside");
  sidebar.className = "attack-risk-sidebar";
  const title = document.createElement("div");
  title.className = "attack-risk-sidebar-title";
  title.append(text("Risks"), chipElement(`${scenarios.length} visible`, "count"));
  const list = document.createElement("div");
  list.className = "attack-risk-sidebar-list";
  if (!scenarios.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "No risk scenarios match the current filters.";
    list.appendChild(empty);
  }
  for (const scenario of scenarios) {
    list.appendChild(renderAttackRiskSidebarCard(scenario));
  }
  sidebar.append(title, list);
  return sidebar;
}

function renderAttackRiskSidebarCard(scenario) {
  const card = document.createElement("button");
  card.type = "button";
  const selectedScenario = selected && selected.id === scenario.id;
  card.className = `attack-risk-sidebar-card ${scenario.tier || "informational"}${selectedScenario ? " selected" : ""}`;
  const title = document.createElement("div");
  title.className = "risk-title";
  title.textContent = scenario.title || "Risk scenario";
  const meta = document.createElement("div");
  meta.className = "risk-meta";
  meta.appendChild(identifierRuns(`${scenario.assetName || "unknown asset"} | ${scenario.entryLabel || "unknown entry"} -> ${scenario.pathLabel || "network path"}`));
  card.append(
    title,
    meta,
    chips([priorityChip(scenario.tier), scoreChip(scenario.score), countChip(scenario.totalFindings || 0, "findings"), exposureChip(scenario.exposure)], 4)
  );
  card.addEventListener("mousedown", event => event.stopPropagation());
  card.addEventListener("click", event => {
    event.preventDefault();
    event.stopPropagation();
    selected = selectedScenario ? null : {...scenario, scenarioKind: "scenario", attackKind: "scenario"};
    render();
  });
  card.addEventListener("keydown", event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    event.stopPropagation();
    selected = selectedScenario ? null : {...scenario, scenarioKind: "scenario", attackKind: "scenario"};
    render();
  });
  return card;
}

function renderAttackGraphNode(node, position) {
  const graphNode = document.createElement("button");
  graphNode.type = "button";
  const selectedNode = selected && (selected.id === node.id || (node.sourceId && selected.id === node.sourceId) || (node.findingKey && selected.findingKey === node.findingKey));
  graphNode.className = `attack-graph-node draggable ${node.tier || "informational"}${node.selected || selectedNode ? " selected" : ""}${node.dimmed ? " dimmed" : ""}`;
  graphNode.dataset.nodeId = node.id;
  graphNode.dataset.nodeType = node.graphType || node.type || "unknown";
  graphNode.dataset.nodeState = node.state || "normal";
  graphNode.style.left = `${position.x}px`;
  graphNode.style.top = `${position.y}px`;
  graphNode.style.width = `${position.width}px`;
  graphNode.style.height = `${position.height}px`;
  graphNode.addEventListener("mousedown", event => beginGraphNodeDrag(event, node, position));
  graphNode.addEventListener("click", event => {
    event.stopPropagation();
    if (suppressNodeClickId === node.id) {
      suppressNodeClickId = null;
      return;
    }
    if (node.expandable) {
      const wasExpanded = expandedGraphNodes.has(node.id);
      toggleGraphNodeExpansion(node.id);
      selected = wasExpanded && selected && selected.id === node.id ? null : {...node, expanded: expandedGraphNodes.has(node.id)};
      render();
    } else if (node.finding) {
      selected = selected && selected.findingKey === node.findingKey ? null : node.finding;
      render();
    } else if (node.graphKind === "entry") {
      const surfaceSelection = {...node, id: node.sourceId || node.id, attackKind: "surface"};
      selected = selected && selected.id === surfaceSelection.id ? null : surfaceSelection;
      render();
    } else {
      selected = selected && selected.id === node.id ? null : node;
      render();
    }
  });
  graphNode.addEventListener("keydown", event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    event.stopPropagation();
    if (node.expandable) {
      const wasExpanded = expandedGraphNodes.has(node.id);
      toggleGraphNodeExpansion(node.id);
      selected = wasExpanded && selected && selected.id === node.id ? null : {...node, expanded: expandedGraphNodes.has(node.id)};
    } else if (node.finding) {
      selected = selected && selected.findingKey === node.findingKey ? null : node.finding;
    } else if (node.graphKind === "entry") {
      const surfaceSelection = {...node, id: node.sourceId || node.id, attackKind: "surface"};
      selected = selected && selected.id === surfaceSelection.id ? null : surfaceSelection;
    } else {
      selected = selected && selected.id === node.id ? null : node;
    }
    render();
  });
  const circle = document.createElement("span");
  circle.className = "attack-graph-circle";
  circle.textContent = nodeIcon(node.graphType || node.type, node.state);
  if (node.expandable) {
    const toggle = document.createElement("span");
    toggle.className = "attack-graph-toggle";
    toggle.textContent = node.expanded ? "-" : "+";
    circle.appendChild(toggle);
  }
  if (node.badge) {
    const badge = document.createElement("span");
    badge.className = "attack-graph-badge";
    badge.textContent = node.badge;
    circle.appendChild(badge);
  }
  const labelText = node.label || node.type || "Node";
  const subtitleText = node.subtitle || "";
  const label = labelElement("span", "attack-graph-label", labelText, GRAPH_LABEL_BUDGET, GRAPH_LABEL_TOKEN);
  const sub = labelElement("span", "attack-graph-sub", subtitleText, GRAPH_SUBTITLE_BUDGET, GRAPH_SUBTITLE_TOKEN);
  // The visible label is shortened, so the accessible name and the hover title
  // both carry the value in full: nothing is only available as a truncation.
  graphNode.title = subtitleText ? `${labelText}\n${subtitleText}` : labelText;
  graphNode.setAttribute("aria-label", subtitleText ? `${labelText}, ${subtitleText}` : labelText);
  graphNode.append(circle, label, sub);
  return graphNode;
}

function toggleGraphNodeExpansion(nodeId) {
  if (expandedGraphNodes.has(nodeId)) {
    expandedGraphNodes.delete(nodeId);
  } else {
    expandedGraphNodes.add(nodeId);
  }
}

function beginGraphNodeDrag(event, node, position) {
  if (event.button !== 0) return;
  event.preventDefault();
  event.stopPropagation();
  nodeDrag = {
    id: node.id,
    x: event.clientX,
    y: event.clientY,
    originX: position.x,
    originY: position.y,
    moved: false,
  };
  event.currentTarget.classList.add("dragging");
}

function nodeIcon(type, state) {
  if (state === "blocked") return "!";
  if (state === "unknown") return "?";
  return {
    entry: "IN",
    lateral: "PIV",
    ingress: "GW",
    hop: "NET",
    service: "SVC",
    workload: "WL",
    artifact: "SB",
    source: "SRC",
    runtime: "RUN",
    posture: "CFG",
    vulnerability: "CVE",
    weakness: "CWE",
    finding: "CVE",
    identity: "ID",
    data: "DB",
    blocker: "!",
    unknown: "?",
  }[type] || ".";
}

function chipElement(text, className) {
  const chip = document.createElement("span");
  chip.className = `chip ${className || "count"}`;
  chip.textContent = text;
  return chip;
}

function categoryChips(categories) {
  const values = (categories || []).map(category => tag(`${category.shortLabel || category.label} ${category.count || 0}`, "count"));
  return chips(values.length ? values : [tag("No categories", "informational")], 5);
}

function priorityText(tierValue) {
  if (tierValue === "urgent") return "Critical";
  const value = String(tierValue || "informational");
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function strongerTier(first, second) {
  const firstValue = first || "informational";
  const secondValue = second || "informational";
  return (tierRank[firstValue] ?? 0) >= (tierRank[secondValue] ?? 0) ? firstValue : secondValue;
}

function renderEntryCard(entry, position) {
  const card = createCard("entry-card", entry.exposure || "unknown", position, entry);
  card.append(
    cardTop(entry.entryLabel || "Unknown entry", [exposureChip(entry.exposure || "unknown"), countChip((entry.linkedPathIds || []).length, "paths")], entry.entrySubtitle || ""),
    smallBody(entry.exposure === "public" ? "Attacker-controlled traffic can start here." : entry.entrySubtitle || "Network entry state is inferred from context evidence.")
  );
  return card;
}

function renderNetworkPathCard(path, position) {
  const linkedAssetCount = pathAssetIds(path).length;
  const datum = {...path, networkKind: "path"};
  const card = createCard("path-card", path.tier || "informational", position, datum);
  card.append(
    cardTop("Network path", [exposureChip(path.exposure || "unknown"), tag(path.pathType || "unresolved", "count"), countChip(linkedAssetCount, "assets")], path.label || "unknown path"),
    smallBody(path.summary || "No linked path evidence.")
  );
  return card;
}

function renderAssetCard(asset, position) {
  const card = createCard("asset-card", asset.tier, position, asset);
  card.append(
    cardTop(asset.name, [priorityChip(asset.tier), scoreChip(asset.score, "max"), countChip(asset.findingKeys.length, "findings")], asset.owner || "unknown owner"),
    assetBody(asset)
  );
  return card;
}

function smallBody(value) {
  const body = document.createElement("div");
  body.className = "body";
  const summary = document.createElement("div");
  summary.className = "sub";
  summary.textContent = value;
  body.append(summary);
  return body;
}

function assetBody(asset) {
  const body = document.createElement("div");
  body.className = "body";
  const paths = networkPathsForAsset(asset.id);
  body.append(
    contextRow("Network", asset.exposures),
    contextRow("Ingress", paths.map(path => path.label).slice(0, 3)),
    contextRow("IAM", [...asset.privileges, ...asset.iamImpacts]),
    contextRow("Criticality", asset.criticalities),
    contextRow("Code", asset.codeExposures),
    contextRow("Source", asset.sourceStates),
    contextRow("Environment", asset.environments)
  );
  if (asset.evidence && asset.evidence.length) {
    body.append(contextRow("Evidence", asset.evidence.slice(0, 2)));
  }
  return body;
}

function renderVulnerabilityCard(vuln, position) {
  const card = createCard("vuln-card", vuln.tier, position, vuln);
  const weakness = isSecurityFinding(vuln.findingType) ? ` | ${vuln.weakness?.weakness || "security finding"}` : "";
  const subtitle = `${compactComponent(vuln.component, vuln.componentVersion)}${weakness} | code ${vuln.codeExposure} | ${vuln.exposure} network | ${vuln.privilege} IAM`;
  card.append(
    cardTop(vuln.label, [priorityChip(vuln.tier), scoreChip(vuln.score), isSecurityFinding(vuln.findingType) ? tag(vuln.weakness?.scanner_type || "scanner", "count") : null, isRuntimeFinding(vuln.findingType) ? tag(vuln.runtimeEvidence?.state || "runtime", "count") : null, vuln.knownExploited ? tag("known exploited", "urgent") : null], subtitle),
    vulnBody(vuln)
  );
  return card;
}

function vulnBody(vuln) {
  const body = document.createElement("div");
  body.className = "body";
  const summary = document.createElement("div");
  summary.className = "sub";
  summary.textContent = vuln.summary || first(vuln.rationale) || "No summary available.";
  body.append(summary);
  return body;
}

function createCard(kind, tierValue, position, datum) {
  position = position || {x: 0, y: 0, width: 220, height: 90};
  const card = document.createElement("div");
  card.className = `card ${kind} ${tierValue}${selected && selected.id === datum.id ? " selected" : ""}`;
  card.dataset.role = kind;
  card.dataset.nodeId = datum.id;
  card.tabIndex = 0;
  card.style.left = `${position.x}px`;
  card.style.top = `${position.y}px`;
  card.style.width = `${position.width}px`;
  card.style.height = `${position.height}px`;
  card.addEventListener("mousedown", event => event.stopPropagation());
  card.addEventListener("click", event => {
    event.stopPropagation();
    selected = datum;
    render();
  });
  card.addEventListener("keydown", event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    event.stopPropagation();
    selected = datum;
    render();
  });
  return card;
}

function cardTop(titleText, chipsValue, subtitle) {
  const top = document.createElement("div");
  top.className = "top";
  const titleWrap = document.createElement("div");
  titleWrap.className = "title";
  const titleMain = labelElement("div", "title-main", titleText, CARD_TITLE_BUDGET, CARD_TOKEN_BUDGET);
  titleWrap.append(titleMain);
  if (subtitle) titleWrap.append(labelElement("div", "sub", subtitle, CARD_SUB_BUDGET, CARD_TOKEN_BUDGET));
  top.append(titleWrap, chips(chipsValue));
  return top;
}

function contextRow(label, values) {
  const row = document.createElement("div");
  row.className = "row";
  const labelEl = document.createElement("div");
  labelEl.className = "label";
  labelEl.textContent = label;
  row.append(labelEl, chips(values && values.length ? values : ["unknown"], 5));
  return row;
}

function chips(values, maxItems = 8) {
  const wrap = document.createElement("div");
  wrap.className = "chips";
  const filtered = (values || []).filter(Boolean);
  for (const value of filtered.slice(0, maxItems)) {
    const data = chipValue(value);
    if (!data.text) continue;
    const chip = document.createElement("span");
    chip.className = `chip ${data.className}`;
    // A chip that CSS clips at 159px throws away the identifier it exists to
    // show; shortening it first keeps the head of the value and the ellipsis,
    // and the untruncated string stays on title.
    const shown = shortenLabel(data.text, CHIP_TEXT_BUDGET, CHIP_TOKEN_BUDGET);
    chip.textContent = shown;
    if (shown !== data.text.trim()) chip.title = data.text;
    wrap.appendChild(chip);
  }
  if (filtered.length > maxItems) {
    const more = document.createElement("span");
    more.className = "chip count";
    more.textContent = `+${filtered.length - maxItems}`;
    wrap.appendChild(more);
  }
  return wrap;
}

function compactComponent(component, version) {
  const value = `${component || "unknown"}@${version || "unknown"}`;
  if (value.length <= 74) return value;
  return `${value.slice(0, 34)}...${value.slice(-30)}`;
}

function chipValue(value) {
  if (value && typeof value === "object") {
    const text = String(value.text || "");
    return {text, className: chipClass(value.className || text)};
  }
  const text = String(value || "");
  return {text, className: chipClass(text)};
}

function tag(text, className) {
  return {text, className};
}

function priorityChip(value) {
  return tag(`priority ${value || "unknown"}`, value || "unknown");
}

function scoreChip(value, suffix = "score") {
  return tag(`${Number(value || 0).toFixed(1)} ${suffix}`, "score");
}

// Singulars matter on a count of one: "1 assets" is the detail that makes an
// otherwise careful artifact read as unfinished. Plurals are English 's' plus
// the two irregulars this report actually produces.
const CHIP_SINGULARS = {deps: "dep", "posture findings": "posture finding", "static findings": "static finding", "runtime findings": "runtime finding"};

function countChip(value, label) {
  const word = Number(value) === 1 ? CHIP_SINGULARS[label] || String(label).replace(/s$/, "") : label;
  return tag(`${value} ${word}`, "count");
}

function exposureChip(value) {
  return tag(`network exposure: ${value || "unknown"}`, value || "unknown");
}

function chipClass(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "unknown";
}

function renderScenarioList(scenarios) {
  const title = document.getElementById("visibleListTitle");
  if (title) title.textContent = "Visible Risk Scenarios";
  const list = document.getElementById("findingList");
  if (!scenarios.length) {
    list.replaceChildren(emptyListElement("risk scenarios"));
    return;
  }
  list.replaceChildren(...scenarios.map(scenario => {
    const item = document.createElement("div");
    item.className = "item";
    item.tabIndex = 0;
    item.setAttribute("role", "button");
    item.addEventListener("click", () => {
      selected = {...scenario, scenarioKind: "scenario", attackKind: "scenario"};
      render();
    });
    item.addEventListener("keydown", event => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      selected = {...scenario, scenarioKind: "scenario", attackKind: "scenario"};
      render();
    });
    const rowTitle = document.createElement("div");
    rowTitle.className = "item-title";
    rowTitle.append(text(scenario.title || "Risk scenario"));
    const chip = document.createElement("span");
    chip.className = `chip ${scenario.tier || "informational"}`;
    chip.textContent = `${scenario.priorityLabel || priorityText(scenario.tier)} ${Number(scenario.score || 0).toFixed(1)}`;
    rowTitle.append(chip);
    const meta = document.createElement("div");
    meta.className = "item-meta";
    const scenarioFindings = scenario.totalFindings || 0;
    meta.appendChild(identifierRuns(`${scenario.assetName || "asset"} | provider ${scenario.provider || "context"} | network exposure ${scenario.exposure || "unknown"} | ${scenarioFindings} ${scenarioFindings === 1 ? "finding" : "findings"}`));
    item.append(rowTitle, meta);
    return item;
  }));
}

function renderFindingList(findings) {
  const title = document.getElementById("visibleListTitle");
  if (title) title.textContent = "Visible Findings";
  const list = document.getElementById("findingList");
  if (!findings.length) {
    list.replaceChildren(emptyListElement("findings"));
    return;
  }
  list.replaceChildren(...findings.map(finding => {
    const item = document.createElement("div");
    item.className = "item";
    item.tabIndex = 0;
    item.setAttribute("role", "button");
    item.addEventListener("click", () => {
      selected = viewMode === "attack" && attackPathByFindingKey.has(finding.key)
        ? {...attackPathByFindingKey.get(finding.key), attackKind: "path"}
        : vulnerabilityByFindingKey.get(finding.key);
      render();
    });
    item.addEventListener("keydown", event => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      selected = viewMode === "attack" && attackPathByFindingKey.has(finding.key)
        ? {...attackPathByFindingKey.get(finding.key), attackKind: "path"}
        : vulnerabilityByFindingKey.get(finding.key);
      render();
    });
    const title = document.createElement("div");
    title.className = "item-title";
    const findingTitle = isSecurityFinding(finding.finding_type)
      ? `${finding.vulnerability.id} ${finding.weakness?.weakness || "security finding"}`
      : `${finding.vulnerability.id} in ${finding.component.name}`;
    title.append(identifierRuns(findingTitle));
    const chip = document.createElement("span");
    chip.className = `chip ${finding.tier}`;
    chip.textContent = `priority ${finding.tier} ${Number(finding.score).toFixed(1)}`;
    title.append(chip);
    const meta = document.createElement("div");
    meta.className = "item-meta";
    const scanner = isSecurityFinding(finding.finding_type) ? ` | scanner ${(finding.weakness || {}).tool || "unknown"}` : "";
    meta.appendChild(identifierRuns(`${finding.artifact.name}${scanner} | code evidence ${codeExposureFromState(finding.source_reachability || {})} | source state ${(finding.source_reachability || {}).state} | network exposure ${(finding.context || {}).exposure || "unknown"} | IAM/RBAC privilege ${(finding.context || {}).privilege || "unknown"}`));
    item.append(title, meta);
    return item;
  }));
}

/* === The evidence chain ==================================================
   The report's thesis is that missing evidence is never safe, so the hero is
   the chain and where it breaks. Each link states its own role and state in
   words; hue and dash pattern repeat that, they never carry it alone. */
const CHAIN_ROLES = {
  entry: "entry",
  ingress: "network",
  hop: "network",
  service: "service",
  workload: "workload",
  artifact: "asset",
  source: "source",
  vulnerability: "finding",
  weakness: "finding",
  runtime: "finding",
  finding: "finding",
  posture: "posture",
  identity: "identity",
  data: "data",
  lateral: "pivot",
  blocker: "control",
  unknown: "gap",
};

function chainRole(type) {
  return CHAIN_ROLES[type] || String(type || "step").replace(/_/g, " ");
}

// Which attack path's evidence does this selection stand on? A scenario or an
// asset carries several, so the highest-priority one is the one shown.
function chainPathFor(datum) {
  if (!datum) return null;
  if (Array.isArray(datum.nodes) && datum.nodes.length && datum.edges) return datum;
  if (datum.path && Array.isArray(datum.path.nodes)) return datum.path;
  if (datum.findingKey && attackPathByFindingKey.has(datum.findingKey)) {
    return attackPathByFindingKey.get(datum.findingKey);
  }
  const paths = (datum.findingKeys || [])
    .map(key => attackPathByFindingKey.get(key))
    .filter(Boolean)
    .sort((a, b) => ((tierRank[b.tier] ?? 0) - (tierRank[a.tier] ?? 0)) || ((b.score || 0) - (a.score || 0)));
  return paths[0] || null;
}

// Walk the edge list from the node nothing points at, so the chain is rendered in
// causal order rather than array order. Anything the walk cannot reach is appended
// rather than dropped: a node that is hard to place is still evidence.
function chainLinks(path) {
  const nodes = path.nodes || [];
  const edges = path.edges || [];
  const byId = new Map(nodes.map(node => [node.id, node]));
  const incoming = new Map();
  const outgoing = new Map();
  for (const edge of edges) {
    if (!incoming.has(edge.to)) incoming.set(edge.to, edge);
    if (!outgoing.has(edge.from)) outgoing.set(edge.from, edge);
  }
  const links = [];
  const seen = new Set();
  let current = nodes.find(node => !incoming.has(node.id)) || nodes[0];
  let edge = null;
  while (current && !seen.has(current.id)) {
    seen.add(current.id);
    links.push({node: current, edge});
    edge = outgoing.get(current.id) || null;
    current = edge ? byId.get(edge.to) : null;
  }
  for (const node of nodes) {
    if (!seen.has(node.id)) links.push({node, edge: incoming.get(node.id) || null});
  }
  return links;
}

function chainNodeState(node) {
  if (!node) return "unknown";
  if (node.state === "blocked") return "blocked";
  if (node.state === "unknown" || node.type === "unknown") return "unknown";
  return hasCollectedEvidence(node) ? "proven" : "unknown";
}

function chainEdgeState(edge) {
  // The head link has no incoming connector by construction. That is not the
  // same as a connector with nothing behind it, and it is the only case where
  // an absent object is not an absence of evidence.
  if (!edge) return "proven";
  if (edge.blocker) return "blocked";
  if (edge.unknown) return "unknown";
  return hasCollectedEvidence(edge) ? "proven" : "unknown";
}

// An unknown node's own label already names the gap ("network path confidence is
// low or unresolved"); the path-level unknowns are the fallback. Never return an
// empty string: a gap with no explanation would read as a decoration.
function chainGapText(node, path) {
  // A step that is unknown only because nothing was collected for it is not a
  // labelled gap, and its own label ("Unknown entry") explains nothing on its
  // own. Say which evidence is missing, which is what the reader has to act on.
  if (node && node.type !== "unknown" && node.state !== "unknown" && !hasCollectedEvidence(node)) {
    const subject = String(node.label || chainRole(node.type) || "this step").trim();
    return `no evidence layer was collected for ${subject}: it rests on supplied context alone, so this report will not call it proven`;
  }
  const own = String(node.label || "").trim();
  const gaps = (path.unknowns || []).filter(Boolean);
  // A single-token label is the subject of the gap, not an account of it: a
  // node whose whole explanation reads "azurerm_container_app.orders" tells the
  // reader nothing, so the path's own unknowns are the better sentence.
  const explains = own && own.toLowerCase() !== "unknown" && /\s/.test(own);
  if (explains) return own;
  if (gaps.length) return gaps.join("; ");
  if (own && own.toLowerCase() !== "unknown") return own;
  return "this step was not covered by any collected evidence";
}

// A gap link names its subject ("network path", "SBOM only") rather than
// repeating the word unknown three times; the state line and the note carry the
// rest. It is never left blank: an unlabelled gap reads as decoration.
function chainNodeName(node, state) {
  if (state === "unknown" && node.type === "unknown") {
    const subject = String(node.label || "").trim();
    return subject ? shortenLabel(subject, 22) : "unknown";
  }
  return node.label || node.type || "step";
}

function setChainNote(kind, label, body) {
  chainNote.className = `chain-note${kind ? ` is-${kind}` : ""}`;
  const parts = [];
  if (label) {
    const marker = document.createElement("span");
    marker.className = "chain-note-kind";
    marker.textContent = `${label} `;
    parts.push(marker);
  }
  parts.push(text(body));
  chainNote.replaceChildren(...parts);
}

let chainPathId = null;
let chainRevealed = false;
let chainBreakElement = null;

// The break is the point of the chain, so it is what the track opens on when the
// chain is wider than its pane -- and it stays that way across a resize. The
// entry link is load bearing too, so the scroll stops as soon as the break is on
// screen rather than centring it: at 1366 the old 45% anchor pushed the entry
// and network links entirely out of view before the reader had seen them.
function scrollChainToBreak() {
  if (!chainTrack) return;
  if (!chainBreakElement || !chainBreakElement.isConnected) {
    chainTrack.scrollLeft = 0;
    updateChainOverflow();
    return;
  }
  const visibleRight = chainTrack.scrollLeft + chainTrack.clientWidth;
  const breakRight = chainBreakElement.offsetLeft + chainBreakElement.offsetWidth;
  if (breakRight > visibleRight) {
    chainTrack.scrollLeft = Math.max(0, breakRight - chainTrack.clientWidth + 12);
  } else if (chainBreakElement.offsetLeft < chainTrack.scrollLeft) {
    chainTrack.scrollLeft = Math.max(0, chainBreakElement.offsetLeft - 12);
  }
  updateChainOverflow();
}

function renderEvidenceChain(datum) {
  const path = chainPathFor(datum);
  chainRevealed = Boolean(path) && path.id === chainPathId;
  chainPathId = path ? path.id : null;
  chainVerdict.className = "chain-verdict";
  if (!path) {
    chainVerdict.textContent = "No evidence chain for this selection";
    chainBreakElement = null;
    chainTrack.replaceChildren();
    setChainNote("", "", DATA.findings.length
      ? "Select a risk scenario or a finding to see the evidence its path stands on."
      : "No findings were produced, so there is no path to trace.");
    return;
  }
  const links = chainLinks(path);
  if (!links.length) {
    chainVerdict.textContent = "No evidence chain for this selection";
    chainBreakElement = null;
    chainTrack.replaceChildren();
    setChainNote("unknown", "unknown", "This path carries no evidence nodes, so no step can be shown as proven.");
    return;
  }
  const track = [];
  let firstBreak = null;
  let breakElement = null;
  let provenLinks = 0;
  links.forEach((link, index) => {
    const nodeState = chainNodeState(link.node);
    const edgeState = chainEdgeState(link.edge);
    if (index > 0) track.push(chainConnector(link.edge, edgeState));
    if (nodeState === "proven" && edgeState === "proven") provenLinks += 1;
    const element = chainLinkElement(link, nodeState, path, index);
    if (!firstBreak && (nodeState !== "proven" || edgeState !== "proven")) {
      firstBreak = {link, nodeState, edgeState, previous: links[index - 1] || null};
      breakElement = element;
    }
    track.push(element);
  });
  chainTrack.replaceChildren(...track);
  chainBreakElement = breakElement;
  // Start at the entry link every time: it is the head of the claim, and the
  // scroll below moves only as far as it must to bring the break into view.
  chainTrack.scrollLeft = 0;
  scrollChainToBreak();

  const total = links.length;
  if (!firstBreak) {
    chainVerdict.className = "chain-verdict is-proven";
    chainVerdict.textContent = `Evidence complete — all ${total} links proven`;
    setChainNote("", "proven", `Every step from ${chainRole(links[0].node.type)} to ${chainRole(links[total - 1].node.type)} is backed by collected evidence for ${path.title || "this finding"}.`);
    return;
  }
  // "stops at gap" names nothing a reader can act on: name the last step that
  // was proven, which is the point the evidence actually reaches.
  const atGap = firstBreak.link.node.type === "unknown" && firstBreak.previous;
  const role = chainRole((atGap ? firstBreak.previous.node : firstBreak.link.node).type);
  const blocked = firstBreak.edgeState === "blocked" || firstBreak.nodeState === "blocked";
  chainVerdict.className = `chain-verdict ${blocked ? "is-blocked" : "is-broken"}`;
  chainVerdict.replaceChildren(
    text(blocked ? "Blocked at " : atGap ? "Evidence stops after " : "Evidence stops at "),
    chainVerdictMark(role),
    text(` — ${provenLinks} of ${total} links proven`)
  );
  setChainNote(
    blocked ? "blocked" : "unknown",
    blocked ? "blocked" : "unknown",
    blocked
      ? `A control stops the path at the ${role} step: ${firstBreak.link.edge?.label || "control evidence"}.`
      : chainGapText(firstBreak.link.node, path)
  );
}

// Nothing is selected. Either the filters hid everything, or the run produced no
// findings at all. Those are different statements and the panel makes both, with
// the inputs that were read, so an empty report is still auditable.
function renderEmptyDetails() {
  const section = document.createElement("section");
  const filtered = DATA.findings.length > 0;
  section.append(heading(filtered ? "Nothing matches the current filters" : "No findings to prioritize"));
  const lead = document.createElement("p");
  lead.className = "empty";
  const coverage = coverageSummary();
  const profile = coverage.profile === "unknown" ? "" : ` under the ${coverage.profile} analysis profile`;
  lead.textContent = filtered
    ? `${DATA.findings.length} findings are in this report but none pass the filters above. Clear a filter, or press Reset, to bring them back.`
    : `This run produced no findings${profile}. That is not the same as being unaffected: it is bounded by what was scanned.`;
  section.append(lead);
  appendList(section, "Evidence that was read", coverage.present.length ? coverage.present : ["nothing — no inputs were supplied"]);
  appendList(section, "Evidence that was absent", coverage.absent.length ? coverage.absent : ["none — every input type supplied at least one record"]);
  details.replaceChildren(section);
}

// Fade only the edge that actually has more chain behind it, so the fade reads
// as "there is more" rather than as a decoration on a chain that already fits.
function updateChainOverflow() {
  const overflow = chainTrack.scrollWidth - chainTrack.clientWidth;
  chainTrack.classList.toggle("fade-start", chainTrack.scrollLeft > 4);
  chainTrack.classList.toggle("fade-end", overflow > 4 && chainTrack.scrollLeft < overflow - 4);
}

function chainVerdictMark(role) {
  const mark = document.createElement("span");
  mark.className = "chain-verdict-mark";
  mark.textContent = role;
  return mark;
}

function chainConnector(edge, state) {
  const connector = document.createElement("span");
  connector.className = "chain-edge";
  connector.dataset.chainState = state;
  connector.setAttribute("aria-hidden", "true");
  const line = document.createElement("span");
  line.className = "chain-edge-line";
  const cap = document.createElement("span");
  cap.className = "chain-edge-cap";
  const label = document.createElement("span");
  label.className = "chain-edge-label";
  label.textContent = state === "proven" ? "" : state;
  if (edge && edge.label) connector.title = edge.label;
  connector.append(line, cap, label);
  return connector;
}

function chainLinkElement(link, state, path, index) {
  const node = link.node;
  const button = document.createElement("button");
  button.type = "button";
  const active = selected && (selected.id === node.id || selected.findingKey === node.rawRef);
  button.className = `chain-link${active ? " is-active" : ""}`;
  const role = chainRole(node.type);
  button.dataset.chainRole = role;
  button.dataset.chainState = state;
  // One subtle reveal when the chain changes path, and none at all while the
  // reader is typing in the filter box, which re-renders on every keystroke.
  if (chainRevealed) button.classList.add("is-static");
  else button.style.animationDelay = `${Math.min(index, 12) * 35}ms`;

  const roleLabel = document.createElement("span");
  roleLabel.className = "chain-role";
  roleLabel.textContent = role;
  const mark = document.createElement("span");
  mark.className = "chain-mark";
  mark.textContent = nodeIcon(node.type, node.state);
  const name = chainNodeName(node, state);
  const nameEl = labelElement("span", "chain-name", name, CHAIN_NAME_BUDGET, CHAIN_NAME_BUDGET);
  const stateEl = document.createElement("span");
  stateEl.className = "chain-state";
  // "proven" is only ever reached with a named evidence layer, and the layer is
  // the more useful word. It is never a fallback for not having one: a link with
  // no layer is unknown by then, and says so.
  stateEl.textContent = state === "proven" ? node.evidenceLayer : state;

  const detail = state === "unknown"
    ? chainGapText(node, path)
    : `${node.subtitle || name} (evidence layer ${node.evidenceLayer})`;
  // The visible name is shortened; the accessible name and the hover title are not.
  const fullName = state === "unknown" && node.type === "unknown" ? "unknown" : node.label || name;
  button.title = `${role}: ${fullName}\n${state}: ${detail}`;
  button.setAttribute("aria-label", `${role}, ${fullName}, ${state}. ${detail}`);
  button.append(roleLabel, mark, nameEl, stateEl);

  const show = () => setChainNote(state === "proven" ? "" : state, `${role} · ${state}`, detail);
  button.addEventListener("mouseenter", show);
  button.addEventListener("focus", show);
  button.addEventListener("mouseleave", () => renderEvidenceChainNote(path));
  button.addEventListener("blur", () => renderEvidenceChainNote(path));
  button.addEventListener("click", event => {
    event.preventDefault();
    selected = {...node, attackKind: "node", path};
    render();
  });
  return button;
}

// Restore the standing verdict note after a hover or focus ends.
function renderEvidenceChainNote(path) {
  const links = chainLinks(path);
  for (const link of links) {
    const nodeState = chainNodeState(link.node);
    const edgeState = chainEdgeState(link.edge);
    if (nodeState === "proven" && edgeState === "proven") continue;
    const blocked = edgeState === "blocked" || nodeState === "blocked";
    setChainNote(
      blocked ? "blocked" : "unknown",
      blocked ? "blocked" : "unknown",
      blocked
        ? `A control stops the path at the ${chainRole(link.node.type)} step: ${link.edge?.label || "control evidence"}.`
        : chainGapText(link.node, path)
    );
    return;
  }
  setChainNote("", "proven", `Every step of this path is backed by collected evidence for ${path.title || "this finding"}.`);
}

function renderDetails(datum) {
  if (!datum) {
    renderEmptyDetails();
    return;
  }
  const section = document.createElement("section");
  if (datum.attackKind === "graphNode") {
    const path = datum.path || {};
    section.append(heading(datum.label || "Attack graph node"));
    section.append(chips([priorityChip(datum.tier || path.tier), scoreChip(datum.score || path.score), tag(datum.graphType || datum.type || "node", "count"), datum.confidence ? tag(`confidence ${datum.confidence}`, "count") : null]));
    if (datum.graphKind === "entryRoot") {
      section.append(kv({
        "node role": "shared outside entry",
        "entry meaning": "One Internet/attacker source shared by every public or external route shown in the graph.",
        "route options": datum.routeCount,
        subtitle: datum.subtitle,
      }));
      appendList(section, "Entry surfaces", datum.surfaceTitles || []);
    } else if (datum.graphKind === "findingGroup") {
      const linkedFindings = (datum.findingKeys || []).map(key => vulnerabilityByFindingKey.get(key)).filter(Boolean);
      section.append(kv({
        "node role": "finding group",
        route: path.title || path.pathLabel,
        provider: path.provider,
        entry: path.entryLabel,
        exposure: path.exposure,
        state: datum.expanded ? "expanded" : "collapsed",
      }));
      appendActionList(section, datum.expanded ? "Collapse findings" : "Expand findings", [{
        label: datum.expanded ? "Collapse finding nodes" : "Show one node per finding",
        onClick: () => {
          toggleGraphNodeExpansion(datum.id);
          selected = {...datum, expanded: expandedGraphNodes.has(datum.id)};
          render();
        },
      }]);
      appendList(section, "Linked findings", linkedFindings.map(finding => `${priorityText(finding.tier)} ${Number(finding.score || 0).toFixed(1)} ${finding.label} in ${finding.component}`));
    } else {
      section.append(kv({
        "node role": humanizeEvidenceKind(datum.graphType || datum.type || "node"),
        route: path.title || path.pathLabel,
        provider: path.provider,
        entry: path.entryLabel,
        exposure: path.exposure,
        "path type": path.pathType,
        subtitle: datum.subtitle,
      }));
      appendActionList(section, "Open related route", [{
        label: `${priorityText(path.tier)} ${Number(path.score || 0).toFixed(1)} ${path.title || path.pathLabel || "route"}`,
        onClick: () => {
          selected = {...path, attackKind: "group"};
          render();
        },
      }]);
      appendList(section, "Affected scenarios", (path.scenarioIds || []).map(id => scenarioById.get(id)).filter(Boolean).map(scenario => `${scenario.priorityLabel || priorityText(scenario.tier)} ${Number(scenario.score || 0).toFixed(1)} ${scenario.title}`));
      appendList(section, "Path steps", path.pathSteps || []);
      appendList(section, "Evidence gaps and blockers", [...(path.unknowns || []), ...(path.blockers || []).map(formatBlocker)]);
    }
  } else if (datum.attackKind === "graphEdge") {
    const path = datum.path || {};
    section.append(heading(datum.label || "Attack graph connection"));
    section.append(chips([priorityChip(datum.tier || path.tier), scoreChip(datum.score || path.score), datum.lateral ? tag("lateral movement", "count") : tag("route transition", "count"), datum.unknown ? tag("unknown", "informational") : null, datum.blocker ? tag("blocked", "medium") : null]));
    section.append(kv({
      from: datum.fromNode?.label || datum.from,
      to: datum.toNode?.label || datum.to,
      route: path.title || path.pathLabel,
      provider: path.provider,
      entry: path.entryLabel,
      exposure: path.exposure,
      "path type": path.pathType,
    }));
    appendActionList(section, "Open related route", [{
      label: `${priorityText(path.tier)} ${Number(path.score || 0).toFixed(1)} ${path.title || path.pathLabel || "route"}`,
      onClick: () => {
        selected = {...path, attackKind: "group"};
        render();
      },
    }]);
    appendList(section, "Path steps", path.pathSteps || []);
    appendList(section, "Evidence gaps and blockers", [...(path.unknowns || []), ...(path.blockers || []).map(formatBlocker)]);
  } else if (datum.attackKind === "surface") {
    section.append(heading(datum.title || "Entry surface"));
    section.append(chips([priorityChip(datum.tier), scoreChip(datum.score), exposureChip(datum.exposure), countChip(datum.routeCount || 0, "routes"), countChip(datum.assetCount || 0, "assets"), countChip(datum.findingCount || 0, "findings")]));
    section.append(kv({
      "entry mode": datum.surfaceModeLabel,
      provider: datum.provider,
      entry: datum.entryLabel,
      confidence: datum.confidence,
      assets: (datum.assetNames || []).join(", "),
      summary: datum.summary,
    }));
    appendActionList(section, "Route options", (datum.groups || []).map(group => ({
      label: `${priorityText(group.tier)} ${Number(group.score || 0).toFixed(1)} ${group.title || group.pathLabel || "route"} (${group.assetCount || 0} assets)`,
      onClick: () => {
        selected = {...group, attackKind: "group"};
        render();
      },
    })));
    appendList(section, "Affected scenarios", (datum.scenarioIds || []).map(id => scenarioById.get(id)).filter(Boolean).map(scenario => `${scenario.priorityLabel || priorityText(scenario.tier)} ${Number(scenario.score || 0).toFixed(1)} ${scenario.title}`));
  } else if (datum.attackKind === "group") {
    section.append(heading(datum.title || "Shared attack path"));
    section.append(chips([priorityChip(datum.tier), scoreChip(datum.score), exposureChip(datum.exposure), countChip(datum.assetCount || 0, "assets"), countChip(datum.findingCount || 0, "findings")]));
    section.append(kv({
      provider: datum.provider,
      entry: datum.entryLabel,
      "path type": datum.pathType,
      confidence: datum.confidence,
      assets: (datum.assetNames || []).join(", "),
      summary: datum.summary,
    }));
    appendList(section, "Path steps", datum.steps || []);
    appendList(section, "Affected scenarios", (datum.scenarioIds || []).map(id => scenarioById.get(id)).filter(Boolean).map(scenario => `${scenario.priorityLabel || priorityText(scenario.tier)} ${Number(scenario.score || 0).toFixed(1)} ${scenario.title}`));
    appendList(section, "Network evidence", [datum.evidence || datum.summary].filter(Boolean));
  } else if (datum.scenarioKind === "scenario" || datum.attackKind === "scenario") {
    const scenario = scenarioById.get(datum.id) || datum;
    section.append(heading(scenario.title || "Risk scenario"));
    section.append(chips([priorityChip(scenario.tier), scoreChip(scenario.score), exposureChip(scenario.exposure), countChip(scenario.totalFindings || 0, "findings"), tag(scenario.status || "Open", "count")]));
    section.append(kv({
      asset: scenario.assetName,
      owner: scenario.owner,
      provider: scenario.provider,
      entry: scenario.entryLabel,
      path: scenario.pathLabel,
      "policy status": scenario.status,
      "in use findings": scenario.inUseCount,
    }));
    appendCategoryPanels(section, scenario.categoryList || []);
    appendActionList(section, "Linked findings", (scenario.findingKeys || []).map(key => {
      const finding = vulnerabilityByFindingKey.get(key);
      return {
        label: finding ? `${finding.tier} ${Number(finding.score || 0).toFixed(1)} ${finding.label} in ${finding.component}` : key,
        onClick: () => {
          selected = finding || scenario;
          render();
        },
      };
    }));
    appendList(section, "Path steps", scenario.pathSteps || []);
    appendList(section, "Evidence summary", scenario.evidenceSummary || []);
    appendList(section, "Blockers and constraints", (scenario.blockers || []).map(formatBlocker));
  } else if (datum.attackKind === "path") {
    section.append(heading(datum.title || "Attack path"));
    section.append(chips([priorityChip(datum.tier), scoreChip(datum.score), tag(datum.findingTypeLabel || datum.findingType, "count"), exposureChip(datum.exposure), tag(`confidence ${datum.confidence || "low"}`, "count")]));
    section.append(kv({
      artifact: datum.artifact?.name,
      owner: datum.owner,
      provider: datum.provider,
      component: datum.component ? `${datum.component.name}@${datum.component.version || "unknown"}` : undefined,
      finding: datum.advisory?.id,
      "known exploited": datum.advisory?.known_exploited ? "yes" : undefined,
    }));
    appendList(section, "Why this is prioritized", datum.why || [datum.shortReason].filter(Boolean));
    appendList(section, "Evidence used", datum.evidenceSummary || []);
    appendList(section, "Unknown evidence and visibility gaps", datum.unknowns || []);
    appendList(section, "Blockers and constraints", (datum.blockers || []).map(formatBlocker));
    appendList(section, "Recommended next steps", datum.remediation || []);
    appendNodeLinks(section, "Path nodes", datum.nodes || [], datum);
    section.append(rawDisclosure("Raw evidence", datum.rawEvidence || datum));
  } else if (datum.attackKind === "node") {
    section.append(heading(datum.label || datum.type || "Attack-path node"));
    section.append(chips([tag(datum.type || "node", "count"), tag(datum.evidenceLayer || "Context", "count"), tag(`confidence ${datum.confidence || "low"}`, "count")]));
    section.append(kv({
      type: datum.type,
      state: datum.state,
      subtitle: datum.subtitle,
      "raw reference": datum.rawRef,
    }));
    if (datum.path) {
      appendActionList(section, "Linked finding", [{
        label: `${datum.path.tier} ${Number(datum.path.score || 0).toFixed(1)} ${datum.path.title}`,
        onClick: () => {
          selected = {...datum.path, attackKind: "path"};
          render();
        },
      }]);
      appendList(section, "Unknown evidence and visibility gaps", datum.path.unknowns || []);
      appendList(section, "Blockers and constraints", (datum.path.blockers || []).map(formatBlocker));
    }
  } else if (datum.architectureKind === "zone") {
    const arch = DATA.architecture || {assets: [], hops: []};
    const zoneAssets = (arch.assets || []).filter(asset => asset.zoneId === datum.id).map(asset => assetById.get(asset.id) || asset);
    const zoneHops = (arch.hops || []).filter(hop => hop.zoneId === datum.id);
    section.append(heading(datum.label));
    section.append(chips([countChip(zoneAssets.length, "assets"), countChip(zoneHops.length, "hops")]));
    section.append(kv({
      purpose: datum.summary,
      assets: zoneAssets.map(asset => asset.name || asset.id).join(", "),
      hops: zoneHops.map(hop => hop.label || hop.id).join(", "),
    }));
  } else if (datum.architectureKind === "hop") {
    const linkedAssets = (datum.assetIds || []).map(assetId => assetById.get(assetId)).filter(Boolean);
    section.append(heading(datum.label || "Network hop"));
    section.append(chips([tag(datum.provider || "Context", "count"), exposureChip(datum.exposure), scoreChip(datum.score || 0, "max")]));
    section.append(kv({
      provider: datum.provider,
      kind: datum.kind,
      exposure: datum.exposure,
      confidence: datum.confidence,
      assets: linkedAssets.map(asset => asset.name || asset.id).join(", "),
      summary: datum.summary,
    }));
    appendList(section, "Blockers and constraints", (datum.blockers || []).map(formatBlocker));
    appendList(section, "Network evidence", [datum.evidence || datum.summary].filter(Boolean));
  } else if (datum.attackKind === "risk") {
    const linkedAssets = (datum.assetIds || []).map(assetId => assetById.get(assetId)).filter(Boolean);
    const linkedFindings = (datum.findingKeys || []).map(key => vulnerabilityByFindingKey.get(key)).filter(Boolean);
    section.append(heading(datum.title || datum.label || "Evidence and impact"));
    section.append(chips([priorityChip(datum.tier), scoreChip(datum.score || 0, "max"), countChip(linkedAssets.length, "assets"), datum.findingCount ? countChip(datum.findingCount, "findings") : null]));
    section.append(kv({
      kind: datum.kind,
      assets: linkedAssets.map(asset => asset.name || asset.id).join(", "),
      summary: datum.summary,
    }));
    appendList(section, "Linked findings", linkedFindings.map(finding => `${finding.tier} ${Number(finding.score || 0).toFixed(1)} ${finding.label}`));
    appendList(section, "Identity/data signals", datum.signals || []);
    appendList(section, "Blockers and gaps", (datum.blockers || []).map(formatBlocker));
    appendList(section, "Linked network paths", (datum.networkPathIds || []).map(pathId => (DATA.networkPaths || []).find(path => path.id === pathId)).filter(Boolean).map(path => path.evidence || path.summary).filter(Boolean));
  } else if (datum.networkKind) {
    const linkedAssets = pathAssetIds(datum).map(assetId => assetById.get(assetId)).filter(Boolean);
    const linkedAssetNames = linkedAssets.map(asset => asset.name || asset.id);
    section.append(heading(datum.networkKind === "entry" ? datum.entryLabel : `${datum.label} -> ${linkedAssetNames.join(", ") || "asset"}`));
    section.append(chips([exposureChip(datum.exposure), scoreChip(datum.score || 0, "max")]));
    section.append(kv({
      assets: linkedAssetNames,
      entry: datum.entryLabel,
      "network exposure": datum.exposure,
      "path type": datum.pathType,
      confidence: datum.confidence,
      provider: datum.provider,
      path: datum.summary,
      owner: datum.owner || linkedAssets.map(asset => asset.owner).filter(Boolean).join(", "),
    }));
    appendList(section, "Path steps", datum.steps || []);
    appendList(section, "Blockers and constraints", (datum.blockers || []).map(formatBlocker));
    appendList(section, "Network evidence", datum.networkKind === "entry"
      ? (datum.linkedPathIds || []).map(pathId => (DATA.networkPaths || []).find(path => path.id === pathId)).filter(Boolean).map(path => path.evidence || path.summary).filter(Boolean)
      : [datum.evidence || datum.summary].filter(Boolean));
  } else if (datum.findingKey) {
    const title = isSecurityFinding(datum.findingType) ? `${datum.label} ${datum.weakness?.weakness || "security finding"}` : `${datum.label} in ${datum.component}`;
    const scannerChips = isSecurityFinding(datum.findingType) ? [tag(datum.weakness?.scanner_type || "scanner", "count"), datum.weakness?.cwe ? tag(datum.weakness.cwe, "count") : null, isRuntimeFinding(datum.findingType) ? tag(datum.runtimeEvidence?.state || "runtime", "count") : null] : [];
    section.append(heading(title));
    section.append(chips([priorityChip(datum.tier), scoreChip(datum.score), ...scannerChips]));
    section.append(kv({
      component: `${datum.component}@${datum.componentVersion}`,
      "finding type": findingTypeLabel(datum.findingType),
      scanner: isSecurityFinding(datum.findingType) ? datum.weakness?.tool : undefined,
      CWE: datum.weakness?.cwe || (isStaticFinding(datum.findingType) || isRuntimeFinding(datum.findingType) ? "unknown" : undefined),
      "runtime state": isRuntimeFinding(datum.findingType) ? datum.runtimeEvidence?.state : undefined,
      URL: isRuntimeFinding(datum.findingType) ? datum.runtimeEvidence?.url : undefined,
      "code evidence": datum.codeExposure,
      "code detail": datum.codeExposureDetail,
      "source state": datum.reachability,
      "network exposure": datum.exposure,
      "IAM/RBAC privilege": datum.privilege,
      "asset criticality": datum.criticality,
      "IAM impact": datum.iamImpacts,
      policy: datum.policyStatus,
    }));
    appendList(section, "Rationale", datum.rationale || []);
    appendList(section, "Correlated evidence", (datum.correlatedEvidence || []).map(item => `${item.correlation_type} (${item.confidence}): ${item.reason}`));
    appendList(section, "Unknown evidence and visibility gaps", datum.unknowns || []);
    appendList(section, "Evidence summary", datum.evidenceSummary || []);
    appendList(section, "Effective exposure path used for scoring", effectivePathLabels(datum.effectivePath));
    appendList(section, "Fix commands", datum.fixCommands || []);
    appendList(section, "Effective IAM/RBAC access", (datum.effectiveAccess || []).map(access => `${access.identity || "identity"} ${access.action || "action"} ${access.decision || "allowed"} (${access.confidence || "unknown"} confidence)`));
    appendList(section, "Context evidence", datum.contextEvidence || []);
    appendList(section, "Source evidence", datum.sourceReason ? [datum.sourceReason] : []);
    appendList(section, "Source locations", (datum.sourceLocations || []).map(location => `${location.path}:${location.line}`));
  } else {
    section.append(heading(`Asset: ${datum.name}`));
    section.append(chips([priorityChip(datum.tier), scoreChip(datum.score, "max"), countChip(datum.findingKeys.length, "findings")]));
    section.append(kv({
      owner: datum.owner,
      reference: datum.reference,
      network: datum.exposures,
      IAM: [...datum.privileges, ...datum.iamImpacts],
      "effective access": (datum.effectiveAccess || []).map(access => access.action || access.impact || "access").slice(0, 5),
      criticality: datum.criticalities,
      "code exposure": datum.codeExposures,
      source: datum.sourceStates,
      environment: datum.environments,
    }));
    appendList(section, "Network paths", networkPathsForAsset(datum.id).map(path => path.evidence || path.summary).filter(Boolean));
    appendList(section, "Evidence", datum.evidence || []);
    appendList(section, "Linked vulnerabilities", (vulnerabilitiesByAssetId.get(datum.id) || []).map(vuln => `${vuln.tier} ${Number(vuln.score).toFixed(1)} ${vuln.label} in ${vuln.component}`));
  }
  details.replaceChildren(section);
}

function codeExposureFromState(source) {
  const state = typeof source === "object" ? source.state : source;
  if (source && typeof source === "object" && source.label) return source.label;
  if (state === "attacker_controlled") return "request-controlled path";
  if (state === "function_reachable") return "reachable vulnerable API";
  if (state === "dependency_reachable") return "dependency evidence";
  if (state === "imported") return "import observed";
  if (state === "unknown_due_to_no_rule") return "no source rule";
  if (state === "package_present") return "SBOM only";
  if (state === "absent") return "absent from scanned source";
  return "unknown source reachability";
}

function effectivePathLabels(path) {
  if (!path || !Array.isArray(path.order)) return [];
  const nodeIds = Array.isArray(path.node_ids) ? path.node_ids : [];
  return path.order.map((step, index) => `${index + 1}. ${step}: ${nodeIds[index] || "unknown"}`);
}

function formatBlocker(blocker) {
  if (!blocker) return "";
  if (typeof blocker === "object") {
    const label = humanizeEvidenceKind(blocker.kind || blocker.type || "blocker");
    const detail = blocker.message || blocker.evidence || blocker.reason || blocker.detail || "";
    const next = blocker.next_step ? ` Next step: ${blocker.next_step}` : "";
    return `${label}: ${detail}${next}`;
  }
  return String(blocker);
}

function humanizeEvidenceKind(value) {
  const known = {
    image_digest_or_exact_image_reference: "Weak artifact identity",
    sbom_path: "Missing SBOM path",
    deployment_workload_match: "Missing deployment workload match",
    strong_deployment_workload_match: "Weak deployment workload match",
    network_path_evidence: "Missing network path evidence",
    network_path_confidence: "Low-confidence network path",
    identity_effective_access_evidence: "Missing identity evidence",
    identity_effective_access_confidence: "Low-confidence identity evidence",
    critical_source_coverage: "Missing external source evidence",
    critical_source_query_family_coverage: "Missing query-family source evidence",
    critical_source_proven_query_family_coverage: "Missing proven query-family evidence",
    critical_security_profile_coverage: "Missing maintained security profile",
    unrendered_or_opaque_iac: "Unrendered IaC wrapper",
    unrendered_or_opaque_kubernetes: "Unrendered Kubernetes wrapper",
    auth_required: "Authentication required",
    api_key_required: "API key required",
    waf_or_firewall_policy: "WAF or firewall policy",
    private_endpoint: "Private endpoint",
    explicit_deny: "Explicit deny",
    explicit_deny_precedence: "Explicit deny precedence",
    scoped_resource: "Scoped resource",
    condition: "Conditional access",
  };
  const key = String(value || "").toLowerCase();
  return known[key] || key.replace(/[_-]+/g, " ").replace(/\b\w/g, letter => letter.toUpperCase());
}

function rawDisclosure(title, value) {
  const detailsEl = document.createElement("details");
  detailsEl.className = "raw-evidence";
  const summary = document.createElement("summary");
  summary.textContent = title;
  const pre = document.createElement("pre");
  pre.textContent = JSON.stringify(value || {}, null, 2);
  detailsEl.append(summary, pre);
  return detailsEl;
}

function heading(value) {
  const h = document.createElement("h2");
  h.textContent = value;
  return h;
}

function kv(data) {
  const wrap = document.createElement("div");
  wrap.className = "kv";
  for (const [key, value] of Object.entries(data || {})) {
    if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) continue;
    const k = document.createElement("div");
    k.textContent = key;
    const v = document.createElement("div");
    v.appendChild(identifierRuns(Array.isArray(value) ? value.join(", ") : String(value)));
    wrap.append(k, v);
  }
  return wrap;
}

function appendList(parent, title, values) {
  if (!values || !values.length) return;
  const h = document.createElement("h2");
  h.textContent = title;
  const list = document.createElement("ul");
  for (const value of values.slice(0, 20)) {
    const item = document.createElement("li");
    item.appendChild(identifierRuns(value));
    list.appendChild(item);
  }
  parent.append(h, list);
}

function appendNodeLinks(parent, title, nodes, path) {
  const items = (nodes || []).map(node => ({
    label: `${node.type || "node"}: ${node.label || node.id}${node.evidenceLayer ? ` (${node.evidenceLayer})` : ""}`,
    onClick: () => {
      selected = {...node, attackKind: "node", path, tier: path.tier, score: path.score};
      render();
    },
  }));
  appendActionList(parent, title, items);
}

function appendCategoryPanels(parent, categories) {
  const visibleCategories = (categories || []).filter(category => (category.items || []).length);
  if (!visibleCategories.length) return;
  const h = document.createElement("h2");
  h.textContent = "Issue categories";
  const wrap = document.createElement("div");
  wrap.className = "category-panels";
  for (const category of visibleCategories) {
    const panel = document.createElement("details");
    panel.className = "category-panel";
    panel.open = true;
    const summary = document.createElement("summary");
    summary.textContent = `${category.label} (${category.count || 0})`;
    const body = document.createElement("div");
    body.className = "category-panel-body";
    for (const item of (category.items || []).slice(0, 12)) {
      const row = document.createElement("div");
      row.className = "category-item";
      const title = document.createElement("div");
      title.className = "category-item-title";
      title.appendChild(identifierRuns(item.label || item.findingKey || "Issue"));
      const detail = document.createElement("div");
      detail.className = "category-item-detail";
      detail.appendChild(identifierRuns([item.detail, item.component, item.severity ? `severity ${item.severity}` : null].filter(Boolean).join(" | ")));
      row.append(title, detail);
      body.appendChild(row);
    }
    panel.append(summary, body);
    wrap.appendChild(panel);
  }
  parent.append(h, wrap);
}

function appendActionList(parent, title, items) {
  if (!items || !items.length) return;
  const h = document.createElement("h2");
  h.textContent = title;
  const list = document.createElement("ul");
  list.className = "detail-action-list";
  for (const item of items.slice(0, 20)) {
    const row = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "detail-link-button";
    button.appendChild(identifierRuns(item.label || "Open item"));
    button.addEventListener("click", event => {
      event.preventDefault();
      event.stopPropagation();
      item.onClick();
    });
    row.appendChild(button);
    list.appendChild(row);
  }
  parent.append(h, list);
}

function text(value) {
  return document.createTextNode(value);
}

function first(values) {
  return values && values.length ? values[0] : "";
}

// A machine identifier is a single unbroken token that carries structure:
// aws_ecs_task_definition.payments, pkg:maven/..., CVE-2021-44228, a file path,
// an image digest. Those get mono. Prose does not.
function isIdentifierText(value) {
  const raw = String(value == null ? "" : value).trim();
  if (!raw || /\s/.test(raw)) return false;
  // Two prose words joined by a slash are prose: "private/no observed ingress"
  // and "Identity/Data" are not resource addresses, and setting them in mono
  // would spend the technical register on the one place it means nothing.
  if (/^[A-Za-z]+\/[A-Za-z]+$/.test(raw)) return false;
  return /[._:/@]/.test(raw) || /^[A-Z]{2,}-\d/.test(raw);
}

// The mono rule has to fire per token, not per string. Applied only to whole
// strings it reached 1 of the 32 identifiers rendered on a page: every CVE id,
// purl and resource address that sits inside a sentence -- which is most of the
// detail rail, the risk-list subtitles and the evidence category lists -- came
// out in the sans UI face. Splitting on whitespace and wrapping the tokens that
// pass isIdentifierText() costs one pass and no new vocabulary.
// Trailing punctuation is peeled off first so "CVE-2021-44228," still matches.
function identifierRuns(value) {
  const fragment = document.createDocumentFragment();
  const raw = String(value == null ? "" : value);
  if (!raw) return fragment;
  for (const piece of raw.split(/(\s+)/)) {
    if (!piece) continue;
    const match = /^([([{"']*)(.*?)([)\]}"',.;:]*)$/.exec(piece);
    const token = match ? match[2] : piece;
    if (!isIdentifierText(token)) {
      fragment.appendChild(text(piece));
      continue;
    }
    if (match[1]) fragment.appendChild(text(match[1]));
    const span = document.createElement("span");
    span.className = "mono";
    span.textContent = token;
    fragment.appendChild(span);
    if (match[3]) fragment.appendChild(text(match[3]));
  }
  return fragment;
}

// Truncate at a separator, never inside a token: the report's worst label bug was
// "aws_ecs_task_def / inition.payment...". Paths keep their tail, because the last
// segments identify the file; everything else keeps its head.
//
// maxToken caps the longest single word as well as the whole string. A fixed-width
// label box can wrap between words but cannot wrap inside one, so a 32-character
// identifier in a 24-character box overflows and is clipped with no ellipsis to
// show for it; capping the token is what keeps the truncation visible and honest.
function shortenLabel(value, budget, maxToken) {
  let raw = String(value == null ? "" : value).trim();
  if (maxToken) {
    raw = raw
      .split(" ")
      .map(token => (token.length > maxToken ? shortenLabel(token, maxToken) : token))
      .join(" ");
  }
  if (raw.length <= budget) return raw;
  if (!isIdentifierText(raw)) {
    // The discriminating part of an evidence string is usually its tail. Taking
    // the head alone rendered "terraform exposure inference: public via…" for
    // both an AWS and an Azure value, and "CSPM evidence from
    // reachability-advisor:…" for two different rules -- byte-identical chips
    // for different evidence. When the last word is an identifier, it is kept
    // and the middle is elided, the way the path branch below already does.
    const words = raw.split(" ");
    const tail = words[words.length - 1];
    if (words.length > 2 && isIdentifierText(tail) && tail.length + 4 <= budget) {
      const room = budget - tail.length - 1;
      const head = [];
      let used = 0;
      for (const word of words.slice(0, -1)) {
        const cost = word.length + (head.length ? 1 : 0);
        if (used + cost > room) break;
        used += cost;
        head.push(word);
      }
      if (head.length) return `${head.join(" ")}…${tail}`;
    }
    const clipped = raw.slice(0, budget).split(" ");
    if (clipped.length > 1) clipped.pop();
    return `${clipped.join(" ").replace(/[\s…]+$/, "")}…`;
  }
  if (raw.includes("/")) {
    const parts = raw.split("/");
    let tail = parts.pop();
    while (parts.length && tail.length + parts[parts.length - 1].length + 2 <= budget) {
      tail = `${parts.pop()}/${tail}`;
    }
    if (tail.length + 2 <= budget) return `…/${tail}`;
    return `…${tail.slice(-(budget - 1))}`;
  }
  // A resource address discriminates on its last segment, so that segment is
  // what survives: four chips all reading "aws_ecs_task_definition…" were four
  // different task definitions, and the 109 characters that told them apart
  // were the ones thrown away. The middle is elided instead, exactly as the
  // '/' branch above already does for paths.
  let last = -1;
  for (const separator of [".", "_", "-", ":"]) last = Math.max(last, raw.lastIndexOf(separator));
  const tail = last > 0 ? raw.slice(last) : "";
  if (tail.length > 1 && tail.length + 5 <= budget) {
    return `${raw.slice(0, budget - tail.length - 1).replace(/[._:-]+$/, "")}…${tail}`;
  }
  const head = raw.slice(0, budget);
  let cut = -1;
  for (const separator of [".", "_", "-", ":"]) cut = Math.max(cut, head.lastIndexOf(separator));
  const kept = cut > budget * 0.45 ? head.slice(0, cut) : head;
  return `${kept.replace(/[._:-]+$/, "")}…`;
}

// A label element that is mono when it holds an identifier, shortened at a token
// boundary, and always carries the untruncated value on title for hover and focus.
function labelElement(tagName, className, value, budget, maxToken) {
  const element = document.createElement(tagName);
  const raw = String(value == null ? "" : value);
  const identifier = isIdentifierText(raw);
  element.className = `${className}${identifier ? " mono" : ""}`;
  const shown = budget ? shortenLabel(raw, budget, maxToken) : raw;
  // A whole-string identifier takes the mono class so its tracking can be tuned
  // per label box; an identifier inside a phrase is wrapped run by run, so a
  // resource address in a graph label reads as an address there too.
  if (identifier) element.textContent = shown;
  else element.appendChild(identifierRuns(shown));
  if (shown !== raw.trim()) element.title = raw;
  return element;
}

function identifierSpan(value, budget, maxToken) {
  const span = document.createElement("span");
  const raw = String(value == null ? "" : value);
  if (isIdentifierText(raw)) span.className = "mono";
  const shown = budget ? shortenLabel(raw, budget, maxToken) : raw;
  span.textContent = shown;
  if (shown !== raw.trim()) span.title = raw;
  return span;
}

let fitClamped = false;

function applyTransform() {
  surface.style.transform = `translate(${transform.x}px, ${transform.y}px) scale(${transform.scale})`;
  updatePrintFit();
  if (!graphScale) return;
  const smallest = Math.round(GRAPH_BASE_TEXT_PX * transform.scale);
  const clipped = surfaceBounds.width * transform.scale > graph.clientWidth + 1
    || surfaceBounds.height * transform.scale > graph.clientHeight + 1;
  const pan = clipped ? " · scroll or drag to pan · ctrl+scroll to zoom" : "";
  const clamp = fitClamped && clipped ? ` · at the ${MIN_GRAPH_TEXT_PX}px floor` : "";
  graphScale.textContent = `${Math.round(transform.scale * 100)}% · ${smallest}px min${clamp}${pan}`;
}

// What activating Fit actually did. When the fit is clamped by the legibility
// floor the transform does not move at all, and a control that answers a press
// with nothing reads as broken rather than as correctly refusing.
function fitOutcomeMessage() {
  const shown = cards.childElementCount;
  if (!fitClamped) return `Fitted at ${Math.round(transform.scale * 100)} percent, all ${shown} nodes in view.`;
  return `Already at the smallest legible size: the ${MIN_GRAPH_TEXT_PX} pixel label floor stops Fit `
    + "from shrinking this graph any further, so nothing moved. Drag or scroll to pan, or narrow the "
    + "filters to draw fewer nodes. The risk list carries every item as text.";
}

// Fit the whole graph into its container, but never below the legibility floor:
// a graph shrunk to 5px type is not fitted, it is destroyed. Content that cannot
// fit at the floor is anchored top-left and panned; content that fits is centred.
function fitGraph() {
  if (boardViews.has(viewMode)) {
    transform = {x: 0, y: 0, scale: 1};
    fitClamped = false;
    applyTransform();
    return;
  }
  const width = graph.clientWidth || 900;
  const height = graph.clientHeight || 600;
  const room = Math.min(
    (width - FIT_PADDING * 2) / surfaceBounds.width,
    (height - FIT_PADDING * 2) / surfaceBounds.height
  );
  // Below 1440 the fit is held by the 11px legibility floor, so pressing Fit
  // changes nothing and the control reads as broken rather than as clamped.
  // The readout says which it is.
  fitClamped = room < MIN_FIT_SCALE;
  const scale = Math.min(MAX_FIT_SCALE, Math.max(MIN_FIT_SCALE, room));
  const scaledWidth = surfaceBounds.width * scale;
  const scaledHeight = surfaceBounds.height * scale;
  transform = {
    scale,
    x: scaledWidth <= width ? Math.round((width - scaledWidth) / 2) : FIT_PADDING,
    y: scaledHeight <= height ? Math.round((height - scaledHeight) / 2) : FIT_PADDING,
  };
  applyTransform();
  // A refit throws the pan away, which would strand a focused node outside the
  // pane -- the debounced resize handler alone did that to one edge in a tab
  // pass. Whatever the fit decides, the focus ring stays where it can be seen.
  panFocusIntoView(document.activeElement);
}

// Decide, for the current surface, whether the printed sheet can hold the whole
// graph at a legible size, and publish the answer for @media print. Both axes,
// capped at 1: a graph smaller than the sheet prints at its own size rather than
// blown up. Height is not optional -- a shell fitted on width alone still ran to
// two and a half sheets and the browser broke it through the middle of a node,
// which is the cropping this guard exists to refuse. Nothing here affects the
// screen.
function updatePrintFit() {
  if (!graphShell) return;
  const width = Math.max(1, surfaceBounds.width);
  const height = Math.max(1, surfaceBounds.height);
  const scale = Math.min(1, PRINT_CONTENT_PX / width, PRINT_CONTENT_HEIGHT_PX / height);
  const fits = boardViews.has(viewMode) || scale >= PRINT_MIN_SCALE;
  surface.style.setProperty("--print-scale", String(Math.round(scale * 1e4) / 1e4));
  graphShell.dataset.printFit = fits ? "whole" : "oversized";
  if (!printNote) return;
  if (fits) {
    printNote.textContent = "";
    return;
  }
  const nodeCount = cards.childElementCount;
  const smallest = Math.round(GRAPH_BASE_TEXT_PX * scale * 10) / 10;
  const axis = PRINT_CONTENT_PX / width <= PRINT_CONTENT_HEIGHT_PX / height
    ? `${Math.round(width)} points wide`
    : `${Math.round(height)} points tall`;
  printNote.textContent =
    `The ${VIEW_TITLES[viewMode] || viewMode} diagram is not printed. It is `
    + `${axis}, so fitting it to this sheet would set its `
    + `${nodeCount} labels at about ${smallest}px, below the ${PRINT_MIN_TEXT_PX}px `
    + "readable floor, and cropping it would hide paths without saying so. The evidence "
    + "chain above and the list below carry the same items, complete, as text.";
}

// The pane pans by transform, so it has no scroll position of its own. When
// focus moved to a node the browser still scrolled the overflow:hidden box to
// reveal it -- measured scrollTop 52 -- which silently offset the canvas from
// the coordinates every hit test and drag uses. Zero it and pan instead.
function resetGraphScroll() {
  if (graph.scrollLeft) graph.scrollLeft = 0;
  if (graph.scrollTop) graph.scrollTop = 0;
}

// Keyboard focus must not land on something the pan has pushed out of sight.
// The graph is held at the legibility floor and is routinely taller than its
// pane, so tabbing through it without this parks the ring off screen.
function panFocusIntoView(target) {
  if (!target || !surface.contains(target)) return;
  resetGraphScroll();
  const box = target.getBoundingClientRect();
  const frame = graph.getBoundingClientRect();
  if (!box.width && !box.height) return;
  let dx = 0;
  let dy = 0;
  if (box.left < frame.left + FIT_PADDING) dx = frame.left + FIT_PADDING - box.left;
  else if (box.right > frame.right - FIT_PADDING) dx = frame.right - FIT_PADDING - box.right;
  if (box.top < frame.top + FIT_PADDING) dy = frame.top + FIT_PADDING - box.top;
  else if (box.bottom > frame.bottom - FIT_PADDING) dy = frame.bottom - FIT_PADDING - box.bottom;
  if (!dx && !dy) return;
  transform.x += dx;
  transform.y += dy;
  applyTransform();
}

// The chain's overflow state goes stale the moment its pane changes width
// without a re-render: the scroll position that put the break on screen is now
// pointing somewhere else and the "there is more to the right" fade never
// appears, so a reader who resizes is left looking at a run of solid proven
// links with no sign that the break -- the whole point of the element -- is off
// screen. The chain is observed alongside the graph, not only re-rendered with
// it.
function setupViewportRefit() {
  let pending = 0;
  const refit = () => {
    window.clearTimeout(pending);
    pending = window.setTimeout(() => {
      fitGraph();
      scrollChainToBreak();
    }, 120);
  };
  window.addEventListener("resize", refit);
  if (window.ResizeObserver) {
    const observer = new window.ResizeObserver(refit);
    if (graphShell) observer.observe(graphShell);
    if (chainTrack) observer.observe(chainTrack);
  }
}

// A graph held at the legibility floor is taller than its pane, so a plain wheel
// pans it, the way a map does. Zoom is on ctrl/cmd, which is also the gesture a
// trackpad pinch already sends.
function onWheel(event) {
  if (!event.ctrlKey && !event.metaKey) {
    event.preventDefault();
    if (event.shiftKey) transform.x -= event.deltaY || event.deltaX;
    else {
      transform.x -= event.deltaX;
      transform.y -= event.deltaY;
    }
    applyTransform();
    return;
  }
  event.preventDefault();
  const factor = event.deltaY > 0 ? 0.9 : 1.1;
  const nextScale = Math.min(3.5, Math.max(0.15, transform.scale * factor));
  const rect = graph.getBoundingClientRect();
  const px = event.clientX - rect.left;
  const py = event.clientY - rect.top;
  const graphX = (px - transform.x) / transform.scale;
  const graphY = (py - transform.y) / transform.scale;
  transform.x = px - graphX * nextScale;
  transform.y = py - graphY * nextScale;
  transform.scale = nextScale;
  applyTransform();
}

function onMouseDown(event) {
  if (nodeDrag) return;
  if (event.button !== 0) return;
  drag = {x: event.clientX, y: event.clientY, tx: transform.x, ty: transform.y};
  graph.classList.add("dragging");
}

function onMouseMove(event) {
  if (nodeDrag) {
    const dx = (event.clientX - nodeDrag.x) / transform.scale;
    const dy = (event.clientY - nodeDrag.y) / transform.scale;
    if (Math.abs(event.clientX - nodeDrag.x) > 2 || Math.abs(event.clientY - nodeDrag.y) > 2) {
      nodeDrag.moved = true;
    }
    nodePositionOverrides.set(nodeDrag.id, {
      x: Math.max(0, nodeDrag.originX + dx),
      y: Math.max(0, nodeDrag.originY + dy),
    });
    render();
    return;
  }
  if (!drag) return;
  transform.x = drag.tx + event.clientX - drag.x;
  transform.y = drag.ty + event.clientY - drag.y;
  applyTransform();
}

function onMouseUp() {
  if (nodeDrag) {
    if (nodeDrag.moved) suppressNodeClickId = nodeDrag.id;
    nodeDrag = null;
  }
  drag = null;
  graph.classList.remove("dragging");
}

init();
</script>
</body>
</html>
"""
