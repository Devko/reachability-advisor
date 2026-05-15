"""Static HTML shell for the interactive report renderer."""

from __future__ import annotations

HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reachability Advisor Evidence Report</title>
<style>
:root {
  --bg: #f5f7fb;
  --panel: #ffffff;
  --ink: #101828;
  --muted: #667085;
  --line: #d7deea;
  --soft: #eef3f8;
  --canvas: #f8fafd;
  --canvas-line: rgba(99, 116, 139, .13);
  --urgent: #8a1f11;
  --high: #c2410c;
  --medium: #b7791f;
  --low: #2563eb;
  --info: #64748b;
  --asset: #0f766e;
  --entry: #334155;
  --path: #475569;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: var(--ink);
  background: var(--bg);
  text-rendering: optimizeLegibility;
}
header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 20px;
  background: linear-gradient(135deg, #111827 0%, #172033 100%);
  color: white;
  border-bottom: 1px solid rgba(255,255,255,.08);
}
h1 {
  margin: 0;
  font-size: 18px;
  letter-spacing: 0;
  font-weight: 650;
}
.subtitle {
  margin-top: 3px;
  color: #cbd5e1;
  font-size: 12px;
}
.stats {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
}
.stat {
  padding: 7px 10px;
  background: rgba(255,255,255,.08);
  border: 1px solid rgba(255,255,255,.16);
  border-radius: 6px;
  font-size: 12px;
  font-variant-numeric: tabular-nums;
}
.toolbar {
  display: grid;
  grid-template-columns: 320px minmax(230px, 1fr) 136px 136px 136px 136px 136px auto auto auto auto;
  gap: 8px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--line);
  background: var(--panel);
  box-shadow: 0 1px 2px rgba(16, 24, 40, .04);
  position: relative;
  z-index: 2;
}
.view-tabs {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 3px;
  padding: 3px;
  border: 1px solid #c9d2df;
  border-radius: 7px;
  background: #eef3f8;
}
.view-tabs button {
  min-width: 0;
  height: 26px;
  padding: 0 8px;
  border: 0;
  background: transparent;
  color: #475467;
  font-size: 12px;
  font-weight: 700;
}
.view-tabs button.active {
  background: white;
  color: #111827;
  box-shadow: 0 1px 2px rgba(16, 24, 40, .12);
}
input, select, button {
  height: 34px;
  border: 1px solid #c9d2df;
  background: white;
  color: var(--ink);
  border-radius: 6px;
  padding: 0 10px;
  font: inherit;
  font-size: 13px;
}
button {
  cursor: pointer;
  background: #162033;
  color: white;
  border-color: #162033;
  min-width: 74px;
  font-weight: 650;
}
button.secondary {
  background: white;
  color: var(--ink);
}
label.check {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  white-space: nowrap;
  color: var(--muted);
}
label.check input {
  width: 16px;
  height: 16px;
}
.layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 410px;
  min-height: calc(100vh - 105px);
}
.layout.with-left-sidebar {
  grid-template-columns: 386px minmax(0, 1fr) 410px;
}
.left-panel {
  display: none;
  min-width: 0;
  overflow: hidden;
  border-right: 1px solid var(--line);
  background: var(--panel);
}
.layout.with-left-sidebar .left-panel {
  display: grid;
  grid-template-rows: minmax(0, 1fr);
}
.graph-shell {
  position: relative;
  min-width: 0;
  overflow: hidden;
  background:
    radial-gradient(circle at 24px 24px, rgba(37,99,235,.06) 0, rgba(37,99,235,0) 240px),
    linear-gradient(var(--canvas-line) 1px, transparent 1px),
    linear-gradient(90deg, var(--canvas-line) 1px, transparent 1px),
    var(--canvas);
  background-size: 100% 100%, 36px 36px, 36px 36px, 100% 100%;
}
#graph {
  width: 100%;
  height: calc(100vh - 105px);
  min-height: 560px;
  position: relative;
  overflow: hidden;
  cursor: grab;
  user-select: none;
}
#graph.dragging { cursor: grabbing; }
#surface {
  position: absolute;
  left: 0;
  top: 0;
  transform-origin: 0 0;
}
#edges {
  position: absolute;
  left: 0;
  top: 0;
  overflow: visible;
  pointer-events: none;
}
#cards {
  position: absolute;
  left: 0;
  top: 0;
}
.card {
  position: absolute;
  background: white;
  border: 1px solid var(--line);
  border-left: 8px solid var(--info);
  border-radius: 8px;
  box-shadow: 0 10px 24px rgba(16, 24, 40, .10), 0 1px 2px rgba(16, 24, 40, .08);
  overflow: hidden;
  cursor: pointer;
  display: flex;
  flex-direction: column;
  contain: layout paint;
}
.card.selected {
  outline: 3px solid #111827;
  outline-offset: 2px;
  box-shadow: 0 16px 34px rgba(16, 24, 40, .18), 0 0 0 1px rgba(17,24,39,.08);
}
.card .top {
  display: grid;
  grid-template-columns: minmax(0, 1fr) max-content;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 14px 9px;
  min-width: 0;
}
.asset-card .top {
  background: #f8fafc;
  border-bottom: 1px solid #e4e9f1;
}
.entry-card {
  border-left-color: var(--entry);
}
.entry-card .top {
  background: #111827;
  color: white;
}
.entry-card .sub {
  color: #cbd5e1;
}
.entry-card .body {
  padding-top: 10px;
}
.path-card {
  border-left-color: var(--path);
}
.path-card .top {
  background: #f1f5f9;
  border-bottom: 1px solid #dbe3ee;
}
.title {
  min-width: 0;
  font-weight: 700;
  font-size: 15px;
  line-height: 1.25;
  overflow: hidden;
}
.title-main {
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.sub {
  margin-top: 3px;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.35;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.body {
  padding: 0 14px 14px;
  min-height: 0;
  overflow: hidden;
  flex: 1;
}
.row {
  display: grid;
  grid-template-columns: 92px minmax(0, 1fr);
  gap: 8px;
  margin-top: 7px;
  font-size: 12px;
  line-height: 1.35;
  min-width: 0;
}
.row .label {
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
}
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  min-width: 0;
  max-width: 100%;
}
.top > .chips {
  max-width: 178px;
  justify-content: flex-end;
}
.chip {
  display: inline-flex;
  align-items: center;
  min-height: 20px;
  border-radius: 999px;
  padding: 2px 7px;
  font-size: 11px;
  background: var(--soft);
  color: #344054;
  white-space: nowrap;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  font-variant-numeric: tabular-nums;
}
.chip.urgent, .chip.high { background: #fee2e2; color: #991b1b; }
.chip.medium { background: #fef3c7; color: #92400e; }
.chip.low { background: #dbeafe; color: #1e40af; }
.chip.informational { background: #e2e8f0; color: #334155; }
.chip.request-controlled-path { background: #dcfce7; color: #166534; }
.chip.reachable-vulnerable-api, .chip.import-observed, .chip.reachable-through-dependency-graph { background: #fef3c7; color: #92400e; }
.chip.sbom-only, .chip.no-source-rule, .chip.absent-from-scanned-source { background: #e2e8f0; color: #334155; }
.chip.score, .chip.count, .chip.paths { background: #eef2f7; color: #344054; }
.card.urgent { border-left-color: var(--urgent); }
.card.high { border-left-color: var(--high); }
.card.medium { border-left-color: var(--medium); }
.card.low { border-left-color: var(--low); }
.card.informational { border-left-color: var(--info); }
.zone-panel {
  position: absolute;
  border: 1px solid #cbd5e1;
  border-radius: 14px;
  background: rgba(255,255,255,.62);
  box-shadow: inset 0 0 0 1px rgba(255,255,255,.74), 0 10px 26px rgba(16,24,40,.06);
  overflow: hidden;
  cursor: pointer;
}
.zone-panel.selected {
  outline: 3px solid #111827;
  outline-offset: 2px;
}
.zone-head {
  padding: 13px 14px 10px;
  border-bottom: 1px solid rgba(148,163,184,.34);
  background: rgba(248,250,252,.9);
}
.zone-title {
  font-size: 15px;
  font-weight: 800;
}
.zone-sub {
  margin-top: 3px;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.35;
}
.architecture-hop {
  border-left-color: #64748b;
  border-radius: 999px;
  box-shadow: 0 8px 18px rgba(16, 24, 40, .12), 0 1px 2px rgba(16, 24, 40, .08);
  overflow: visible;
}
.architecture-hop .top {
  background: #f8fafc;
  border-bottom: 0;
  grid-template-columns: minmax(0, 1fr) max-content;
  padding: 10px 14px 8px;
}
.architecture-hop .body {
  display: none;
}
.architecture-hop .title-main {
  -webkit-line-clamp: 1;
}
.architecture-hop[data-hop-kind="entry"] {
  border-left-color: #0f172a;
  border-radius: 18px;
  background: #0f172a;
  color: white;
}
.architecture-hop[data-hop-kind="entry"] .top {
  background: #0f172a;
}
.architecture-hop[data-hop-kind="entry"] .sub {
  color: #cbd5e1;
}
.architecture-asset {
  border-left-width: 9px;
}
.architecture-asset .top {
  grid-template-columns: minmax(0, 1fr);
  gap: 8px;
  background: #ffffff;
  border-bottom: 1px solid #e4e9f1;
}
.architecture-asset .top > .chips {
  max-width: 100%;
  justify-content: flex-start;
}
.architecture-asset .title-main {
  -webkit-line-clamp: 2;
}
.architecture-asset .body {
  padding-top: 9px;
}
.attack-path-card {
  border-left-width: 8px;
}
.attack-path-card .top {
  background: #f8fafc;
  border-bottom: 1px solid #e4e9f1;
}
.attack-risk-sidebar {
  min-width: 0;
  height: calc(100vh - 105px);
  overflow: auto;
  padding: 14px 12px;
  background: #ffffff;
}
.attack-risk-sidebar-title {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  align-items: center;
  padding: 0 2px 12px;
  color: #111827;
  font-size: 14px;
  font-weight: 850;
}
.attack-risk-sidebar-list {
  display: grid;
  gap: 10px;
}
.attack-risk-sidebar-card {
  width: 100%;
  height: auto;
  min-height: 0;
  border: 1px solid #d7deea;
  border-left-width: 7px;
  border-radius: 8px;
  background: #ffffff;
  color: var(--ink);
  padding: 10px 10px 9px;
  text-align: left;
  cursor: pointer;
  box-shadow: 0 8px 20px rgba(15, 23, 42, .07);
  font: inherit;
  overflow: visible;
}
.attack-risk-sidebar-card:hover,
.attack-risk-sidebar-card.selected {
  border-color: #aab7c8;
  background: #f8fafc;
}
.attack-risk-sidebar-card.urgent {
  border-left-color: #8b1e12;
}
.attack-risk-sidebar-card.high {
  border-left-color: #c2410c;
}
.attack-risk-sidebar-card.medium {
  border-left-color: #b7791f;
}
.attack-risk-sidebar-card.low {
  border-left-color: #2563eb;
}
.attack-risk-sidebar-card.informational {
  border-left-color: #64748b;
}
.attack-risk-sidebar-card .risk-title {
  font-size: 13px;
  line-height: 1.2;
  font-weight: 800;
  color: #111827;
  overflow-wrap: anywhere;
}
.attack-risk-sidebar-card .risk-meta {
  margin-top: 5px;
  font-size: 11px;
  line-height: 1.25;
  color: var(--muted);
  overflow-wrap: anywhere;
}
.attack-risk-sidebar-card .chips {
  margin-top: 8px;
}
.attack-graph-node {
  position: absolute;
  display: grid;
  grid-template-rows: max-content max-content max-content;
  justify-items: center;
  align-content: start;
  gap: 4px;
  border: 0;
  padding: 0;
  background: transparent;
  color: #111827;
  cursor: pointer;
  text-align: center;
  min-width: 0;
  transition: opacity .16s ease, transform .16s ease;
}
.attack-graph-node.draggable {
  cursor: grab;
}
.attack-graph-node.dragging {
  cursor: grabbing;
  z-index: 12;
}
.attack-graph-node:focus {
  outline: none;
}
.attack-graph-node:hover {
  transform: translateY(-2px);
}
.attack-graph-node.selected .attack-graph-circle,
.attack-graph-node:focus .attack-graph-circle {
  outline: 3px solid #111827;
  outline-offset: 4px;
}
.attack-graph-node.dimmed {
  opacity: .32;
}
.attack-graph-circle {
  position: relative;
  width: 58px;
  height: 58px;
  border-radius: 999px;
  display: grid;
  place-items: center;
  border: 3px solid #ffffff;
  background: #475569;
  color: white;
  box-shadow: 0 16px 34px rgba(15, 23, 42, .18), 0 0 0 1px rgba(15, 23, 42, .10);
  font-size: 13px;
  font-weight: 850;
  transition: box-shadow .16s ease, transform .16s ease;
}
.attack-graph-node:hover .attack-graph-circle {
  box-shadow: 0 20px 42px rgba(15, 23, 42, .22), 0 0 0 1px rgba(15, 23, 42, .14);
}
.attack-graph-node[data-node-type="entry"] .attack-graph-circle {
  width: 78px;
  height: 78px;
  background: linear-gradient(135deg, #2563eb 0%, #0f766e 100%);
  font-size: 16px;
}
.attack-graph-node[data-node-type="lateral"] .attack-graph-circle {
  width: 78px;
  height: 78px;
  background: linear-gradient(135deg, #7c3aed 0%, #2563eb 100%);
  font-size: 15px;
}
.attack-graph-node[data-node-type="ingress"] .attack-graph-circle {
  background: linear-gradient(135deg, #f97316 0%, #c2410c 100%);
}
.attack-graph-node[data-node-type="workload"] .attack-graph-circle,
.attack-graph-node[data-node-type="runtime"] .attack-graph-circle {
  background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
}
.attack-graph-node[data-node-type="identity"] .attack-graph-circle {
  background: linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%);
}
.attack-graph-node[data-node-type="data"] .attack-graph-circle {
  background: linear-gradient(135deg, #059669 0%, #047857 100%);
}
.attack-graph-node[data-node-type="vulnerability"] .attack-graph-circle,
.attack-graph-node[data-node-type="weakness"] .attack-graph-circle {
  background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
}
.attack-graph-node[data-node-type="finding"].urgent .attack-graph-circle,
.attack-graph-node[data-node-type="finding"].high .attack-graph-circle {
  background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
}
.attack-graph-node[data-node-type="finding"].medium .attack-graph-circle {
  background: linear-gradient(135deg, #d97706 0%, #92400e 100%);
}
.attack-graph-node[data-node-type="finding"].low .attack-graph-circle {
  background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
}
.attack-graph-node[data-node-type="finding"].informational .attack-graph-circle {
  background: linear-gradient(135deg, #64748b 0%, #334155 100%);
}
.attack-graph-node[data-node-type="unknown"] .attack-graph-circle,
.attack-graph-node[data-node-state="unknown"] .attack-graph-circle {
  background: #64748b;
  border-style: dashed;
}
.attack-graph-node[data-node-state="blocked"] .attack-graph-circle {
  background: #c2410c;
  border-style: dashed;
}
.attack-graph-badge {
  position: absolute;
  right: -5px;
  top: -6px;
  min-width: 22px;
  height: 22px;
  padding: 0 5px;
  border-radius: 999px;
  display: grid;
  place-items: center;
  background: #dc2626;
  color: #ffffff;
  border: 2px solid #ffffff;
  font-size: 11px;
  font-weight: 850;
  line-height: 1;
}
.attack-graph-toggle {
  position: absolute;
  left: -5px;
  top: -6px;
  width: 22px;
  height: 22px;
  border-radius: 999px;
  display: grid;
  place-items: center;
  background: #ffffff;
  color: #111827;
  border: 2px solid #cbd5e1;
  font-size: 14px;
  font-weight: 850;
  line-height: 1;
}
.attack-graph-label {
  width: 132px;
  color: #111827;
  font-size: 13px;
  font-weight: 800;
  line-height: 1.16;
  padding: 3px 6px;
  border-radius: 999px;
  background: rgba(255, 255, 255, .86);
  box-shadow: 0 6px 16px rgba(15, 23, 42, .07);
  overflow-wrap: anywhere;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.attack-graph-sub {
  width: 132px;
  color: #667085;
  font-size: 11px;
  line-height: 1.2;
  overflow-wrap: anywhere;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.edge.attack-path {
  stroke: #334155;
  stroke-width: 2.4;
  opacity: .9;
}
.edge.attack-graph-edge {
  stroke: #475569;
  stroke-width: 2.4;
  opacity: .82;
  marker-end: url(#edge-arrow);
  pointer-events: stroke;
  cursor: pointer;
  stroke-linecap: round;
}
.edge.attack-graph-edge.high,
.edge.attack-graph-edge.urgent {
  stroke: #dc2626;
}
.edge.attack-graph-edge.medium {
  stroke: #b7791f;
}
.edge.attack-graph-edge.lateral {
  stroke: #7c3aed;
}
.edge.attack-graph-edge.unknown {
  stroke-dasharray: 7 6;
}
.edge.attack-graph-edge.blocker {
  stroke-dasharray: 2 6;
  stroke: #c2410c;
}
.edge.attack-graph-edge.selected {
  stroke-width: 3.1;
  opacity: 1;
  animation: pulse-edge 1.8s ease-in-out infinite;
}
.edge.attack-graph-edge:hover,
.edge.attack-graph-edge:focus {
  stroke-width: 4;
  opacity: 1;
  outline: none;
}
.edge.attack-graph-edge.dimmed {
  opacity: .18;
  stroke-width: 1.6;
}
.edge.attack-path.unknown {
  stroke-dasharray: 7 6;
  stroke: #64748b;
}
.edge.attack-path.blocker {
  stroke-dasharray: 2 6;
  stroke: #c2410c;
}
.edge.attack-path.selected {
  animation: pulse-edge 1.8s ease-in-out infinite;
}
.edge.attack-path.dimmed {
  opacity: .24;
  stroke-width: 1.8;
}
@keyframes pulse-edge {
  0%, 100% { opacity: .72; }
  50% { opacity: 1; }
}
.finding-board {
  position: absolute;
  display: grid;
  grid-template-columns: repeat(3, 360px);
  gap: 16px;
  align-items: start;
}
.finding-board .vuln-card {
  position: relative;
  width: 360px;
  height: 132px;
}
.risk-board {
  position: absolute;
  left: 42px;
  top: 42px;
  width: 1180px;
  border: 1px solid #d7deea;
  border-radius: 10px;
  background: rgba(255,255,255,.94);
  box-shadow: 0 12px 28px rgba(16,24,40,.10);
  overflow: hidden;
}
.risk-board-head {
  display: grid;
  grid-template-columns: 130px minmax(340px, 1fr) 250px 78px 82px 160px 104px;
  gap: 0;
  padding: 10px 12px;
  border-bottom: 1px solid #d7deea;
  background: #f8fafc;
  color: #475467;
  font-size: 11px;
  font-weight: 800;
  text-transform: uppercase;
}
.risk-row {
  display: grid;
  grid-template-columns: 130px minmax(340px, 1fr) 250px 78px 82px 160px 104px;
  gap: 0;
  align-items: center;
  min-height: 78px;
  padding: 10px 12px;
  border-bottom: 1px solid #e4e9f1;
  cursor: pointer;
}
.risk-row:last-child {
  border-bottom: 0;
}
.risk-row:hover,
.risk-row.selected {
  background: #f8fafc;
}
.risk-row.selected {
  box-shadow: inset 4px 0 0 #111827;
}
.risk-cell {
  min-width: 0;
  padding-right: 12px;
  font-size: 12px;
}
.risk-severity {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-weight: 800;
}
.risk-dot {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  background: var(--info);
}
.risk-dot.urgent { background: var(--urgent); }
.risk-dot.high { background: var(--high); }
.risk-dot.medium { background: var(--medium); }
.risk-dot.low { background: var(--low); }
.risk-title {
  font-weight: 800;
  font-size: 14px;
  line-height: 1.25;
  overflow-wrap: anywhere;
}
.risk-meta {
  margin-top: 4px;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.35;
  overflow-wrap: anywhere;
}
.risk-status {
  display: inline-flex;
  justify-content: center;
  min-width: 72px;
  padding: 4px 8px;
  border-radius: 999px;
  background: #eef2f7;
  color: #344054;
  font-weight: 800;
  font-size: 11px;
}
.risk-status.open { background: #dbeafe; color: #1e40af; }
.risk-status.excepted { background: #e2e8f0; color: #334155; }
.risk-status.mixed { background: #fef3c7; color: #92400e; }
.risk-path-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px solid #bfdbfe;
  border-radius: 8px;
  background: #eff6ff;
  color: #1d4ed8;
  padding: 6px 9px;
  font: inherit;
  font-size: 12px;
  font-weight: 800;
  text-decoration: none;
  cursor: pointer;
  white-space: nowrap;
}
.risk-path-link:hover,
.risk-path-link:focus {
  border-color: #2563eb;
  background: #dbeafe;
  outline: none;
}
.category-panels {
  display: grid;
  gap: 8px;
  margin-top: 10px;
}
.category-panel {
  border: 1px solid #d7deea;
  border-radius: 8px;
  background: #f8fafc;
  overflow: hidden;
}
.category-panel summary {
  cursor: pointer;
  padding: 9px 10px;
  font-size: 13px;
  font-weight: 800;
}
.category-panel-body {
  padding: 0 10px 10px;
}
.category-item {
  padding: 8px 0;
  border-top: 1px solid #e4e9f1;
  font-size: 12px;
  line-height: 1.4;
}
.category-item-title {
  font-weight: 750;
  overflow-wrap: anywhere;
}
.category-item-detail {
  margin-top: 2px;
  color: var(--muted);
  overflow-wrap: anywhere;
}
.vuln-card .title {
  font-size: 14px;
}
.vuln-card .top > .chips {
  max-width: 158px;
}
.vuln-card .sub,
.path-card .sub,
.entry-card .sub {
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.vuln-card .body {
  padding-top: 0;
}
.asset-card .body {
  padding-top: 9px;
}
.path-card .body .sub,
.vuln-card .body .sub {
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.lane-label {
  position: absolute;
  height: 28px;
  padding: 6px 10px;
  border: 1px solid #d7deea;
  border-radius: 999px;
  background: rgba(255,255,255,.86);
  color: #475467;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0;
  box-shadow: 0 4px 14px rgba(16,24,40,.08);
  pointer-events: none;
}
.edge {
  fill: none;
  stroke: #94a3b8;
  stroke-width: 2;
  opacity: .82;
  stroke-linecap: round;
  stroke-linejoin: round;
  marker-end: url(#edge-arrow);
}
.edge.network {
  stroke: #475569;
  stroke-width: 2.6;
}
.edge.vulnerability {
  opacity: .72;
}
.edge.architecture {
  opacity: .48;
  stroke-width: 2.1;
}
.edge.entry {
  stroke-dasharray: 7 5;
}
.edge.risk-edge {
  stroke-dasharray: 3 5;
  opacity: .58;
}
.edge.urgent { stroke: var(--urgent); stroke-width: 3; }
.edge.high { stroke: var(--high); stroke-width: 2.6; }
.edge.medium { stroke: var(--medium); }
.edge.low { stroke: var(--low); }
.edge.active {
  opacity: 1;
  stroke-width: 3.4;
  filter: drop-shadow(0 1px 3px rgba(16,24,40,.28));
}
.right-panel {
  border-left: 1px solid var(--line);
  background: var(--panel);
  min-width: 0;
  overflow: hidden;
  display: grid;
  grid-template-rows: auto minmax(180px, 42vh) 1fr;
}
.layout.with-left-sidebar .right-panel {
  grid-template-rows: auto 1fr;
}
.layout.with-left-sidebar .finding-list {
  display: none;
}
.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 12px;
  border-bottom: 1px solid var(--line);
}
.legend span {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 12px;
  color: var(--muted);
}
.swatch {
  width: 10px;
  height: 10px;
  border-radius: 2px;
}
.details, .finding-list {
  padding: 12px;
  overflow: auto;
}
.details {
  border-bottom: 1px solid var(--line);
}
.details h2, .finding-list h2 {
  margin: 0 0 10px;
  font-size: 14px;
  overflow-wrap: anywhere;
}
.empty {
  color: var(--muted);
  font-size: 13px;
  line-height: 1.45;
}
.kv {
  display: grid;
  grid-template-columns: 116px minmax(0, 1fr);
  gap: 5px 8px;
  font-size: 12px;
  margin: 8px 0;
  line-height: 1.45;
}
.kv div:nth-child(odd) {
  color: var(--muted);
}
.kv div:nth-child(even) {
  overflow-wrap: anywhere;
}
.item {
  padding: 10px;
  border: 1px solid var(--line);
  border-radius: 7px;
  margin-bottom: 8px;
  background: #fbfcfe;
  cursor: pointer;
}
.item:hover {
  border-color: #9aa8bb;
}
.item-title {
  font-size: 13px;
  font-weight: 650;
  display: grid;
  grid-template-columns: minmax(0, 1fr) max-content;
  gap: 8px;
  min-width: 0;
  overflow-wrap: anywhere;
}
.item-meta {
  margin-top: 5px;
  font-size: 12px;
  color: var(--muted);
  overflow-wrap: anywhere;
  line-height: 1.35;
}
ul {
  margin: 6px 0 0 17px;
  padding: 0;
}
li {
  margin: 4px 0;
  font-size: 12px;
}
.raw-evidence {
  margin-top: 12px;
  border: 1px solid #d7deea;
  border-radius: 8px;
  background: #f8fafc;
  overflow: hidden;
}
.raw-evidence summary {
  cursor: pointer;
  padding: 9px 10px;
  font-weight: 700;
  font-size: 13px;
}
.raw-evidence pre {
  margin: 0;
  padding: 10px;
  max-height: 280px;
  overflow: auto;
  border-top: 1px solid #e4e9f1;
  font-size: 11px;
  white-space: pre-wrap;
}
.detail-action-list {
  list-style: none;
  padding-left: 0;
}
.detail-action-list li {
  margin: 6px 0;
}
.detail-link-button {
  width: 100%;
  text-align: left;
  border: 1px solid #dbe3ee;
  border-radius: 8px;
  background: #f8fafc;
  padding: 8px 10px;
  color: #1f2937;
  font: inherit;
  cursor: pointer;
  overflow-wrap: anywhere;
}
.detail-link-button:hover,
.detail-link-button:focus {
  border-color: #2563eb;
  background: #eff6ff;
  outline: none;
}
@media (max-width: 980px) {
  .toolbar { grid-template-columns: 1fr 1fr; }
  .layout { grid-template-columns: 1fr; }
  .layout.with-left-sidebar { grid-template-columns: 1fr; }
  .left-panel { border-right: 0; border-bottom: 1px solid var(--line); }
  .attack-risk-sidebar { height: auto; max-height: 34vh; }
  .right-panel { border-left: 0; border-top: 1px solid var(--line); }
  #graph { height: 58vh; min-height: 430px; }
}
</style>
</head>
<body>
<header>
  <div>
    <h1>Reachability Advisor Evidence Report</h1>
    <div class="subtitle" id="generated"></div>
  </div>
  <div class="stats" id="stats"></div>
</header>
<section class="toolbar">
  <div class="view-tabs" role="tablist" aria-label="Visual report view">
    <button id="attackTab" type="button" data-view="attack">Attack Paths</button>
    <button id="architectureTab" type="button" data-view="architecture">Architecture</button>
    <button id="evidenceTab" type="button" data-view="evidence">Evidence Paths</button>
    <button id="riskTab" type="button" class="active" data-view="risk">Risk</button>
  </div>
  <input id="search" type="search" placeholder="Search asset, component, CVE, scanner rule, IAM/RBAC, network, owner">
  <select id="tier">
    <option value="informational">All priorities</option>
    <option value="urgent">Urgent only</option>
    <option value="high">High or urgent</option>
    <option value="medium">Medium or higher</option>
    <option value="low">Low or higher</option>
  </select>
  <select id="exposure">
    <option value="">All exposures</option>
  </select>
  <select id="findingType">
    <option value="">All finding types</option>
    <option value="dependency_vulnerability">Dependency vulnerabilities</option>
    <option value="static_code_weakness">Static scanner findings (SAST)</option>
    <option value="dynamic_runtime_observation">Runtime scanner findings (DAST)</option>
    <option value="cloud_posture_finding">Cloud posture findings (CSPM)</option>
    <option value="correlated_security_finding">Correlated security findings</option>
  </select>
  <select id="confidence">
    <option value="">All confidence</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
  </select>
  <select id="evidenceLayer">
    <option value="">All evidence layers</option>
  </select>
  <select id="topLimit">
    <option value="50">Top 50</option>
    <option value="100">Top 100</option>
    <option value="">All findings</option>
  </select>
  <label class="check"><input id="highestPerAsset" type="checkbox" checked> highest risk per asset</label>
  <label class="check"><input id="activeOnly" type="checkbox" checked> hide excepted findings</label>
  <button id="fit" title="Fit the current graph into the visible area">Fit</button>
  <button id="reset" class="secondary" title="Reset graph zoom and pan">Reset</button>
</section>
<main class="layout" id="layout">
  <aside class="left-panel" id="leftPanel">
    <div id="riskSidebar"></div>
  </aside>
  <section class="graph-shell">
    <div id="graph" role="img" aria-label="Attack paths, architecture zones, network hops, assets, and evidence path graph">
      <div id="surface">
        <svg id="edges"></svg>
        <div id="cards"></div>
      </div>
    </div>
  </section>
  <aside class="right-panel">
    <div class="legend">
      <span><i class="swatch" style="background:var(--urgent)"></i>urgent</span>
      <span><i class="swatch" style="background:var(--high)"></i>high</span>
      <span><i class="swatch" style="background:var(--medium)"></i>medium</span>
      <span><i class="swatch" style="background:var(--low)"></i>low</span>
      <span><i class="swatch" style="background:var(--info)"></i>informational</span>
    </div>
    <section class="details" id="details"></section>
    <section class="finding-list">
      <h2 id="visibleListTitle">Visible Risk Scenarios</h2>
      <div id="findingList"></div>
    </section>
  </aside>
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
const pathWidth = 290;
const pathHeight = 152;
const assetWidth = 410;
const assetHeight = 292;
const vulnWidth = 500;
const vulnHeight = 112;
const rowGap = 64;
const vulnGap = 16;
const entryX = 56;
const pathX = 318;
const assetX = 660;
const vulnX = 1130;
const laneY = 28;
const firstRowY = 78;
const archZoneWidth = 360;
const archZoneGap = 22;
const archItemGap = 14;
const archMarginX = 46;
const archMarginY = 58;
const archZoneHeader = 74;
const archHopWidth = 255;
const archHopHeight = 68;
const archEntryWidth = 230;
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

function init() {
  document.getElementById("generated").textContent = `${DATA.metadata.tool} ${DATA.metadata.version} generated ${DATA.metadata.generated_at}`;
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
  document.getElementById("fit").addEventListener("click", fitGraph);
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
  window.addEventListener("mousemove", onMouseMove);
  window.addEventListener("mouseup", onMouseUp);
  render();
  window.setTimeout(fitGraph, 0);
}

function renderStats() {
  const stats = document.getElementById("stats");
  const s = DATA.stats;
  const parts = [
    `${s.finding_count} findings`,
    `${(s.finding_types || {}).static_code_weakness || 0} static`,
    `${(s.finding_types || {}).dynamic_runtime_observation || 0} runtime`,
    `${(s.finding_types || {}).cloud_posture_finding || 0} posture`,
    `${s.artifact_count} assets`,
    `${s.component_count} components`,
    `${s.tiers.urgent || 0} urgent`,
    `${s.tiers.high || 0} high`
  ];
  stats.replaceChildren(...parts.map(value => {
    const el = document.createElement("div");
    el.className = "stat";
    el.textContent = value;
    return el;
  }));
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
    tab.classList.toggle("active", (tab.dataset.view || "architecture") === viewMode);
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
  } else if (viewMode === "risk" || viewMode === "findings") {
    riskSidebar.replaceChildren();
    const layout = layoutRiskScenarios(riskScenarios);
    edgesSvg.replaceChildren(renderEdgeDefs());
    cards.replaceChildren(renderRiskBoard(riskScenarios, layout));
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
  renderDetails(selected);
  applyTransform();
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
        graphEdges.push(attackGraphEdge(surfaceNodeId, routeId, path, pathSelected, dimmed, false, false, "Entry to network route"));
        previousNodeId = routeId;
      }
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
        graphEdges.push(attackGraphEdge(previousNodeId, viewNodeId, path, pathSelected, dimmed, node.state === "unknown", node.state === "blocked", `${path.pathType || "route"} step`));
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
      graphEdges.push(attackGraphEdge(previousNodeId, assetId, path, pathSelected, dimmed, false, false, "Route reaches workload"));
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
      graphEdges.push(attackGraphEdge(assetId, issueId, path, pathSelected, dimmed, false, false, "Workload has linked findings"));
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
          graphEdges.push(attackGraphEdge(issueId, findingId, {...path, tier: findingDatum.tier, score: findingDatum.score}, pathSelected, dimmed, false, false, "Finding detail"));
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

function attackGraphEdge(from, to, path, selectedEdge, dimmed, unknown, blocker, label) {
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
    unknown: Boolean(unknown),
    blocker: Boolean(blocker),
    lateral: path.surfaceMode === "lateral" || path.exposure === "internal",
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

function layoutRiskScenarios(scenarios) {
  if (selected && (selected.scenarioKind === "scenario" || selected.attackKind === "scenario") && !scenarios.some(scenario => scenario.id === selected.id)) {
    selected = null;
  }
  if (!selected && scenarios.length) {
    selected = {...scenarios[0], scenarioKind: "scenario", attackKind: "scenario"};
  }
  const rowHeight = 78;
  surfaceBounds = {
    width: 1280,
    height: Math.max(620, 42 + 44 + Math.max(1, scenarios.length) * rowHeight + 90),
    maxVulnCount: scenarios.length,
  };
  return {rowHeight};
}

function renderRiskBoard(scenarios, layout) {
  const board = document.createElement("div");
  board.className = "risk-board";
  const header = document.createElement("div");
  header.className = "risk-board-head";
  for (const label of ["Priority", "Risk scenario", "Evidence categories", "Findings", "In-use findings", "Context", "Attack path"]) {
    const cell = document.createElement("div");
    cell.textContent = label;
    header.appendChild(cell);
  }
  board.appendChild(header);
  if (!scenarios.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.style.padding = "18px";
    empty.textContent = "No risk scenarios match the current filters. Clear one or more filters to see more results.";
    board.appendChild(empty);
    return board;
  }
  for (const scenario of scenarios) {
    board.appendChild(renderRiskRow(scenario, layout));
  }
  return board;
}

function openScenarioAttackPath(scenario) {
  viewMode = "attack";
  selected = {...scenario, scenarioKind: "scenario", attackKind: "scenario"};
  render();
  window.setTimeout(fitGraph, 0);
}

function renderRiskRow(scenario, layout) {
  const row = document.createElement("div");
  row.className = `risk-row${selected && selected.id === scenario.id ? " selected" : ""}`;
  row.style.minHeight = `${layout.rowHeight}px`;
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.addEventListener("click", () => {
    selected = {...scenario, scenarioKind: "scenario", attackKind: "scenario"};
    render();
  });
  row.addEventListener("keydown", event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    selected = {...scenario, scenarioKind: "scenario", attackKind: "scenario"};
    render();
  });

  const severity = document.createElement("div");
  severity.className = "risk-cell";
  const severityWrap = document.createElement("span");
  severityWrap.className = "risk-severity";
  const dot = document.createElement("span");
  dot.className = `risk-dot ${scenario.tier || "informational"}`;
  const severityText = document.createElement("span");
  severityText.textContent = scenario.priorityLabel || priorityText(scenario.tier);
  severityWrap.append(dot, severityText);
  severity.appendChild(severityWrap);

  const risk = document.createElement("div");
  risk.className = "risk-cell";
  const title = document.createElement("div");
  title.className = "risk-title";
  title.textContent = scenario.title || "Risk scenario";
  const meta = document.createElement("div");
  meta.className = "risk-meta";
  meta.textContent = `${scenario.assetName || "unknown asset"} | entry: ${scenario.entryLabel || "unknown entry"} -> path: ${scenario.pathLabel || "network path"}`;
  risk.append(title, meta);

  const categories = document.createElement("div");
  categories.className = "risk-cell";
  categories.append(categoryChips(scenario.categorySummary || []));

  const total = document.createElement("div");
  total.className = "risk-cell";
  total.textContent = String(scenario.totalFindings || 0);

  const inUse = document.createElement("div");
  inUse.className = "risk-cell";
  inUse.textContent = String(scenario.inUseCount || 0);

  const context = document.createElement("div");
  context.className = "risk-cell";
  context.append(chips([exposureChip(scenario.exposure), scenario.provider, countChip((scenario.categoryCounts || {}).identity_data_access || 0, "IAM")], 3));

  const pathCell = document.createElement("div");
  pathCell.className = "risk-cell";
  const attackPathLink = document.createElement("a");
  attackPathLink.className = "risk-path-link";
  attackPathLink.href = `#attack-path-${scenario.attackPathGroupId || scenario.id}`;
  attackPathLink.textContent = "Open attack path";
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
  arrow.setAttribute("fill", "#64748b");
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
    paths.push(edgePath(entry.x + entry.width, entry.y + entry.height / 2, path.x, path.y + path.height / 2, `edge network entry ${pathNode.exposure}`, entryNodeId(pathNode), pathNode.id));
    for (const assetId of pathAssetIds(pathNode)) {
      const asset = layout.assets.get(assetId);
      if (!asset) continue;
      paths.push(edgePath(path.x + path.width, path.y + path.height / 2, asset.x, asset.y + asset.height / 2, `edge network ${pathNode.tier}`, pathNode.id, assetId));
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
    paths.push(fanEdgePath(x1, y1, busX, x2, y2, `edge vulnerability ${vuln.tier}`, vuln.assetId, vuln.id));
  }
  return paths;
}

function renderArchitectureEdges(layout) {
  const paths = [];
  const arch = DATA.architecture || {edges: []};
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
    paths.push(architectureEdgePath(source, target, `edge network architecture ${edge.tier || "informational"}`, edge.source, edge.target));
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
    const className = `edge ${edge.graph ? "attack-graph-edge" : "attack-path"} ${edge.tier || "informational"}${edge.unknown ? " unknown" : ""}${edge.blocker ? " blocker" : ""}${edge.lateral ? " lateral" : ""}${selectedEdge ? " selected" : ""}${edge.dimmed ? " dimmed" : ""}`;
    if (edge.graph) {
      paths.push(attackGraphEdgePath(source, target, className, sourceId, targetId, edgeDatum));
    } else {
      paths.push(edgePath(source.x + source.width, source.y + source.height / 2, target.x, target.y + target.height / 2, className, sourceId, targetId));
    }
  }
  return paths;
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

function architectureEdgePath(source, target, className, sourceId, targetId) {
  const x1 = source.x + source.width;
  const y1 = source.y + source.height / 2;
  const x2 = target.x;
  const y2 = target.y + target.height / 2;
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("class", className);
  path.dataset.edgeSource = sourceId;
  path.dataset.edgeTarget = targetId;
  const midX = x1 + Math.max(34, (x2 - x1) / 2);
  path.setAttribute("d", `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`);
  markActiveEdge(path, sourceId, targetId);
  return path;
}

function edgePath(x1, y1, x2, y2, className, sourceId, targetId) {
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("class", className);
  path.dataset.edgeSource = sourceId;
  path.dataset.edgeTarget = targetId;
  path.setAttribute("d", `M ${x1} ${y1} C ${x1 + 42} ${y1}, ${x2 - 42} ${y2}, ${x2} ${y2}`);
  markActiveEdge(path, sourceId, targetId);
  return path;
}

function fanEdgePath(x1, y1, busX, x2, y2, className, sourceId, targetId) {
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("class", className);
  path.dataset.edgeSource = sourceId;
  path.dataset.edgeTarget = targetId;
  path.setAttribute("d", `M ${x1} ${y1} C ${busX} ${y1}, ${busX} ${y2}, ${x2} ${y2}`);
  markActiveEdge(path, sourceId, targetId);
  return path;
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
  sub.textContent = `${assetCount} assets | ${hopCount} hops`;
  head.append(title, sub);
  panel.append(head);
  return panel;
}

function renderArchitectureHop(hop, position) {
  const card = createCard("architecture-hop", hop.tier || "informational", position, hop);
  card.dataset.hopKind = hop.kind || "hop";
  card.append(
    cardTop(hop.label || "Network hop", [tag(hop.provider || "Context", "count"), countChip((hop.assetIds || []).length, "assets")], hop.kind || hop.confidence || "")
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
      counts.dynamic_runtime_observation ? tag(`${counts.dynamic_runtime_observation} runtime`, "count") : null,
      counts.static_code_weakness ? tag(`${counts.static_code_weakness} static`, "count") : null,
      counts.cloud_posture_finding ? tag(`${counts.cloud_posture_finding} posture`, "count") : null,
      counts.dependency_vulnerability ? tag(`${counts.dependency_vulnerability} deps`, "count") : null,
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
  meta.textContent = `${scenario.assetName || "unknown asset"} | ${scenario.entryLabel || "unknown entry"} -> ${scenario.pathLabel || "network path"}`;
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
  const label = document.createElement("span");
  label.className = "attack-graph-label";
  label.textContent = node.label || node.type || "Node";
  const sub = document.createElement("span");
  sub.className = "attack-graph-sub";
  sub.textContent = node.subtitle || "";
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
  const titleMain = document.createElement("div");
  titleMain.className = "title-main";
  titleMain.textContent = titleText;
  titleWrap.append(titleMain);
  if (subtitle) {
    const sub = document.createElement("div");
    sub.className = "sub";
    sub.textContent = subtitle;
    titleWrap.append(sub);
  }
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
    chip.textContent = data.text;
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

function countChip(value, label) {
  return tag(`${value} ${label}`, "count");
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
    list.innerHTML = '<div class="empty">No risk scenarios match the current filters. Clear one or more filters to see more results.</div>';
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
    meta.textContent = `${scenario.assetName || "asset"} | provider ${scenario.provider || "context"} | network exposure ${scenario.exposure || "unknown"} | ${scenario.totalFindings || 0} findings`;
    item.append(rowTitle, meta);
    return item;
  }));
}

function renderFindingList(findings) {
  const title = document.getElementById("visibleListTitle");
  if (title) title.textContent = "Visible Findings";
  const list = document.getElementById("findingList");
  if (!findings.length) {
    list.innerHTML = '<div class="empty">No findings match the current filters. Clear one or more filters to see more results.</div>';
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
    title.append(text(findingTitle));
    const chip = document.createElement("span");
    chip.className = `chip ${finding.tier}`;
    chip.textContent = `priority ${finding.tier} ${Number(finding.score).toFixed(1)}`;
    title.append(chip);
    const meta = document.createElement("div");
    meta.className = "item-meta";
    const scanner = isSecurityFinding(finding.finding_type) ? ` | scanner ${(finding.weakness || {}).tool || "unknown"}` : "";
    meta.textContent = `${finding.artifact.name}${scanner} | code evidence ${codeExposureFromState(finding.source_reachability || {})} | source state ${(finding.source_reachability || {}).state} | network exposure ${(finding.context || {}).exposure || "unknown"} | IAM/RBAC privilege ${(finding.context || {}).privilege || "unknown"}`;
    item.append(title, meta);
    return item;
  }));
}

function renderDetails(datum) {
  if (!datum) {
    details.innerHTML = '<h2>Details</h2><div class="empty">Select a risk scenario, attack path, asset, or finding. Use mouse wheel to zoom and drag the graph background to pan.</div>';
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
      "finding type": isRuntimeFinding(datum.findingType) ? "dynamic runtime observation" : isSecurityFinding(datum.findingType) ? "static code weakness" : "dependency vulnerability",
      scanner: isSecurityFinding(datum.findingType) ? datum.weakness?.tool : undefined,
      CWE: isSecurityFinding(datum.findingType) ? (datum.weakness?.cwe || "unknown") : undefined,
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
    v.textContent = Array.isArray(value) ? value.join(", ") : String(value);
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
    item.textContent = value;
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
      title.textContent = item.label || item.findingKey || "Issue";
      const detail = document.createElement("div");
      detail.className = "category-item-detail";
      detail.textContent = [item.detail, item.component, item.severity ? `severity ${item.severity}` : null].filter(Boolean).join(" | ");
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
    button.textContent = item.label || "Open item";
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

function applyTransform() {
  surface.style.transform = `translate(${transform.x}px, ${transform.y}px) scale(${transform.scale})`;
}

function fitGraph() {
  const width = graph.clientWidth || 900;
  const height = graph.clientHeight || 600;
  const scale = Math.min(1.25, Math.max(0.18, Math.min((width - 70) / surfaceBounds.width, (height - 70) / surfaceBounds.height)));
  transform = {scale, x: 35, y: 35};
  applyTransform();
}

function onWheel(event) {
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
