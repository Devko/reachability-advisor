"""Output renderers for CI and IDE workflows."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .evidence_graph import build_evidence_graph
from .models import Finding, SourceLocation, Tier, reachability_label
from .remediation import build_remediation_groups


def _metadata(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "tool": "reachability-advisor",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        data.update(extra)
    return data


def write_json_findings(findings: list[Finding], path: str | Path, metadata: dict[str, Any] | None = None) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    remediations = build_remediation_groups(findings)
    metadata_with_rollup = dict(metadata or {})
    metadata_with_rollup.setdefault("remediation_groups", len(remediations))
    out.write_text(
        json.dumps(
            {
                "metadata": _metadata(metadata_with_rollup),
                "remediations": remediations,
                "evidence_graph": build_evidence_graph(findings, metadata=metadata_with_rollup),
                "findings": [finding.to_json() for finding in findings],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def load_findings_json(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def _primary_location(finding: Finding) -> SourceLocation | None:
    return finding.source.locations[0] if finding.source.locations else None


def _level(tier: Tier) -> str:
    if tier in {Tier.URGENT, Tier.HIGH}:
        return "error"
    if tier == Tier.MEDIUM:
        return "warning"
    return "note"


def write_sarif(findings: list[Finding], path: str | Path) -> None:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = finding.vulnerability.id
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.vulnerability.id,
                "shortDescription": {"text": finding.vulnerability.summary or f"Vulnerability {rule_id}"},
                "help": {"text": "Reachability-aware dependency vulnerability finding."},
                "properties": {"security-severity": str(finding.vulnerability.cvss or finding.score / 10)},
            },
        )
        location = _primary_location(finding)
        physical_location: dict[str, Any]
        if location:
            physical_location = {
                "artifactLocation": {"uri": str(location.path)},
                "region": {"startLine": location.line, "startColumn": max(1, location.column)},
            }
        else:
            physical_location = {"artifactLocation": {"uri": f"sbom://{finding.artifact.name}/{finding.component.name}"}}
        results.append(
            {
                "ruleId": rule_id,
                "level": _level(finding.tier),
                "message": {"text": _finding_message(finding)},
                "locations": [{"physicalLocation": physical_location}],
                "properties": {
                    "finding_key": finding.key,
                    "tier": finding.tier.value,
                    "score": round(finding.score, 2),
                    "artifact": finding.artifact.name,
                    "component": finding.component.name,
                    "reachability": finding.source.reachability.value,
                },
            }
        )
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Reachability Advisor",
                        "informationUri": "https://github.com/example/reachability-advisor",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def write_diagnostics(findings: list[Finding], path: str | Path) -> None:
    diagnostics = []
    for finding in findings:
        location = _primary_location(finding)
        uri = str(location.path) if location else f"sbom://{finding.artifact.name}/{finding.component.name}"
        line = (location.line - 1) if location else 0
        column = (location.column - 1) if location else 0
        diagnostics.append(
            {
                "uri": uri,
                "range": {"start": {"line": line, "character": column}, "end": {"line": line, "character": column + 1}},
                "severity": _diagnostic_severity(finding.tier),
                "message": _finding_message(finding),
                "source": "Reachability Advisor",
                "code": finding.vulnerability.id,
                "finding_key": finding.key,
                "artifact": finding.artifact.name,
                "component": finding.component.name,
                "tier": finding.tier.value,
                "score": round(finding.score, 2),
                "confidence": finding.confidence.value,
                "source_reachability": finding.source.reachability.value,
                "source_evidence": finding.source.evidence_source,
                "context": {
                    "exposure": finding.context.exposure,
                    "privilege": finding.context.privilege,
                    "criticality": finding.context.criticality,
                    "owner": finding.context.owner,
                },
                "explanation": "; ".join(finding.rationale[:4]),
                "evidence": {
                    "source_locations": [location.to_json() for location in finding.source.locations],
                    "network_paths": finding.context.network_paths,
                    "effective_access": finding.context.effective_access,
                    "context_evidence": finding.context.evidence[:12],
                },
            }
        )
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"diagnostics": diagnostics}, indent=2), encoding="utf-8")


def _diagnostic_severity(tier: Tier) -> int:
    # VS Code DiagnosticSeverity: Error=0? API constants are 0-3 in the JS extension below.
    return {Tier.URGENT: 0, Tier.HIGH: 0, Tier.MEDIUM: 1, Tier.LOW: 2, Tier.INFORMATIONAL: 3}[tier]


def _finding_message(finding: Finding) -> str:
    return (
        f"{finding.vulnerability.id} in {finding.component.name}@{finding.component.version or 'unknown'} "
        f"is {finding.tier.value} (score {finding.score:.1f}); "
        f"source={reachability_label(finding.source.reachability)}; exposure={finding.context.exposure}; "
        f"owner={finding.context.owner or 'unknown'}"
    )


def write_markdown_report(findings: list[Finding], path: str | Path, max_findings: int = 15) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    remediations = build_remediation_groups(findings)
    lines = [
        "# Reachability Advisor PR Summary",
        "",
        f"Generated at: {datetime.now(timezone.utc).isoformat()}",
        "",
        "This report prioritizes dependency vulnerabilities using SBOM presence, source reachability, Terraform deployment context, and policy state. It does not prove exploitability and must not be used for automatic suppression without review.",
        "",
        "## Remediation queue",
        "",
    ]
    if not findings:
        lines.append("No matching vulnerable components were found.")
    for index, remediation in enumerate(remediations[:max_findings], start=1):
        lines.extend(_remediation_markdown(index, remediation))
    if len(remediations) > max_findings:
        lines.append(f"\n{len(remediations) - max_findings} additional remediation groups omitted from this summary. See JSON output for details.")
    if findings:
        lines.extend(["", "## Highest-scoring findings", ""])
    for index, finding in enumerate(findings[:max_findings], start=1):
        lines.extend(_finding_markdown(index, finding))
    if len(findings) > max_findings:
        lines.append(f"\n{len(findings) - max_findings} additional findings omitted from this summary. See JSON/SARIF output for details.")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _remediation_markdown(index: int, remediation: dict[str, Any]) -> list[str]:
    component = remediation["component"]
    context = remediation["context"]
    owner = context.get("owner") or "unknown owner"
    vulnerabilities = remediation["top_vulnerabilities"]
    lines = [
        f"### {index}. {str(remediation['tier']).upper()}: `{component['display_name']}@{component.get('version') or 'unknown'}`",
        "",
        f"- Artifact: `{remediation['artifact']['name']}`",
        f"- Vulnerabilities grouped: `{remediation['vulnerability_count']}`",
        f"- Max score: `{float(remediation['max_score']):.1f}`; confidence: `{remediation['confidence']}`",
        f"- Owner: `{owner}`",
        f"- Source signal: `{remediation.get('reachability_label', remediation['reachability'])}` (`{remediation['reachability']}`)",
        f"- Context: exposure=`{context['exposure']}`, environment=`{context['environment']}`, privilege=`{context['privilege']}`, criticality=`{context.get('criticality', 'unknown')}`",
    ]
    if context.get("iam_impacts"):
        lines.append(f"- IAM impacts: `{', '.join(context['iam_impacts'])}`")
    if remediation.get("suggested_fix"):
        lines.append(f"- Suggested fix: `{remediation['suggested_fix']}`")
    elif not remediation.get("fix_available"):
        lines.append("- Suggested fix: no fixed version was reported by vulnerability intelligence")
    if vulnerabilities:
        shown = vulnerabilities[:5]
        lines.append("- Included vulnerabilities:")
        for vulnerability in shown:
            lines.append(
                f"  - `{vulnerability['id']}` score `{float(vulnerability['score']):.1f}` "
                f"severity `{vulnerability['severity']}`"
            )
        if len(vulnerabilities) > len(shown):
            lines.append(f"  - {len(vulnerabilities) - len(shown)} more in JSON output")
    lines.append("")
    return lines


def _finding_markdown(index: int, finding: Finding) -> list[str]:
    owner = finding.context.owner or "unknown owner"
    lines = [
        f"### {index}. {finding.tier.value.upper()}: {finding.vulnerability.id} in `{finding.component.name}`",
        "",
        f"- Artifact: `{finding.artifact.name}`",
        f"- Component: `{finding.component.name}@{finding.component.version or 'unknown'}`",
        f"- Score: `{finding.score:.1f}`; confidence: `{finding.confidence.value}`",
        f"- Owner: `{owner}`",
        f"- Source signal: `{reachability_label(finding.source.reachability)}` (`{finding.source.reachability.value}`) - {finding.source.reason}",
        f"- Context: exposure=`{finding.context.exposure}`, environment=`{finding.context.environment}`, privilege=`{finding.context.privilege}`, criticality=`{finding.context.criticality}`",
    ]
    if finding.context.iam_impacts:
        lines.append(f"- IAM impacts: `{', '.join(finding.context.iam_impacts)}`")
    if finding.fix_commands:
        lines.append("- Suggested fix:")
        for command in finding.fix_commands:
            lines.append(f"  - `{command}`")
    if finding.source.locations:
        lines.append("- Evidence locations:")
        for location in finding.source.locations[:3]:
            lines.append(f"  - `{location.path}:{location.line}` - {location.snippet}")
    lines.append("- Why it matters:")
    for reason in finding.rationale[:5]:
        lines.append(f"  - {reason}")
    lines.append("")
    return lines


def write_annotations(findings: list[Finding], path: str | Path, min_tier: Tier = Tier.HIGH, max_findings: int = 20) -> None:
    order = {Tier.INFORMATIONAL: 0, Tier.LOW: 1, Tier.MEDIUM: 2, Tier.HIGH: 3, Tier.URGENT: 4}
    lines: list[str] = []
    for finding in findings:
        if order[finding.tier] < order[min_tier]:
            continue
        location = _primary_location(finding)
        if location:
            lines.append(f"::error file={location.path},line={location.line},col={location.column}::{_escape_annotation(_finding_message(finding))}")
        else:
            lines.append(f"::warning title=Reachability Advisor::{_escape_annotation(_finding_message(finding))}")
        if len(lines) >= max_findings:
            break
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _escape_annotation(message: str) -> str:
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def render_table(findings: list[Finding], limit: int = 20) -> str:
    rows = [("Tier", "Score", "Artifact", "Component", "Vulnerability", "Reachability", "Owner")]
    for finding in findings[:limit]:
        rows.append(
            (
                finding.tier.value,
                f"{finding.score:.1f}",
                finding.artifact.name,
                finding.component.name,
                finding.vulnerability.id,
                reachability_label(finding.source.reachability),
                finding.context.owner or "unknown",
            )
        )
    widths = [max(len(str(row[i])) for row in rows) for i in range(len(rows[0]))]
    rendered = []
    for index, row in enumerate(rows):
        rendered.append(" | ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))
        if index == 0:
            rendered.append("-+-".join("-" * width for width in widths))
    return "\n".join(rendered)


def explain_finding(data: dict[str, Any], key: str | None = None, artifact: str | None = None, vulnerability: str | None = None, component: str | None = None) -> str:
    findings = data.get("findings", []) if isinstance(data, dict) else []
    selected = None
    for finding in findings:
        if key and finding.get("key") == key:
            selected = finding
            break
        if artifact and vulnerability and component and finding.get("artifact", {}).get("name") == artifact and finding.get("vulnerability", {}).get("id") == vulnerability and finding.get("component", {}).get("name") == component:
            selected = finding
            break
    if selected is None:
        raise ValueError("finding not found")
    lines = [
        f"# Explanation: {selected['vulnerability']['id']} in {selected['component']['name']}",
        "",
        f"Artifact: `{selected['artifact']['name']}`",
        f"Tier: `{selected['tier']}`; score: `{selected['score']}`; confidence: `{selected['confidence']}`",
        "",
        "## Evidence",
        f"- Source reachability: `{selected['source_reachability'].get('label', selected['source_reachability']['state'])}` (`{selected['source_reachability']['state']}`) - {selected['source_reachability']['reason']}",
        f"- Context: exposure=`{selected['context']['exposure']}`, environment=`{selected['context']['environment']}`, privilege=`{selected['context']['privilege']}`, criticality=`{selected['context'].get('criticality', 'unknown')}`",
    ]
    if selected["context"].get("iam_impacts"):
        lines.append(f"- IAM impacts: `{', '.join(selected['context']['iam_impacts'])}`")
    lines.extend(["", "## Rationale"])
    for reason in selected.get("rationale", []):
        lines.append(f"- {reason}")
    if selected.get("fix_commands"):
        lines.append("\n## Suggested fixes")
        for command in selected["fix_commands"]:
            lines.append(f"- `{command}`")
    return "\n".join(lines) + "\n"
