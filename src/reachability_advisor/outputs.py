"""Output renderers for CI and IDE workflows."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .evidence_graph import build_evidence_graph
from .finding_types import (
    canonical_finding_type,
    is_dependency_finding,
    is_dynamic_finding,
    is_posture_finding,
    is_security_finding,
    is_static_finding,
)
from .input_limits import read_text_limited
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
    data = json.loads(read_text_limited(Path(path), "findings"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def _primary_location(finding: Finding) -> SourceLocation | None:
    return finding.source.locations[0] if finding.source.locations else None


def _is_dependency(finding: Finding) -> bool:
    return is_dependency_finding(finding.finding_type)


def _is_static(finding: Finding) -> bool:
    return is_static_finding(finding.finding_type)


def _is_dynamic(finding: Finding) -> bool:
    return is_dynamic_finding(finding.finding_type)


def _is_posture(finding: Finding) -> bool:
    return is_posture_finding(finding.finding_type)


def _is_security_finding(finding: Finding) -> bool:
    return is_security_finding(finding.finding_type)


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
                "help": {"text": _sarif_rule_help(finding)},
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
        elif _is_dynamic(finding):
            uri = finding.runtime_evidence.url or f"security-evidence://{finding.artifact.name}/{finding.vulnerability.id}"
            physical_location = {"artifactLocation": {"uri": uri}}
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
                    "finding_type": finding.finding_type,
                    "weakness": finding.weakness,
                    "reachability": finding.source.reachability.value,
                    "runtime_evidence": finding.runtime_evidence.to_json(),
                    "posture_evidence": finding.posture_evidence.to_json(),
                    "correlated_evidence": [item.to_json() for item in finding.correlated_evidence],
                    "unknowns": finding.unknowns,
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


def _sarif_rule_help(finding: Finding) -> str:
    if _is_dependency(finding):
        return "Dependency vulnerability prioritized with SBOM, source, deployment, network, IAM/RBAC, and policy evidence."
    if _is_dynamic(finding):
        return "Runtime scanner observation from DAST or similar evidence. Source reachability is reported only when source evidence exists."
    if _is_posture(finding):
        return "Cloud posture finding from imported CSPM evidence or native local IaC checks. This is configuration context, not proof of exploitability."
    return "Static scanner finding from SAST or source evidence. Data flow and source locations are reported when the scanner supplied them."


def write_diagnostics(findings: list[Finding], path: str | Path) -> None:
    diagnostics = []
    for finding in findings:
        location = _primary_location(finding)
        if location is None:
            continue
        uri = str(location.path)
        line = location.line - 1
        column = location.column - 1
        diagnostics.append(
            {
                "uri": uri,
                "range": {"start": {"line": line, "character": column}, "end": {"line": line, "character": column + 1}},
                "severity": _diagnostic_severity(finding.tier),
                "message": _finding_message(finding),
                "source": "Reachability Advisor",
                "code": finding.vulnerability.id,
                "finding_key": finding.key,
                "finding_type": finding.finding_type,
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
                    "effective_exposure": finding.context.effective_exposure,
                    "context_evidence": finding.context.evidence[:12],
                    "runtime_evidence": finding.runtime_evidence.to_json(),
                    "posture_evidence": finding.posture_evidence.to_json(),
                    "correlated_evidence": [item.to_json() for item in finding.correlated_evidence],
                    "unknowns": finding.unknowns,
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
    if _is_security_finding(finding):
        weakness = finding.weakness.get("weakness") or finding.vulnerability.summary or finding.vulnerability.id
        tool = finding.weakness.get("tool") or finding.source.evidence_source
        location = f" at {finding.component.name}" if finding.component.name else ""
        evidence = f"runtime={finding.runtime_evidence.state.value}; " if _is_dynamic(finding) else ""
        return (
            f"{finding.vulnerability.id} ({weakness}) reported by {tool}{location} "
            f"has priority {finding.tier.value} (score {finding.score:.1f}); "
            f"{evidence}source evidence={reachability_label(finding.source.reachability)}; network exposure={finding.context.exposure}; "
            f"owner={finding.context.owner or 'unknown'}"
        )
    return (
        f"{finding.vulnerability.id} in {finding.component.name}@{finding.component.version or 'unknown'} "
        f"has priority {finding.tier.value} (score {finding.score:.1f}); "
        f"source evidence={reachability_label(finding.source.reachability)}; network exposure={finding.context.exposure}; "
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
        "This report prioritizes dependency vulnerabilities, static scanner findings, runtime scanner observations, and cloud posture findings using SBOM, source, Terraform, Kubernetes, network, IAM/RBAC, and policy evidence. It does not prove exploitability and must not be used for automatic suppression without review.",
        "",
        "## Remediation queue",
        "",
    ]
    if not findings:
        lines.append("No matching dependency vulnerabilities or imported scanner findings were found for the supplied evidence.")
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
    lines.extend(_typed_markdown_sections(findings, max_findings=max_findings))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _typed_markdown_sections(findings: list[Finding], max_findings: int = 15) -> list[str]:
    sections: list[tuple[str, list[Finding]]] = [
        ("Fix now", [finding for finding in findings if finding.tier in {Tier.URGENT, Tier.HIGH}]),
        ("Investigate", [finding for finding in findings if finding.tier == Tier.MEDIUM]),
        ("Runtime scanner findings", [finding for finding in findings if _is_dynamic(finding)]),
        ("Static scanner findings", [finding for finding in findings if _is_static(finding)]),
        ("Cloud posture findings", [finding for finding in findings if _is_posture(finding)]),
        ("Dependency findings", [finding for finding in findings if _is_dependency(finding)]),
        ("Correlated findings", [finding for finding in findings if finding.correlated_evidence]),
        ("Visibility gaps", [finding for finding in findings if finding.unknowns]),
    ]
    lines: list[str] = []
    for heading, items in sections:
        lines.extend(["", f"## {heading}", ""])
        if not items:
            lines.append("None.")
            continue
        for finding in items[:max_findings]:
            lines.append(f"- `{finding.tier.value}` `{finding.vulnerability.id}` on `{finding.artifact.name}`: {_markdown_summary(finding)}")
        if len(items) > max_findings:
            lines.append(f"- {len(items) - max_findings} more in JSON output")
    return lines


def _markdown_summary(finding: Finding) -> str:
    if _is_dynamic(finding):
        state = finding.runtime_evidence.state.value
        unknowns = f"; unknown: {', '.join(finding.unknowns[:2])}" if finding.unknowns else ""
        return f"runtime evidence `{state}`, source evidence `{finding.source.reachability.value}`{unknowns}"
    if _is_static(finding):
        return f"static scanner evidence `{finding.source.evidence_source}`, source evidence `{finding.source.reachability.value}`"
    if _is_posture(finding):
        posture = finding.posture_evidence
        return f"posture `{posture.rule_id}`, resource `{posture.resource_id or finding.component.name}`, expected `{posture.expected or 'unknown'}`, actual `{posture.actual or 'unknown'}`"
    return f"dependency `{finding.component.display_name}`, source evidence `{finding.source.reachability.value}`"


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
        f"- Source evidence: `{remediation.get('reachability_label', remediation['reachability'])}` (`{remediation['reachability']}`)",
        f"- Runtime/deployment context: network exposure=`{context['exposure']}`, environment=`{context['environment']}`, IAM/RBAC privilege=`{context['privilege']}`, asset criticality=`{context.get('criticality', 'unknown')}`",
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
    title = (
        f"{finding.vulnerability.id} in `{finding.component.name}`"
        if _is_dependency(finding)
        else f"{finding.vulnerability.id} `{finding.weakness.get('weakness') or finding.vulnerability.summary or 'security finding'}`"
    )
    component_label = (
        f"{finding.component.name}@{finding.component.version or 'unknown'}"
        if _is_dependency(finding)
        else finding.component.name
    )
    lines = [
        f"### {index}. {finding.tier.value.upper()}: {title}",
        "",
        f"- Artifact: `{finding.artifact.name}`",
        f"- Component: `{component_label}`",
        f"- Finding type: `{finding.finding_type}`",
        f"- Score: `{finding.score:.1f}`; confidence: `{finding.confidence.value}`",
        f"- Owner: `{owner}`",
        f"- Source evidence: `{reachability_label(finding.source.reachability)}` (`{finding.source.reachability.value}`) - {finding.source.reason}",
        f"- Runtime/deployment context: network exposure=`{finding.context.exposure}`, environment=`{finding.context.environment}`, IAM/RBAC privilege=`{finding.context.privilege}`, asset criticality=`{finding.context.criticality}`",
    ]
    if _is_security_finding(finding):
        lines.append(f"- Scanner: `{finding.weakness.get('tool', 'unknown')}`; type=`{finding.weakness.get('scanner_type', 'unknown')}`; CWE=`{finding.weakness.get('cwe') or 'unknown'}`")
    if _is_dynamic(finding):
        runtime = finding.runtime_evidence
        lines.append(f"- Runtime evidence: state=`{runtime.state.value}`, confidence=`{runtime.confidence.value}`, url=`{runtime.url or 'unknown'}`, method=`{runtime.method or 'unknown'}`")
    if _is_posture(finding):
        posture = finding.posture_evidence
        lines.append(f"- Posture evidence: resource=`{posture.resource_id or 'unknown'}`, type=`{posture.resource_type or 'unknown'}`, provider=`{posture.provider or 'unknown'}`")
        lines.append(f"- Expected/actual: `{posture.expected or 'unknown'}` / `{posture.actual or 'unknown'}`")
    if finding.correlated_evidence:
        lines.append("- Correlated evidence:")
        for item in finding.correlated_evidence[:3]:
            lines.append(f"  - `{item.correlation_type}` confidence=`{item.confidence.value}`: {item.reason}")
    if finding.unknowns:
        lines.append("- Unknown evidence and visibility gaps:")
        for unknown in finding.unknowns[:5]:
            lines.append(f"  - {unknown}")
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
            file_property = _escape_annotation_property(str(location.path))
            line_property = _annotation_number(location.line)
            column_property = _annotation_number(location.column)
            lines.append(f"::error file={file_property},line={line_property},col={column_property}::{_escape_annotation_message(_finding_message(finding))}")
        else:
            lines.append(f"::warning title=Reachability Advisor::{_escape_annotation_message(_finding_message(finding))}")
        if len(lines) >= max_findings:
            break
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _escape_annotation_message(message: str) -> str:
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_annotation_property(value: str) -> str:
    return _escape_annotation_message(value).replace(":", "%3A").replace(",", "%2C")


def _annotation_number(value: int) -> int:
    return max(1, int(value))


def render_table(findings: list[Finding], limit: int = 20) -> str:
    rows = [("Priority", "Score", "Artifact", "Component", "Finding", "Source evidence", "Owner")]
    for finding in findings[:limit]:
        rows.append(
            (
                finding.tier.value,
                f"{finding.score:.1f}",
                finding.artifact.name,
                finding.component.name,
                finding.vulnerability.id if _is_dependency(finding) else f"{finding.vulnerability.id} ({finding.weakness.get('weakness', 'security finding')})",
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
    finding_type = canonical_finding_type(str(selected.get("finding_type") or "dependency_vulnerability"))
    selected_is_security_finding = is_security_finding(finding_type)
    weakness = selected.get("weakness", {}) if isinstance(selected.get("weakness"), dict) else {}
    title = (
        f"{selected['vulnerability']['id']} in {selected['component']['name']}"
        if not selected_is_security_finding
        else f"{selected['vulnerability']['id']} {weakness.get('weakness') or 'security finding'}"
    )
    lines = [
        f"# Explanation: {title}",
        "",
        f"Artifact: `{selected['artifact']['name']}`",
        f"Priority: `{selected['tier']}`; score: `{selected['score']}`; confidence: `{selected['confidence']}`",
        "",
        "## Evidence",
        f"- Source evidence: `{selected['source_reachability'].get('label', selected['source_reachability']['state'])}` (`{selected['source_reachability']['state']}`) - {selected['source_reachability']['reason']}",
        f"- Runtime/deployment context: network exposure=`{selected['context']['exposure']}`, environment=`{selected['context']['environment']}`, IAM/RBAC privilege=`{selected['context']['privilege']}`, asset criticality=`{selected['context'].get('criticality', 'unknown')}`",
    ]
    if selected["context"].get("iam_impacts"):
        lines.append(f"- IAM impacts: `{', '.join(selected['context']['iam_impacts'])}`")
    if selected_is_security_finding:
        lines.append(f"- Scanner: `{weakness.get('tool', 'unknown')}`; type=`{weakness.get('scanner_type', 'unknown')}`; CWE=`{weakness.get('cwe') or 'unknown'}`")
    runtime = selected.get("runtime_evidence", {}) if isinstance(selected.get("runtime_evidence"), dict) else {}
    if finding_type == "dynamic_runtime_observation":
        lines.append(f"- Runtime evidence: state=`{runtime.get('state', 'unknown')}`, url=`{runtime.get('url') or 'unknown'}`, method=`{runtime.get('method') or 'unknown'}`")
    posture = selected.get("posture_evidence", {}) if isinstance(selected.get("posture_evidence"), dict) else {}
    if finding_type == "cloud_posture_finding":
        lines.append(f"- Posture evidence: resource=`{posture.get('resource_id') or 'unknown'}`, provider=`{posture.get('provider') or 'unknown'}`, expected=`{posture.get('expected') or 'unknown'}`, actual=`{posture.get('actual') or 'unknown'}`")
    unknowns = selected.get("unknowns", [])
    if isinstance(unknowns, list) and unknowns:
        lines.extend(["", "## Unknown Evidence And Visibility Gaps"])
        for unknown in unknowns:
            lines.append(f"- {unknown}")
    lines.extend(["", "## Rationale"])
    for reason in selected.get("rationale", []):
        lines.append(f"- {reason}")
    if selected.get("fix_commands"):
        lines.append("\n## Suggested fixes")
        for command in selected["fix_commands"]:
            lines.append(f"- `{command}`")
    return "\n".join(lines) + "\n"
