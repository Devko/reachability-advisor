"""Non-destructive finding correlation."""

from __future__ import annotations

from urllib.parse import urlparse

from .finding_types import canonical_finding_type
from .models import Confidence, CorrelationEvidence, Finding
from .scoring import apply_graph_score


def apply_correlations(findings: list[Finding]) -> list[Finding]:
    """Attach correlation evidence without hiding or merging original findings."""

    for left_index, left in enumerate(findings):
        for right in findings[left_index + 1 :]:
            correlation = _correlate(left, right)
            if correlation is None:
                continue
            _attach(left, right, correlation[0], correlation[1], correlation[2])
            _attach(right, left, correlation[0], correlation[1], correlation[2])
    for finding in findings:
        _apply_corroboration_score(finding)
    return sorted(findings, key=lambda item: item.score, reverse=True)


def _correlate(left: Finding, right: Finding) -> tuple[str, Confidence, str] | None:
    left_type = canonical_finding_type(left.finding_type)
    right_type = canonical_finding_type(right.finding_type)
    types = {left_type, right_type}
    if types == {"static_code_weakness", "dynamic_runtime_observation"}:
        if _route_key(left) and _route_key(left) == _route_key(right) and _cwe(left) and _cwe(left) == _cwe(right):
            return ("sast_dast_route_match", Confidence.HIGH, "SAST and DAST evidence share route and CWE.")
        if _route_key(left) and _route_key(left) == _route_key(right):
            return ("sast_dast_route_match", Confidence.MEDIUM, "SAST and DAST evidence share route.")
        if _cwe(left) and _cwe(left) == _cwe(right):
            return ("multi_tool_same_cwe", Confidence.MEDIUM, "SAST and DAST evidence share CWE.")
    if types == {"dependency_vulnerability", "dynamic_runtime_observation"} and left.artifact.name == right.artifact.name:
        return ("sca_dast_same_artifact", Confidence.LOW, "Dependency and DAST findings affect the same artifact; this is context, not causality.")
    if types == {"dependency_vulnerability", "static_code_weakness"} and left.artifact.name == right.artifact.name:
        if _cwe(left) and _cwe(left) == _cwe(right):
            return ("sca_sast_same_sink_or_package_family", Confidence.MEDIUM, "Dependency and SAST findings share CWE in the same artifact.")
        return ("weak_possible_relation", Confidence.LOW, "Dependency and SAST findings share artifact only.")
    return None


def _attach(finding: Finding, related: Finding, correlation_type: str, confidence: Confidence, reason: str) -> None:
    if any(item.related_finding_key == related.key and item.correlation_type == correlation_type for item in finding.correlated_evidence):
        return
    finding.correlated_evidence.append(
        CorrelationEvidence(
            correlation_type=correlation_type,
            related_finding_key=related.key,
            confidence=confidence,
            reason=reason,
            evidence={
                "related_finding_type": related.finding_type,
                "related_artifact": related.artifact.name,
                "related_rule_or_vulnerability": related.vulnerability.id,
            },
        )
    )


def _apply_corroboration_score(finding: Finding) -> None:
    if not finding.correlated_evidence:
        return
    original = finding.score
    original_tier = finding.tier
    apply_graph_score(finding)
    strongest = max(finding.correlated_evidence, key=lambda item: {"high": 3, "medium": 2, "low": 1}.get(item.confidence.value, 0))
    finding.rationale.append(f"corroborating scanner evidence ({strongest.correlation_type}) was evaluated by the graph decision")
    if original < 65 <= finding.score or original_tier != finding.tier:
        finding.score_details.setdefault("gates", []).append({
            "name": "corroboration_threshold_crossed",
            "status": "passed",
            "reason": "corroboration changed the graph priority decision",
        })

def _route_key(finding: Finding) -> str:
    route = str(finding.weakness.get("route") or "")
    url = str(finding.weakness.get("url") or finding.runtime_evidence.url or "")
    if route:
        return _normalize_route(route)
    if url:
        parsed = urlparse(url)
        return _normalize_route(parsed.path or "/")
    return ""


def _cwe(finding: Finding) -> str:
    value = str(finding.weakness.get("cwe") or "")
    if value:
        return value.upper()
    aliases = [alias.upper() for alias in finding.vulnerability.aliases]
    return next((alias for alias in aliases if alias.startswith("CWE-")), "")


def _normalize_route(value: str) -> str:
    value = value.split("?", 1)[0].strip().lower()
    return value if value.startswith("/") else f"/{value}" if value else ""


__all__ = ["apply_correlations"]
