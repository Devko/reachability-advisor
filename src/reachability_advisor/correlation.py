"""Non-destructive finding correlation."""

from __future__ import annotations

import os
from urllib.parse import urlparse

from .finding_types import (
    CLOUD_POSTURE_FINDING,
    DEPENDENCY_VULNERABILITY,
    DYNAMIC_RUNTIME_OBSERVATION,
    STATIC_CODE_WEAKNESS,
    canonical_finding_type,
)
from .models import Confidence, CorrelationEvidence, Finding
from .scoring import apply_graph_score

DEFAULT_MAX_CORRELATIONS_PER_RELATION = 25
MAX_CORRELATIONS_ENV = "REACHABILITY_ADVISOR_MAX_CORRELATIONS_PER_RELATION"

_RELATION_SAST_DAST = "sast_dast_route_or_cwe"
_RELATION_SCA_DAST_ARTIFACT = "sca_dast_same_artifact"
_RELATION_SCA_SAST_ARTIFACT = "sca_sast_same_artifact"
_RELATION_CSPM_ARTIFACT = "cspm_same_artifact"


def max_correlations_per_relation() -> int:
    """Per-finding ceiling on correlations attached for one relation kind."""

    raw = os.environ.get(MAX_CORRELATIONS_ENV)
    if not raw:
        return DEFAULT_MAX_CORRELATIONS_PER_RELATION
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_CORRELATIONS_PER_RELATION
    return value if value > 0 else DEFAULT_MAX_CORRELATIONS_PER_RELATION


def apply_correlations(findings: list[Finding]) -> list[Finding]:
    """Attach correlation evidence without hiding or merging original findings.

    Candidate pairs are drawn from per-relation indexes instead of an all-pairs
    scan, and the artifact-scoped relations are bounded per finding: those fire on
    an artifact-name match alone, so a monorepo or a ZAP report with thousands of
    alert instances would otherwise emit a quadratic number of low-signal records.
    Anything the ceiling drops is reported as a visibility gap on the finding --
    truncated correlation coverage is an unknown, never silently discarded.
    """

    limit = max_correlations_per_relation()
    pairs, dropped = _candidate_pairs(findings, limit)
    ledgers = [_AttachLedger(finding, limit) for finding in findings]
    for left_index, right_index in sorted(pairs):
        left = findings[left_index]
        right = findings[right_index]
        correlation = _correlate(left, right)
        if correlation is None:
            continue
        _attach(left, right, correlation, ledgers[left_index])
        _attach(right, left, correlation, ledgers[right_index])
    for index, counts in sorted(dropped.items()):
        _record_truncated_coverage(findings[index], counts, limit)
    for finding in findings:
        _apply_corroboration_score(finding)
    return sorted(findings, key=lambda item: item.score, reverse=True)


def _candidate_pairs(findings: list[Finding], limit: int) -> tuple[set[tuple[int, int]], dict[int, dict[str, int]]]:
    """Index findings per correlation rule and return the bounded candidate pairs.

    The indexes mirror ``_correlate`` exactly, so no pair that would correlate is
    lost. In particular the SAST/DAST rule is indexed by route and CWE only: it is
    deliberately cross-artifact, because unmapped DAST records carry a synthetic
    ``unmapped:`` artifact and must still correlate to SAST by route.
    """

    pairs: set[tuple[int, int]] = set()
    dropped: dict[int, dict[str, int]] = {}
    artifact_members: dict[str, list[int]] = {}
    artifact_types: dict[str, dict[str, list[int]]] = {}
    route_index: dict[str, dict[str, list[int]]] = {}
    cwe_index: dict[str, dict[str, list[int]]] = {}
    weakness_entries: list[tuple[int, str, str, str]] = []

    for index, finding in enumerate(findings):
        finding_type = canonical_finding_type(finding.finding_type)
        artifact_members.setdefault(finding.artifact.name, []).append(index)
        artifact_types.setdefault(finding.artifact.name, {}).setdefault(finding_type, []).append(index)
        if finding_type not in {STATIC_CODE_WEAKNESS, DYNAMIC_RUNTIME_OBSERVATION}:
            continue
        route = _route_key(finding)
        cwe = _cwe(finding)
        weakness_entries.append((index, finding_type, route, cwe))
        if route:
            route_index.setdefault(route, {}).setdefault(finding_type, []).append(index)
        if cwe:
            cwe_index.setdefault(cwe, {}).setdefault(finding_type, []).append(index)

    for index, finding_type, route, cwe in weakness_entries:
        peer_type = DYNAMIC_RUNTIME_OBSERVATION if finding_type == STATIC_CODE_WEAKNESS else STATIC_CODE_WEAKNESS
        peers = sorted(set(route_index.get(route, {}).get(peer_type, ())) | set(cwe_index.get(cwe, {}).get(peer_type, ())))
        _plan_partners(index, peers, len(peers), limit, _RELATION_SAST_DAST, pairs, dropped)

    for artifact, groups in artifact_types.items():
        dependency = groups.get(DEPENDENCY_VULNERABILITY, [])
        dynamic = groups.get(DYNAMIC_RUNTIME_OBSERVATION, [])
        static = groups.get(STATIC_CODE_WEAKNESS, [])
        posture = groups.get(CLOUD_POSTURE_FINDING, [])
        _plan_cross(dependency, dynamic, limit, _RELATION_SCA_DAST_ARTIFACT, pairs, dropped)
        _plan_cross(dependency, static, limit, _RELATION_SCA_SAST_ARTIFACT, pairs, dropped)
        if posture:
            posture_set = set(posture)
            others = [index for index in artifact_members[artifact] if index not in posture_set]
            _plan_cross(posture, others, limit, _RELATION_CSPM_ARTIFACT, pairs, dropped)
            _plan_within(posture, limit, _RELATION_CSPM_ARTIFACT, pairs, dropped)
    return pairs, dropped


def _plan_cross(
    lefts: list[int],
    rights: list[int],
    limit: int,
    relation: str,
    pairs: set[tuple[int, int]],
    dropped: dict[int, dict[str, int]],
) -> None:
    """Pair two disjoint index groups, giving each member at most ``limit`` peers."""

    if not lefts or not rights:
        return
    for index in lefts:
        _plan_partners(index, rights, len(rights), limit, relation, pairs, dropped)
    for index in rights:
        _plan_partners(index, lefts, len(lefts), limit, relation, pairs, dropped)


def _plan_within(
    members: list[int],
    limit: int,
    relation: str,
    pairs: set[tuple[int, int]],
    dropped: dict[int, dict[str, int]],
) -> None:
    """Pair a group with itself, giving each member at most ``limit`` peers."""

    if len(members) < 2:
        return
    for index in members:
        _plan_partners(index, members, len(members) - 1, limit, relation, pairs, dropped)


def _plan_partners(
    index: int,
    peers: list[int],
    peer_count: int,
    limit: int,
    relation: str,
    pairs: set[tuple[int, int]],
    dropped: dict[int, dict[str, int]],
) -> None:
    used = 0
    for peer in peers:
        if peer == index:
            continue
        if used >= limit:
            break
        pairs.add((index, peer) if index < peer else (peer, index))
        used += 1
    skipped = peer_count - used
    if skipped > 0:
        counts = dropped.setdefault(index, {})
        counts[relation] = counts.get(relation, 0) + skipped


def _correlate(left: Finding, right: Finding) -> tuple[str, Confidence, str] | None:
    left_type = canonical_finding_type(left.finding_type)
    right_type = canonical_finding_type(right.finding_type)
    types = {left_type, right_type}
    if types == {STATIC_CODE_WEAKNESS, DYNAMIC_RUNTIME_OBSERVATION}:
        left_route = _route_key(left)
        left_cwe = _cwe(left)
        route_match = bool(left_route) and left_route == _route_key(right)
        cwe_match = bool(left_cwe) and left_cwe == _cwe(right)
        if route_match and cwe_match:
            return ("sast_dast_route_match", Confidence.HIGH, "SAST and DAST evidence share route and CWE.")
        if route_match:
            return ("sast_dast_route_match", Confidence.MEDIUM, "SAST and DAST evidence share route.")
        if cwe_match:
            return ("multi_tool_same_cwe", Confidence.MEDIUM, "SAST and DAST evidence share CWE.")
    if types == {DEPENDENCY_VULNERABILITY, DYNAMIC_RUNTIME_OBSERVATION} and left.artifact.name == right.artifact.name:
        return ("sca_dast_same_artifact", Confidence.LOW, "Dependency and DAST findings affect the same artifact; this is context, not causality.")
    if types == {DEPENDENCY_VULNERABILITY, STATIC_CODE_WEAKNESS} and left.artifact.name == right.artifact.name:
        if _cwe(left) and _cwe(left) == _cwe(right):
            return ("sca_sast_same_sink_or_package_family", Confidence.MEDIUM, "Dependency and SAST findings share CWE in the same artifact.")
        return ("weak_possible_relation", Confidence.LOW, "Dependency and SAST findings share artifact only.")
    if CLOUD_POSTURE_FINDING in types and left.artifact.name == right.artifact.name:
        posture = left if left_type == CLOUD_POSTURE_FINDING else right
        other = right if posture is left else left
        if posture.context.exposure in {"public", "external"} and canonical_finding_type(other.finding_type) in {DEPENDENCY_VULNERABILITY, STATIC_CODE_WEAKNESS, DYNAMIC_RUNTIME_OBSERVATION}:
            return ("cspm_deployment_match", Confidence.MEDIUM, "CSPM public exposure evidence applies to the same mapped workload.")
        if posture.context.iam_impacts or posture.context.privilege in {"admin", "sensitive"}:
            return ("cspm_blast_radius_context", Confidence.MEDIUM, "CSPM identity or data posture applies to the same mapped workload.")
        return ("weak_possible_relation", Confidence.LOW, "CSPM and security finding share a mapped resource or artifact only.")
    return None


class _AttachLedger:
    """Per-finding dedupe set plus the per-correlation-type ceiling.

    The dedupe key stays ``(related finding key, correlation type)`` so behaviour is
    unchanged; it is a set instead of the previous linear scan over the attached
    list, which made correlation cubic in the number of findings.
    """

    def __init__(self, finding: Finding, limit: int) -> None:
        self.limit = limit
        self.seen = {(item.related_finding_key, item.correlation_type) for item in finding.correlated_evidence}
        self.counts: dict[str, int] = {}
        for item in finding.correlated_evidence:
            self.counts[item.correlation_type] = self.counts.get(item.correlation_type, 0) + 1

    def admit(self, related_key: str, correlation_type: str) -> bool:
        marker = (related_key, correlation_type)
        if marker in self.seen or self.counts.get(correlation_type, 0) >= self.limit:
            return False
        self.seen.add(marker)
        self.counts[correlation_type] = self.counts.get(correlation_type, 0) + 1
        return True


def _attach(finding: Finding, related: Finding, correlation: tuple[str, Confidence, str], ledger: _AttachLedger) -> None:
    correlation_type, confidence, reason = correlation
    if not ledger.admit(related.key, correlation_type):
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


def _record_truncated_coverage(finding: Finding, counts: dict[str, int], limit: int) -> None:
    for relation, skipped in sorted(counts.items()):
        unknown = f"correlation coverage incomplete: {skipped} further {relation} peers were not recorded (per-relation cap {limit})"
        if unknown not in finding.unknowns:
            finding.unknowns.append(unknown)


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


__all__ = ["apply_correlations", "max_correlations_per_relation"]
