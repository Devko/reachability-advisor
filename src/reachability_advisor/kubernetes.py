"""Rendered Kubernetes manifest context analysis.

The analyzer consumes rendered YAML or JSON manifests. It is intentionally
static: it does not contact a cluster and it does not evaluate Helm templates.
It extracts workload, service, ingress, and RBAC evidence that can be merged
with Terraform and explicit context JSON.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .artifacts import ArtifactMatch, artifact_match_evidence
from .iam_capabilities import dedupe_iam_capabilities
from .models import Artifact, Confidence, ContextEvidence
from .terraform import max_confidence, max_criticality, max_exposure, max_privilege


class KubernetesManifestError(ValueError):
    """Raised when rendered Kubernetes manifests cannot be read."""


@dataclass(frozen=True)
class KubernetesResource:
    path: Path
    document_index: int
    kind: str
    name: str
    namespace: str
    values: dict[str, Any]

    @property
    def address(self) -> str:
        return f"{_kind_resource_type(self.kind)}.{self.name}"


@dataclass(frozen=True)
class RoleGrant:
    privilege: str = "unknown"
    impacts: frozenset[str] = field(default_factory=frozenset)
    capabilities: tuple[dict[str, Any], ...] = ()
    evidence: str = ""


@dataclass(frozen=True)
class WorkloadMatch:
    resource: KubernetesResource
    match: ArtifactMatch
    target: str


@dataclass(frozen=True)
class KubernetesAnalysis:
    contexts: dict[str, ContextEvidence]
    coverage: dict[str, Any]


WORKLOAD_KINDS = {
    "CronJob",
    "DaemonSet",
    "Deployment",
    "Job",
    "Pod",
    "ReplicaSet",
    "StatefulSet",
}
RBAC_KINDS = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}
NETWORK_POLICY_KINDS = {"NetworkPolicy"}
MANIFEST_SUFFIXES = {".yaml", ".yml", ".json"}
MUTATING_VERBS = {"*", "create", "update", "patch", "delete", "deletecollection", "impersonate", "bind", "escalate"}
READ_VERBS = {"get", "list", "watch"}
COMPUTE_RESOURCES = {"pods", "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs"}
NETWORK_RESOURCES = {"services", "ingresses", "ingressclasses", "networkpolicies"}
IAM_RESOURCES = {"roles", "rolebindings", "clusterroles", "clusterrolebindings", "serviceaccounts"}


def analyze_kubernetes_manifests(
    paths: Iterable[str | Path] | None,
    artifacts: list[Artifact],
    *,
    infer_lateral_from_public_entry: bool = False,
) -> KubernetesAnalysis:
    """Infer deployment context from rendered Kubernetes manifests."""

    manifest_files = _manifest_files(paths or [])
    resources: list[KubernetesResource] = []
    for path in manifest_files:
        resources.extend(load_kubernetes_resources(path))
    contexts = _contexts_from_resources(resources, artifacts, infer_lateral_from_public_entry=infer_lateral_from_public_entry)
    coverage = _coverage_report(resources, artifacts, contexts, manifest_files)
    return KubernetesAnalysis(contexts=contexts, coverage=coverage)


def load_kubernetes_resources(path: str | Path) -> list[KubernetesResource]:
    manifest_path = Path(path)
    try:
        text = manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise KubernetesManifestError(f"{manifest_path}: read failed: {exc}") from exc
    try:
        documents = _parse_manifest_documents(text, manifest_path)
    except (json.JSONDecodeError, ValueError) as exc:
        raise KubernetesManifestError(f"{manifest_path}: invalid manifest: {exc}") from exc
    resources: list[KubernetesResource] = []
    for index, document in enumerate(documents):
        if not isinstance(document, dict):
            continue
        kind = str(document.get("kind") or "").strip()
        name = str(_nested(document, "metadata", "name") or "").strip()
        if not kind or not name:
            continue
        namespace = str(_nested(document, "metadata", "namespace") or "default").strip() or "default"
        resources.append(
            KubernetesResource(
                path=manifest_path,
                document_index=index,
                kind=kind,
                name=name,
                namespace=namespace,
                values=document,
            )
        )
    return resources


def empty_kubernetes_coverage_report() -> dict[str, Any]:
    return _coverage_report([], [], {}, [])


def _manifest_files(paths: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            raise KubernetesManifestError(f"{path}: path does not exist")
        if path.is_file():
            if path.suffix.lower() not in MANIFEST_SUFFIXES:
                raise KubernetesManifestError(f"{path}: expected .yaml, .yml, or .json")
            files.append(path)
            continue
        if path.is_dir():
            files.extend(sorted(item for item in path.rglob("*") if item.is_file() and item.suffix.lower() in MANIFEST_SUFFIXES))
            continue
        raise KubernetesManifestError(f"{path}: expected file or directory")
    return sorted(dict.fromkeys(files))


def _parse_manifest_documents(text: str, path: Path) -> list[Any]:
    if path.suffix.lower() == ".json":
        return _json_manifest_documents(json.loads(text))
    documents: list[Any] = []
    for raw in text.split("\n---"):
        document = _parse_yaml_document(raw)
        if document:
            documents.extend(_json_manifest_documents(document))
    return documents


def _json_manifest_documents(data: Any) -> list[Any]:
    if isinstance(data, dict) and data.get("kind") == "List" and isinstance(data.get("items"), list):
        return list(data["items"])
    if isinstance(data, list):
        return data
    return [data]


def _parse_yaml_document(raw: str) -> dict[str, Any]:
    lines = _yaml_lines(raw)
    if not lines:
        return {}
    parsed, _ = _parse_yaml_block(lines, 0, lines[0][0])
    return parsed if isinstance(parsed, dict) else {}


def _yaml_lines(raw: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for line in raw.splitlines():
        trimmed = _strip_comment(line).rstrip()
        if not trimmed.strip():
            continue
        indent = len(trimmed) - len(trimmed.lstrip(" "))
        lines.append((indent, trimmed.strip()))
    return lines


def _strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index]
    return line


def _parse_yaml_block(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines):
        return {}, index
    if lines[index][1].startswith("- "):
        return _parse_yaml_list(lines, index, indent)
    return _parse_yaml_mapping(lines, index, indent)


def _parse_yaml_mapping(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while index < len(lines):
        line_indent, content = lines[index]
        if line_indent < indent:
            break
        if line_indent > indent or content.startswith("- "):
            break
        if ":" not in content:
            index += 1
            continue
        key, raw_value = content.split(":", 1)
        key = key.strip()
        value = raw_value.strip()
        index += 1
        if value:
            mapping[key] = _parse_scalar(value)
        elif index < len(lines) and lines[index][0] > line_indent:
            child, index = _parse_yaml_block(lines, index, lines[index][0])
            mapping[key] = child
        else:
            mapping[key] = {}
    return mapping, index


def _parse_yaml_list(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[list[Any], int]:
    values: list[Any] = []
    while index < len(lines):
        line_indent, content = lines[index]
        if line_indent < indent or not content.startswith("- "):
            break
        if line_indent > indent:
            break
        item_text = content[2:].strip()
        index += 1
        if not item_text:
            if index < len(lines) and lines[index][0] > line_indent:
                child, index = _parse_yaml_block(lines, index, lines[index][0])
                values.append(child)
            else:
                values.append(None)
            continue
        if ":" in item_text:
            key, raw_value = item_text.split(":", 1)
            item: dict[str, Any] = {}
            value = raw_value.strip()
            if value:
                item[key.strip()] = _parse_scalar(value)
            elif index < len(lines) and lines[index][0] > line_indent:
                child, index = _parse_yaml_block(lines, index, lines[index][0])
                item[key.strip()] = child
            else:
                item[key.strip()] = {}
            if index < len(lines) and lines[index][0] > line_indent:
                continuation, index = _parse_yaml_block(lines, index, lines[index][0])
                if isinstance(continuation, dict):
                    item.update(continuation)
            values.append(item)
        else:
            values.append(_parse_scalar(item_text))
    return values, index


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"", "null", "Null", "NULL", "~"}:
        return None
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if value.startswith("[") and value.endswith("]"):
        return [_parse_scalar(item) for item in _split_inline_items(value[1:-1]) if item.strip()]
    if value.startswith("{") and value.endswith("}"):
        result: dict[str, Any] = {}
        for item in _split_inline_items(value[1:-1]):
            if ":" not in item:
                continue
            key, raw_value = item.split(":", 1)
            result[_strip_quotes(key.strip())] = _parse_scalar(raw_value.strip())
        return result
    return _strip_quotes(value)


def _split_inline_items(value: str) -> list[str]:
    items: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    for char in value:
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        if char == "," and not in_single and not in_double:
            items.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        items.append("".join(current).strip())
    return items


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _contexts_from_resources(
    resources: list[KubernetesResource],
    artifacts: list[Artifact],
    *,
    infer_lateral_from_public_entry: bool,
) -> dict[str, ContextEvidence]:
    workloads = [resource for resource in resources if resource.kind in WORKLOAD_KINDS]
    services = [resource for resource in resources if resource.kind == "Service"]
    ingresses = [resource for resource in resources if resource.kind == "Ingress"]
    network_policies = [resource for resource in resources if resource.kind in NETWORK_POLICY_KINDS]
    targets_by_service = {service.name: _service_targets(service, workloads) for service in services}
    ingress_services = {ingress.name: _ingress_service_names(ingress) for ingress in ingresses}
    public_entry = _public_entry(services, ingresses, targets_by_service, ingress_services)
    grants_by_service_account = _rbac_grants(resources)

    contexts: dict[str, ContextEvidence] = {}
    for artifact in artifacts:
        match = _best_workload_match(artifact, workloads)
        if not match:
            continue
        workload = match.resource
        workload_ref = workload.address
        matched_services = [service for service in services if workload in targets_by_service.get(service.name, [])]
        matched_ingresses = [
            ingress
            for ingress in ingresses
            if any(workload in targets_by_service.get(service_name, []) for service_name in ingress_services.get(ingress.name, set()))
        ]
        exposures: list[str] = []
        evidence: list[str] = []
        for service in matched_services:
            service_type = str(_nested(service.values, "spec", "type") or "ClusterIP")
            exposure = _service_exposure(service)
            exposures.append(exposure)
            evidence.append(f"context network path: {exposure} via {service.address} {service_type} -> {workload_ref}")
        for ingress in matched_ingresses:
            exposure = _ingress_exposure(ingress)
            exposures.append(exposure)
            service_name = next(iter(ingress_services.get(ingress.name, set())), "unknown-service")
            evidence.append(f"context network path: {exposure} via {ingress.address} -> kubernetes_service.{service_name} -> {workload_ref}")
        exposure = _max_exposure(exposures)
        selected_network_policies = _network_policies_for_workload(workload, network_policies)
        if _network_policies_deny_all_ingress(selected_network_policies):
            exposure = "private"
            evidence.append(f"context network policy: private via {workload_ref}; selected NetworkPolicy resources deny all ingress")
        if exposure == "unknown":
            exposure = "private"
            evidence.append(f"context network path: private via {workload_ref}; no Service or Ingress targets this workload")
        elif infer_lateral_from_public_entry and exposure == "internal" and public_entry:
            evidence.insert(0, f"context network path: internal via {public_entry} -> {workload_ref}")
        evidence.append(f"kubernetes artifact match: {match.match.method} matched {artifact.name} to {workload_ref} via {match.target}")

        service_account = _workload_service_account(workload)
        grants = grants_by_service_account.get((workload.namespace, service_account), [])
        privilege, impacts, capabilities = _aggregate_grants(grants)
        if grants:
            evidence.extend(grant.evidence for grant in grants if grant.evidence)
        criticality = _network_iam_criticality(exposure, privilege, impacts)
        confidence = Confidence.HIGH if match.match.score >= 72 and exposures else Confidence.MEDIUM
        contexts[artifact.name] = ContextEvidence(
            environment="unknown",
            exposure=exposure,
            privilege=privilege,
            criticality=criticality,
            iam_impacts=sorted(impacts),
            iam_capabilities=capabilities,
            source="kubernetes-manifest",
            confidence=confidence,
            evidence=evidence,
        )
    return contexts


def _best_workload_match(artifact: Artifact, workloads: list[KubernetesResource]) -> WorkloadMatch | None:
    best: WorkloadMatch | None = None
    for workload in workloads:
        targets = sorted(_workload_names(workload) | _workload_images(workload))
        for target in targets:
            match = artifact_match_evidence(artifact, target)
            if match.matched and (best is None or match.score > best.match.score):
                best = WorkloadMatch(resource=workload, match=match, target=target)
    return best


def _service_targets(service: KubernetesResource, workloads: list[KubernetesResource]) -> list[KubernetesResource]:
    selector = _string_mapping(_nested(service.values, "spec", "selector"))
    if not selector:
        return [workload for workload in workloads if service.name in _workload_names(workload)]
    targets = []
    for workload in workloads:
        labels = _workload_labels(workload)
        if all(labels.get(key) == value for key, value in selector.items()):
            targets.append(workload)
    return targets


def _service_exposure(service: KubernetesResource) -> str:
    service_type = str(_nested(service.values, "spec", "type") or "ClusterIP")
    name = service.name.lower()
    if service_type in {"LoadBalancer", "NodePort"}:
        return "public"
    if service_type == "ExternalName" or "external" in name:
        return "external"
    return "internal"


def _ingress_exposure(ingress: KubernetesResource) -> str:
    annotations = _string_mapping(_nested(ingress.values, "metadata", "annotations"))
    text = json.dumps(annotations, sort_keys=True).lower()
    if "internal" in text or "private" in text:
        return "internal"
    return "public"


def _public_entry(
    services: list[KubernetesResource],
    ingresses: list[KubernetesResource],
    targets_by_service: Mapping[str, list[KubernetesResource]],
    ingress_services: Mapping[str, set[str]],
) -> str | None:
    for service in services:
        if _service_exposure(service) == "public":
            target = targets_by_service.get(service.name, [])
            suffix = f" -> {target[0].address}" if target else ""
            return f"{service.address} {str(_nested(service.values, 'spec', 'type') or 'ClusterIP')}{suffix}"
    for ingress in ingresses:
        if _ingress_exposure(ingress) != "public":
            continue
        service_name = next(iter(ingress_services.get(ingress.name, set())), None)
        suffix = f" -> kubernetes_service.{service_name}" if service_name else ""
        return f"{ingress.address}{suffix}"
    return None


def _ingress_service_names(ingress: KubernetesResource) -> set[str]:
    names: set[str] = set()
    _collect_ingress_service_names(ingress.values, names)
    return names


def _collect_ingress_service_names(value: Any, names: set[str]) -> None:
    if isinstance(value, dict):
        service = value.get("service")
        if isinstance(service, dict) and service.get("name"):
            names.add(str(service["name"]))
        if value.get("serviceName"):
            names.add(str(value["serviceName"]))
        for child in value.values():
            _collect_ingress_service_names(child, names)
    elif isinstance(value, list):
        for child in value:
            _collect_ingress_service_names(child, names)


def _workload_names(workload: KubernetesResource) -> set[str]:
    names = {workload.name}
    names.update(_workload_labels(workload).values())
    return {name for name in names if name}


def _workload_labels(workload: KubernetesResource) -> dict[str, str]:
    labels: dict[str, str] = {}
    for raw in (
        _nested(workload.values, "metadata", "labels"),
        _nested(workload.values, "spec", "selector", "matchLabels"),
        _nested(workload.values, "spec", "template", "metadata", "labels"),
        _nested(workload.values, "spec", "jobTemplate", "spec", "template", "metadata", "labels"),
    ):
        labels.update(_string_mapping(raw))
    return labels


def _workload_images(workload: KubernetesResource) -> set[str]:
    images: set[str] = set()
    _collect_key_values(workload.values, "image", images)
    return images


def _workload_service_account(workload: KubernetesResource) -> str:
    value = (
        _nested(workload.values, "spec", "template", "spec", "serviceAccountName")
        or _nested(workload.values, "spec", "serviceAccountName")
        or _nested(workload.values, "spec", "jobTemplate", "spec", "template", "spec", "serviceAccountName")
        or "default"
    )
    return str(value)


def _network_policies_for_workload(workload: KubernetesResource, policies: list[KubernetesResource]) -> list[KubernetesResource]:
    labels = _workload_labels(workload)
    selected: list[KubernetesResource] = []
    for policy in policies:
        if policy.namespace != workload.namespace:
            continue
        selector = _string_mapping(_nested(policy.values, "spec", "podSelector", "matchLabels"))
        if selector and not all(labels.get(key) == value for key, value in selector.items()):
            continue
        selected.append(policy)
    return selected


def _network_policies_deny_all_ingress(policies: list[KubernetesResource]) -> bool:
    ingress_policies = [policy for policy in policies if _network_policy_controls_ingress(policy)]
    if not ingress_policies:
        return False
    # Kubernetes NetworkPolicy ingress allows are additive. A selected deny-all
    # policy only blocks ingress completely when no selected ingress policy has
    # an explicit allow rule.
    return not any(_as_list(_nested(policy.values, "spec", "ingress")) for policy in ingress_policies)


def _network_policy_controls_ingress(policy: KubernetesResource) -> bool:
    policy_types = {str(item).lower() for item in _string_list(_nested(policy.values, "spec", "policyTypes"))}
    if policy_types:
        return "ingress" in policy_types
    return True


def _rbac_grants(resources: list[KubernetesResource]) -> dict[tuple[str, str], list[RoleGrant]]:
    role_grants: dict[tuple[str, str, str], RoleGrant] = {}
    for resource in resources:
        if resource.kind not in {"Role", "ClusterRole"}:
            continue
        key = (resource.kind, "" if resource.kind == "ClusterRole" else resource.namespace, resource.name)
        role_grants[key] = _classify_role(resource)

    grants_by_service_account: dict[tuple[str, str], list[RoleGrant]] = {}
    for binding in resources:
        if binding.kind not in {"RoleBinding", "ClusterRoleBinding"}:
            continue
        role_ref = _as_dict(binding.values.get("roleRef"))
        role_kind = str(role_ref.get("kind") or "Role")
        role_name = str(role_ref.get("name") or "")
        role_namespace = "" if role_kind == "ClusterRole" else binding.namespace
        role_grant = role_grants.get((role_kind, role_namespace, role_name), _classify_role_name(role_kind, role_name))
        grant = RoleGrant(
            privilege=role_grant.privilege,
            impacts=role_grant.impacts,
            capabilities=role_grant.capabilities,
            evidence=f"kubernetes RBAC: {role_grant.privilege} via {binding.address} -> {role_kind}.{role_name} impact={','.join(sorted(role_grant.impacts)) or 'none'}",
        )
        for namespace, name in _binding_service_accounts(binding):
            grants_by_service_account.setdefault((namespace, name), []).append(grant)
    return grants_by_service_account


def _classify_role(resource: KubernetesResource) -> RoleGrant:
    name_grant = _classify_role_name(resource.kind, resource.name)
    best = name_grant.privilege
    impacts = set(name_grant.impacts)
    capabilities = list(name_grant.capabilities)
    for rule in _as_list(resource.values.get("rules")):
        if not isinstance(rule, dict):
            continue
        verbs = {item.lower() for item in _string_list(rule.get("verbs"))}
        k8s_resources = {item.lower() for item in _string_list(rule.get("resources"))}
        if "*" in verbs or "*" in k8s_resources:
            best = max_privilege(best, "admin")
            impacts.add("admin_control")
            capabilities.append(_rbac_capability(rule, "admin_control"))
        elif k8s_resources & {"secrets"} and verbs & READ_VERBS:
            best = max_privilege(best, "sensitive")
            impacts.add("data_access")
            capabilities.append(_rbac_capability(rule, "data_access"))
        elif k8s_resources & IAM_RESOURCES and verbs & MUTATING_VERBS:
            best = max_privilege(best, "sensitive")
            impacts.add("iam_escalation")
            capabilities.append(_rbac_capability(rule, "iam_escalation"))
        elif k8s_resources & NETWORK_RESOURCES and verbs & MUTATING_VERBS:
            best = max_privilege(best, "sensitive")
            impacts.add("network_control")
            capabilities.append(_rbac_capability(rule, "network_control"))
        elif k8s_resources & COMPUTE_RESOURCES and verbs & MUTATING_VERBS:
            best = max_privilege(best, "sensitive")
            impacts.add("compute_control")
            capabilities.append(_rbac_capability(rule, "compute_control"))
        elif verbs:
            best = max_privilege(best, "limited")
            capabilities.append(_rbac_capability(rule, "limited_access"))
    return RoleGrant(privilege=best, impacts=frozenset(impacts), capabilities=tuple(dedupe_iam_capabilities(capabilities)))


def _classify_role_name(kind: str, name: str) -> RoleGrant:
    text = f"{kind}:{name}".lower()
    if "cluster-admin" in text:
        return RoleGrant(privilege="admin", impacts=frozenset({"admin_control"}), capabilities=(_named_role_capability(text, "admin_control"),))
    if text.endswith(":admin") or "admin" in text:
        return RoleGrant(privilege="sensitive", impacts=frozenset({"iam_escalation", "compute_control"}), capabilities=(_named_role_capability(text, "iam_escalation"), _named_role_capability(text, "compute_control")))
    if "edit" in text:
        return RoleGrant(privilege="sensitive", impacts=frozenset({"compute_control"}), capabilities=(_named_role_capability(text, "compute_control"),))
    if "view" in text or "read" in text:
        return RoleGrant(privilege="limited", impacts=frozenset(), capabilities=(_named_role_capability(text, "limited_access"),))
    return RoleGrant(privilege="unknown", impacts=frozenset())


def _binding_service_accounts(binding: KubernetesResource) -> set[tuple[str, str]]:
    subjects = _as_list(binding.values.get("subjects"))
    service_accounts: set[tuple[str, str]] = set()
    for subject in subjects:
        if not isinstance(subject, dict) or str(subject.get("kind") or "") != "ServiceAccount":
            continue
        name = str(subject.get("name") or "default")
        namespace = str(subject.get("namespace") or binding.namespace)
        service_accounts.add((namespace, name))
    return service_accounts


def _aggregate_grants(grants: list[RoleGrant]) -> tuple[str, set[str], list[dict[str, Any]]]:
    privilege = "unknown"
    impacts: set[str] = set()
    capabilities: list[dict[str, Any]] = []
    for grant in grants:
        privilege = max_privilege(privilege, grant.privilege)
        impacts.update(grant.impacts)
        capabilities.extend(grant.capabilities)
    return privilege, impacts, dedupe_iam_capabilities(capabilities)


def _rbac_capability(rule: Mapping[str, Any], impact: str) -> dict[str, Any]:
    verbs = _string_list(rule.get("verbs"))
    resources = _string_list(rule.get("resources"))
    return {
        "action": ",".join(verbs) or "unknown",
        "impact": impact,
        "access": _access_for_impact(impact),
        "effect": "allow",
        "resource_refs": resources,
        "evidence": f"kubernetes RBAC rule verbs={','.join(verbs) or 'unknown'} resources={','.join(resources) or 'unknown'}",
        "source": "kubernetes-rbac",
    }


def _named_role_capability(name: str, impact: str) -> dict[str, Any]:
    return {
        "action": name,
        "impact": impact,
        "access": _access_for_impact(impact),
        "effect": "allow",
        "resource_refs": [],
        "evidence": f"kubernetes RBAC role name {name}",
        "source": "kubernetes-rbac",
    }


def _access_for_impact(impact: str) -> str:
    return {
        "admin_control": "admin",
        "iam_escalation": "privilege_escalation",
        "network_control": "network_mutation",
        "compute_control": "compute_mutation",
        "data_access": "sensitive_data",
    }.get(impact, "limited")


def _network_iam_criticality(exposure: str, privilege: str, impacts: set[str]) -> str:
    critical_impacts = set(impacts)
    if privilege == "admin":
        critical_impacts.add("admin_control")
    if not critical_impacts:
        return "medium" if privilege == "sensitive" and exposure in {"public", "external", "internal"} else "unknown"
    if exposure in {"public", "external", "internal"}:
        return "high"
    if exposure == "private":
        return "medium"
    return "medium" if critical_impacts - {"admin_control"} else "unknown"


def _coverage_report(
    resources: list[KubernetesResource],
    artifacts: list[Artifact],
    contexts: Mapping[str, ContextEvidence],
    manifest_files: list[Path],
) -> dict[str, Any]:
    kind_counts: dict[str, int] = {}
    for resource in resources:
        kind_counts[resource.kind] = kind_counts.get(resource.kind, 0) + 1
    exposure_counts: dict[str, int] = {}
    privilege_counts: dict[str, int] = {}
    for context in contexts.values():
        exposure_counts[context.exposure] = exposure_counts.get(context.exposure, 0) + 1
        privilege_counts[context.privilege] = privilege_counts.get(context.privilege, 0) + 1
    requested = len(artifacts)
    matched = len(contexts)
    return {
        "schema_version": "1.0",
        "summary": {
            "manifest_files_scanned": len(manifest_files),
            "total_resources": len(resources),
            "workload_resources": sum(1 for resource in resources if resource.kind in WORKLOAD_KINDS),
            "service_resources": kind_counts.get("Service", 0),
            "ingress_resources": kind_counts.get("Ingress", 0),
            "network_policy_resources": sum(kind_counts.get(kind, 0) for kind in NETWORK_POLICY_KINDS),
            "rbac_resources": sum(kind_counts.get(kind, 0) for kind in RBAC_KINDS),
            "artifacts_requested": requested,
            "artifacts_matched": matched,
            "artifact_match_coverage": round(matched / requested, 4) if requested else 1.0,
            "contexts_generated": matched,
            "exposure_counts": dict(sorted(exposure_counts.items())),
            "privilege_counts": dict(sorted(privilege_counts.items())),
        },
        "resources": [
            {
                "path": str(resource.path),
                "document_index": resource.document_index,
                "kind": resource.kind,
                "name": resource.name,
                "namespace": resource.namespace,
                "address": resource.address,
            }
            for resource in resources
        ],
        "unmatched_artifacts": [artifact.name for artifact in artifacts if artifact.name not in contexts],
        "notes": [
            "Rendered Kubernetes manifest evidence is static and local. It does not query a live cluster.",
            "LoadBalancer, NodePort, and public Ingress objects create public exposure. ClusterIP services create internal exposure.",
            "Selected NetworkPolicy resources with no ingress allow rules override Service/Ingress exposure to private.",
            "RBAC privilege is derived from rendered Role, ClusterRole, RoleBinding, and ClusterRoleBinding objects.",
        ],
    }


def _kind_resource_type(kind: str) -> str:
    output = []
    for index, char in enumerate(kind):
        if index and char.isupper() and not kind[index - 1].isupper():
            output.append("_")
        output.append(char.lower())
    return "kubernetes_" + "".join(output)


def _max_exposure(values: list[str]) -> str:
    result = "unknown"
    for value in values:
        result = max_exposure(result, value)
    return result


def merge_context_evidence(left: ContextEvidence, right: ContextEvidence) -> ContextEvidence:
    """Merge context from multiple local evidence streams."""

    return ContextEvidence(
        environment=_prefer_known(left.environment, right.environment),
        exposure=max_exposure(left.exposure, right.exposure),
        privilege=max_privilege(left.privilege, right.privilege),
        criticality=max_criticality(left.criticality, right.criticality),
        iam_impacts=sorted({*left.iam_impacts, *right.iam_impacts}),
        iam_capabilities=dedupe_iam_capabilities([*left.iam_capabilities, *right.iam_capabilities]),
        effective_access=[*left.effective_access, *right.effective_access],
        network_paths=[*left.network_paths, *right.network_paths],
        owner=left.owner or right.owner,
        source="+".join(dict.fromkeys(part for part in [*left.source.split("+"), *right.source.split("+")] if part and part != "none")),
        confidence=max_confidence(left.confidence, right.confidence),
        evidence=[*left.evidence, *right.evidence],
    )


def merge_context_maps(target: dict[str, ContextEvidence], updates: Mapping[str, ContextEvidence]) -> dict[str, ContextEvidence]:
    for artifact_name, update in updates.items():
        if artifact_name in target:
            target[artifact_name] = merge_context_evidence(target[artifact_name], update)
        else:
            target[artifact_name] = update
    return target


def _prefer_known(left: str, right: str) -> str:
    return left if left and left != "unknown" else right


def _nested(mapping: Any, *path: str) -> Any:
    current = mapping
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items() if item is not None}


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if value is None:
        return []
    return [str(value)]


def _collect_key_values(value: Any, key: str, output: set[str]) -> None:
    if isinstance(value, dict):
        for item_key, item_value in value.items():
            if item_key == key and item_value is not None:
                output.add(str(item_value))
            else:
                _collect_key_values(item_value, key, output)
    elif isinstance(value, list):
        for item in value:
            _collect_key_values(item, key, output)


__all__ = [
    "KubernetesAnalysis",
    "KubernetesManifestError",
    "KubernetesResource",
    "analyze_kubernetes_manifests",
    "empty_kubernetes_coverage_report",
    "load_kubernetes_resources",
    "merge_context_maps",
]
