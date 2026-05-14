"""Native local CSPM checks over rendered Terraform and Kubernetes evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import Confidence, ContextEvidence, SourceLocation
from .security_evidence_model import SecurityEvidenceRecord


def native_posture_records(
    terraform_coverage: dict[str, Any],
    kubernetes_coverage: dict[str, Any],
    _contexts: dict[str, ContextEvidence],
) -> list[SecurityEvidenceRecord]:
    """Emit conservative CSPM records from local IaC/rendered evidence only."""

    records: list[SecurityEvidenceRecord] = []
    records.extend(_terraform_records(terraform_coverage))
    records.extend(_kubernetes_records(kubernetes_coverage))
    # Context records already inform graph scoring. Native CSPM emits only
    # concrete IaC/resource checks to avoid duplicating every mapped workload as
    # a standalone posture finding.
    return _dedupe_records(records)


def _terraform_records(coverage: dict[str, Any]) -> list[SecurityEvidenceRecord]:
    records: list[SecurityEvidenceRecord] = []
    for row in _resource_rows(coverage):
        provider = _provider(row)
        if provider not in {"aws", "azure", "gcp", "google", "azurerm"}:
            continue
        address = _first(row, "address", "resource", "name") or "terraform-resource"
        resource_type = _first(row, "type", "resource_type") or ""
        category = _first(row, "category") or ""
        values = _dict(row.get("values"))
        network_paths = _list(row.get("network_paths"))
        effective_access = _list(row.get("effective_access"))
        if _has_public_path(network_paths) and not _has_auth_or_waf(network_paths):
            records.append(_record("RA-CSPM-PUBLIC-INGRESS-NO-BLOCKER", "Public ingress lacks auth/WAF evidence", "high", provider, address, resource_type, "network", "expected auth or WAF evidence", "public ingress without blocker evidence", "native_iac", row))
        if category == "sensitive_data" and (_has_public_path(network_paths) or _boolish(values.get("public"))):
            records.append(_record("RA-CSPM-PUBLIC-SENSITIVE-DATA", "Sensitive data resource appears publicly reachable", "critical", provider, address, resource_type, "data", "private data access", "public or externally reachable data resource", "native_iac", row))
        if _broad_access(effective_access) or _broad_policy(values):
            records.append(_record("RA-CSPM-BROAD-IAM", "Broad administrative IAM capability", "high", provider, address, resource_type, "identity", "least privilege", "broad or administrative permission", "native_iac", row))
        if _public_database(resource_type, values, network_paths):
            records.append(_record("RA-CSPM-PUBLIC-DATABASE", "Database or cache endpoint is publicly reachable", "high", provider, address, resource_type, "data", "private database endpoint", "public database/cache endpoint", "native_iac", row))
        if _explicit_encryption_disabled(values):
            records.append(_record("RA-CSPM-ENCRYPTION-DISABLED", "Encryption is explicitly disabled", "medium", provider, address, resource_type, "encryption", "encryption enabled", "encryption disabled in local evidence", "native_iac", row))
    return records


def _kubernetes_records(coverage: dict[str, Any]) -> list[SecurityEvidenceRecord]:
    records: list[SecurityEvidenceRecord] = []
    for row in _resource_rows(coverage):
        kind = (_first(row, "kind", "type", "resource_type") or "").lower()
        address = _first(row, "address", "name", "resource") or f"kubernetes-{kind or 'resource'}"
        values = _dict(row.get("values"))
        spec = _dict(values.get("spec")) or values
        if _k8s_privileged(spec):
            records.append(_record("RA-CSPM-K8S-PRIVILEGED-CONTAINER", "Kubernetes workload runs privileged or with host access", "high", "kubernetes", address, kind, "workload", "restricted pod security", "privileged, hostPath, hostPID, hostNetwork, or hostIPC", "native_iac", row))
        if _k8s_broad_rbac(kind, values):
            records.append(_record("RA-CSPM-K8S-BROAD-RBAC", "Kubernetes RBAC grants broad permissions", "high", "kubernetes", address, kind, "identity", "least-privilege RBAC", "wildcard or cluster-admin style RBAC", "native_iac", row))
        if _k8s_public_service(kind, spec) and not _has_auth_hint(row):
            records.append(_record("RA-CSPM-K8S-PUBLIC-INGRESS-NO-AUTH", "Kubernetes public ingress lacks auth hints", "high", "kubernetes", address, kind, "network", "auth or policy gate for public ingress", "public LoadBalancer/Ingress without auth hint", "native_iac", row))
        if _k8s_sensitive_env(spec):
            records.append(_record("RA-CSPM-K8S-SENSITIVE-ENV", "Kubernetes workload has sensitive environment variables", "medium", "kubernetes", address, kind, "secrets", "secret references or externalized secrets", "sensitive-looking environment variable in manifest", "native_iac", row))
    return records


def _record(
    rule_id: str,
    title: str,
    severity: str,
    provider: str,
    resource_id: str,
    resource_type: str,
    service: str,
    expected: str,
    actual: str,
    evidence_source: str,
    raw: dict[str, Any],
    *,
    artifact: str | None = None,
    exposure: str | None = None,
) -> SecurityEvidenceRecord:
    source = _source_from_row(raw)
    return SecurityEvidenceRecord(
        scanner_type="cspm",
        tool="reachability-advisor",
        rule_id=rule_id,
        weakness=title,
        severity=severity,
        confidence=Confidence.MEDIUM,
        artifact=artifact,
        component=resource_id,
        message=title,
        source=source,
        exposure=exposure,
        provider=provider,
        resource_id=resource_id,
        resource_type=resource_type,
        service=service,
        control=service,
        expected=expected,
        actual=actual,
        evidence_source=evidence_source,
        remediation=_remediation(rule_id),
        raw=raw,
        input_path=evidence_source,
    )


def _resource_rows(coverage: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _list(coverage.get("resources"))
    return [row for row in rows if isinstance(row, dict)]


def _source_from_row(row: dict[str, Any]) -> SourceLocation | None:
    path = _first(row, "path", "file", "source")
    if not path:
        return None
    try:
        line = int(_first(row, "line", "start_line") or 1)
    except ValueError:
        line = 1
    return SourceLocation(path=Path(path), line=max(1, line))


def _provider(row: dict[str, Any]) -> str:
    provider = (_first(row, "provider") or "").lower()
    resource_type = (_first(row, "type", "resource_type") or "").lower()
    if provider:
        return {"google": "gcp", "azurerm": "azure"}.get(provider, provider)
    if resource_type.startswith("aws_"):
        return "aws"
    if resource_type.startswith("azurerm_") or resource_type.startswith("microsoft."):
        return "azure"
    if resource_type.startswith("google_"):
        return "gcp"
    return "context"


def _has_public_path(paths: list[Any]) -> bool:
    return any(isinstance(path, dict) and str(path.get("exposure") or "").lower() in {"public", "external"} for path in paths)


def _has_auth_or_waf(paths: list[Any]) -> bool:
    text = " ".join(str(path).lower() for path in paths)
    return any(token in text for token in ("waf", "authorizer", "authentication", "oauth", "jwt", "auth"))


def _broad_access(records: list[Any]) -> bool:
    text = " ".join(str(record).lower() for record in records)
    return any(token in text for token in ("admin", "\"*\"", "iam_escalation", "network_control", "compute_control"))


def _broad_policy(values: dict[str, Any]) -> bool:
    text = str(values).lower()
    return any(token in text for token in ("administratoraccess", "\"action\": \"*\"", "'action': '*'", "\"actions\": [\"*\"]", "owner"))


def _public_database(resource_type: str, values: dict[str, Any], paths: list[Any]) -> bool:
    text = f"{resource_type} {values}".lower()
    return any(token in text for token in ("database", "db_instance", "rds", "sql", "redis", "cache", "cosmos")) and (_has_public_path(paths) or _boolish(values.get("publicly_accessible")) or _boolish(values.get("public_network_access_enabled")))


def _explicit_encryption_disabled(values: dict[str, Any]) -> bool:
    for key, value in values.items():
        normalized = str(key).lower()
        if "encrypt" in normalized and value is False:
            return True
    return False


def _k8s_privileged(spec: dict[str, Any]) -> bool:
    text = str(spec).lower()
    return any(token in text for token in ("'privileged': true", '"privileged": true', "hostpath", "'hostnetwork': true", '"hostnetwork": true', "'hostpid': true", '"hostpid": true', "'hostipc': true", '"hostipc": true'))


def _k8s_broad_rbac(kind: str, values: dict[str, Any]) -> bool:
    text = str(values).lower()
    return kind in {"clusterrole", "role", "clusterrolebinding", "rolebinding"} and any(token in text for token in ("cluster-admin", "'*'", '"*"'))


def _k8s_public_service(kind: str, spec: dict[str, Any]) -> bool:
    text = str(spec).lower()
    if kind == "service":
        return any(token in text for token in ("loadbalancer", "externalip", "external-ip", "externalname"))
    if kind == "ingress":
        return any(token in text for token in ("rules", "host", "ingressclass", "loadbalancer"))
    return False


def _k8s_sensitive_env(spec: dict[str, Any]) -> bool:
    text = str(spec).lower()
    return any(token in text for token in ("password", "secret", "token", "private_key", "access_key"))


def _has_auth_hint(row: dict[str, Any]) -> bool:
    text = str(row).lower()
    return any(token in text for token in ("auth", "oauth", "jwt", "iap", "nginx.ingress.kubernetes.io/auth", "networkpolicy"))


def _remediation(rule_id: str) -> str:
    return {
        "RA-CSPM-PUBLIC-INGRESS-NO-BLOCKER": "Add an authentication, WAF, firewall, or network policy control and re-render deployment evidence.",
        "RA-CSPM-PUBLIC-SENSITIVE-DATA": "Remove public access from the data resource and verify the rendered plan no longer exposes it.",
        "RA-CSPM-BROAD-IAM": "Replace broad administrative permissions with resource-scoped actions.",
        "RA-CSPM-PUBLIC-DATABASE": "Disable public database access and place the endpoint behind private networking.",
        "RA-CSPM-ENCRYPTION-DISABLED": "Enable encryption in the IaC source and regenerate the plan.",
        "RA-CSPM-K8S-PRIVILEGED-CONTAINER": "Remove privileged/host access and apply restricted pod security settings.",
        "RA-CSPM-K8S-BROAD-RBAC": "Scope Kubernetes RBAC verbs/resources to the minimum required set.",
        "RA-CSPM-K8S-PUBLIC-INGRESS-NO-AUTH": "Add ingress authentication or a network policy and re-render manifests.",
        "RA-CSPM-K8S-SENSITIVE-ENV": "Move sensitive values to secret references or external secret management.",
    }.get(rule_id, "Review the posture control, update IaC, and rerun Reachability Advisor.")


def _first(row: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (int, float)):
            return str(value)
    return None


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _boolish(value: Any) -> bool:
    return value is True or str(value).lower() in {"true", "1", "yes", "enabled", "allow", "public"}


def _dedupe_records(records: list[SecurityEvidenceRecord]) -> list[SecurityEvidenceRecord]:
    seen: set[tuple[str, str]] = set()
    deduped: list[SecurityEvidenceRecord] = []
    for record in records:
        key = (record.rule_id, record.resource_id or record.component or "")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return deduped


__all__ = ["native_posture_records"]
