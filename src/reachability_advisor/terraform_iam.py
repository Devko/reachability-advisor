"""Terraform IAM privilege and impact classification."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from .iam_capabilities import capability_effective_risk, capability_risk_multiplier
from .terraform_values import listify, value_reference_candidates

CRITICAL_IAM_IMPACTS = {"admin_control", "iam_escalation", "network_control", "compute_control", "data_access"}
NETWORK_PIVOT_IAM_IMPACTS = {"admin_control", "iam_escalation", "network_control"}
ADMIN_ROLE_TOKENS = (
    "administratoraccess",
    "owner",
    "contributor",
    "roles/owner",
    "roles/editor",
    "roles/iam.serviceaccounttokencreator",
    "roles/iam.serviceaccountadmin",
    "roles/resourcemanager.projectiambindingadmin",
    "role_definition_id=owner",
    "cluster-admin",
)
SENSITIVE_ROLE_TOKENS = (
    "secret",
    "key vault",
    "keyvault",
    "kms",
    "decrypt",
    "sql",
    "database",
    "cloudsql",
    "bigquery",
    "storage.admin",
    "storage.objectadmin",
    "storage.objectviewer",
    "roles/secretmanager.secretaccessor",
    "roles/cloudsql.admin",
    "roles/bigquery.admin",
    "roles/storage.admin",
)
ROLE_CATALOG: dict[str, tuple[str, tuple[str, ...]]] = {
    "administratoraccess": ("admin", ("admin_control",)),
    "arn:aws:iam::aws:policy/administratoraccess": ("admin", ("admin_control",)),
    "iamfullaccess": ("sensitive", ("iam_escalation",)),
    "arn:aws:iam::aws:policy/iamfullaccess": ("sensitive", ("iam_escalation",)),
    "poweruseraccess": ("sensitive", ("compute_control", "data_access", "network_control")),
    "arn:aws:iam::aws:policy/poweruseraccess": ("sensitive", ("compute_control", "data_access", "network_control")),
    "amazonec2fullaccess": ("sensitive", ("compute_control", "network_control")),
    "amazonvpcfullaccess": ("sensitive", ("network_control",)),
    "awslambda_fullaccess": ("sensitive", ("compute_control",)),
    "amazonecs_fullaccess": ("sensitive", ("compute_control",)),
    "secretsmanagerreadwrite": ("sensitive", ("data_access",)),
    "secretsmanagerreadonly": ("sensitive", ("data_access",)),
    "readonlyaccess": ("limited", ("limited_access",)),
    "securityaudit": ("limited", ("limited_access",)),
    "owner": ("admin", ("admin_control",)),
    "role_definition_id=owner": ("admin", ("admin_control",)),
    "user access administrator": ("sensitive", ("iam_escalation",)),
    "contributor": ("admin", ("admin_control", "compute_control", "network_control")),
    "network contributor": ("sensitive", ("network_control",)),
    "virtual machine contributor": ("sensitive", ("compute_control",)),
    "key vault administrator": ("admin", ("admin_control", "data_access")),
    "key vault secrets officer": ("sensitive", ("data_access",)),
    "key vault secrets user": ("sensitive", ("data_access",)),
    "storage blob data reader": ("limited", ("limited_access",)),
    "reader": ("limited", ("limited_access",)),
    "roles/owner": ("admin", ("admin_control",)),
    "roles/editor": ("sensitive", ("compute_control", "data_access", "network_control")),
    "roles/viewer": ("limited", ("limited_access",)),
    "roles/iam.serviceaccountadmin": ("sensitive", ("iam_escalation",)),
    "roles/iam.serviceaccountuser": ("sensitive", ("iam_escalation",)),
    "roles/iam.serviceaccounttokencreator": ("sensitive", ("iam_escalation",)),
    "roles/compute.networkadmin": ("sensitive", ("network_control",)),
    "roles/run.admin": ("sensitive", ("compute_control",)),
    "roles/cloudfunctions.admin": ("sensitive", ("compute_control",)),
    "roles/container.admin": ("sensitive", ("compute_control",)),
    "roles/secretmanager.secretaccessor": ("sensitive", ("data_access",)),
    "roles/storage.objectviewer": ("limited", ("limited_access",)),
    "roles/storage.admin": ("sensitive", ("data_access",)),
}


class TerraformIamResource(Protocol):
    @property
    def address(self) -> str:
        ...

    @property
    def type(self) -> str:
        ...

    @property
    def values(self) -> dict[str, Any]:
        ...


@dataclass(frozen=True)
class IamCapability:
    action: str
    impact: str
    access: str = "unknown"
    effect: str = "allow"
    resource_refs: tuple[str, ...] = ()
    resource_scope: str = "unknown"
    condition_keys: tuple[str, ...] = ()
    evidence: str = ""
    source: str = "terraform"
    provider: str = "unknown"
    catalog: str = ""
    policy_layer: str = "identity_policy"

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "action": self.action,
            "impact": self.impact,
            "access": self.access,
            "effect": self.effect,
            "resource_refs": list(self.resource_refs),
            "resource_scope": self.resource_scope,
            "condition_keys": list(self.condition_keys),
            "evidence": self.evidence,
            "source": self.source,
            "provider": self.provider,
            "catalog": self.catalog,
            "policy_layer": self.policy_layer,
        }
        data["effective_risk"] = capability_effective_risk(data)
        data["risk_multiplier"] = capability_risk_multiplier(data)
        return data


@dataclass(frozen=True)
class IamGrant:
    privilege: str
    impacts: tuple[str, ...] = ()
    capabilities: tuple[IamCapability, ...] = ()
    resource_refs: tuple[str, ...] = ()
    evidence: str = ""


def privilege_for_resource(resource: TerraformIamResource) -> str:
    return iam_grant_for_resource(resource).privilege


def iam_grant_for_resource(resource: TerraformIamResource) -> IamGrant:
    values = resource.values
    rtype = resource.type
    if rtype in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}:
        privilege, impacts, resource_refs = classify_policy_details(values.get("policy"))
        evidence = _iam_grant_evidence(resource, privilege, impacts)
        return IamGrant(
            privilege=privilege,
            impacts=tuple(sorted(impacts)),
            capabilities=tuple(_policy_capabilities(values.get("policy"), resource, impacts, resource_refs, evidence)),
            resource_refs=tuple(sorted(resource_refs)),
            evidence=evidence,
        )
    if rtype == "aws_iam_role_policy_attachment":
        privilege, impacts = classify_role_text_details(values.get("policy_arn") or values.get("policy"))
        evidence = _iam_grant_evidence(resource, privilege, impacts)
        return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), capabilities=tuple(_role_text_capabilities(values.get("policy_arn") or values.get("policy"), resource, impacts, evidence)), evidence=evidence)
    if rtype == "aws_iam_role":
        if values.get("managed_policy_arns"):
            privilege, impacts = classify_role_text_details(values.get("managed_policy_arns"))
            evidence = _iam_grant_evidence(resource, privilege, impacts)
            return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), capabilities=tuple(_role_text_capabilities(values.get("managed_policy_arns"), resource, impacts, evidence)), evidence=evidence)
        privilege, impacts, resource_refs = _embedded_policy_details(values.get("inline_policy") or values.get("inline_policies"))
        evidence = _iam_grant_evidence(resource, privilege, impacts)
        return IamGrant(
            privilege=privilege,
            impacts=tuple(sorted(impacts)),
            capabilities=tuple(_embedded_policy_capabilities(values.get("inline_policy") or values.get("inline_policies"), resource, impacts, resource_refs, evidence)),
            resource_refs=tuple(sorted(resource_refs)),
            evidence=evidence,
        )
    if rtype == "azurerm_role_assignment":
        privilege, impacts = classify_role_text_details(values.get("role_definition_name") or values.get("role_definition_id"))
        evidence = _iam_grant_evidence(resource, privilege, impacts)
        return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), capabilities=tuple(_role_text_capabilities(values.get("role_definition_name") or values.get("role_definition_id"), resource, impacts, evidence)), evidence=evidence)
    if rtype == "azurerm_key_vault_access_policy":
        privilege, impacts = _azure_key_vault_privilege_details(values)
        refs = tuple(sorted(value_reference_candidates(values.get("key_vault_id"))))
        evidence = _iam_grant_evidence(resource, privilege, impacts)
        return IamGrant(
            privilege=privilege,
            impacts=tuple(sorted(impacts)),
            capabilities=tuple(_capability("key_vault_access_policy", impact, refs, evidence, resource.address) for impact in sorted(impacts)) or (_limited_capability("key_vault_access_policy", refs, evidence, resource.address),),
            resource_refs=refs,
            evidence=evidence,
        )
    if rtype in {
        "google_project_iam_member",
        "google_project_iam_binding",
        "google_organization_iam_member",
        "google_folder_iam_member",
        "google_billing_account_iam_member",
        "google_service_account_iam_member",
        "google_service_account_iam_binding",
        "google_kms_crypto_key_iam_member",
        "google_kms_crypto_key_iam_binding",
        "google_artifact_registry_repository_iam_member",
        "google_secret_manager_secret_iam_member",
        "google_iap_web_cloud_run_service_iam_member",
    }:
        privilege, impacts = classify_role_text_details(values.get("role"))
        resource_refs = (
            value_reference_candidates(values.get("project"))
            | value_reference_candidates(values.get("secret_id"))
            | value_reference_candidates(values.get("resource"))
            | value_reference_candidates(values.get("name"))
        )
        evidence = _iam_grant_evidence(resource, privilege, impacts)
        return IamGrant(
            privilege=privilege,
            impacts=tuple(sorted(impacts)),
            capabilities=tuple(_role_text_capabilities(values.get("role"), resource, impacts, evidence, resource_refs)),
            resource_refs=tuple(sorted(resource_refs)),
            evidence=evidence,
        )
    if rtype in {"kubernetes_role_binding", "kubernetes_cluster_role_binding", "kubernetes_role_binding_v1", "kubernetes_cluster_role_binding_v1", "kubernetes_role_v1", "kubernetes_cluster_role_v1"}:
        privilege, impacts = classify_role_text_details(values.get("role_ref") or values.get("metadata"))
        evidence = _iam_grant_evidence(resource, privilege, impacts)
        return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), capabilities=tuple(_role_text_capabilities(values.get("role_ref") or values.get("metadata"), resource, impacts, evidence)), evidence=evidence)
    return IamGrant(privilege="unknown", evidence=f"unknown IAM on {resource.address}")


def classify_policy(policy: Any) -> str:
    return classify_policy_details(policy)[0]


def classify_policy_details(policy: Any) -> tuple[str, set[str], set[str]]:
    if not policy:
        return "unknown", set(), set()
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            privilege, text_impacts = classify_role_text_details(policy)
            return privilege, text_impacts, set()
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    best = "unknown"
    impacts: set[str] = set()
    resource_refs: set[str] = set()
    for statement in statements:
        if not isinstance(statement, dict) or str(statement.get("Effect", "Allow")).lower() != "allow":
            continue
        resource_refs.update(value_reference_candidates(statement.get("Resource")))
        resource_refs.update(value_reference_candidates(statement.get("NotResource")))
        if "NotAction" in statement:
            best = _max_privilege(best, "admin")
            impacts.add("admin_control")
            continue
        actions = [str(action).lower() for action in listify(statement.get("Action"))]
        if "*" in actions or any(action.endswith(":*") for action in actions):
            best = _max_privilege(best, "admin")
            impacts.add("admin_control")
            for action in actions:
                impacts.update(_iam_action_impacts(action))
        else:
            for action in actions:
                impacts.update(_iam_action_impacts(action))
        if impacts & CRITICAL_IAM_IMPACTS and best != "admin":
            best = _max_privilege(best, "sensitive")
        elif actions:
            best = _max_privilege(best, "limited")
    return best, impacts, resource_refs


def classify_role_text(value: Any) -> str:
    return classify_role_text_details(value)[0]


def classify_role_text_details(value: Any) -> tuple[str, set[str]]:
    text = json.dumps(value, sort_keys=True).lower() if isinstance(value, (dict, list)) else str(value or "").lower()
    if not text:
        return "unknown", set()
    catalog_match = _catalog_role_match(text)
    if catalog_match:
        return catalog_match[0], set(catalog_match[1])
    impacts = _iam_text_impacts(text)
    if any(token in text for token in ADMIN_ROLE_TOKENS):
        impacts.add("admin_control")
        return "admin", impacts
    if any(token in text for token in SENSITIVE_ROLE_TOKENS) or impacts & CRITICAL_IAM_IMPACTS:
        return "sensitive", impacts
    if "role" in text or "policy" in text or ":" in text:
        return "limited", impacts
    return "unknown", impacts


def _catalog_role_match(text: str) -> tuple[str, tuple[str, ...]] | None:
    compact = text.replace("_", "").replace("-", "").replace(" ", "")
    for token, result in sorted(ROLE_CATALOG.items(), key=lambda item: len(item[0]), reverse=True):
        token_compact = token.replace("_", "").replace("-", "").replace(" ", "")
        if token in text or token_compact in compact:
            return result
    return None


def _embedded_policy_details(value: Any) -> tuple[str, set[str], set[str]]:
    best = "unknown"
    impacts: set[str] = set()
    resource_refs: set[str] = set()
    for item in listify(value):
        policy = item.get("policy") if isinstance(item, dict) else item
        privilege, policy_impacts, policy_refs = classify_policy_details(policy)
        best = _max_privilege(best, privilege)
        impacts.update(policy_impacts)
        resource_refs.update(policy_refs)
    return best, impacts, resource_refs


def _embedded_policy_capabilities(value: Any, resource: TerraformIamResource, fallback_impacts: set[str], fallback_refs: set[str], evidence: str) -> list[IamCapability]:
    capabilities: list[IamCapability] = []
    for item in listify(value):
        policy = item.get("policy") if isinstance(item, dict) else item
        capabilities.extend(_policy_capabilities(policy, resource, fallback_impacts, fallback_refs, evidence))
    return capabilities


def _policy_capabilities(policy: Any, resource: TerraformIamResource, fallback_impacts: set[str], fallback_refs: set[str], evidence: str) -> list[IamCapability]:
    if not policy:
        return []
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return _role_text_capabilities(policy, resource, fallback_impacts, evidence, fallback_refs)
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    capabilities: list[IamCapability] = []
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        effect = str(statement.get("Effect", "Allow")).lower()
        if effect not in {"allow", "deny"}:
            continue
        refs = value_reference_candidates(statement.get("Resource"))
        refs.update(value_reference_candidates(statement.get("NotResource")))
        if not refs:
            refs = set(fallback_refs)
        condition_keys = _condition_keys(statement.get("Condition"))
        resource_scope = _statement_resource_scope(statement, refs)
        if "NotAction" in statement:
            actions = [f"not:{action}" for action in _string_actions(statement.get("NotAction"))] or ["not:*"]
            impacts = {"admin_control"}
        else:
            actions = _string_actions(statement.get("Action")) or ["unknown"]
            impacts = set()
        for action in actions:
            action_impacts = impacts or _iam_action_impacts(action)
            if not action_impacts and fallback_impacts and len(actions) == 1:
                action_impacts = set(fallback_impacts)
            if not action_impacts:
                capabilities.append(_limited_capability(action, refs, evidence, resource.address, condition_keys=condition_keys, resource_scope=resource_scope, effect=effect, policy_layer=_policy_layer_for_resource(resource)))
                continue
            for impact in sorted(action_impacts):
                capabilities.append(_capability(action, impact, refs, evidence, resource.address, condition_keys=condition_keys, resource_scope=resource_scope, effect=effect, policy_layer=_policy_layer_for_resource(resource)))
    if not capabilities and fallback_impacts:
        for impact in sorted(fallback_impacts):
            capabilities.append(_capability("policy", impact, fallback_refs, evidence, resource.address, policy_layer=_policy_layer_for_resource(resource)))
    return capabilities


def _role_text_capabilities(value: Any, resource: TerraformIamResource, impacts: set[str], evidence: str, refs: set[str] | tuple[str, ...] = ()) -> list[IamCapability]:
    text = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value or "")
    action = _compact_action(text) or "role"
    if impacts:
        catalog = "provider-role-catalog" if _catalog_role_match(text.lower()) else ""
        return [_capability(action, impact, refs, evidence, resource.address, catalog=catalog, policy_layer=_policy_layer_for_resource(resource)) for impact in sorted(impacts)]
    if classify_role_text(value) in {"limited", "sensitive", "admin"}:
        return [_limited_capability(action, refs, evidence, resource.address, policy_layer=_policy_layer_for_resource(resource))]
    return []


def _string_actions(value: Any) -> list[str]:
    return [str(action).lower() for action in listify(value) if str(action).strip()]


def _capability(
    action: str,
    impact: str,
    refs: set[str] | tuple[str, ...],
    evidence: str,
    source: str,
    *,
    condition_keys: tuple[str, ...] = (),
    resource_scope: str | None = None,
    catalog: str = "",
    effect: str = "allow",
    policy_layer: str = "identity_policy",
) -> IamCapability:
    resource_refs = tuple(sorted(str(ref) for ref in refs if ref))
    return IamCapability(
        action=_compact_action(action) or "unknown",
        impact=impact,
        access=_access_for_impact(impact),
        effect=effect,
        resource_refs=resource_refs,
        resource_scope=resource_scope or _resource_scope(resource_refs),
        condition_keys=condition_keys,
        evidence=evidence,
        source=source,
        provider=_provider_from_resource_address(source),
        catalog=catalog,
        policy_layer=policy_layer,
    )


def _limited_capability(
    action: str,
    refs: set[str] | tuple[str, ...],
    evidence: str,
    source: str,
    *,
    condition_keys: tuple[str, ...] = (),
    resource_scope: str | None = None,
    effect: str = "allow",
    policy_layer: str = "identity_policy",
) -> IamCapability:
    resource_refs = tuple(sorted(str(ref) for ref in refs if ref))
    return IamCapability(
        action=_compact_action(action) or "limited",
        impact="limited_access",
        access="limited",
        effect=effect,
        resource_refs=resource_refs,
        resource_scope=resource_scope or _resource_scope(resource_refs),
        condition_keys=condition_keys,
        evidence=evidence,
        source=source,
        provider=_provider_from_resource_address(source),
        policy_layer=policy_layer,
    )


def _policy_layer_for_resource(resource: TerraformIamResource) -> str:
    rtype = resource.type
    values = resource.values
    if rtype in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_role_policy_attachment"}:
        return "identity_policy"
    if rtype == "aws_iam_role" and values.get("assume_role_policy"):
        return "trust_policy"
    if "permissions_boundary" in values:
        return "permissions_boundary"
    if "service_control_policy" in rtype or rtype.endswith("_policy_attachment") and "organizations" in str(values).lower():
        return "service_control_policy"
    if rtype in {"google_secret_manager_secret_iam_member", "google_kms_crypto_key_iam_member", "google_artifact_registry_repository_iam_member", "google_iap_web_cloud_run_service_iam_member"}:
        return "resource_policy"
    if rtype in {"kubernetes_role_binding", "kubernetes_cluster_role_binding", "kubernetes_role_binding_v1", "kubernetes_cluster_role_binding_v1", "kubernetes_role_v1", "kubernetes_cluster_role_v1"}:
        return "kubernetes_rbac"
    if rtype in {"azurerm_role_assignment", "azurerm_key_vault_access_policy"}:
        return "provider_role_assignment"
    return "identity_policy"


def _condition_keys(condition: Any) -> tuple[str, ...]:
    keys: set[str] = set()
    if isinstance(condition, dict):
        for operator, body in condition.items():
            keys.add(str(operator))
            if isinstance(body, dict):
                keys.update(str(key) for key in body)
    return tuple(sorted(keys))


def _statement_resource_scope(statement: dict[str, Any], refs: set[str] | tuple[str, ...]) -> str:
    if "NotResource" in statement:
        return "wildcard"
    return _resource_scope(tuple(str(ref) for ref in refs if ref))


def _resource_scope(resource_refs: tuple[str, ...]) -> str:
    if not resource_refs:
        return "unknown"
    if any(ref in {"*", "*:*"} or ref.lower().startswith("not:") for ref in resource_refs):
        return "wildcard"
    return "scoped"


def _provider_from_resource_address(address: str) -> str:
    if address.startswith("aws_"):
        return "aws"
    if address.startswith("azurerm_") or address.startswith("azuread_"):
        return "azure"
    if address.startswith("google_"):
        return "gcp"
    if address.startswith("kubernetes_"):
        return "kubernetes"
    return "unknown"


def _access_for_impact(impact: str) -> str:
    return {
        "admin_control": "admin",
        "iam_escalation": "privilege_escalation",
        "network_control": "network_mutation",
        "compute_control": "compute_mutation",
        "data_access": "sensitive_data",
    }.get(impact, "limited")


def _compact_action(value: str) -> str:
    text = str(value or "").strip()
    if len(text) <= 140:
        return text
    return text[:137] + "..."


def _iam_grant_evidence(resource: TerraformIamResource, privilege: str, impacts: set[str]) -> str:
    impact_text = ",".join(sorted(impacts)) if impacts else "none"
    return f"{privilege} IAM on {resource.address} impact={impact_text}"


def _iam_action_impacts(action: str) -> set[str]:
    action = action.lower()
    impacts: set[str] = set()
    if action in {"*", "*:*"}:
        impacts.add("admin_control")
        return impacts
    if _is_sensitive_action(action):
        impacts.add("data_access")
    if (action.startswith("iam:") or action.startswith("sts:")) and any(token in action for token in ("passrole", "assumerole", "attach", "putrolepolicy", "createpolicyversion", "setdefaultpolicyversion", "updateassumerolepolicy", "createaccesskey", "serviceaccount")):
        impacts.add("iam_escalation")
    if action.startswith(("ec2:", "elasticloadbalancing:", "route53:")) and any(token in action for token in ("securitygroup", "authorize", "revoke", "route", "vpc", "subnet", "transitgateway", "vpn", "peering", "networkinterface", "loadbalancer", "listener", "targetgroup", "*")):
        impacts.add("network_control")
    if action.startswith(("lambda:", "ecs:", "eks:", "ssm:", "apprunner:", "run.", "cloudfunctions.", "container.")) and any(token in action for token in ("update", "create", "run", "execute", "sendcommand", "invoke", "admin", "*")):
        impacts.add("compute_control")
    if action.startswith(("compute.firewalls", "compute.routes", "compute.networks", "compute.subnetworks", "compute.vpn", "compute.interconnect", "networkmanagement.")):
        impacts.add("network_control")
    if action.startswith(("microsoft.network/", "network.")) or "/network/" in action:
        impacts.add("network_control")
    if "serviceaccounts.actas" in action or "iam.serviceaccounts" in action:
        impacts.add("iam_escalation")
    return impacts


def _iam_text_impacts(text: str) -> set[str]:
    impacts: set[str] = set()
    if any(token in text for token in ("network contributor", "networkadmin", "compute.networkadmin", "securityadmin", "firewall", "route", "vpc", "vnet", "load balancer", "application gateway")):
        impacts.add("network_control")
    if any(token in text for token in ("user access administrator", "serviceaccounttokencreator", "serviceaccountuser", "iam.serviceaccount", "iam.serviceaccountadmin", "projectiambindingadmin", "passrole")):
        impacts.add("iam_escalation")
    if any(token in text for token in ("secret", "key vault", "keyvault", "kms", "decrypt", "sql", "database", "cloudsql", "bigquery", "storage", "s3", "dynamodb")):
        impacts.add("data_access")
    if any(token in text for token in ("run.admin", "cloudfunctions.admin", "container.admin", "lambda", "ecs", "eks", "compute.admin", "virtual machine contributor", "vm contributor")):
        impacts.add("compute_control")
    return impacts


def _is_sensitive_action(action: str) -> bool:
    sensitive_prefixes = (
        "secretsmanager:",
        "ssm:getparameter",
        "kms:decrypt",
        "rds:",
        "dynamodb:",
        "s3:getobject",
        "s3:putobject",
        "sql",
        "bigquery",
        "storage",
    )
    return any(action.startswith(prefix) or prefix in action for prefix in sensitive_prefixes)


def _azure_key_vault_privilege(values: dict[str, Any]) -> str:
    return _azure_key_vault_privilege_details(values)[0]


def _azure_key_vault_privilege_details(values: dict[str, Any]) -> tuple[str, set[str]]:
    permissions = json.dumps(values.get("secret_permissions") or values.get("key_permissions") or values.get("certificate_permissions") or [], sort_keys=True).lower()
    if any(word in permissions for word in ("all", "purge", "delete", "set")):
        return "admin", {"admin_control", "data_access"}
    if any(word in permissions for word in ("get", "list", "decrypt")):
        return "sensitive", {"data_access"}
    return "unknown", set()


def _max_privilege(left: str, right: str) -> str:
    return left if _privilege_rank(left) >= _privilege_rank(right) else right


def _privilege_rank(value: str) -> int:
    return {"unknown": 0, "none": 1, "limited": 2, "sensitive": 3, "admin": 4}.get(value, 0)


__all__ = [
    "CRITICAL_IAM_IMPACTS",
    "IamCapability",
    "IamGrant",
    "NETWORK_PIVOT_IAM_IMPACTS",
    "classify_policy",
    "classify_policy_details",
    "classify_role_text",
    "classify_role_text_details",
    "iam_grant_for_resource",
    "privilege_for_resource",
]
