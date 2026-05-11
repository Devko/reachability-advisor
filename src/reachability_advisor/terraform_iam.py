"""Terraform IAM privilege and impact classification."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

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
class IamGrant:
    privilege: str
    impacts: tuple[str, ...] = ()
    resource_refs: tuple[str, ...] = ()
    evidence: str = ""


def privilege_for_resource(resource: TerraformIamResource) -> str:
    return iam_grant_for_resource(resource).privilege


def iam_grant_for_resource(resource: TerraformIamResource) -> IamGrant:
    values = resource.values
    rtype = resource.type
    if rtype in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}:
        privilege, impacts, resource_refs = classify_policy_details(values.get("policy"))
        return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), resource_refs=tuple(sorted(resource_refs)), evidence=_iam_grant_evidence(resource, privilege, impacts))
    if rtype == "aws_iam_role_policy_attachment":
        privilege, impacts = classify_role_text_details(values.get("policy_arn") or values.get("policy"))
        return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), evidence=_iam_grant_evidence(resource, privilege, impacts))
    if rtype == "aws_iam_role":
        if values.get("managed_policy_arns"):
            privilege, impacts = classify_role_text_details(values.get("managed_policy_arns"))
            return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), evidence=_iam_grant_evidence(resource, privilege, impacts))
        privilege, impacts, resource_refs = _embedded_policy_details(values.get("inline_policy") or values.get("inline_policies"))
        return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), resource_refs=tuple(sorted(resource_refs)), evidence=_iam_grant_evidence(resource, privilege, impacts))
    if rtype == "azurerm_role_assignment":
        privilege, impacts = classify_role_text_details(values.get("role_definition_name") or values.get("role_definition_id"))
        return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), evidence=_iam_grant_evidence(resource, privilege, impacts))
    if rtype == "azurerm_key_vault_access_policy":
        privilege, impacts = _azure_key_vault_privilege_details(values)
        return IamGrant(
            privilege=privilege,
            impacts=tuple(sorted(impacts)),
            resource_refs=tuple(sorted(value_reference_candidates(values.get("key_vault_id")))),
            evidence=_iam_grant_evidence(resource, privilege, impacts),
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
        return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), resource_refs=tuple(sorted(resource_refs)), evidence=_iam_grant_evidence(resource, privilege, impacts))
    if rtype in {"kubernetes_role_binding", "kubernetes_cluster_role_binding", "kubernetes_role_binding_v1", "kubernetes_cluster_role_binding_v1", "kubernetes_role_v1", "kubernetes_cluster_role_v1"}:
        privilege, impacts = classify_role_text_details(values.get("role_ref") or values.get("metadata"))
        return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), evidence=_iam_grant_evidence(resource, privilege, impacts))
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
    impacts = _iam_text_impacts(text)
    if any(token in text for token in ADMIN_ROLE_TOKENS):
        impacts.add("admin_control")
        return "admin", impacts
    if any(token in text for token in SENSITIVE_ROLE_TOKENS) or impacts & CRITICAL_IAM_IMPACTS:
        return "sensitive", impacts
    if "role" in text or "policy" in text or ":" in text:
        return "limited", impacts
    return "unknown", impacts


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
    "IamGrant",
    "NETWORK_PIVOT_IAM_IMPACTS",
    "classify_policy",
    "classify_policy_details",
    "classify_role_text",
    "classify_role_text_details",
    "iam_grant_for_resource",
    "privilege_for_resource",
]
