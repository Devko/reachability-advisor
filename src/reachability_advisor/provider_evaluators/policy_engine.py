"""Structured provider policy evaluation for effective IAM access records."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

PolicyRecord = dict[str, Any]


@dataclass(frozen=True)
class PolicyConditionAst:
    operator: str
    key: str
    values: tuple[str, ...]
    raw: Any


@dataclass(frozen=True)
class PolicyStatementAst:
    provider: str
    layer: str
    effect: str
    actions: tuple[str, ...]
    not_actions: tuple[str, ...]
    resources: tuple[str, ...]
    not_resources: tuple[str, ...]
    principals: tuple[str, ...]
    not_principals: tuple[str, ...]
    conditions: tuple[PolicyConditionAst, ...]
    raw: PolicyRecord


@dataclass(frozen=True)
class PolicyRequest:
    provider: str
    principal: str
    action: str
    resource: str
    context: PolicyRecord


@dataclass(frozen=True)
class StatementMatch:
    statement: PolicyStatementAst
    matched: bool
    action_matched: bool
    resource_matched: bool
    principal_matched: bool
    condition_state: str
    condition_keys: tuple[str, ...]
    condition_blockers: tuple[PolicyRecord, ...]
    unknowns: tuple[str, ...]

AZURE_ROLE_ACTION_HINTS: dict[str, list[str]] = {
    "owner": ["*"],
    "contributor": ["*"],
    "user access administrator": ["Microsoft.Authorization/*"],
    "network contributor": ["Microsoft.Network/*"],
    "key vault administrator": ["Microsoft.KeyVault/*"],
    "key vault secrets officer": ["Microsoft.KeyVault/vaults/secrets/*"],
    "key vault secrets user": ["Microsoft.KeyVault/vaults/secrets/*", "Microsoft.KeyVault/vaults/secrets/read"],
    "storage blob data contributor": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"],
    "storage blob data reader": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
    "reader": ["*/read"],
}

GCP_ROLE_PERMISSION_HINTS: dict[str, list[str]] = {
    "roles/owner": ["*"],
    "roles/editor": ["*"],
    "roles/viewer": ["*.get", "*.list"],
    "roles/secretmanager.secretaccessor": ["secretmanager.versions.access", "secretmanager.secrets.get"],
    "roles/iam.serviceaccountuser": ["iam.serviceAccounts.actAs"],
    "roles/iam.serviceaccounttokencreator": ["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signJwt", "iamcredentials.*"],
    "roles/iam.serviceaccountadmin": ["iam.serviceAccounts.*"],
    "roles/compute.networkadmin": ["compute.*"],
    "roles/run.admin": ["run.*"],
    "roles/cloudfunctions.admin": ["cloudfunctions.*"],
    "roles/container.admin": ["container.*"],
    "roles/storage.objectviewer": ["storage.objects.get", "storage.objects.list"],
    "roles/storage.admin": ["storage.*"],
}


def evaluate_aws_policy_records(records: list[PolicyRecord]) -> list[PolicyRecord]:
    return [_evaluate_policy_record(record, "aws", _aws_documents, _evaluate_aws) for record in records]


def evaluate_azure_policy_records(records: list[PolicyRecord]) -> list[PolicyRecord]:
    return [_evaluate_policy_record(record, "azure", _azure_documents, _evaluate_azure) for record in records]


def evaluate_gcp_policy_records(records: list[PolicyRecord]) -> list[PolicyRecord]:
    return [_evaluate_policy_record(record, "gcp", _gcp_documents, _evaluate_gcp) for record in records]


def evaluate_kubernetes_policy_records(records: list[PolicyRecord]) -> list[PolicyRecord]:
    return [_evaluate_policy_record(record, "kubernetes", _kubernetes_documents, _evaluate_kubernetes) for record in records]


def _evaluate_policy_record(
    record: PolicyRecord,
    provider: str,
    document_loader: Callable[[PolicyRecord], list[PolicyRecord]],
    evaluator: Callable[[PolicyRecord, list[PolicyRecord]], PolicyRecord],
) -> PolicyRecord:
    documents = document_loader(record)
    if not documents:
        return record
    evaluation = evaluator(record, documents)
    enriched = dict(record)
    enriched["policy_evaluation"] = evaluation
    enriched["decision"] = evaluation["decision"]
    enriched["decision_basis"] = evaluation["decision_basis"]
    enriched["effect"] = "deny" if evaluation["decision"].startswith("denied") else "allow"
    enriched["confidence"] = _stronger_confidence(str(record.get("confidence") or "low"), str(evaluation.get("confidence") or "low"))
    enriched["blockers"] = _dedupe_objects([*_objects(record.get("blockers")), *_objects(evaluation.get("blockers"))])
    enriched["unknowns"] = _dedupe_strings([*_strings(record.get("unknowns")), *_strings(evaluation.get("unknowns"))])
    enriched.setdefault("provider", provider)
    if evaluation.get("policy_layer"):
        enriched["policy_layer"] = evaluation["policy_layer"]
    if evaluation.get("resource_scope"):
        enriched["resource_scope"] = evaluation["resource_scope"]
    if evaluation.get("condition_keys"):
        existing = _strings(record.get("condition_keys"))
        enriched["condition_keys"] = _dedupe_strings([*existing, *_strings(evaluation.get("condition_keys"))])
    return enriched


def _aws_documents(record: PolicyRecord) -> list[PolicyRecord]:
    return _documents_from_keys(
        record,
        {
            "identity_policy": "identity_policy",
            "identity_policies": "identity_policy",
            "resource_policy": "resource_policy",
            "resource_policies": "resource_policy",
            "permissions_boundary": "permissions_boundary",
            "permission_boundary": "permissions_boundary",
            "service_control_policy": "service_control_policy",
            "service_control_policies": "service_control_policy",
            "session_policy": "session_policy",
            "session_policies": "session_policy",
            "trust_policy": "trust_policy",
            "trust_policies": "trust_policy",
            "policy_document": str(record.get("policy_layer") or "identity_policy"),
            "policy_documents": str(record.get("policy_layer") or "identity_policy"),
        },
    )


def _azure_documents(record: PolicyRecord) -> list[PolicyRecord]:
    return _documents_from_keys(
        record,
        {
            "deny_assignment": "deny_assignment",
            "deny_assignments": "deny_assignment",
            "role_assignment": "role_assignment",
            "role_assignments": "role_assignment",
            "role_definition": "role_definition",
            "role_definitions": "role_definition",
            "resource_policy": "resource_policy",
            "resource_policies": "resource_policy",
            "policy_document": str(record.get("policy_layer") or "role_assignment"),
            "policy_documents": str(record.get("policy_layer") or "role_assignment"),
        },
    )


def _gcp_documents(record: PolicyRecord) -> list[PolicyRecord]:
    return _documents_from_keys(
        record,
        {
            "deny_policy": "deny_policy",
            "deny_policies": "deny_policy",
            "iam_policy": "iam_policy",
            "iam_policies": "iam_policy",
            "resource_policy": "resource_policy",
            "resource_policies": "resource_policy",
            "principal_access_boundary": "principal_access_boundary",
            "principal_access_boundaries": "principal_access_boundary",
            "organization_policy": "organization_policy",
            "organization_policies": "organization_policy",
            "policy_document": str(record.get("policy_layer") or "iam_policy"),
            "policy_documents": str(record.get("policy_layer") or "iam_policy"),
        },
    )


def _kubernetes_documents(record: PolicyRecord) -> list[PolicyRecord]:
    return _documents_from_keys(
        record,
        {
            "rules": "kubernetes_rbac",
            "role": "role",
            "roles": "role",
            "cluster_role": "cluster_role",
            "cluster_roles": "cluster_role",
            "role_binding": "role_binding",
            "role_bindings": "role_binding",
            "cluster_role_binding": "cluster_role_binding",
            "cluster_role_bindings": "cluster_role_binding",
            "policy_document": str(record.get("policy_layer") or "kubernetes_rbac"),
            "policy_documents": str(record.get("policy_layer") or "kubernetes_rbac"),
        },
    )


def _documents_from_keys(record: PolicyRecord, keys: dict[str, str]) -> list[PolicyRecord]:
    documents: list[PolicyRecord] = []
    for key, default_layer in keys.items():
        if key not in record:
            continue
        for item in _listify(record.get(key)):
            document = _parse_document(item)
            if document is None:
                continue
            if isinstance(document, list):
                layer = default_layer
                payload: Any = document
            else:
                layer = str(document.get("layer") or document.get("policy_layer") or default_layer)
                payload = document.get("document") if isinstance(document.get("document"), (dict, list)) else document
            documents.append({"layer": layer, "document": payload, "source_key": key})
    return documents


def _parse_document(value: Any) -> PolicyRecord | list[Any] | None:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"text": value}
        if isinstance(parsed, (dict, list)):
            return parsed
    return None


def _evaluate_aws(record: PolicyRecord, documents: list[PolicyRecord]) -> PolicyRecord:
    action = _action(record)
    resource = _resource(record)
    request = _policy_request(record, "aws", action, resource)
    order: list[dict[str, str]] = []
    matched: list[PolicyRecord] = []
    blockers: list[PolicyRecord] = []
    unknowns: list[str] = []
    conditions: list[str] = []
    allow_layers: set[str] = set()
    explicit_denies: set[str] = set()
    docs_by_layer = _documents_by_layer(documents)

    for layer, docs in docs_by_layer.items():
        layer_matched = False
        layer_allowed = False
        layer_conditional = False
        for statement in _aws_statement_asts(layer, docs):
            statement_match = _evaluate_statement(statement, request)
            if not statement_match.matched:
                continue
            layer_matched = True
            matched.append(_statement_match_from_ast(statement_match))
            conditions.extend(statement_match.condition_keys)
            blockers.extend(statement_match.condition_blockers)
            unknowns.extend(statement_match.unknowns)
            layer_conditional = layer_conditional or statement_match.condition_state == "constrained"
            effect = statement.effect
            if effect == "deny":
                if statement_match.condition_state == "constrained":
                    blockers.append(_blocker("conditional_explicit_deny", "constrains", "aws", f"{layer} conditional deny could apply to {action}"))
                else:
                    explicit_denies.add(layer)
                    blockers.append(_blocker(_aws_deny_kind(layer), "blocks", "aws", f"{layer} denies {action}"))
            else:
                layer_allowed = True
                allow_layers.add(layer)
        order.append(
            {
                "step": layer,
                "state": "deny"
                if layer in explicit_denies
                else "conditional_allow"
                if layer_allowed and layer_conditional
                else "allow"
                if layer_allowed
                else "not_matched"
                if not layer_matched
                else "matched",
            }
        )

    intersection_layers = {
        "permissions_boundary": "permission_boundary",
        "service_control_policy": "scp_deny",
        "session_policy": "session_policy",
    }
    for layer, blocker_kind in intersection_layers.items():
        if layer in docs_by_layer and layer not in allow_layers and layer not in explicit_denies:
            blockers.append(_blocker(blocker_kind, "blocks", "aws", f"{layer} has no matching allow for {action}"))
            explicit_denies.add(layer)

    if "trust_policy" in docs_by_layer and action in {"sts:assumerole", "sts:*", "*"} and "trust_policy" not in allow_layers and "trust_policy" not in explicit_denies:
        blockers.append(_blocker("trust_policy_deny", "blocks", "aws", f"trust policy does not allow {action}"))
        explicit_denies.add("trust_policy")

    granting_layers = {"identity_policy", "resource_policy", "trust_policy"} & set(docs_by_layer)
    if granting_layers and not (allow_layers & granting_layers) and not explicit_denies:
        blockers.append(_blocker("implicit_deny", "blocks", "aws", f"no identity/resource/trust policy allows {action}"))
        explicit_denies.add("implicit_deny")

    decision = "denied" if explicit_denies else "constrained_allow" if conditions else "allowed"
    return _evaluation_result(
        provider="aws",
        decision=decision,
        basis=_basis("policy_engine", decision, sorted(explicit_denies) or sorted(allow_layers)),
        policy_layer=_strongest_layer(sorted(explicit_denies) or sorted(allow_layers) or list(docs_by_layer)),
        blockers=blockers,
        unknowns=unknowns,
        matched=matched,
        order=order,
        conditions=conditions,
        resource_scope=_scope_from_resource(resource),
    )


def _evaluate_azure(record: PolicyRecord, documents: list[PolicyRecord]) -> PolicyRecord:
    action = _action(record)
    resource = _resource(record)
    request = _policy_request(record, "azure", action, resource)
    order: list[dict[str, str]] = []
    matched: list[PolicyRecord] = []
    blockers: list[PolicyRecord] = []
    unknowns: list[str] = []
    conditions: list[str] = []
    allow_layers: set[str] = set()
    deny_layers: set[str] = set()
    docs_by_layer = _documents_by_layer(documents)

    for layer, docs in docs_by_layer.items():
        layer_allowed = False
        layer_denied = False
        layer_conditional = False
        for statement in _azure_statement_asts(layer, docs):
            statement_match = _evaluate_statement(statement, request)
            if not statement_match.matched:
                continue
            matched.append(_statement_match_from_ast(statement_match))
            conditions.extend(statement_match.condition_keys)
            blockers.extend(statement_match.condition_blockers)
            unknowns.extend(statement_match.unknowns)
            layer_conditional = layer_conditional or statement_match.condition_state == "constrained"
            if layer == "deny_assignment" or statement.effect == "deny":
                if statement_match.condition_state == "constrained":
                    blockers.append(_blocker("conditional_deny_assignment", "constrains", "azure", f"{layer} conditional deny could apply to {action}"))
                else:
                    layer_denied = True
                    deny_layers.add(layer)
                    blockers.append(_blocker("deny_assignment" if layer == "deny_assignment" else "resource_policy_deny", "blocks", "azure", f"{layer} denies {action}"))
            else:
                layer_allowed = True
                allow_layers.add(layer)
        if _layer_has_pim(docs):
            blockers.append(_blocker("pim_eligible_only", "constrains", "azure", "PIM activation is required before access is effective"))
            conditions.append("pim_activation")
        order.append({"step": layer, "state": "deny" if layer_denied else "conditional_allow" if layer_allowed and layer_conditional else "allow" if layer_allowed else "not_matched"})

    if {"role_assignment", "role_definition", "resource_policy"} & set(docs_by_layer) and not allow_layers and not deny_layers:
        deny_layers.add("implicit_deny")
        blockers.append(_blocker("role_assignment_missing_allow", "blocks", "azure", f"no role assignment or resource policy allows {action}"))

    for scope_kind in _azure_scope_blockers(resource, documents):
        blockers.append(_blocker(scope_kind, "constrains", "azure", f"Azure scope constraint: {scope_kind}"))

    decision = "denied" if deny_layers else "constrained_allow" if blockers else "allowed"
    return _evaluation_result(
        provider="azure",
        decision=decision,
        basis=_basis("policy_engine", decision, sorted(deny_layers) or sorted(allow_layers)),
        policy_layer=_strongest_layer(sorted(deny_layers) or sorted(allow_layers) or list(docs_by_layer)),
        blockers=blockers,
        unknowns=unknowns,
        matched=matched,
        order=order,
        conditions=conditions,
        resource_scope=_scope_from_resource(resource),
    )


def _evaluate_gcp(record: PolicyRecord, documents: list[PolicyRecord]) -> PolicyRecord:
    action = _action(record)
    resource = _resource(record)
    request = _policy_request(record, "gcp", action, resource)
    order: list[dict[str, str]] = []
    matched: list[PolicyRecord] = []
    blockers: list[PolicyRecord] = []
    unknowns: list[str] = []
    conditions: list[str] = []
    allow_layers: set[str] = set()
    deny_layers: set[str] = set()
    docs_by_layer = _documents_by_layer(documents)

    for layer, docs in docs_by_layer.items():
        layer_allowed = False
        layer_denied = False
        layer_conditional = False
        for statement in _gcp_statement_asts(layer, docs):
            statement_match = _evaluate_statement(statement, request)
            if not statement_match.matched:
                continue
            matched.append(_statement_match_from_ast(statement_match))
            conditions.extend(statement_match.condition_keys)
            blockers.extend(statement_match.condition_blockers)
            unknowns.extend(statement_match.unknowns)
            layer_conditional = layer_conditional or statement_match.condition_state == "constrained"
            if layer in {"deny_policy", "organization_policy"} or statement.effect == "deny":
                if statement_match.condition_state == "constrained":
                    blockers.append(_blocker("conditional_deny_policy", "constrains", "gcp", f"{layer} conditional deny could apply to {action}"))
                else:
                    layer_denied = True
                    deny_layers.add(layer)
                    blockers.append(_blocker(_gcp_deny_kind(layer), "blocks", "gcp", f"{layer} denies {action}"))
            else:
                layer_allowed = True
                allow_layers.add(layer)
        if layer == "principal_access_boundary" and layer not in allow_layers and layer not in deny_layers:
            layer_denied = True
            deny_layers.add(layer)
            blockers.append(_blocker("principal_access_boundary_deny", "blocks", "gcp", f"principal access boundary has no matching allow for {action}"))
        order.append({"step": layer, "state": "deny" if layer_denied else "conditional_allow" if layer_allowed and layer_conditional else "allow" if layer_allowed else "not_matched"})

    if {"iam_policy", "resource_policy"} & set(docs_by_layer) and not allow_layers and not deny_layers:
        deny_layers.add("implicit_deny")
        blockers.append(_blocker("implicit_deny", "blocks", "gcp", f"no IAM binding allows {action}"))

    if _gcp_workload_identity(record, documents):
        blockers.append(_blocker("workload_identity_condition", "constrains", "gcp", "Workload Identity mapping participates in access"))
    if "serviceaccounts.actas" in action or "iamcredentials." in action:
        blockers.append(_blocker("service_account_impersonation", "constrains", "gcp", f"{action} can impersonate or mint service account credentials"))
    for scope_kind in _gcp_scope_blockers(resource, documents):
        blockers.append(_blocker(scope_kind, "constrains", "gcp", f"GCP scope constraint: {scope_kind}"))

    decision = "denied" if deny_layers else "constrained_allow" if blockers else "allowed"
    return _evaluation_result(
        provider="gcp",
        decision=decision,
        basis=_basis("policy_engine", decision, sorted(deny_layers) or sorted(allow_layers)),
        policy_layer=_strongest_layer(sorted(deny_layers) or sorted(allow_layers) or list(docs_by_layer)),
        blockers=blockers,
        unknowns=unknowns,
        matched=matched,
        order=order,
        conditions=conditions,
        resource_scope=_scope_from_resource(resource),
    )


def _evaluate_kubernetes(record: PolicyRecord, documents: list[PolicyRecord]) -> PolicyRecord:
    action = _action(record)
    verb, resource = _kubernetes_action_parts(action, _resource(record))
    request = _policy_request(record, "kubernetes", verb, resource)
    order: list[dict[str, str]] = []
    matched: list[PolicyRecord] = []
    blockers: list[PolicyRecord] = []
    unknowns: list[str] = []
    conditions: list[str] = []
    allow_layers: set[str] = set()
    deny_layers: set[str] = set()
    docs_by_layer = _documents_by_layer(documents)

    for layer, docs in docs_by_layer.items():
        layer_allowed = False
        layer_denied = False
        layer_conditional = False
        for rule in _kubernetes_statement_asts(layer, docs):
            statement_match = _evaluate_statement(rule, request)
            if not statement_match.matched:
                continue
            matched.append(_statement_match_from_ast(statement_match))
            conditions.extend(statement_match.condition_keys)
            blockers.extend(statement_match.condition_blockers)
            unknowns.extend(statement_match.unknowns)
            layer_conditional = layer_conditional or statement_match.condition_state == "constrained"
            if bool(rule.raw.get("deny")) or rule.effect == "deny":
                if statement_match.condition_state == "constrained":
                    blockers.append(_blocker("conditional_rbac_deny", "constrains", "kubernetes", f"{layer} conditional deny could apply to {verb} {resource}"))
                else:
                    layer_denied = True
                    deny_layers.add(layer)
                    blockers.append(_blocker("rbac_deny", "blocks", "kubernetes", f"{layer} denies {verb} {resource}"))
            else:
                layer_allowed = True
                allow_layers.add(layer)
            if rule.raw.get("resourceNames") or rule.raw.get("resource_names"):
                blockers.append(_blocker("rbac_resource_names", "constrains", "kubernetes", "RBAC rule is scoped to resourceNames"))
            if rule.raw.get("nonResourceURLs") or rule.raw.get("non_resource_urls"):
                blockers.append(_blocker("non_resource_url_scope", "constrains", "kubernetes", "RBAC rule is scoped to non-resource URLs"))
        if _layer_has_aggregation_rule(docs):
            blockers.append(_blocker("aggregation_rule_scope", "constrains", "kubernetes", "ClusterRole aggregation affects effective permissions"))
        order.append({"step": layer, "state": "deny" if layer_denied else "conditional_allow" if layer_allowed and layer_conditional else "allow" if layer_allowed else "not_matched"})

    if docs_by_layer and not allow_layers and not deny_layers:
        deny_layers.add("implicit_deny")
        blockers.append(_blocker("rbac_deny", "blocks", "kubernetes", f"no RBAC rule allows {verb} {resource}"))
    for risky in sorted(set(_kubernetes_privilege_escalation_verbs(verb, resource))):
        blockers.append(_blocker("privilege_escalation_verb", "constrains", "kubernetes", f"RBAC grants high-risk verb {risky}"))
    for scope_kind in _kubernetes_scope_blockers(record, documents):
        blockers.append(_blocker(scope_kind, "constrains", "kubernetes", f"Kubernetes scope constraint: {scope_kind}"))

    decision = "denied" if deny_layers else "constrained_allow" if blockers else "allowed"
    return _evaluation_result(
        provider="kubernetes",
        decision=decision,
        basis=_basis("policy_engine", decision, sorted(deny_layers) or sorted(allow_layers)),
        policy_layer=_strongest_layer(sorted(deny_layers) or sorted(allow_layers) or list(docs_by_layer)),
        blockers=blockers,
        unknowns=unknowns,
        matched=matched,
        order=order,
        conditions=conditions,
        resource_scope=str(record.get("resource_scope") or _scope_from_resource(resource)),
    )


def _policy_statements(documents: list[PolicyRecord]) -> list[PolicyRecord]:
    statements: list[PolicyRecord] = []
    for document in documents:
        payload = document.get("document", document)
        if isinstance(payload, list):
            statements.extend(dict(item) for item in payload if isinstance(item, dict))
            continue
        if not isinstance(payload, dict):
            continue
        raw = payload.get("Statement") or payload.get("statement") or payload.get("statements") or payload.get("rules") or payload.get("permissions")
        if raw is None and any(
            key in payload
            for key in (
                "Action",
                "actions",
                "dataActions",
                "denyActions",
                "includedPermissions",
                "deniedPermissions",
                "permissions",
                "verbs",
                "Effect",
                "effect",
            )
        ):
            raw = payload
        for item in _listify(raw):
            if isinstance(item, dict):
                statements.append(dict(item))
    return statements


def _azure_statements(layer: str, documents: list[PolicyRecord]) -> list[PolicyRecord]:
    statements: list[PolicyRecord] = []
    for document in documents:
        payload = document.get("document", document)
        if not isinstance(payload, dict):
            continue
        role_name = _first_string(payload, ("roleName", "role_name", "roleDefinitionName", "role_definition_name", "role", "name"))
        role_actions = _azure_role_actions(role_name)
        if role_actions:
            statements.append(
                {
                    "actions": role_actions,
                    "scope": payload.get("scope") or payload.get("assignableScopes") or payload.get("assignable_scopes"),
                    "condition": payload.get("condition"),
                    "role": role_name,
                    "principalId": payload.get("principalId") or payload.get("principal_id") or payload.get("principal"),
                }
            )
    for statement in _policy_statements(documents):
        if "permissions" in statement and isinstance(statement["permissions"], list):
            for permission in statement["permissions"]:
                if isinstance(permission, dict):
                    merged = dict(permission)
                    merged.setdefault("scope", statement.get("scope"))
                    merged.setdefault("condition", statement.get("condition"))
                    merged.setdefault("principalId", statement.get("principalId") or statement.get("principal_id") or statement.get("principal"))
                    statements.append(merged)
        else:
            statements.append(statement)
    if layer == "deny_assignment":
        for statement in statements:
            statement.setdefault("Effect", "Deny")
    return statements


def _gcp_statements(layer: str, documents: list[PolicyRecord]) -> list[PolicyRecord]:
    statements: list[PolicyRecord] = []
    for document in documents:
        payload = document.get("document", document)
        for binding in _listify(payload.get("bindings") if isinstance(payload, dict) else None):
            if isinstance(binding, dict):
                statement = dict(binding)
                role_permissions = _gcp_role_permissions(_first_string(statement, ("role", "name")))
                if role_permissions and not _first_patterns(statement, ("permissions", "includedPermissions", "deniedPermissions", "permission")):
                    statement["permissions"] = role_permissions
                statements.append(statement)
        for rule in _listify(payload.get("rules") if isinstance(payload, dict) else None):
            if isinstance(rule, dict):
                statements.append(dict(rule))
        if isinstance(payload, dict):
            role_permissions = _gcp_role_permissions(_first_string(payload, ("role", "name")))
            if role_permissions:
                statements.append(
                    {
                        "permissions": role_permissions,
                        "resources": payload.get("resources") or payload.get("resource"),
                        "condition": payload.get("condition"),
                        "role": payload.get("role") or payload.get("name"),
                    }
                )
        statements.extend(_policy_statements([document]))
    if layer in {"deny_policy", "organization_policy"}:
        for statement in statements:
            statement.setdefault("Effect", "Deny")
    return statements


def _kubernetes_rules(documents: list[PolicyRecord]) -> list[PolicyRecord]:
    rules: list[PolicyRecord] = []
    for document in documents:
        payload = document.get("document", document)
        subjects = _principal_patterns(payload, ("subjects", "subject", "users", "groups", "serviceAccounts", "service_accounts")) if isinstance(payload, dict) else []
        if isinstance(payload, list):
            rules.extend(dict(item) for item in payload if isinstance(item, dict))
            continue
        if not isinstance(payload, dict):
            continue
        for rule in _listify(payload.get("rules") or payload.get("rule") or payload):
            if isinstance(rule, dict):
                merged = dict(rule)
                if subjects and not any(key in merged for key in ("subjects", "subject", "users", "groups", "serviceAccounts", "service_accounts")):
                    merged["subjects"] = subjects
                rules.append(merged)
    return rules


def _policy_request(record: PolicyRecord, provider: str, action: str, resource: str) -> PolicyRequest:
    return PolicyRequest(
        provider=provider,
        principal=_principal(record),
        action=action,
        resource=resource,
        context=_request_context(record, provider, action, resource),
    )


def _statement_asts(
    provider: str,
    layer: str,
    statements: list[PolicyRecord],
    *,
    action_keys: tuple[str, ...],
    not_action_keys: tuple[str, ...],
    resource_keys: tuple[str, ...],
    not_resource_keys: tuple[str, ...],
) -> list[PolicyStatementAst]:
    return [
        PolicyStatementAst(
            provider=provider,
            layer=layer,
            effect=_effect(statement),
            actions=tuple(_first_patterns(statement, action_keys)),
            not_actions=tuple(_first_patterns(statement, not_action_keys)),
            resources=tuple(_first_patterns(statement, resource_keys)),
            not_resources=tuple(_first_patterns(statement, not_resource_keys)),
            principals=tuple(_principal_patterns(statement, _principal_keys(provider))),
            not_principals=tuple(_principal_patterns(statement, _not_principal_keys(provider))),
            conditions=tuple(_condition_asts(statement)),
            raw=statement,
        )
        for statement in statements
    ]


def _aws_statement_asts(layer: str, documents: list[PolicyRecord]) -> list[PolicyStatementAst]:
    return _statement_asts(
        "aws",
        layer,
        _policy_statements(documents),
        action_keys=("Action", "action", "actions"),
        not_action_keys=("NotAction", "not_actions"),
        resource_keys=("Resource", "resource", "resources"),
        not_resource_keys=("NotResource", "not_resources"),
    )


def _azure_statement_asts(layer: str, documents: list[PolicyRecord]) -> list[PolicyStatementAst]:
    return _statement_asts(
        "azure",
        layer,
        _azure_statements(layer, documents),
        action_keys=("actions", "Actions", "dataActions", "DataActions", "denyActions", "notActions"),
        not_action_keys=("notActions", "NotActions", "notDataActions", "NotDataActions", "excludeActions"),
        resource_keys=("scope", "scopes", "resource", "resources", "assignableScopes", "assignable_scopes"),
        not_resource_keys=("notScopes", "excludedScopes"),
    )


def _gcp_statement_asts(layer: str, documents: list[PolicyRecord]) -> list[PolicyStatementAst]:
    return _statement_asts(
        "gcp",
        layer,
        _gcp_statements(layer, documents),
        action_keys=("permissions", "includedPermissions", "deniedPermissions", "permission", "role"),
        not_action_keys=("exceptionPermissions", "excludedPermissions"),
        resource_keys=("resources", "resource", "scope", "projects", "folders", "organizations"),
        not_resource_keys=("excludedResources", "exceptionResources"),
    )


def _kubernetes_statement_asts(layer: str, documents: list[PolicyRecord]) -> list[PolicyStatementAst]:
    return _statement_asts(
        "kubernetes",
        layer,
        _kubernetes_rules(documents),
        action_keys=("verbs", "verb"),
        not_action_keys=("notVerbs", "not_verbs"),
        resource_keys=("resources", "resource", "nonResourceURLs", "non_resource_urls"),
        not_resource_keys=("notResources", "not_resources"),
    )


def _evaluate_statement(statement: PolicyStatementAst, request: PolicyRequest) -> StatementMatch:
    action_matched = _pattern_set_applies(statement.actions, statement.not_actions, request.action)
    resource_matched = _resource_pattern_set_applies(statement, request)
    principal_matched = _pattern_set_applies(statement.principals, statement.not_principals, request.principal, default_when_empty=True)
    condition_state, condition_blockers, unknowns = _conditions_apply(statement, request)
    matched = action_matched and resource_matched and principal_matched and condition_state != "not_satisfied"
    return StatementMatch(
        statement=statement,
        matched=matched,
        action_matched=action_matched,
        resource_matched=resource_matched,
        principal_matched=principal_matched,
        condition_state=condition_state,
        condition_keys=tuple(_condition_ast_keys(statement.conditions)),
        condition_blockers=tuple(condition_blockers),
        unknowns=tuple(unknowns),
    )


def _first_patterns(statement: PolicyRecord, keys: tuple[str, ...]) -> list[str]:
    for key in keys:
        if key in statement:
            return _strings_from_any(statement.get(key))
    return []


def _principal_keys(provider: str) -> tuple[str, ...]:
    common = ("Principal", "principal", "principals", "member", "members", "principalId", "principal_id", "identity")
    if provider == "kubernetes":
        return (*common, "subjects", "subject", "users", "groups", "serviceAccounts", "service_accounts")
    if provider == "aws":
        return (*common, "AWS", "Service", "Federated")
    return common


def _not_principal_keys(provider: str) -> tuple[str, ...]:
    if provider == "aws":
        return ("NotPrincipal", "not_principal", "notPrincipals", "not_principals")
    return ("notPrincipal", "not_principal", "notPrincipals", "not_principals", "excludedPrincipals", "excluded_principals")


def _principal_patterns(statement: Any, keys: tuple[str, ...]) -> list[str]:
    patterns: list[str] = []
    if not isinstance(statement, dict):
        return patterns
    for key in keys:
        if key not in statement:
            continue
        patterns.extend(_principal_values(statement.get(key)))
    return _dedupe_strings([pattern.lower() for pattern in patterns])


def _principal_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_principal_values(item))
        return values
    if isinstance(value, dict):
        values = []
        for key, item in value.items():
            if key in {"kind", "apiGroup", "namespace", "name"}:
                continue
            values.extend(_principal_values(item))
        if {"kind", "namespace", "name"} & set(value):
            kind = str(value.get("kind") or "").lower()
            namespace = str(value.get("namespace") or "").strip()
            name = str(value.get("name") or "").strip()
            if kind == "serviceaccount" and namespace and name:
                values.append(f"system:serviceaccount:{namespace}:{name}")
            elif name:
                values.append(name)
        return values
    return [str(value)]


def _first_string(value: PolicyRecord, keys: tuple[str, ...]) -> str:
    for key in keys:
        raw = value.get(key)
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return ""


def _azure_role_actions(role_name: str) -> list[str]:
    return AZURE_ROLE_ACTION_HINTS.get(role_name.lower(), [])


def _gcp_role_permissions(role_name: str) -> list[str]:
    return GCP_ROLE_PERMISSION_HINTS.get(role_name.lower(), [])


def _patterns_match(patterns: list[str], value: str) -> bool:
    if not patterns:
        return True
    value = str(value or "").lower()
    for pattern in patterns:
        candidate = str(pattern or "").lower()
        if candidate in {"*", "*:*"}:
            return True
        if candidate == value:
            return True
        if candidate.endswith("*") and value.startswith(candidate[:-1]):
            return True
        if candidate.startswith("*") and value.endswith(candidate[1:]):
            return True
        if candidate in value:
            return True
    return False


def _pattern_set_applies(
    patterns: tuple[str, ...],
    not_patterns: tuple[str, ...],
    value: str,
    *,
    default_when_empty: bool = False,
) -> bool:
    if not_patterns and _patterns_match(list(not_patterns), value):
        return False
    if patterns:
        return _patterns_match(list(patterns), value)
    return default_when_empty or not not_patterns


def _documents_by_layer(documents: list[PolicyRecord]) -> dict[str, list[PolicyRecord]]:
    by_layer: dict[str, list[PolicyRecord]] = {}
    for document in documents:
        layer = str(document.get("layer") or "identity_policy").lower()
        by_layer.setdefault(layer, []).append(document)
    return by_layer


def _effect(statement: PolicyRecord) -> str:
    return str(statement.get("Effect") or statement.get("effect") or "Allow").lower()


def _action(record: PolicyRecord) -> str:
    return str(record.get("action") or record.get("permission") or "*").lower()


def _resource(record: PolicyRecord) -> str:
    for key in ("resource", "target_resource", "scope"):
        value = str(record.get(key) or "").lower()
        if value:
            return value
    raw = record.get("target_resources") or record.get("resource_refs")
    values = _strings_from_any(raw)
    return values[0].lower() if values else "*"


def _principal(record: PolicyRecord) -> str:
    for key in ("principal", "identity", "member", "service_account", "serviceAccount", "subject", "user", "group"):
        value = str(record.get(key) or "").strip()
        if value:
            return value.lower()
    return "*"


def _request_context(record: PolicyRecord, provider: str, action: str, resource: str) -> PolicyRecord:
    context: PolicyRecord = {
        "provider": provider,
        "action": action,
        "permission": action,
        "resource": resource,
        "resource.name": resource,
        "principal": _principal(record),
        "identity": _principal(record),
        "aws:principalarn": _principal(record),
        "aws:resourcearn": resource,
    }
    for key in (
        "condition_context",
        "request_context",
        "context",
        "principal_tags",
        "resource_tags",
        "claims",
        "annotations",
        "labels",
    ):
        raw = record.get(key)
        if isinstance(raw, dict):
            for item_key, value in raw.items():
                context[str(item_key).lower()] = value
    for key, alias in (
        ("principal_org_id", "aws:principalorgid"),
        ("source_vpce", "aws:sourcevpce"),
        ("source_vpc", "aws:sourcevpc"),
        ("source_account", "aws:sourceaccount"),
        ("source_arn", "aws:sourcearn"),
        ("tenant_id", "tenant"),
        ("namespace", "namespace"),
    ):
        if key in record:
            context[alias] = record[key]
    return context


def _condition_keys(statement: PolicyRecord) -> list[str]:
    keys: set[str] = set()
    for condition_key in ("Condition", "condition", "conditionExpression", "expression", "when"):
        condition = statement.get(condition_key)
        if isinstance(condition, dict):
            for operator, body in condition.items():
                keys.add(str(operator))
                if isinstance(body, dict):
                    keys.update(str(key) for key in body)
        elif condition:
            keys.add(condition_key)
    return sorted(keys)


def _condition_asts(statement: PolicyRecord) -> list[PolicyConditionAst]:
    conditions: list[PolicyConditionAst] = []
    for condition_key in ("Condition", "condition"):
        condition = statement.get(condition_key)
        if isinstance(condition, dict):
            conditions.extend(_condition_asts_from_dict(condition))
        elif condition:
            conditions.append(PolicyConditionAst(operator=condition_key, key=condition_key, values=(str(condition),), raw=condition))
    for condition_key in ("conditionExpression", "expression", "when"):
        condition = statement.get(condition_key)
        if condition:
            conditions.append(PolicyConditionAst(operator="expression", key=condition_key, values=(str(condition),), raw=condition))
    return conditions


def _condition_asts_from_dict(condition: PolicyRecord) -> list[PolicyConditionAst]:
    conditions: list[PolicyConditionAst] = []
    if "expression" in condition or "conditionExpression" in condition:
        expression = str(condition.get("expression") or condition.get("conditionExpression") or "")
        if expression:
            conditions.append(PolicyConditionAst(operator="expression", key="expression", values=(expression,), raw=condition))
        return conditions
    for operator, body in condition.items():
        if isinstance(body, dict):
            for key, value in body.items():
                conditions.append(
                    PolicyConditionAst(
                        operator=str(operator),
                        key=str(key),
                        values=tuple(_strings_from_any(value)),
                        raw={operator: {key: value}},
                    )
                )
        else:
            conditions.append(
                PolicyConditionAst(
                    operator=str(operator),
                    key=str(operator),
                    values=tuple(_strings_from_any(body)),
                    raw={operator: body},
                )
            )
    return conditions


def _condition_ast_keys(conditions: tuple[PolicyConditionAst, ...]) -> list[str]:
    keys: list[str] = []
    for condition in conditions:
        keys.append(condition.operator)
        keys.append(condition.key)
    return _dedupe_strings(keys)


def _conditions_apply(statement: PolicyStatementAst, request: PolicyRequest) -> tuple[str, list[PolicyRecord], list[str]]:
    if not statement.conditions:
        return "satisfied", [], []
    blockers: list[PolicyRecord] = []
    unknowns: list[str] = []
    constrained = False
    for condition in statement.conditions:
        state = _condition_applies(condition, request)
        if state == "not_satisfied":
            return "not_satisfied", [], []
        blockers.append(_blocker(_condition_blocker_kind(statement.provider), "constrains", statement.provider, f"condition key {condition.key}"))
        if state == "unknown":
            constrained = True
            unknowns.append(f"condition {condition.key} was not fully evaluated")
    return ("constrained" if constrained else "satisfied"), blockers, unknowns


def _condition_applies(condition: PolicyConditionAst, request: PolicyRequest) -> str:
    operator = condition.operator.lower()
    expression = condition.values[0] if condition.values else ""
    if operator == "expression":
        return _expression_condition_applies(expression, request)
    observed = _context_value(request.context, condition.key)
    if observed is None and operator.endswith("ifexists"):
        return "satisfied"
    if observed is None:
        return "unknown"
    observed_values = _strings_from_any(observed)
    expected = list(condition.values)
    base_operator = operator.removesuffix("ifexists").split(":")[-1]
    if base_operator in {"stringequals", "arnequals", "numeric equals", "numericequals"}:
        return "satisfied" if any(item in expected for item in observed_values) else "not_satisfied"
    if base_operator in {"stringnotequals", "arnnotequals"}:
        return "satisfied" if all(item not in expected for item in observed_values) else "not_satisfied"
    if base_operator in {"stringlike", "arnlike"}:
        return "satisfied" if any(_patterns_match(expected, item) for item in observed_values) else "not_satisfied"
    if base_operator in {"stringnotlike", "arnnotlike"}:
        return "satisfied" if all(not _patterns_match(expected, item) for item in observed_values) else "not_satisfied"
    if base_operator == "bool":
        return "satisfied" if any(_bool_string(item) in {_bool_string(value) for value in expected} for item in observed_values) else "not_satisfied"
    return "unknown"


def _expression_condition_applies(expression: str, request: PolicyRequest) -> str:
    text = expression.strip()
    lowered = text.lower()
    if not text:
        return "satisfied"
    if "resource.name.startswith" in lowered:
        prefix = _quoted_argument(text)
        return "satisfied" if prefix and request.resource.startswith(prefix.lower()) else "not_satisfied"
    if "resource.name ==" in lowered:
        expected = _quoted_argument(text)
        return "satisfied" if expected and request.resource == expected.lower() else "not_satisfied"
    if "principal" in lowered or "member" in lowered or "subject" in lowered:
        expected = _quoted_argument(text)
        if expected:
            return "satisfied" if _patterns_match([expected], request.principal) else "not_satisfied"
    return "unknown"


def _context_value(context: PolicyRecord, key: str) -> Any:
    normalized = key.lower()
    if normalized in context:
        return context[normalized]
    compact = normalized.replace(":", "_").replace(".", "_")
    for candidate, value in context.items():
        candidate_normalized = str(candidate).lower()
        if candidate_normalized == normalized or candidate_normalized.replace(":", "_").replace(".", "_") == compact:
            return value
    return None


def _quoted_argument(value: str) -> str:
    for quote in ("'", '"'):
        first = value.find(quote)
        if first == -1:
            continue
        second = value.find(quote, first + 1)
        if second != -1:
            return value[first + 1 : second]
    return ""


def _bool_string(value: str) -> str:
    return "true" if str(value).lower() in {"true", "1", "yes"} else "false"


def _condition_blocker_kind(provider: str) -> str:
    return {
        "aws": "condition",
        "azure": "role_assignment_condition",
        "gcp": "conditional_iam_binding",
        "kubernetes": "rbac_condition",
    }.get(provider, "condition")


def _layer_has_pim(documents: list[PolicyRecord]) -> bool:
    text = json.dumps(documents, sort_keys=True, default=str).lower()
    return "pim" in text or "eligible" in text


def _layer_has_aggregation_rule(documents: list[PolicyRecord]) -> bool:
    text = json.dumps(documents, sort_keys=True, default=str).lower()
    return "aggregationrule" in text or "aggregation_rule" in text


def _gcp_workload_identity(record: PolicyRecord, documents: list[PolicyRecord]) -> bool:
    text = json.dumps({"record": record, "documents": documents}, sort_keys=True, default=str).lower()
    return "workload_identity" in text or "iam.gke.io/gcp-service-account" in text


def _azure_scope_blockers(resource: str, documents: list[PolicyRecord]) -> list[str]:
    text = f"{resource} {json.dumps(documents, sort_keys=True, default=str)}".lower()
    if "managementgroups" in text or "management_group" in text:
        return ["management_group_scope"]
    if "resourcegroups" in text or "resource_group" in text:
        return ["resource_group_scope"]
    if "subscriptions/" in text or "subscription" in text:
        return ["subscription_scope"]
    return []


def _gcp_scope_blockers(resource: str, documents: list[PolicyRecord]) -> list[str]:
    text = f"{resource} {json.dumps(documents, sort_keys=True, default=str)}".lower()
    if "organizations/" in text or "organization" in text:
        return ["organization_scope"]
    if "folders/" in text or "folder" in text:
        return ["folder_scope"]
    if "projects/" in text or "project" in text:
        return ["project_scope"]
    return []


def _kubernetes_scope_blockers(record: PolicyRecord, documents: list[PolicyRecord]) -> list[str]:
    text = f"{json.dumps(record, sort_keys=True, default=str)} {json.dumps(documents, sort_keys=True, default=str)}".lower()
    blockers: list[str] = []
    if "serviceaccount" in text or "service_account" in text:
        blockers.append("service_account_scope")
    if "namespace" in text and "clusterrole" not in text:
        blockers.append("namespace_scope")
    return blockers


def _kubernetes_action_parts(action: str, resource: str) -> tuple[str, str]:
    tokens = [token for token in action.replace("/", " / ").split() if token != "/"]
    if len(tokens) >= 2:
        return tokens[0].lower(), "/".join(tokens[1:]).lower()
    return action.lower(), resource.lower()


def _resource_pattern_set_applies(statement: PolicyStatementAst, request: PolicyRequest) -> bool:
    if statement.not_resources and _patterns_match(list(statement.not_resources), request.resource):
        return False
    if statement.resources:
        patterns = list(statement.resources)
        return _patterns_match(patterns, request.resource) or _provider_scope_applies(request.provider, patterns, request.resource)
    return not statement.not_resources


def _provider_scope_applies(provider: str, patterns: list[str], resource: str) -> bool:
    resource = resource.lower()
    if provider == "azure":
        return any(_azure_scope_applies(pattern, resource) for pattern in patterns)
    if provider == "gcp":
        return any(_gcp_scope_applies(pattern, resource) for pattern in patterns)
    return False


def _azure_scope_applies(pattern: str, resource: str) -> bool:
    pattern = pattern.lower()
    return ("managementgroups/" in pattern or "managementgroup" in pattern) and resource.startswith("/subscriptions/")


def _gcp_scope_applies(pattern: str, resource: str) -> bool:
    pattern = pattern.lower()
    return (
        pattern.startswith("organizations/")
        and (resource.startswith("projects/") or resource.startswith("folders/"))
    ) or (pattern.startswith("folders/") and resource.startswith("projects/"))


def _kubernetes_privilege_escalation_verbs(verb: str, resource: str) -> list[str]:
    combined = f"{verb} {resource}".lower()
    return [marker for marker in ("impersonate", "bind", "escalate", "pods/exec", "create pods/exec") if marker in combined]


def _aws_deny_kind(layer: str) -> str:
    return {
        "permissions_boundary": "permission_boundary",
        "service_control_policy": "scp_deny",
        "resource_policy": "resource_policy_deny",
        "trust_policy": "trust_policy_deny",
    }.get(layer, "explicit_deny_precedence")


def _gcp_deny_kind(layer: str) -> str:
    return {
        "deny_policy": "deny_policy",
        "principal_access_boundary": "principal_access_boundary_deny",
        "organization_policy": "organization_policy_deny",
        "resource_policy": "resource_policy_deny",
    }.get(layer, "explicit_deny")


def _basis(prefix: str, decision: str, layers: list[str]) -> str:
    layer_text = ",".join(layer for layer in layers if layer) or "unknown"
    return f"{prefix}:{decision}:{layer_text}"


def _strongest_layer(layers: list[str]) -> str:
    rank = {
        "explicit_deny": 99,
        "deny_policy": 90,
        "deny_assignment": 90,
        "resource_policy": 80,
        "permissions_boundary": 70,
        "service_control_policy": 70,
        "principal_access_boundary": 70,
        "organization_policy": 65,
        "trust_policy": 60,
        "identity_policy": 50,
        "iam_policy": 50,
        "role_assignment": 50,
        "kubernetes_rbac": 50,
    }
    return max(layers, key=lambda item: rank.get(item, 0), default="unknown")


def _scope_from_resource(resource: str) -> str:
    if not resource or resource in {"*", "*:*"}:
        return "wildcard"
    return "wildcard" if resource.startswith("not:") else "scoped"


def _statement_match_from_ast(match: StatementMatch) -> PolicyRecord:
    statement = match.statement
    return {
        "layer": statement.layer,
        "effect": statement.effect,
        "actions": list(statement.actions),
        "not_actions": list(statement.not_actions),
        "resources": list(statement.resources),
        "not_resources": list(statement.not_resources),
        "principals": list(statement.principals),
        "not_principals": list(statement.not_principals),
        "conditions": list(match.condition_keys),
        "condition_state": match.condition_state,
        "matched": {
            "action": match.action_matched,
            "resource": match.resource_matched,
            "principal": match.principal_matched,
        },
    }


def _evaluation_result(
    *,
    provider: str,
    decision: str,
    basis: str,
    policy_layer: str,
    blockers: list[PolicyRecord],
    unknowns: list[str],
    matched: list[PolicyRecord],
    order: list[dict[str, str]],
    conditions: list[str],
    resource_scope: str,
) -> PolicyRecord:
    return {
        "engine": f"{provider}.structured_policy",
        "provider": provider,
        "decision": decision,
        "decision_basis": basis,
        "policy_layer": policy_layer,
        "blockers": _dedupe_objects(blockers),
        "unknowns": _dedupe_strings(unknowns),
        "matched_statements": _dedupe_objects(matched),
        "evaluation_order": order,
        "condition_keys": _dedupe_strings(conditions),
        "resource_scope": resource_scope,
        "confidence": "high" if decision == "denied" or matched else "medium",
    }


def _blocker(kind: str, effect: str, provider: str, evidence: str) -> PolicyRecord:
    return {"kind": kind, "effect": effect, "provider": provider, "evidence": evidence}


def _listify(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _objects(value: Any) -> list[PolicyRecord]:
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    return [str(item) for item in value if str(item)] if isinstance(value, list) else []


def _strings_from_any(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).lower() for item in value if str(item)]
    if isinstance(value, dict):
        return [str(item).lower() for item in value.values() if isinstance(item, str) and item]
    return [str(value).lower()] if str(value) else []


def _dedupe_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    for value in values:
        if value and value not in deduped:
            deduped.append(value)
    return deduped


def _dedupe_objects(values: list[PolicyRecord]) -> list[PolicyRecord]:
    deduped: list[PolicyRecord] = []
    seen: set[str] = set()
    for value in values:
        token = json.dumps(value, sort_keys=True, default=str)
        if token in seen:
            continue
        seen.add(token)
        deduped.append(value)
    return deduped


def _stronger_confidence(left: str, right: str) -> str:
    left = left.lower()
    right = right.lower()
    rank = {"low": 1, "medium": 2, "high": 3}
    return left if rank.get(left, 1) >= rank.get(right, 1) else right
