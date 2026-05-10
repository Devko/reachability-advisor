"""Multi-cloud Terraform plan context extraction.

This module keeps Terraform support focused on CI and IDE workflows.  It does
not try to become a full cloud posture platform.  The goal is to read a local
``terraform show -json`` plan, classify every observed resource, infer conservative
artifact context for dependency findings, and produce a coverage report that
shows what was semantically understood and what remained a visibility gap.

Design guarantees:
* every resource in the plan is accounted for in coverage output;
* unsupported or unclassified resources are reported, never silently ignored;
* missing links are treated as unknown, not safe;
* resource-type support is declared in ``TERRAFORM_COVERAGE_MANIFEST`` and tested.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .artifacts import artifact_candidates, artifact_match_evidence, clean_image_reference
from .models import Artifact, Confidence, ContextEvidence


class TerraformContextError(ValueError):
    """Raised when Terraform JSON cannot be parsed."""


@dataclass(frozen=True)
class ResourceSupport:
    provider: str
    category: str
    types: tuple[str, ...]
    description: str


TERRAFORM_COVERAGE_MANIFEST: tuple[ResourceSupport, ...] = (
    ResourceSupport(
        provider="aws",
        category="workload",
        types=(
            "aws_ecs_cluster",
            "aws_ecs_service",
            "aws_ecs_task_definition",
            "aws_lambda_function",
            "aws_apprunner_service",
            "aws_batch_job_definition",
            "aws_instance",
            "aws_launch_template",
            "aws_eks_cluster",
        ),
        description="Container, serverless, batch, VM, and Kubernetes control-plane workload hints.",
    ),
    ResourceSupport(
        provider="aws",
        category="exposure",
        types=(
            "aws_security_group",
            "aws_security_group_rule",
            "aws_lb",
            "aws_lb_listener",
            "aws_lb_listener_rule",
            "aws_api_gateway_rest_api",
            "aws_api_gateway_method",
            "aws_apigatewayv2_api",
            "aws_apigatewayv2_route",
            "aws_lambda_function_url",
            "aws_cloudfront_distribution",
        ),
        description="Internet-facing network, load balancer, API, function URL, and CDN exposure hints.",
    ),
    ResourceSupport(
        provider="aws",
        category="identity",
        types=(
            "aws_iam_role",
            "aws_iam_policy",
            "aws_iam_role_policy",
            "aws_iam_role_policy_attachment",
            "aws_iam_user_policy",
            "aws_iam_group_policy",
            "aws_iam_instance_profile",
        ),
        description="IAM policy and role hints used for blast-radius scoring.",
    ),
    ResourceSupport(
        provider="aws",
        category="sensitive_data",
        types=(
            "aws_secretsmanager_secret",
            "aws_ssm_parameter",
            "aws_db_instance",
            "aws_rds_cluster",
            "aws_dynamodb_table",
            "aws_s3_bucket",
            "aws_kms_key",
        ),
        description="Sensitive data and secret-adjacent resources used as blast-radius hints.",
    ),
    ResourceSupport(
        provider="aws",
        category="supporting",
        types=(
            "aws_cloudwatch_log_group",
            "aws_appautoscaling_target",
            "aws_appautoscaling_policy",
            "aws_ecr_repository",
            "aws_vpc",
            "aws_subnet",
        ),
        description="Common supporting resources emitted by ECS/Fargate and container platform modules.",
    ),
    ResourceSupport(
        provider="azure",
        category="workload",
        types=(
            "azurerm_linux_web_app",
            "azurerm_windows_web_app",
            "azurerm_app_service",
            "azurerm_function_app",
            "azurerm_linux_function_app",
            "azurerm_windows_function_app",
            "azurerm_container_app",
            "azurerm_container_app_environment",
            "azurerm_container_group",
            "azurerm_kubernetes_cluster",
            "azurerm_linux_virtual_machine",
            "azurerm_windows_virtual_machine",
            "azurerm_virtual_machine",
        ),
        description="App Service, Functions, Container Apps, ACI, AKS, and VM workload hints.",
    ),
    ResourceSupport(
        provider="azure",
        category="exposure",
        types=(
            "azurerm_public_ip",
            "azurerm_application_gateway",
            "azurerm_lb",
            "azurerm_network_security_group",
            "azurerm_network_security_rule",
            "azurerm_frontdoor_endpoint",
            "azurerm_cdn_frontdoor_endpoint",
        ),
        description="Public IP, gateway, load balancer, NSG, Front Door, and CDN exposure hints.",
    ),
    ResourceSupport(
        provider="azure",
        category="identity",
        types=(
            "azurerm_role_assignment",
            "azurerm_user_assigned_identity",
            "azurerm_key_vault_access_policy",
            "azuread_application",
            "azuread_service_principal",
        ),
        description="Role assignment, managed identity, and key-vault access-policy hints.",
    ),
    ResourceSupport(
        provider="azure",
        category="sensitive_data",
        types=(
            "azurerm_key_vault",
            "azurerm_key_vault_secret",
            "azurerm_storage_account",
            "azurerm_mssql_server",
            "azurerm_mssql_database",
            "azurerm_postgresql_flexible_server",
            "azurerm_mysql_flexible_server",
            "azurerm_cosmosdb_account",
        ),
        description="Key Vault, storage, database, and Cosmos DB blast-radius hints.",
    ),
    ResourceSupport(
        provider="azure",
        category="supporting",
        types=(
            "azurerm_resource_group",
            "azurerm_log_analytics_workspace",
            "azurerm_container_registry",
            "azurerm_private_endpoint",
            "azurerm_virtual_network",
            "azurerm_subnet",
        ),
        description="Common supporting resources emitted by Azure Container Apps and App Service modules.",
    ),
    ResourceSupport(
        provider="gcp",
        category="workload",
        types=(
            "google_cloud_run_service",
            "google_cloud_run_v2_service",
            "google_cloudfunctions_function",
            "google_cloudfunctions2_function",
            "google_container_cluster",
            "google_compute_instance",
            "google_compute_instance_template",
        ),
        description="Cloud Run, Cloud Functions, GKE, and Compute Engine workload hints.",
    ),
    ResourceSupport(
        provider="gcp",
        category="exposure",
        types=(
            "google_compute_firewall",
            "google_cloud_run_service_iam_member",
            "google_cloud_run_service_iam_binding",
            "google_cloudfunctions_function_iam_member",
            "google_cloudfunctions2_function_iam_member",
            "google_compute_forwarding_rule",
            "google_compute_global_forwarding_rule",
            "google_compute_backend_service",
            "google_cloud_run_domain_mapping",
        ),
        description="Firewall, allUsers invoker grants, forwarding rules, backend-service, and Cloud Run domain exposure hints.",
    ),
    ResourceSupport(
        provider="gcp",
        category="identity",
        types=(
            "google_project_iam_member",
            "google_project_iam_binding",
            "google_service_account",
            "google_service_account_iam_member",
            "google_service_account_iam_binding",
            "google_kms_crypto_key_iam_member",
            "google_kms_crypto_key_iam_binding",
        ),
        description="IAM grants and service-account/KMS permission hints.",
    ),
    ResourceSupport(
        provider="gcp",
        category="sensitive_data",
        types=(
            "google_secret_manager_secret",
            "google_storage_bucket",
            "google_sql_database_instance",
            "google_bigquery_dataset",
            "google_kms_crypto_key",
        ),
        description="Secret Manager, Cloud Storage, Cloud SQL, BigQuery, and KMS blast-radius hints.",
    ),
    ResourceSupport(
        provider="gcp",
        category="supporting",
        types=(
            "google_project_service",
            "google_artifact_registry_repository",
            "google_project",
            "google_compute_network",
            "google_compute_subnetwork",
        ),
        description="Common supporting resources emitted by Cloud Run and GKE module fixtures.",
    ),
    ResourceSupport(
        provider="kubernetes",
        category="workload",
        types=(
            "kubernetes_deployment",
            "kubernetes_stateful_set",
            "kubernetes_daemon_set",
            "kubernetes_job",
            "kubernetes_cron_job",
            "kubernetes_pod",
            "kubernetes_manifest",
        ),
        description="Kubernetes-provider workload and manifest image hints.",
    ),
    ResourceSupport(
        provider="kubernetes",
        category="exposure",
        types=("kubernetes_service", "kubernetes_ingress", "kubernetes_ingress_v1"),
        description="Kubernetes Service and Ingress exposure hints.",
    ),
    ResourceSupport(
        provider="kubernetes",
        category="identity",
        types=("kubernetes_service_account", "kubernetes_role_binding", "kubernetes_cluster_role_binding"),
        description="Kubernetes service-account and role-binding hints, including IRSA annotations.",
    ),
    ResourceSupport(
        provider="kubernetes",
        category="supporting",
        types=("kubernetes_namespace", "kubernetes_config_map", "kubernetes_secret"),
        description="Common supporting Kubernetes-provider resources included in community fixture packs.",
    ),
)

SUPPORTED_TYPE_TO_CLASS: dict[str, tuple[str, str]] = {
    rtype: (support.provider, support.category)
    for support in TERRAFORM_COVERAGE_MANIFEST
    for rtype in support.types
}

SENSITIVE_RESOURCE_TYPES = {
    rtype
    for support in TERRAFORM_COVERAGE_MANIFEST
    if support.category == "sensitive_data"
    for rtype in support.types
}

PUBLIC_TOKEN_VALUES = {"0.0.0.0/0", "::/0", "*", "internet", "all", "allusers", "allauthenticatedusers"}
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


@dataclass(frozen=True)
class TerraformResource:
    address: str
    type: str
    name: str
    values: dict[str, Any]

    @property
    def provider(self) -> str:
        return provider_for_type(self.type)

    @property
    def category(self) -> str:
        return SUPPORTED_TYPE_TO_CLASS.get(self.type, (self.provider, "unclassified"))[1]

    @property
    def supported(self) -> bool:
        return self.type in SUPPORTED_TYPE_TO_CLASS


@dataclass
class ArtifactContextAccumulator:
    artifact: Artifact
    environment: str = "unknown"
    exposure: str = "unknown"
    privilege: str = "unknown"
    criticality: str = "unknown"
    owner: str | None = None
    confidence: Confidence = Confidence.LOW
    evidence: list[str] = field(default_factory=list)
    matched_resources: list[str] = field(default_factory=list)
    providers: set[str] = field(default_factory=set)

    def add_resource(self, resource: TerraformResource, image: str | None = None, match_method: str = "unknown", match_score: int = 0) -> None:
        self.providers.add(resource.provider)
        self.matched_resources.append(resource.address)
        message = f"matched {resource.provider} {resource.type} {resource.address}"
        if image:
            message += f" image={image}"
        if match_method != "unknown":
            message += f" artifact_match={match_method}:{match_score}"
        self.evidence.append(message)
        self.environment = tag_or_label(resource.values, "environment", self.environment) or self.environment
        self.environment = tag_or_label(resource.values, "env", self.environment) or self.environment
        self.owner = tag_or_label(resource.values, "owner", self.owner)
        self.owner = tag_or_label(resource.values, "team", self.owner)
        if resource.supported:
            self.confidence = max_confidence(self.confidence, Confidence.MEDIUM)

    def as_context(self, source: str) -> ContextEvidence:
        evidence = list(dict.fromkeys(self.evidence))
        providers = ",".join(sorted(self.providers)) if self.providers else "unknown"
        if providers != "unknown":
            evidence.append(f"provider context: {providers}")
        return ContextEvidence(
            environment=self.environment,
            exposure=self.exposure,
            privilege=self.privilege,
            criticality=self.criticality,
            owner=self.owner,
            source=source,
            confidence=self.confidence,
            evidence=evidence,
        )


@dataclass
class TerraformAnalysis:
    contexts: dict[str, ContextEvidence]
    coverage: dict[str, Any]


class TerraformAnalyzer:
    """Analyze Terraform plan JSON and infer conservative artifact context."""

    def __init__(self, plan: dict[str, Any], artifacts: list[Artifact], source_name: str = "terraform-plan") -> None:
        self.plan = plan
        self.artifacts = artifacts
        self.source_name = source_name
        self.resources = extract_resources(plan)
        self._resource_by_address = {resource.address: resource for resource in self.resources}
        self._global_exposure_by_provider = self._global_exposure()
        self._public_functions = self._public_function_names()
        self._public_cloud_run_services = self._public_cloud_run_services()
        self._privilege_by_provider = self._provider_privileges()
        self._has_sensitive_by_provider = self._sensitive_resources_by_provider()

    def analyze(self) -> TerraformAnalysis:
        contexts: dict[str, ContextEvidence] = {}
        match_rows: list[dict[str, Any]] = []
        accumulators = {artifact.name: ArtifactContextAccumulator(artifact=artifact) for artifact in self.artifacts}
        for artifact in self.artifacts:
            accumulator = accumulators[artifact.name]
            accumulator.environment = str(artifact.properties.get("environment") or artifact.properties.get("env") or "unknown").lower()
            accumulator.owner = artifact.properties.get("owner") or artifact.properties.get("team") or artifact.properties.get("ownership:owner")
            for resource in self.resources:
                if resource.category != "workload":
                    continue
                matched_image = None
                match_method = "none"
                match_score = 0
                for image in find_image_references(resource.values):
                    match = artifact_match_evidence(artifact, image)
                    if match.matched and match.score > match_score:
                        matched_image = image
                        match_method = match.method
                        match_score = match.score
                if not matched_image and workload_name_matches(artifact, resource):
                    matched_image = artifact.reference or artifact.name
                    match_method = "workload-name"
                    match_score = 45
                if not matched_image:
                    continue
                accumulator.add_resource(resource, matched_image, match_method=match_method, match_score=match_score)
                exposure = exposure_for_matched_workload(resource, self._global_exposure_by_provider, self._public_functions, self._public_cloud_run_services)
                accumulator.exposure = max_exposure(accumulator.exposure, exposure)
                accumulator.privilege = max_privilege(accumulator.privilege, self._privilege_by_provider.get(resource.provider, "unknown"))
                if self._has_sensitive_by_provider.get(resource.provider) and accumulator.privilege == "unknown":
                    accumulator.privilege = "limited"
                match_rows.append({"artifact": artifact.name, "resource": resource.address, "type": resource.type, "provider": resource.provider, "image": matched_image, "match_method": match_method, "match_score": match_score})
            if accumulator.matched_resources:
                if accumulator.exposure == "unknown":
                    accumulator.exposure = self._global_exposure_by_provider.get("all", self._global_exposure_by_provider.get(next(iter(accumulator.providers), "unknown"), "unknown"))
                if accumulator.privilege == "unknown":
                    accumulator.privilege = self._privilege_by_provider.get("all", "unknown")
                contexts[artifact.name] = accumulator.as_context(source=f"terraform:{self.source_name}")
        return TerraformAnalysis(contexts=contexts, coverage=coverage_report(self.resources, self.artifacts, match_rows))

    def _global_exposure(self) -> dict[str, str]:
        exposure: dict[str, str] = {}
        for resource in self.resources:
            current = exposure.get(resource.provider, "unknown")
            if resource.category == "exposure" and is_public_exposure(resource):
                exposure[resource.provider] = max_exposure(current, "public")
                exposure["all"] = max_exposure(exposure.get("all", "unknown"), "public")
            elif resource.category == "exposure":
                exposure[resource.provider] = max_exposure(current, "internal")
        return exposure

    def _public_function_names(self) -> set[str]:
        public: set[str] = set()
        for resource in self.resources:
            values = resource.values
            if resource.type == "aws_lambda_function_url" and str(values.get("authorization_type") or "").upper() == "NONE":
                function_name = values.get("function_name") or values.get("function_arn")
                if function_name:
                    public.add(str(function_name))
            if resource.type in {"google_cloudfunctions_function_iam_member", "google_cloudfunctions2_function_iam_member"} and _iam_member_is_public_invoker(values):
                name = values.get("cloud_function") or values.get("cloud_function_name") or values.get("name")
                if name:
                    public.add(str(name))
        return public

    def _public_cloud_run_services(self) -> set[str]:
        public: set[str] = set()
        for resource in self.resources:
            if resource.type not in {"google_cloud_run_service_iam_member", "google_cloud_run_service_iam_binding"}:
                continue
            if not _iam_member_is_public_invoker(resource.values):
                continue
            service = resource.values.get("service") or resource.values.get("name")
            if service:
                public.add(str(service))
        return public

    def _provider_privileges(self) -> dict[str, str]:
        privileges: dict[str, str] = {}
        for resource in self.resources:
            privilege = privilege_for_resource(resource)
            if privilege == "unknown":
                continue
            privileges[resource.provider] = max_privilege(privileges.get(resource.provider, "unknown"), privilege)
            privileges["all"] = max_privilege(privileges.get("all", "unknown"), privilege)
        return privileges

    def _sensitive_resources_by_provider(self) -> dict[str, bool]:
        result: dict[str, bool] = {}
        for resource in self.resources:
            if resource.type in SENSITIVE_RESOURCE_TYPES:
                result[resource.provider] = True
                result["all"] = True
        return result


def load_terraform_plan(path: str | Path) -> dict[str, Any]:
    plan_path = Path(path)
    try:
        data = json.loads(plan_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TerraformContextError(f"{plan_path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise TerraformContextError(f"{plan_path}: expected a JSON object")
    return data


def analyze_terraform_plan(path: str | Path | None, artifacts: list[Artifact]) -> TerraformAnalysis:
    if not path:
        return TerraformAnalysis(contexts={}, coverage=empty_coverage_report())
    plan_path = Path(path)
    plan = load_terraform_plan(plan_path)
    return TerraformAnalyzer(plan, artifacts, source_name=plan_path.name).analyze()


def extract_resources(plan: dict[str, Any]) -> list[TerraformResource]:
    resources: dict[str, TerraformResource] = {}

    def add(raw: dict[str, Any]) -> None:
        if not isinstance(raw, dict):
            return
        rtype = str(raw.get("type") or "")
        if not rtype:
            return
        address = str(raw.get("address") or f"{rtype}.{raw.get('name') or len(resources)}")
        values = raw.get("values") if isinstance(raw.get("values"), dict) else {}
        resources[address] = TerraformResource(address=address, type=rtype, name=str(raw.get("name") or ""), values=values)

    root = plan.get("planned_values", {}).get("root_module", {}) if isinstance(plan.get("planned_values"), dict) else {}

    def walk_module(module: dict[str, Any]) -> None:
        for raw_resource in module.get("resources", []) or []:
            add(raw_resource)
        for child in module.get("child_modules", []) or []:
            if isinstance(child, dict):
                walk_module(child)

    if isinstance(root, dict):
        walk_module(root)

    for change in plan.get("resource_changes", []) or []:
        if not isinstance(change, dict):
            continue
        after = change.get("change", {}).get("after") if isinstance(change.get("change"), dict) else None
        if isinstance(after, dict):
            add({"address": change.get("address"), "type": change.get("type"), "name": change.get("name"), "values": after})

    return list(resources.values())


def provider_for_type(resource_type: str) -> str:
    if resource_type.startswith("aws_"):
        return "aws"
    if resource_type.startswith("azurerm_") or resource_type.startswith("azuread_"):
        return "azure"
    if resource_type.startswith("google_"):
        return "gcp"
    if resource_type.startswith("kubernetes_"):
        return "kubernetes"
    return "unknown"


def find_image_references(values: Any) -> list[str]:
    """Find likely container image strings across provider-specific shapes."""

    found: list[str] = []

    def add(value: Any) -> None:
        if isinstance(value, str):
            cleaned = _clean_image_value(value)
            if cleaned and _looks_like_image_reference(cleaned):
                found.append(cleaned)

    def walk(value: Any, key_hint: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                key_l = str(key).lower()
                if key_l in {"image", "image_uri", "image_identifier", "container_image", "docker_image", "docker_image_name", "repository_url"}:
                    add(item)
                    if isinstance(item, (list, dict)):
                        walk(item, key_l)
                elif key_l == "linux_fx_version":
                    add(item)
                    if isinstance(item, (list, dict)):
                        walk(item, key_l)
                elif key_l in {"container_definitions", "task_container_properties"} and isinstance(item, str):
                    try:
                        decoded = json.loads(item)
                    except json.JSONDecodeError:
                        add(item)
                    else:
                        walk(decoded, key_l)
                else:
                    walk(item, key_l)
        elif isinstance(value, list):
            for item in value:
                walk(item, key_hint)
        elif isinstance(value, str) and key_hint in {"image", "image_uri", "image_identifier", "docker_image", "linux_fx_version"}:
            add(value)

    walk(values)
    return list(dict.fromkeys(found))


def _clean_image_value(value: str) -> str | None:
    return clean_image_reference(value)


def _looks_like_image_reference(value: str) -> bool:
    if "${" in value:
        return True
    if ":" in value or "/" in value or "@sha256:" in value:
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value))


def image_matches(artifact: Artifact, image: str | None) -> bool:
    return artifact_match_evidence(artifact, image).matched


def candidate_artifact_references(artifact: Artifact) -> set[str]:
    return artifact_candidates(artifact)


def _strip_image_version(value: str) -> str:
    value = value.split("@sha256:", 1)[0]
    if ":" in value.rsplit("/", 1)[-1]:
        return value.rsplit(":", 1)[0]
    return value


def workload_name_matches(artifact: Artifact, resource: TerraformResource) -> bool:
    values = resource.values
    names = {
        str(resource.name or ""),
        str(values.get("name") or ""),
        str(values.get("function_name") or ""),
        str(values.get("service_name") or ""),
        str(values.get("app_name") or ""),
    }
    artifact_name = artifact.name.lower()
    return any(name and (artifact_name == name.lower() or artifact_name in name.lower()) for name in names)


def exposure_for_matched_workload(
    resource: TerraformResource,
    global_exposure_by_provider: dict[str, str],
    public_functions: set[str],
    public_cloud_run_services: set[str],
) -> str:
    values = resource.values
    if resource.type == "aws_apprunner_service":
        return "public"
    if resource.type == "aws_lambda_function":
        names = {str(values.get("function_name") or ""), str(values.get("name") or ""), str(values.get("arn") or "")}
        if any(name in public_functions for name in names if name):
            return "public"
    if resource.type in {"azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_app_service", "azurerm_function_app", "azurerm_linux_function_app", "azurerm_windows_function_app"}:
        public_network = values.get("public_network_access_enabled")
        return "internal" if public_network is False else "public"
    if resource.type == "azurerm_container_app":
        if _azure_container_app_external_ingress(values):
            return "public"
    if resource.type in {"google_cloud_run_service", "google_cloud_run_v2_service"}:
        names = {str(values.get("name") or ""), str(resource.name or "")}
        if any(name in public_cloud_run_services for name in names if name):
            return "public"
        ingress = str(values.get("ingress") or "").lower()
        if ingress in {"all", "ingress_traffic_all", "all_traffic"}:
            return "external"
    if resource.type.startswith("kubernetes_") and resource.type != "kubernetes_manifest":
        return global_exposure_by_provider.get("kubernetes", "unknown")
    return global_exposure_by_provider.get(resource.provider, "unknown")


def _azure_container_app_external_ingress(values: dict[str, Any]) -> bool:
    ingress = values.get("ingress")
    if isinstance(ingress, list):
        return any(isinstance(item, dict) and bool(item.get("external_enabled")) for item in ingress)
    if isinstance(ingress, dict):
        return bool(ingress.get("external_enabled"))
    return False


def is_public_exposure(resource: TerraformResource) -> bool:
    values = resource.values
    rtype = resource.type
    if rtype in {"aws_lb", "azurerm_public_ip", "azurerm_application_gateway", "azurerm_frontdoor_endpoint", "azurerm_cdn_frontdoor_endpoint", "google_compute_forwarding_rule", "google_compute_global_forwarding_rule"}:
        if str(values.get("internal") or "").lower() == "true":
            return False
        return True
    if rtype in {"aws_security_group", "aws_security_group_rule"}:
        return _aws_security_group_is_public(values)
    if rtype in {"azurerm_network_security_group", "azurerm_network_security_rule"}:
        return _azure_nsg_is_public(values)
    if rtype == "google_compute_firewall":
        return _gcp_firewall_is_public(values)
    if rtype == "aws_lambda_function_url":
        return str(values.get("authorization_type") or "").upper() == "NONE"
    if rtype in {"google_cloud_run_service_iam_member", "google_cloud_run_service_iam_binding", "google_cloudfunctions_function_iam_member", "google_cloudfunctions2_function_iam_member"}:
        return _iam_member_is_public_invoker(values)
    if rtype in {"kubernetes_service", "kubernetes_ingress", "kubernetes_ingress_v1"}:
        return _kubernetes_exposure_is_public(values)
    if rtype in {"aws_apigatewayv2_api", "aws_api_gateway_rest_api", "aws_cloudfront_distribution", "google_cloud_run_domain_mapping"}:
        return True
    return False


def _aws_security_group_is_public(values: dict[str, Any]) -> bool:
    rules: list[Any] = []
    for key in ("ingress", "ingress_with_cidr_blocks"):
        item = values.get(key)
        if isinstance(item, list):
            rules.extend(item)
        elif isinstance(item, dict):
            rules.append(item)
    if values.get("type") == "ingress":
        rules.append(values)
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        cidrs = _listify(rule.get("cidr_blocks")) + _listify(rule.get("ipv6_cidr_blocks"))
        if any(str(cidr).lower() in PUBLIC_TOKEN_VALUES for cidr in cidrs):
            return True
    return False


def _azure_nsg_is_public(values: dict[str, Any]) -> bool:
    rules: list[Any] = []
    for key in ("security_rule", "security_rules"):
        item = values.get(key)
        if isinstance(item, list):
            rules.extend(item)
        elif isinstance(item, dict):
            rules.append(item)
    if values.get("source_address_prefix") or values.get("source_address_prefixes"):
        rules.append(values)
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        direction = str(rule.get("direction") or "Inbound").lower()
        access = str(rule.get("access") or "Allow").lower()
        if direction != "inbound" or access != "allow":
            continue
        sources = _listify(rule.get("source_address_prefix")) + _listify(rule.get("source_address_prefixes"))
        if any(str(source).lower() in PUBLIC_TOKEN_VALUES for source in sources):
            return True
    return False


def _gcp_firewall_is_public(values: dict[str, Any]) -> bool:
    ranges = _listify(values.get("source_ranges"))
    direction = str(values.get("direction") or "INGRESS").lower()
    disabled = bool(values.get("disabled"))
    return not disabled and direction == "ingress" and any(str(item).lower() in PUBLIC_TOKEN_VALUES for item in ranges)


def _iam_member_is_public_invoker(values: dict[str, Any]) -> bool:
    role = str(values.get("role") or "").lower()
    members = _listify(values.get("member")) + _listify(values.get("members"))
    return "invoker" in role and any(str(member).lower() in {"allusers", "allauthenticatedusers"} for member in members)


def _kubernetes_exposure_is_public(values: dict[str, Any]) -> bool:
    service_type = str(values.get("type") or "").lower()
    if service_type == "loadbalancer":
        return True
    annotations = values.get("annotations") if isinstance(values.get("annotations"), dict) else {}
    if any("ingress" in str(key).lower() for key in annotations):
        return True
    return bool(values.get("rules") or values.get("spec"))


def privilege_for_resource(resource: TerraformResource) -> str:
    values = resource.values
    rtype = resource.type
    if rtype in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}:
        return classify_policy(values.get("policy"))
    if rtype == "aws_iam_role_policy_attachment":
        return classify_role_text(values.get("policy_arn") or values.get("policy"))
    if rtype == "aws_iam_role":
        return classify_role_text(values.get("managed_policy_arns") or values.get("name") or values.get("arn"))
    if rtype == "azurerm_role_assignment":
        return classify_role_text(values.get("role_definition_name") or values.get("role_definition_id"))
    if rtype == "azurerm_key_vault_access_policy":
        return _azure_key_vault_privilege(values)
    if rtype in {"google_project_iam_member", "google_project_iam_binding", "google_service_account_iam_member", "google_service_account_iam_binding", "google_kms_crypto_key_iam_member", "google_kms_crypto_key_iam_binding"}:
        return classify_role_text(values.get("role"))
    if rtype in {"kubernetes_role_binding", "kubernetes_cluster_role_binding"}:
        return classify_role_text(values.get("role_ref") or values.get("metadata"))
    return "unknown"


def classify_policy(policy: Any) -> str:
    if not policy:
        return "unknown"
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return classify_role_text(policy)
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    best = "unknown"
    for statement in statements:
        if not isinstance(statement, dict) or str(statement.get("Effect", "Allow")).lower() != "allow":
            continue
        if "NotAction" in statement:
            best = max_privilege(best, "admin")
            continue
        actions = [str(action).lower() for action in _listify(statement.get("Action"))]
        if "*" in actions or any(action.endswith(":*") for action in actions):
            best = max_privilege(best, "admin")
        elif any(_is_sensitive_action(action) for action in actions):
            best = max_privilege(best, "sensitive")
        elif actions:
            best = max_privilege(best, "limited")
    return best


def classify_role_text(value: Any) -> str:
    text = json.dumps(value, sort_keys=True).lower() if isinstance(value, (dict, list)) else str(value or "").lower()
    if not text:
        return "unknown"
    if any(token in text for token in ADMIN_ROLE_TOKENS):
        return "admin"
    if any(token in text for token in SENSITIVE_ROLE_TOKENS):
        return "sensitive"
    if "role" in text or "policy" in text or ":" in text:
        return "limited"
    return "unknown"


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
    permissions = json.dumps(values.get("secret_permissions") or values.get("key_permissions") or values.get("certificate_permissions") or [], sort_keys=True).lower()
    if any(word in permissions for word in ("all", "purge", "delete", "set")):
        return "admin"
    if any(word in permissions for word in ("get", "list", "decrypt")):
        return "sensitive"
    return "unknown"


def max_privilege(left: str, right: str) -> str:
    return left if privilege_rank(left) >= privilege_rank(right) else right


def privilege_rank(value: str) -> int:
    return {"unknown": 0, "none": 1, "limited": 2, "sensitive": 3, "admin": 4}.get(value, 0)


def max_exposure(left: str, right: str) -> str:
    return left if exposure_rank(left) >= exposure_rank(right) else right


def exposure_rank(value: str) -> int:
    return {"unknown": 0, "none": 1, "private": 2, "internal": 3, "external": 4, "public": 5}.get(value, 0)


def max_confidence(left: Confidence, right: Confidence) -> Confidence:
    rank = {Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}
    return left if rank[left] >= rank[right] else right


def tag_or_label(values: dict[str, Any], key: str, fallback: str | None = None) -> str | None:
    containers = []
    for container_key in ("tags", "labels", "metadata", "annotations"):
        item = values.get(container_key)
        if isinstance(item, dict):
            containers.append(item)
        elif isinstance(item, list):
            containers.extend(sub for sub in item if isinstance(sub, dict))
    key_l = key.lower()
    for container in containers:
        for candidate_key, candidate_value in container.items():
            if str(candidate_key).lower() in {key_l, f"app.{key_l}", f"app.kubernetes.io/{key_l}", f"reachability/{key_l}", "team" if key_l == "owner" else key_l}:
                return str(candidate_value).lower()
    return fallback


def _listify(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def coverage_report(resources: list[TerraformResource], artifacts: list[Artifact], matches: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(resources)
    classified = sum(1 for resource in resources if resource.supported)
    provider_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    unsupported: list[dict[str, str]] = []
    resource_rows: list[dict[str, Any]] = []
    for resource in resources:
        provider_counts[resource.provider] = provider_counts.get(resource.provider, 0) + 1
        category_counts[resource.category] = category_counts.get(resource.category, 0) + 1
        row = {
            "address": resource.address,
            "type": resource.type,
            "provider": resource.provider,
            "category": resource.category,
            "supported": resource.supported,
        }
        resource_rows.append(row)
        if not resource.supported:
            unsupported.append({"address": resource.address, "type": resource.type, "provider": resource.provider, "reason": "resource type is accounted for but not semantically classified"})
    matched_artifacts = sorted({row["artifact"] for row in matches})
    unmatched_artifacts = sorted(artifact.name for artifact in artifacts if artifact.name not in matched_artifacts)
    manifest = manifest_report()
    return {
        "schema_version": "2.0",
        "summary": {
            "total_resources": total,
            "accounted_resources": total,
            "resource_accounting_coverage": 1.0,
            "semantically_classified_resources": classified,
            "semantic_classification_coverage": round(classified / total, 4) if total else 1.0,
            "unsupported_or_unclassified_resources": len(unsupported),
            "artifacts_requested": len(artifacts),
            "artifacts_matched": len(matched_artifacts),
            "artifact_match_coverage": round(len(matched_artifacts) / len(artifacts), 4) if artifacts else 1.0,
            "providers_seen": provider_counts,
            "categories_seen": category_counts,
        },
        "manifest": manifest,
        "resource_types_seen": sorted({resource.type for resource in resources}),
        "artifact_matches": matches,
        "matched_artifacts": matched_artifacts,
        "unmatched_artifacts": unmatched_artifacts,
        "resources": resource_rows,
        "visibility_gaps": unsupported,
        "notes": [
            "100% resource accounting means every Terraform resource in the plan is represented in this report.",
            "Semantic coverage is limited to the declared manifest; unclassified resources are visibility gaps, not safe states.",
            "Use source reachability and explicit context files for evidence that Terraform cannot infer from a static plan.",
        ],
    }


def empty_coverage_report() -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "summary": {
            "total_resources": 0,
            "accounted_resources": 0,
            "resource_accounting_coverage": 1.0,
            "semantically_classified_resources": 0,
            "semantic_classification_coverage": 1.0,
            "unsupported_or_unclassified_resources": 0,
            "artifacts_requested": 0,
            "artifacts_matched": 0,
            "artifact_match_coverage": 1.0,
            "providers_seen": {},
            "categories_seen": {},
        },
        "manifest": manifest_report(),
        "resource_types_seen": [],
        "artifact_matches": [],
        "matched_artifacts": [],
        "unmatched_artifacts": [],
        "resources": [],
        "visibility_gaps": [],
        "notes": [],
    }


def manifest_report() -> dict[str, Any]:
    providers: dict[str, dict[str, Any]] = {}
    for support in TERRAFORM_COVERAGE_MANIFEST:
        provider = providers.setdefault(support.provider, {"categories": {}, "resource_type_count": 0})
        provider["categories"][support.category] = {"types": list(support.types), "description": support.description}
        provider["resource_type_count"] += len(support.types)
    return {
        "supported_providers": sorted(providers),
        "provider_count": len(providers),
        "resource_type_count": sum(len(support.types) for support in TERRAFORM_COVERAGE_MANIFEST),
        "providers": providers,
    }


__all__ = [
    "TERRAFORM_COVERAGE_MANIFEST",
    "SUPPORTED_TYPE_TO_CLASS",
    "TerraformAnalysis",
    "TerraformAnalyzer",
    "TerraformContextError",
    "analyze_terraform_plan",
    "classify_policy",
    "classify_role_text",
    "coverage_report",
    "empty_coverage_report",
    "extract_resources",
    "find_image_references",
    "image_matches",
    "is_public_exposure",
    "manifest_report",
    "privilege_for_resource",
    "provider_for_type",
]
