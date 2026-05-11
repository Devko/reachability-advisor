"""Multi-cloud Terraform plan context extraction.

This module keeps Terraform support focused on CI and IDE workflows.  It does
not try to become a full cloud posture platform.  The goal is to read a local
``terraform show -json`` plan, classify every observed resource, infer conservative
artifact context for dependency findings, and produce a coverage report that
shows what was semantically understood and what remained a visibility gap.

Design guarantees:
* every resource in the plan is accounted for in coverage output;
* unsupported or unclassified resources are reported, never silently ignored;
* missing links are treated as unknown;
* resource-type support is declared in ``TERRAFORM_COVERAGE_MANIFEST`` and tested.
"""

from __future__ import annotations

import json
import ipaddress
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
            "aws_alb",
            "aws_alb_listener",
            "aws_alb_listener_rule",
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
            "aws_secretsmanager_secret_version",
            "aws_ssm_parameter",
            "aws_db_instance",
            "aws_rds_cluster",
            "aws_dynamodb_table",
            "aws_s3_bucket",
            "aws_kms_key",
            "aws_mq_broker",
        ),
        description="Sensitive data and secret-adjacent resources used as blast-radius hints.",
    ),
    ResourceSupport(
        provider="aws",
        category="supporting",
        types=(
            "aws_cloudwatch_log_group",
            "aws_cloudwatch_log_resource_policy",
            "aws_cloudwatch_metric_alarm",
            "aws_cloudwatch_event_rule",
            "aws_cloudwatch_event_target",
            "aws_appautoscaling_target",
            "aws_appautoscaling_policy",
            "aws_codebuild_project",
            "aws_codecommit_repository",
            "aws_codedeploy_app",
            "aws_codedeploy_deployment_group",
            "aws_codepipeline",
            "aws_ecr_repository",
            "aws_network_interface",
            "aws_lb_target_group",
            "aws_lb_target_group_attachment",
            "aws_alb_target_group",
            "aws_alb_target_group_attachment",
            "aws_vpc",
            "aws_vpc_peering_connection",
            "aws_subnet",
            "aws_internet_gateway",
            "aws_nat_gateway",
            "aws_eip",
            "aws_customer_gateway",
            "aws_vpn_gateway",
            "aws_vpn_connection",
            "aws_ec2_transit_gateway",
            "aws_ec2_transit_gateway_vpc_attachment",
            "aws_ec2_transit_gateway_peering_attachment",
            "aws_route",
            "aws_route_table",
            "aws_default_route_table",
            "aws_route_table_association",
            "aws_db_subnet_group",
            "aws_eks_addon",
            "aws_apprunner_vpc_connector",
            "aws_apprunner_vpc_ingress_connection",
            "aws_service_discovery_private_dns_namespace",
            "aws_sns_topic",
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
            "azurerm_key_vault_key",
            "azurerm_storage_account",
            "azurerm_storage_container",
            "azurerm_storage_account_customer_managed_key",
            "azurerm_mssql_server",
            "azurerm_mssql_database",
            "azurerm_postgresql_flexible_server",
            "azurerm_mysql_flexible_server",
            "azurerm_cosmosdb_account",
            "azurerm_cognitive_account",
            "azurerm_cognitive_deployment",
            "azurerm_container_registry_token_password",
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
            "azurerm_container_registry_token",
            "azurerm_private_endpoint",
            "azurerm_private_dns_zone",
            "azurerm_private_dns_zone_virtual_network_link",
            "azurerm_private_dns_a_record",
            "azurerm_virtual_network",
            "azurerm_virtual_network_peering",
            "azurerm_virtual_network_gateway",
            "azurerm_virtual_network_gateway_connection",
            "azurerm_express_route_circuit",
            "azurerm_express_route_connection",
            "azurerm_subnet",
            "azurerm_network_interface",
            "azurerm_network_interface_backend_address_pool_association",
            "azurerm_network_interface_application_gateway_backend_address_pool_association",
            "azurerm_container_app_environment_dapr_component",
            "azurerm_container_app_environment_storage",
            "azurerm_log_analytics_solution",
            "azurerm_log_analytics_storage_insights",
            "azurerm_application_insights",
            "azurerm_monitor_diagnostic_setting",
        ),
        description="Common supporting resources emitted by Azure Container Apps and App Service modules.",
    ),
    ResourceSupport(
        provider="gcp",
        category="workload",
        types=(
            "google_cloud_run_service",
            "google_cloud_run_v2_service",
            "google_cloud_run_v2_job",
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
            "google_cloud_run_v2_service_iam_member",
            "google_cloud_run_v2_service_iam_binding",
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
            "google_organization_iam_member",
            "google_folder_iam_member",
            "google_billing_account_iam_member",
            "google_service_account",
            "google_service_account_iam_member",
            "google_service_account_iam_binding",
            "google_kms_crypto_key_iam_member",
            "google_kms_crypto_key_iam_binding",
            "google_artifact_registry_repository_iam_member",
            "google_secret_manager_secret_iam_member",
            "google_iap_web_cloud_run_service_iam_member",
            "google_project_service_identity",
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
            "google_service_account_key",
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
            "google_folder",
            "google_compute_network",
            "google_compute_network_peering",
            "google_compute_subnetwork",
            "google_compute_global_address",
            "google_compute_region_network_endpoint_group",
            "google_compute_security_policy",
            "google_compute_shared_vpc_service_project",
            "google_compute_vpn_gateway",
            "google_compute_ha_vpn_gateway",
            "google_compute_vpn_tunnel",
            "google_compute_interconnect_attachment",
            "google_compute_router",
            "google_compute_router_peer",
            "google_compute_router_nat",
            "google_dns_policy",
            "google_gke_hub_feature",
            "google_gke_hub_membership",
            "google_vpc_access_connector",
            "google_access_context_manager_access_policy",
            "google_access_context_manager_service_perimeter_resource",
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
        types=(
            "kubernetes_service_account",
            "kubernetes_role_binding",
            "kubernetes_cluster_role_binding",
            "kubernetes_role_v1",
            "kubernetes_role_binding_v1",
            "kubernetes_cluster_role_v1",
            "kubernetes_cluster_role_binding_v1",
        ),
        description="Kubernetes service-account and role-binding hints, including IRSA annotations.",
    ),
    ResourceSupport(
        provider="kubernetes",
        category="supporting",
        types=(
            "kubernetes_namespace",
            "kubernetes_namespace_v1",
            "kubernetes_config_map",
            "kubernetes_secret",
            "helm_release",
            "kubectl_manifest",
        ),
        description="Common supporting Kubernetes-provider resources and opaque Helm/Kubectl manifest wrappers included in community fixture packs.",
    ),
    ResourceSupport(
        provider="terraform",
        category="supporting",
        types=(
            "random_string",
            "random_id",
            "random_integer",
            "random_password",
            "random_pet",
            "null_resource",
            "time_sleep",
            "local_file",
            "template_file",
            "terraform_data",
            "terracurl_request",
        ),
        description="Terraform helper resources that affect provisioning but do not provide direct workload, exposure, identity, or data context.",
    ),
    ResourceSupport(
        provider="docker",
        category="supporting",
        types=("docker_image", "docker_tag"),
        description="Local Docker provider resources used by examples to build or tag container images.",
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

OPAQUE_MANIFEST_WRAPPER_TYPES = {"helm_release", "kubectl_manifest"}

PUBLIC_TOKEN_VALUES = {"0.0.0.0/0", "::/0", "*", "internet", "all", "allusers", "allauthenticatedusers"}
INTERNAL_TOKEN_VALUES = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "virtualnetwork",
    "vnet",
    "vpc",
    "private",
    "privatelink",
    "azureloadbalancer",
    "vpn",
    "onprem",
    "on-prem",
}
NETWORK_BRIDGE_RESOURCE_TYPES = {
    "aws_vpc_peering_connection",
    "aws_customer_gateway",
    "aws_vpn_gateway",
    "aws_vpn_connection",
    "aws_ec2_transit_gateway",
    "aws_ec2_transit_gateway_vpc_attachment",
    "aws_ec2_transit_gateway_peering_attachment",
    "azurerm_virtual_network_peering",
    "azurerm_virtual_network_gateway",
    "azurerm_virtual_network_gateway_connection",
    "azurerm_express_route_circuit",
    "azurerm_express_route_connection",
    "google_compute_network_peering",
    "google_compute_shared_vpc_service_project",
    "google_compute_vpn_gateway",
    "google_compute_ha_vpn_gateway",
    "google_compute_vpn_tunnel",
    "google_compute_interconnect_attachment",
    "google_compute_router_peer",
}
PRIVATE_NETWORK_RESOURCE_TYPES = {
    "aws_vpc",
    "aws_subnet",
    "aws_network_interface",
    "azurerm_virtual_network",
    "azurerm_subnet",
    "azurerm_network_interface",
    "azurerm_private_endpoint",
    "google_compute_network",
    "google_compute_subnetwork",
    "google_vpc_access_connector",
}
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

AZAPI_ARM_TYPE_TO_CATEGORY = {
    "microsoft.app/containerapps": "workload",
    "microsoft.app/jobs": "workload",
    "microsoft.app/managedenvironments": "workload",
    "microsoft.app/managedenvironments/daprcomponents": "supporting",
    "microsoft.app/managedenvironments/storages": "supporting",
    "microsoft.insights/components": "supporting",
    "microsoft.insights/diagnosticsettings": "supporting",
    "microsoft.operationalinsights/workspaces": "supporting",
    "microsoft.network/applicationgateways": "exposure",
    "microsoft.network/frontdoors": "exposure",
    "microsoft.network/loadbalancers": "exposure",
    "microsoft.network/publicipaddresses": "exposure",
    "microsoft.network/privateendpoints": "supporting",
    "microsoft.network/privatednszones": "supporting",
    "microsoft.network/virtualnetworks": "supporting",
    "microsoft.network/virtualnetworks/subnets": "supporting",
    "microsoft.containerregistry/registries": "supporting",
    "microsoft.managedidentity/userassignedidentities": "identity",
    "microsoft.authorization/roleassignments": "identity",
    "microsoft.keyvault/vaults": "sensitive_data",
    "microsoft.keyvault/vaults/secrets": "sensitive_data",
    "microsoft.keyvault/vaults/keys": "sensitive_data",
    "microsoft.storage/storageaccounts": "sensitive_data",
    "microsoft.storage/storageaccounts/blobservices/containers": "sensitive_data",
    "microsoft.cognitiveservices/accounts": "sensitive_data",
    "microsoft.cognitiveservices/accounts/deployments": "sensitive_data",
    "microsoft.sql/servers": "sensitive_data",
    "microsoft.sql/servers/databases": "sensitive_data",
    "microsoft.dbforpostgresql/flexibleservers": "sensitive_data",
    "microsoft.documentdb/databaseaccounts": "sensitive_data",
}


@dataclass(frozen=True)
class TerraformResource:
    address: str
    type: str
    name: str
    values: dict[str, Any]

    @property
    def provider(self) -> str:
        return classification_for_resource(self.type, self.values)[0]

    @property
    def category(self) -> str:
        return classification_for_resource(self.type, self.values)[1]

    @property
    def supported(self) -> bool:
        return resource_type_supported(self.type, self.values)


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
    iam_impacts: set[str] = field(default_factory=set)

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
            iam_impacts=sorted(self.iam_impacts),
            owner=self.owner,
            source=source,
            confidence=self.confidence,
            evidence=evidence,
        )


@dataclass
class TerraformAnalysis:
    contexts: dict[str, ContextEvidence]
    coverage: dict[str, Any]


@dataclass(frozen=True)
class IamGrant:
    privilege: str
    impacts: tuple[str, ...] = ()
    resource_refs: tuple[str, ...] = ()
    evidence: str = ""


@dataclass(frozen=True)
class NetworkPathEdge:
    target: str
    reason: str
    exposure_cap: str | None = None
    hidden: bool = False


@dataclass
class NetworkPathAnalysis:
    exposure_by_address: dict[str, str] = field(default_factory=dict)
    evidence_by_address: dict[str, list[str]] = field(default_factory=dict)
    privilege_by_address: dict[str, str] = field(default_factory=dict)
    privilege_evidence_by_address: dict[str, list[str]] = field(default_factory=dict)
    iam_impacts_by_address: dict[str, set[str]] = field(default_factory=dict)
    iam_target_evidence_by_address: dict[str, list[str]] = field(default_factory=dict)


class TerraformNetworkGraph:
    """Directed network reachability graph derived from Terraform resources."""

    def __init__(self, resources: list[TerraformResource]) -> None:
        self.resources = resources
        self.edges: dict[str, list[NetworkPathEdge]] = {}
        self.seeds: dict[str, tuple[str, list[str]]] = {}
        self.identity_privilege_by_ref: dict[str, str] = {}
        self.identity_evidence_by_ref: dict[str, list[str]] = {}
        self.identity_grants_by_ref: dict[str, list[IamGrant]] = {}
        self.sensitive_resources = [resource for resource in resources if resource.category == "sensitive_data"]
        self.privilege_by_address: dict[str, str] = {}
        self.privilege_evidence_by_address: dict[str, list[str]] = {}
        self.iam_impacts_by_address: dict[str, set[str]] = {}
        self.iam_target_evidence_by_address: dict[str, list[str]] = {}

    def analyze(self) -> NetworkPathAnalysis:
        self._build_identity_index()
        self._build_graph()
        exposure_by_node, evidence_by_node = self._walk()
        exposure_by_address: dict[str, str] = {}
        evidence_by_address: dict[str, list[str]] = {}
        for resource in self.resources:
            node = self._resource_node(resource)
            exposure = exposure_by_node.get(node, "unknown")
            if exposure != "unknown":
                exposure_by_address[resource.address] = exposure
                path = evidence_by_node.get(node, [])
                if path:
                    evidence_by_address[resource.address] = [f"terraform network path: {exposure} via {' -> '.join(path)}"]
        return NetworkPathAnalysis(
            exposure_by_address=exposure_by_address,
            evidence_by_address=evidence_by_address,
            privilege_by_address=self.privilege_by_address,
            privilege_evidence_by_address=self.privilege_evidence_by_address,
            iam_impacts_by_address=self.iam_impacts_by_address,
            iam_target_evidence_by_address=self.iam_target_evidence_by_address,
        )

    def _build_identity_index(self) -> None:
        for resource in self.resources:
            grant = iam_grant_for_resource(resource)
            if grant.privilege == "unknown":
                continue
            for ref in self._identity_refs_for_resource(resource):
                self._record_identity_grant(ref, grant)

        for resource in self.resources:
            if resource.type != "aws_iam_role_policy_attachment":
                continue
            role_refs = _value_reference_candidates(resource.values.get("role")) | _value_reference_candidates(resource.values.get("roles"))
            policy_refs = _value_reference_candidates(resource.values.get("policy_arn")) | _value_reference_candidates(resource.values.get("policy"))
            inherited_grants: list[IamGrant] = []
            for policy_ref in policy_refs:
                inherited_grants.extend(self.identity_grants_by_ref.get(policy_ref, []))
            for role_ref in role_refs:
                for grant in inherited_grants:
                    self._record_identity_grant(role_ref, grant)

        for resource in self.resources:
            if resource.category != "workload":
                continue
            privilege = "unknown"
            evidence: list[str] = []
            impacts: set[str] = set()
            target_evidence: list[str] = []
            for ref in self._workload_identity_refs(resource):
                ref_privilege = self.identity_privilege_by_ref.get(ref, "unknown")
                if ref_privilege == "unknown":
                    continue
                privilege = max_privilege(privilege, ref_privilege)
                evidence.extend(self.identity_evidence_by_ref.get(ref, []))
                for grant in self.identity_grants_by_ref.get(ref, []):
                    impacts.update(grant.impacts)
                    target_evidence.extend(self._target_evidence_for_grant(grant))
            if privilege != "unknown":
                self.privilege_by_address[resource.address] = privilege
                self.privilege_evidence_by_address[resource.address] = list(dict.fromkeys(evidence))
            if impacts:
                self.iam_impacts_by_address[resource.address] = impacts
            if target_evidence:
                self.iam_target_evidence_by_address[resource.address] = list(dict.fromkeys(target_evidence))

    def _build_graph(self) -> None:
        for resource in self.resources:
            self._add_resource_aliases(resource)
            if resource.type in {"aws_security_group", "aws_security_group_rule"}:
                self._add_aws_security_group(resource)
            elif resource.type in {"aws_lb", "aws_alb"}:
                self._add_aws_load_balancer(resource)
            elif resource.type in {"aws_lb_listener", "aws_alb_listener", "aws_lb_listener_rule", "aws_alb_listener_rule"}:
                self._add_aws_listener(resource)
            elif resource.type in {"aws_lb_target_group_attachment", "aws_alb_target_group_attachment"}:
                self._add_aws_target_group_attachment(resource)
            elif resource.type in {
                "azurerm_network_interface_backend_address_pool_association",
                "azurerm_network_interface_application_gateway_backend_address_pool_association",
            }:
                self._add_azure_backend_pool_association(resource)
            elif resource.type in {"kubernetes_service", "kubernetes_ingress", "kubernetes_ingress_v1"}:
                self._add_kubernetes_exposure(resource)
            else:
                self._add_generic_exposure(resource)
            self._add_cloud_backend_edges(resource)

        for resource in self.resources:
            if resource.category == "workload":
                self._add_workload_edges(resource)
            if resource.type in NETWORK_BRIDGE_RESOURCE_TYPES:
                self._seed(self._provider_bridge_node(resource.provider), "internal", f"{resource.address} network bridge")

    def _walk(self) -> tuple[dict[str, str], dict[str, list[str]]]:
        exposure_by_node: dict[str, str] = {}
        evidence_by_node: dict[str, list[str]] = {}
        queue: list[str] = []
        for node, (exposure, evidence) in self.seeds.items():
            if exposure_rank(exposure) > exposure_rank(exposure_by_node.get(node, "unknown")):
                exposure_by_node[node] = exposure
                evidence_by_node[node] = evidence
                queue.append(node)
        while queue:
            source = queue.pop(0)
            source_exposure = exposure_by_node[source]
            for edge in self.edges.get(source, []):
                candidate = _cap_exposure(source_exposure, edge.exposure_cap)
                if exposure_rank(candidate) <= exposure_rank(exposure_by_node.get(edge.target, "unknown")):
                    continue
                exposure_by_node[edge.target] = candidate
                if edge.hidden:
                    evidence_by_node[edge.target] = list(evidence_by_node.get(source, []))
                else:
                    evidence_by_node[edge.target] = list(evidence_by_node.get(source, [])) + [edge.reason]
                queue.append(edge.target)
        return exposure_by_node, evidence_by_node

    def _add_resource_aliases(self, resource: TerraformResource) -> None:
        resource_node = self._resource_node(resource)
        for ref in _resource_identifiers(resource):
            self._add_edge(self._ref_node(ref), resource_node, f"{ref} identifies {resource.address}", hidden=True)

    def _add_aws_security_group(self, resource: TerraformResource) -> None:
        exposure = exposure_for_resource(resource)
        target_refs = _resource_identifiers(resource) if resource.type == "aws_security_group" else _value_reference_candidates(resource.values.get("security_group_id"))
        if exposure in {"public", "external", "internal"}:
            for ref in target_refs:
                self._seed(self._sg_node(ref), exposure, f"{resource.address} {exposure} ingress")
        for source_ref in _security_group_source_refs(resource.values):
            for target_ref in target_refs:
                self._add_edge(self._sg_node(source_ref), self._sg_node(target_ref), f"{resource.address} allows traffic from {source_ref}", exposure_cap="internal")

    def _add_aws_load_balancer(self, resource: TerraformResource) -> None:
        exposure = exposure_for_resource(resource)
        if exposure in {"public", "internal"}:
            for ref in _resource_identifiers(resource):
                self._seed(self._lb_node(ref), exposure, f"{resource.address} {exposure} load balancer")

    def _add_aws_listener(self, resource: TerraformResource) -> None:
        lb_refs = _load_balancer_refs(resource.values)
        target_group_refs = _target_group_refs(resource.values)
        if not target_group_refs:
            return
        if not lb_refs:
            lb_refs = _value_reference_candidates(resource.values)
        for lb_ref in lb_refs:
            for target_group_ref in target_group_refs:
                self._add_edge(self._lb_node(lb_ref), self._target_group_node(target_group_ref), f"{resource.address} forwards to {target_group_ref}")

    def _add_aws_target_group_attachment(self, resource: TerraformResource) -> None:
        target_group_refs = _target_group_refs(resource.values)
        target_refs = _value_reference_candidates(resource.values.get("target_id"))
        target_refs.update(_value_reference_candidates(resource.values.get("target_ids")))
        target_refs.update(_value_reference_candidates(resource.values.get("instance_id")))
        if not target_group_refs or not target_refs:
            return
        for target_group_ref in target_group_refs:
            for target_ref in target_refs:
                self._add_edge(self._target_group_node(target_group_ref), self._ref_node(target_ref), f"{resource.address} attaches target {target_ref}")

    def _add_azure_backend_pool_association(self, resource: TerraformResource) -> None:
        pool_refs = _value_reference_candidates(resource.values.get("backend_address_pool_id"))
        pool_refs.update(_value_reference_candidates(resource.values.get("backend_address_pool_ids")))
        nic_refs = _network_interface_refs(resource.values)
        if not pool_refs or not nic_refs:
            return
        for pool_ref in pool_refs:
            for nic_ref in nic_refs:
                self._add_edge(self._ref_node(pool_ref), self._ref_node(nic_ref), f"{resource.address} attaches network interface {nic_ref}")

    def _add_kubernetes_exposure(self, resource: TerraformResource) -> None:
        exposure = exposure_for_resource(resource)
        if is_public_exposure(resource):
            exposure = "public"
        elif exposure == "unknown":
            exposure = "internal"
        if exposure == "unknown":
            return
        for name in _kubernetes_names_and_selectors(resource):
            self._seed(self._kubernetes_name_node(name), exposure, f"{resource.address} selects {name}")

    def _add_generic_exposure(self, resource: TerraformResource) -> None:
        exposure = exposure_for_resource(resource)
        if exposure == "unknown":
            return
        node = self._resource_node(resource)
        if resource.type in NETWORK_BRIDGE_RESOURCE_TYPES:
            self._seed(self._provider_bridge_node(resource.provider), "internal", f"{resource.address} network bridge")
        elif resource.category == "exposure" and resource.provider in {"azure", "gcp"}:
            self._seed(node, exposure, f"{resource.address} {exposure} exposure")
            for ref in _exposure_backend_refs(resource.values):
                self._add_edge(node, self._ref_node(ref), f"{resource.address} forwards to {ref}")
        elif exposure in {"public", "external", "internal"}:
            self._seed(node, exposure, f"{resource.address} {exposure} exposure")

    def _add_cloud_backend_edges(self, resource: TerraformResource) -> None:
        if resource.provider not in {"azure", "gcp"}:
            return
        if resource.category not in {"exposure", "supporting"} and resource.type not in {
            "google_compute_backend_service",
            "google_compute_region_network_endpoint_group",
        }:
            return
        node = self._resource_node(resource)
        for ref in _exposure_backend_refs(resource.values):
            self._add_edge(node, self._ref_node(ref), f"{resource.address} forwards to {ref}")

    def _add_workload_edges(self, resource: TerraformResource) -> None:
        resource_node = self._resource_node(resource)
        for sg_ref in _security_group_refs(resource.values):
            self._add_edge(self._sg_node(sg_ref), resource_node, f"{sg_ref} reaches {resource.address}")
            self._add_edge(resource_node, self._sg_node(sg_ref), f"{resource.address} can originate from {sg_ref}", exposure_cap="internal")
        for nic_ref in _network_interface_refs(resource.values):
            self._add_edge(self._ref_node(nic_ref), resource_node, f"{nic_ref} attaches to {resource.address}")
        for target_group_ref in _target_group_refs(resource.values):
            self._add_edge(self._target_group_node(target_group_ref), resource_node, f"{target_group_ref} targets {resource.address}")
        for task_def_ref in _value_reference_candidates(resource.values.get("task_definition")):
            self._add_edge(resource_node, self._ref_node(task_def_ref), f"{resource.address} runs task definition {task_def_ref}")
        if resource.type.startswith("kubernetes_"):
            for name in _kubernetes_names_and_selectors(resource):
                self._add_edge(self._kubernetes_name_node(name), resource_node, f"{name} selects {resource.address}")
                self._add_edge(resource_node, self._kubernetes_name_node(name), f"{resource.address} can reach cluster service {name}", exposure_cap="internal")
        if _has_private_network_attachment(resource.values):
            self._add_edge(self._provider_bridge_node(resource.provider), resource_node, f"{resource.provider} private network reaches {resource.address}", exposure_cap="internal")
        if _has_direct_public_address(resource.values):
            self._seed(resource_node, "public", f"{resource.address} direct public address")
        privilege = self.privilege_by_address.get(resource.address, "unknown")
        impacts = self.iam_impacts_by_address.get(resource.address, set())
        if privilege == "admin" or impacts & NETWORK_PIVOT_IAM_IMPACTS:
            impact_text = ",".join(sorted(impacts & NETWORK_PIVOT_IAM_IMPACTS)) or "admin_control"
            self._add_edge(resource_node, self._provider_bridge_node(resource.provider), f"{resource.address} IAM impact {impact_text} can alter provider network reachability", exposure_cap="internal")

    def _identity_refs_for_resource(self, resource: TerraformResource) -> set[str]:
        values = resource.values
        refs: set[str] = set()
        if resource.type in {"aws_iam_role", "aws_iam_policy"}:
            refs.update(_resource_identifiers(resource))
        if resource.type in {"aws_iam_role_policy", "aws_iam_role_policy_attachment"}:
            refs.update(_value_reference_candidates(values.get("role")))
            refs.update(_value_reference_candidates(values.get("roles")))
        if resource.type == "azurerm_role_assignment":
            refs.update(_value_reference_candidates(values.get("principal_id")))
            refs.update(_value_reference_candidates(values.get("principal_ids")))
        if resource.type == "azurerm_key_vault_access_policy":
            refs.update(_value_reference_candidates(values.get("object_id")))
            refs.update(_value_reference_candidates(values.get("application_id")))
            refs.update(_value_reference_candidates(values.get("principal_id")))
        if resource.type == "azurerm_user_assigned_identity":
            refs.update(_value_reference_candidates(values.get("principal_id")))
            refs.update(_value_reference_candidates(values.get("client_id")))
        if resource.type.startswith("google_") and "_iam_" in resource.type:
            refs.update(_member_identity_refs(values.get("member")))
            refs.update(_member_identity_refs(values.get("members")))
        if resource.type == "google_service_account":
            refs.update(_value_reference_candidates(values.get("account_id")))
            refs.update(_value_reference_candidates(values.get("email")))
        if resource.type in {"kubernetes_role_binding", "kubernetes_cluster_role_binding", "kubernetes_role_binding_v1", "kubernetes_cluster_role_binding_v1"}:
            refs.update(_kubernetes_subject_refs(values))
        return {ref for ref in refs if ref}

    def _workload_identity_refs(self, resource: TerraformResource) -> set[str]:
        refs = set(_resource_identifiers(resource))
        refs.update(_identity_value_refs(resource.values))
        if resource.type.startswith("kubernetes_"):
            refs.update(_kubernetes_names_and_selectors(resource))
        return {ref for ref in refs if ref}

    def _record_identity_grant(self, ref: str, grant: IamGrant) -> None:
        if not ref:
            return
        key = str(ref).lower()
        self.identity_privilege_by_ref[key] = max_privilege(self.identity_privilege_by_ref.get(key, "unknown"), grant.privilege)
        self.identity_evidence_by_ref.setdefault(key, []).append(grant.evidence)
        self.identity_grants_by_ref.setdefault(key, []).append(grant)

    def _target_evidence_for_grant(self, grant: IamGrant) -> list[str]:
        if not grant.resource_refs:
            return []
        target_resources: list[str] = []
        grant_refs = set(grant.resource_refs)
        for resource in self.sensitive_resources:
            if _references_any(grant_refs, _resource_identifiers(resource)):
                target_resources.append(resource.address)
        if target_resources:
            return [f"{grant.evidence} targets {address}" for address in sorted(set(target_resources))]
        if "*" in grant_refs and "data_access" in grant.impacts:
            return [f"{grant.evidence} targets any sensitive resource"]
        return []

    def _seed(self, node: str, exposure: str, evidence: str) -> None:
        current = self.seeds.get(node)
        if current and exposure_rank(current[0]) >= exposure_rank(exposure):
            return
        self.seeds[node] = (exposure, [evidence])

    def _add_edge(self, source: str, target: str, reason: str, exposure_cap: str | None = None, hidden: bool = False) -> None:
        if not source or not target:
            return
        self.edges.setdefault(source, []).append(NetworkPathEdge(target=target, reason=reason, exposure_cap=exposure_cap, hidden=hidden))

    @staticmethod
    def _resource_node(resource: TerraformResource) -> str:
        return f"resource:{resource.address.lower()}"

    @staticmethod
    def _ref_node(ref: str) -> str:
        return f"ref:{str(ref).lower()}"

    @staticmethod
    def _sg_node(ref: str) -> str:
        return f"aws:sg:{str(ref).lower()}"

    @staticmethod
    def _target_group_node(ref: str) -> str:
        return f"aws:tg:{str(ref).lower()}"

    @staticmethod
    def _lb_node(ref: str) -> str:
        return f"aws:lb:{str(ref).lower()}"

    @staticmethod
    def _provider_bridge_node(provider: str) -> str:
        return f"provider:{provider}:network-bridge"

    @staticmethod
    def _kubernetes_name_node(name: str) -> str:
        return f"kubernetes:name:{str(name).lower()}"


class TerraformAnalyzer:
    """Analyze Terraform plan JSON and infer conservative artifact context."""

    def __init__(self, plan: dict[str, Any], artifacts: list[Artifact], source_name: str = "terraform-plan") -> None:
        self.plan = plan
        self.artifacts = artifacts
        self.source_name = source_name
        self.resources = extract_resources(plan)
        self._resource_by_address = {resource.address: resource for resource in self.resources}
        self._global_exposure_by_provider = self._global_exposure()
        self._public_security_groups = self._public_security_group_refs()
        self._external_security_groups = self._external_security_group_refs()
        self._internal_security_groups = self._internal_security_group_refs()
        self._public_target_groups = self._public_target_group_refs()
        self._internal_target_groups = self._internal_target_group_refs()
        self._public_ecs_task_definitions = self._public_ecs_task_definition_refs()
        self._ecs_task_definition_exposure = self._ecs_task_definition_exposure_refs()
        self._public_functions = self._public_function_names()
        self._public_cloud_run_services = self._public_cloud_run_services()
        self._kubernetes_workload_exposure = self._kubernetes_workload_exposure()
        self._network_paths = TerraformNetworkGraph(self.resources).analyze()

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
                exposure = exposure_for_matched_workload(
                    resource,
                    self._global_exposure_by_provider,
                    self._public_functions,
                    self._public_cloud_run_services,
                    self._public_security_groups,
                    self._external_security_groups,
                    self._internal_security_groups,
                    self._public_target_groups,
                    self._internal_target_groups,
                    self._public_ecs_task_definitions,
                    self._ecs_task_definition_exposure,
                    self._kubernetes_workload_exposure,
                )
                path_exposure = self._network_paths.exposure_by_address.get(resource.address, "unknown")
                exposure = max_exposure(exposure, path_exposure)
                accumulator.exposure = max_exposure(accumulator.exposure, exposure)
                for item in self._network_paths.evidence_by_address.get(resource.address, []):
                    accumulator.evidence.append(item)
                if exposure != "unknown":
                    accumulator.evidence.append(f"terraform exposure inference: {exposure} via {resource.address}")
                path_privilege = self._network_paths.privilege_by_address.get(resource.address, "unknown")
                accumulator.privilege = max_privilege(accumulator.privilege, path_privilege)
                for item in self._network_paths.privilege_evidence_by_address.get(resource.address, []):
                    accumulator.evidence.append(f"terraform identity path: {item}")
                for item in self._network_paths.iam_target_evidence_by_address.get(resource.address, []):
                    accumulator.evidence.append(f"terraform identity target: {item}")
                iam_impacts = self._network_paths.iam_impacts_by_address.get(resource.address, set())
                accumulator.iam_impacts.update(iam_impacts)
                iam_criticality = _network_iam_criticality(exposure, path_privilege, iam_impacts)
                accumulator.criticality = max_criticality(accumulator.criticality, iam_criticality)
                if iam_criticality != "unknown":
                    accumulator.evidence.append(f"terraform IAM impact criticality: {iam_criticality} via {resource.address} impacts={','.join(sorted(iam_impacts)) or path_privilege}")
                match_rows.append({"artifact": artifact.name, "resource": resource.address, "type": resource.type, "provider": resource.provider, "image": matched_image, "match_method": match_method, "match_score": match_score})
            if accumulator.matched_resources:
                contexts[artifact.name] = accumulator.as_context(source=f"terraform:{self.source_name}")
        return TerraformAnalysis(contexts=contexts, coverage=coverage_report(self.resources, self.artifacts, match_rows))

    def _global_exposure(self) -> dict[str, str]:
        exposure: dict[str, str] = {}
        for resource in self.resources:
            if resource.type not in NETWORK_BRIDGE_RESOURCE_TYPES:
                continue
            exposure[resource.provider] = max_exposure(exposure.get(resource.provider, "unknown"), "internal")
            exposure["all"] = max_exposure(exposure.get("all", "unknown"), "internal")
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

    def _public_security_group_refs(self) -> set[str]:
        public: set[str] = set()
        security_groups = [resource for resource in self.resources if resource.type == "aws_security_group"]
        for resource in security_groups:
            if is_public_exposure(resource):
                public.update(_resource_identifiers(resource))
        for resource in self.resources:
            if resource.type == "aws_security_group_rule" and is_public_exposure(resource):
                public.update(_value_reference_candidates(resource.values.get("security_group_id")))

        return public

    def _internal_security_group_refs(self) -> set[str]:
        internal: set[str] = set()
        security_groups = [resource for resource in self.resources if resource.type == "aws_security_group"]
        for resource in security_groups:
            if not is_public_exposure(resource) and _aws_security_group_has_internal_ingress(resource.values):
                internal.update(_resource_identifiers(resource))
        for resource in self.resources:
            if resource.type == "aws_security_group_rule" and not is_public_exposure(resource) and _aws_security_group_has_internal_ingress(resource.values):
                internal.update(_value_reference_candidates(resource.values.get("security_group_id")))

        changed = True
        while changed:
            changed = False
            for resource in security_groups:
                identifiers = _resource_identifiers(resource)
                if identifiers & internal or identifiers & self._public_security_groups:
                    continue
                source_refs = _security_group_source_refs(resource.values)
                if _references_any(source_refs, internal) or _references_any(source_refs, self._external_security_groups) or _references_any(source_refs, self._public_security_groups):
                    internal.update(identifiers)
                    changed = True
        return internal

    def _external_security_group_refs(self) -> set[str]:
        external: set[str] = set()
        security_groups = [resource for resource in self.resources if resource.type == "aws_security_group"]
        for resource in security_groups:
            if _aws_security_group_ingress_exposure(resource.values) == "external":
                external.update(_resource_identifiers(resource))
        for resource in self.resources:
            if resource.type == "aws_security_group_rule" and _aws_security_group_ingress_exposure(resource.values) == "external":
                external.update(_value_reference_candidates(resource.values.get("security_group_id")))
        return external

    def _public_load_balancer_refs(self) -> set[str]:
        public: set[str] = set()
        for resource in self.resources:
            if resource.type in {"aws_lb", "aws_alb"} and is_public_exposure(resource):
                public.update(_resource_identifiers(resource))
        return public

    def _internal_load_balancer_refs(self) -> set[str]:
        internal: set[str] = set()
        for resource in self.resources:
            if resource.type in {"aws_lb", "aws_alb"} and not is_public_exposure(resource):
                internal.update(_resource_identifiers(resource))
        return internal

    def _public_target_group_refs(self) -> set[str]:
        public_lbs = self._public_load_balancer_refs()
        public_tgs: set[str] = set()
        target_groups = [resource for resource in self.resources if resource.type in {"aws_lb_target_group", "aws_alb_target_group"}]
        for resource in self.resources:
            if resource.type not in {"aws_lb_listener", "aws_alb_listener", "aws_lb_listener_rule", "aws_alb_listener_rule"}:
                continue
            if resource.type in {"aws_lb_listener", "aws_alb_listener"} and not _references_any(_load_balancer_refs(resource.values), public_lbs):
                continue
            public_tgs.update(_value_reference_candidates(_target_group_refs(resource.values)))
        for target_group in target_groups:
            if _references_any(_resource_identifiers(target_group), public_tgs):
                public_tgs.update(_resource_identifiers(target_group))
        return public_tgs

    def _internal_target_group_refs(self) -> set[str]:
        internal_lbs = self._internal_load_balancer_refs()
        internal_tgs: set[str] = set()
        target_groups = [resource for resource in self.resources if resource.type in {"aws_lb_target_group", "aws_alb_target_group"}]
        for resource in self.resources:
            if resource.type not in {"aws_lb_listener", "aws_alb_listener", "aws_lb_listener_rule", "aws_alb_listener_rule"}:
                continue
            if resource.type in {"aws_lb_listener", "aws_alb_listener"} and not _references_any(_load_balancer_refs(resource.values), internal_lbs):
                continue
            internal_tgs.update(_value_reference_candidates(_target_group_refs(resource.values)))
        for target_group in target_groups:
            if _references_any(_resource_identifiers(target_group), internal_tgs):
                internal_tgs.update(_resource_identifiers(target_group))
        return internal_tgs

    def _public_ecs_task_definition_refs(self) -> set[str]:
        public_task_defs: set[str] = set()
        for resource in self.resources:
            if resource.type != "aws_ecs_service":
                continue
            if not _ecs_service_is_public(resource.values, self._public_security_groups, self._public_target_groups):
                continue
            public_task_defs.update(_value_reference_candidates(resource.values.get("task_definition")))
        for resource in self.resources:
            if resource.type == "aws_ecs_task_definition" and _references_any(_resource_identifiers(resource), public_task_defs):
                public_task_defs.update(_resource_identifiers(resource))
        return public_task_defs

    def _ecs_task_definition_exposure_refs(self) -> dict[str, str]:
        exposure_by_ref: dict[str, str] = {}
        for resource in self.resources:
            if resource.type != "aws_ecs_service":
                continue
            exposure = _ecs_service_exposure(
                resource.values,
                self._public_security_groups,
                self._external_security_groups,
                self._internal_security_groups,
                self._public_target_groups,
                self._internal_target_groups,
                self._provider_network_fallback(resource.provider),
            )
            if exposure == "unknown":
                continue
            for ref in _value_reference_candidates(resource.values.get("task_definition")):
                exposure_by_ref[ref] = max_exposure(exposure_by_ref.get(ref, "unknown"), exposure)
        for resource in self.resources:
            if resource.type != "aws_ecs_task_definition":
                continue
            identifiers = _resource_identifiers(resource)
            matched = [level for ref, level in exposure_by_ref.items() if _references_any(identifiers, {ref})]
            for level in matched:
                for identifier in identifiers:
                    exposure_by_ref[identifier] = max_exposure(exposure_by_ref.get(identifier, "unknown"), level)
        return exposure_by_ref

    def _public_cloud_run_services(self) -> set[str]:
        public: set[str] = set()
        for resource in self.resources:
            if resource.type not in {"google_cloud_run_service_iam_member", "google_cloud_run_service_iam_binding", "google_cloud_run_v2_service_iam_member", "google_cloud_run_v2_service_iam_binding"}:
                continue
            if not _iam_member_is_public_invoker(resource.values):
                continue
            service = resource.values.get("service") or resource.values.get("name")
            if service:
                public.add(str(service))
        return public

    def _kubernetes_workload_exposure(self) -> dict[str, str]:
        exposure_by_name: dict[str, str] = {}
        for resource in self.resources:
            if resource.type not in {"kubernetes_service", "kubernetes_ingress", "kubernetes_ingress_v1"}:
                continue
            exposure = exposure_for_resource(resource)
            if is_public_exposure(resource):
                exposure = "public"
            elif exposure == "unknown":
                exposure = "internal"
            for name in _kubernetes_names_and_selectors(resource):
                exposure_by_name[name] = max_exposure(exposure_by_name.get(name, "unknown"), exposure)
        return exposure_by_name

    def _provider_network_fallback(self, provider: str) -> str:
        return self._global_exposure_by_provider.get(provider, "unknown")

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


def _normalized_arm_type(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip().strip('"').strip("'")
    if not text:
        return None
    return text.split("@", 1)[0].lower()


def azapi_arm_category(value: Any) -> str | None:
    """Return a semantic category for an AzAPI ARM resource type."""

    arm_type = _normalized_arm_type(value)
    if not arm_type:
        return None
    if arm_type in AZAPI_ARM_TYPE_TO_CATEGORY:
        return AZAPI_ARM_TYPE_TO_CATEGORY[arm_type]
    # Child resources often add one or more path segments. Prefer the most
    # specific parent that is explicitly declared above.
    parts = arm_type.split("/")
    while len(parts) > 2:
        parts.pop()
        parent = "/".join(parts)
        if parent in AZAPI_ARM_TYPE_TO_CATEGORY:
            return AZAPI_ARM_TYPE_TO_CATEGORY[parent]
    return None


def classification_for_resource(resource_type: str, values: dict[str, Any] | None = None) -> tuple[str, str]:
    if resource_type.startswith("azapi_"):
        return "azure", azapi_arm_category((values or {}).get("type")) or "unclassified"
    if resource_type in SUPPORTED_TYPE_TO_CLASS:
        return SUPPORTED_TYPE_TO_CLASS[resource_type]
    return provider_for_type(resource_type), "unclassified"


def resource_type_supported(resource_type: str, values: dict[str, Any] | None = None) -> bool:
    if resource_type.startswith("azapi_"):
        return azapi_arm_category((values or {}).get("type")) is not None
    return resource_type in SUPPORTED_TYPE_TO_CLASS


def provider_for_type(resource_type: str) -> str:
    if resource_type.startswith("aws_"):
        return "aws"
    if resource_type.startswith("azurerm_") or resource_type.startswith("azuread_") or resource_type.startswith("azapi_"):
        return "azure"
    if resource_type.startswith("google_"):
        return "gcp"
    if resource_type.startswith("kubernetes_") or resource_type.startswith("kubectl_") or resource_type.startswith("helm_"):
        return "kubernetes"
    if resource_type.startswith("random_") or resource_type.startswith("time_") or resource_type in {"null_resource", "local_file", "template_file", "terraform_data", "terracurl_request"}:
        return "terraform"
    if resource_type.startswith("docker_"):
        return "docker"
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
        str(values.get("family") or ""),
        str(values.get("container_name") or ""),
    }
    artifact_name = artifact.name.lower()
    return any(name and (artifact_name == name.lower() or artifact_name in name.lower()) for name in names)


def exposure_for_matched_workload(
    resource: TerraformResource,
    global_exposure_by_provider: dict[str, str],
    public_functions: set[str],
    public_cloud_run_services: set[str],
    public_security_groups: set[str] | None = None,
    external_security_groups: set[str] | None = None,
    internal_security_groups: set[str] | None = None,
    public_target_groups: set[str] | None = None,
    internal_target_groups: set[str] | None = None,
    public_ecs_task_definitions: set[str] | None = None,
    ecs_task_definition_exposure: dict[str, str] | None = None,
    kubernetes_workload_exposure: dict[str, str] | None = None,
) -> str:
    values = resource.values
    public_security_groups = public_security_groups or set()
    external_security_groups = external_security_groups or set()
    internal_security_groups = internal_security_groups or set()
    public_target_groups = public_target_groups or set()
    internal_target_groups = internal_target_groups or set()
    public_ecs_task_definitions = public_ecs_task_definitions or set()
    ecs_task_definition_exposure = ecs_task_definition_exposure or {}
    kubernetes_workload_exposure = kubernetes_workload_exposure or {}
    provider_fallback = _provider_network_fallback(global_exposure_by_provider.get(resource.provider, "unknown"))
    if resource.type == "aws_apprunner_service":
        public_network = values.get("publicly_accessible")
        if public_network is None:
            public_network = values.get("is_publicly_accessible")
        return "public" if public_network is not False else "internal"
    if resource.type == "aws_ecs_service":
        return _ecs_service_exposure(values, public_security_groups, external_security_groups, internal_security_groups, public_target_groups, internal_target_groups, provider_fallback)
    if resource.type == "aws_ecs_task_definition":
        if _references_any(_resource_identifiers(resource), public_ecs_task_definitions):
            return "public"
        exposure = _max_referenced_exposure(_resource_identifiers(resource), ecs_task_definition_exposure)
        return exposure if exposure != "unknown" else _workload_network_exposure(values, provider_fallback)
    if resource.type == "aws_lambda_function":
        names = {str(values.get("function_name") or ""), str(values.get("name") or ""), str(values.get("arn") or "")}
        if any(name in public_functions for name in names if name):
            return "public"
        return _workload_network_exposure(values, provider_fallback)
    if resource.type in {"aws_instance", "aws_launch_template", "aws_batch_job_definition", "aws_eks_cluster"}:
        if _has_direct_public_address(values) or _references_any(_security_group_refs(values), public_security_groups):
            return "public"
        if _references_any(_security_group_refs(values), external_security_groups):
            return "external"
        if _references_any(_security_group_refs(values), internal_security_groups):
            return "internal"
        return _workload_network_exposure(values, provider_fallback)
    if resource.type in {"azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_app_service", "azurerm_function_app", "azurerm_linux_function_app", "azurerm_windows_function_app"}:
        public_network = values.get("public_network_access_enabled")
        if public_network is False:
            return "internal" if provider_fallback == "internal" else "private"
        return "public"
    if resource.type == "azurerm_container_app":
        if _azure_container_app_external_ingress(values):
            return "public"
        if _azure_container_app_has_ingress(values):
            return "internal"
        return _workload_network_exposure(values, provider_fallback)
    if resource.type.startswith("azapi_") and _normalized_arm_type(values.get("type")) == "microsoft.app/containerapps":
        if _azure_container_app_external_ingress(values):
            return "public"
        if _azure_container_app_has_ingress(values):
            return "internal"
        return _workload_network_exposure(values, provider_fallback)
    if resource.type in {"azurerm_container_group", "azurerm_kubernetes_cluster", "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_virtual_machine"}:
        if _has_direct_public_address(values):
            return "public"
        return _workload_network_exposure(values, provider_fallback)
    if resource.type in {"google_cloud_run_service", "google_cloud_run_v2_service"}:
        names = {str(values.get("name") or ""), str(resource.name or "")}
        if any(name in public_cloud_run_services for name in names if name):
            return "public"
        ingress = str(values.get("ingress") or "").lower()
        if ingress in {"all", "ingress_traffic_all", "all_traffic"}:
            return "external"
        if "internal" in ingress:
            return "internal"
        return _workload_network_exposure(values, provider_fallback)
    if resource.type in {"google_cloudfunctions_function", "google_cloudfunctions2_function"}:
        if _references_any(_resource_identifiers(resource), public_functions):
            return "public"
        return _workload_network_exposure(values, provider_fallback)
    if resource.type in {"google_container_cluster", "google_compute_instance", "google_compute_instance_template"}:
        if _has_direct_public_address(values):
            return "public"
        return _workload_network_exposure(values, provider_fallback)
    if resource.type.startswith("kubernetes_") and resource.type != "kubernetes_manifest":
        exposure = _max_referenced_exposure(_kubernetes_names_and_selectors(resource), kubernetes_workload_exposure)
        return exposure if exposure != "unknown" else _workload_network_exposure(values, provider_fallback)
    return _workload_network_exposure(values, provider_fallback)


def _azure_container_app_external_ingress(values: dict[str, Any]) -> bool:
    ingress = values.get("ingress")
    if isinstance(ingress, list):
        return any(isinstance(item, dict) and bool(item.get("external_enabled") or item.get("external")) for item in ingress)
    if isinstance(ingress, dict):
        return bool(ingress.get("external_enabled") or ingress.get("external"))
    return False


def _azure_container_app_has_ingress(values: dict[str, Any]) -> bool:
    ingress = values.get("ingress")
    if isinstance(ingress, list):
        return any(isinstance(item, dict) for item in ingress)
    return isinstance(ingress, dict)


def exposure_for_resource(resource: TerraformResource) -> str:
    """Classify a resource's network exposure without assigning it to an artifact."""

    values = resource.values
    rtype = resource.type
    if is_public_exposure(resource):
        return "public"
    if _has_direct_public_address(values):
        return "public"
    if rtype in NETWORK_BRIDGE_RESOURCE_TYPES:
        return "internal"
    if rtype in {"aws_security_group", "aws_security_group_rule"}:
        return _aws_security_group_ingress_exposure(values)
    if rtype in {"azurerm_network_security_group", "azurerm_network_security_rule"}:
        return _azure_nsg_ingress_exposure(values)
    if rtype == "google_compute_firewall":
        return _gcp_firewall_exposure(values)
    if rtype in {"aws_lb", "aws_alb", "azurerm_lb", "azurerm_application_gateway"}:
        return "internal"
    if rtype in {"google_compute_forwarding_rule", "google_compute_global_forwarding_rule"} and str(values.get("load_balancing_scheme") or "").lower().startswith("internal"):
        return "internal"
    if rtype in {"kubernetes_service", "kubernetes_ingress", "kubernetes_ingress_v1"}:
        return _kubernetes_exposure_level(values)
    if rtype in PRIVATE_NETWORK_RESOURCE_TYPES or _has_private_network_attachment(values):
        return "private"
    return "unknown"


def is_public_exposure(resource: TerraformResource) -> bool:
    values = resource.values
    rtype = resource.type
    if rtype in {"aws_lb", "aws_alb", "azurerm_public_ip", "azurerm_application_gateway", "azurerm_lb", "azurerm_frontdoor_endpoint", "azurerm_cdn_frontdoor_endpoint", "google_compute_forwarding_rule", "google_compute_global_forwarding_rule"}:
        if str(values.get("internal") or "").lower() == "true":
            return False
        if rtype in {"azurerm_application_gateway", "azurerm_lb"} and _azure_has_private_frontend_only(values):
            return False
        if rtype in {"google_compute_forwarding_rule", "google_compute_global_forwarding_rule"} and str(values.get("load_balancing_scheme") or "").lower().startswith("internal"):
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
    if rtype in {"google_cloud_run_service_iam_member", "google_cloud_run_service_iam_binding", "google_cloud_run_v2_service_iam_member", "google_cloud_run_v2_service_iam_binding", "google_cloudfunctions_function_iam_member", "google_cloudfunctions2_function_iam_member"}:
        return _iam_member_is_public_invoker(values)
    if rtype.startswith("azapi_") and resource.category == "exposure":
        return True
    if rtype in {"kubernetes_service", "kubernetes_ingress", "kubernetes_ingress_v1"}:
        return _kubernetes_exposure_is_public(values)
    if rtype in {"aws_apigatewayv2_api", "aws_api_gateway_rest_api", "aws_cloudfront_distribution", "google_cloud_run_domain_mapping"}:
        return True
    return False


def _aws_security_group_is_public(values: dict[str, Any]) -> bool:
    return _aws_security_group_ingress_exposure(values) == "public"


def _aws_security_group_has_internal_ingress(values: dict[str, Any]) -> bool:
    return _aws_security_group_ingress_exposure(values) == "internal"


def _aws_security_group_ingress_exposure(values: dict[str, Any]) -> str:
    rules: list[Any] = []
    for key in ("ingress", "ingress_with_cidr_blocks"):
        item = values.get(key)
        if isinstance(item, list):
            rules.extend(item)
        elif isinstance(item, dict):
            rules.append(item)
    if values.get("type") == "ingress":
        rules.append(values)
    result = "unknown"
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        cidrs = _listify(rule.get("cidr_blocks")) + _listify(rule.get("ipv6_cidr_blocks"))
        sources = cidrs + _listify(rule.get("source_security_group_id")) + _listify(rule.get("source_security_group_ids")) + _listify(rule.get("security_groups"))
        exposure = "unknown"
        for source in sources:
            exposure = max_exposure(exposure, _network_source_exposure(source))
        if exposure != "unknown":
            result = max_exposure(result, exposure)
    return result


def _azure_nsg_is_public(values: dict[str, Any]) -> bool:
    return _azure_nsg_ingress_exposure(values) == "public"


def _azure_nsg_ingress_exposure(values: dict[str, Any]) -> str:
    rules: list[Any] = []
    for key in ("security_rule", "security_rules"):
        item = values.get(key)
        if isinstance(item, list):
            rules.extend(item)
        elif isinstance(item, dict):
            rules.append(item)
    if values.get("source_address_prefix") or values.get("source_address_prefixes"):
        rules.append(values)
    result = "unknown"
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        direction = str(rule.get("direction") or "Inbound").lower()
        access = str(rule.get("access") or "Allow").lower()
        if direction != "inbound" or access != "allow":
            continue
        sources = _listify(rule.get("source_address_prefix")) + _listify(rule.get("source_address_prefixes"))
        exposure = "unknown"
        for source in sources:
            exposure = max_exposure(exposure, _network_source_exposure(source))
        if exposure != "unknown":
            result = max_exposure(result, exposure)
    return result


def _gcp_firewall_is_public(values: dict[str, Any]) -> bool:
    return _gcp_firewall_exposure(values) == "public"


def _gcp_firewall_exposure(values: dict[str, Any]) -> str:
    ranges = _listify(values.get("source_ranges"))
    direction = str(values.get("direction") or "INGRESS").lower()
    disabled = bool(values.get("disabled"))
    if disabled or direction != "ingress":
        return "unknown"
    exposure = "unknown"
    for item in ranges:
        exposure = max_exposure(exposure, _network_source_exposure(item))
    return exposure


def _iam_member_is_public_invoker(values: dict[str, Any]) -> bool:
    role = str(values.get("role") or "").lower()
    members = _listify(values.get("member")) + _listify(values.get("members"))
    return "invoker" in role and any(str(member).lower() in {"allusers", "allauthenticatedusers"} for member in members)


def _kubernetes_exposure_is_public(values: dict[str, Any]) -> bool:
    return _kubernetes_exposure_level(values) == "public"


def _kubernetes_exposure_level(values: dict[str, Any]) -> str:
    service_type = str(values.get("type") or "").lower()
    if service_type == "loadbalancer":
        return "public"
    if service_type in {"clusterip", "nodeport"}:
        return "internal"
    annotations = values.get("annotations") if isinstance(values.get("annotations"), dict) else {}
    if any("ingress" in str(key).lower() for key in annotations):
        return "public"
    if values.get("rules") or values.get("spec"):
        return "public"
    return "unknown"


def _ecs_service_is_public(values: dict[str, Any], public_security_groups: set[str], public_target_groups: set[str]) -> bool:
    return _references_any(_security_group_refs(values), public_security_groups) or _references_any(_target_group_refs(values), public_target_groups)


def _ecs_service_exposure(
    values: dict[str, Any],
    public_security_groups: set[str],
    external_security_groups: set[str],
    internal_security_groups: set[str],
    public_target_groups: set[str],
    internal_target_groups: set[str],
    provider_fallback: str,
) -> str:
    security_group_refs = _security_group_refs(values)
    target_group_refs = _target_group_refs(values)
    if _references_any(security_group_refs, public_security_groups) or _references_any(target_group_refs, public_target_groups):
        return "public"
    if _references_any(security_group_refs, external_security_groups):
        return "external"
    if _references_any(security_group_refs, internal_security_groups) or _references_any(target_group_refs, internal_target_groups):
        return "internal"
    if security_group_refs or target_group_refs or _has_private_network_attachment(values):
        return max_exposure("private", provider_fallback)
    return _workload_network_exposure(values, provider_fallback)


def _provider_network_fallback(exposure: str) -> str:
    return exposure if exposure == "internal" else "unknown"


def _workload_network_exposure(values: dict[str, Any], provider_fallback: str) -> str:
    if _has_direct_public_address(values):
        return "public"
    if _has_private_network_attachment(values):
        return max_exposure("private", provider_fallback)
    return "unknown"


def _cap_exposure(value: str, cap: str | None) -> str:
    if not cap or exposure_rank(value) <= exposure_rank(cap):
        return value
    return cap


def _exposure_backend_refs(values: Any) -> set[str]:
    refs: set[str] = set()
    backend_tokens = {
        "backend",
        "target",
        "target_group",
        "pool",
        "endpoint",
        "network_endpoint_group",
        "instance_group",
        "service",
    }

    def walk(value: Any, key_hint: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                key_l = str(key).lower()
                if any(token in key_l for token in backend_tokens):
                    refs.update(_value_reference_candidates(item))
                if isinstance(item, (dict, list)):
                    walk(item, key_l)
        elif isinstance(value, list):
            for item in value:
                walk(item, key_hint)

    walk(values)
    return refs


def _identity_value_refs(values: Any) -> set[str]:
    refs: set[str] = set()
    identity_keys = {
        "role",
        "role_arn",
        "task_role_arn",
        "execution_role_arn",
        "iam_role",
        "iam_instance_profile",
        "instance_profile",
        "service_account",
        "service_account_name",
        "service_account_email",
        "service_account_id",
        "serviceaccountname",
        "identity",
        "identity_id",
        "identity_ids",
        "principal_id",
        "principal_ids",
        "client_id",
        "managed_identity_id",
        "user_assigned_identity_id",
        "user_assigned_identity_ids",
    }
    if isinstance(values, dict):
        for key, value in values.items():
            key_l = str(key).lower()
            if key_l in identity_keys or "identity" in key_l or "service_account" in key_l:
                refs.update(_value_reference_candidates(value))
                refs.update(_member_identity_refs(value))
            if key_l in {"annotations", "metadata"}:
                refs.update(_value_reference_candidates(value))
            if isinstance(value, (dict, list)):
                refs.update(_identity_value_refs(value))
    elif isinstance(values, list):
        for item in values:
            refs.update(_identity_value_refs(item))
    return refs


def _member_identity_refs(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        for item in value.values():
            refs.update(_member_identity_refs(item))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            refs.update(_member_identity_refs(item))
    elif value is not None:
        text = str(value).strip().strip('"').strip("'").lower()
        if not text:
            return refs
        refs.update(_value_reference_candidates(text))
        if text.startswith("serviceaccount:"):
            text = text.split(":", 1)[1]
            refs.add(text)
        if "@" in text:
            refs.add(text.split("@", 1)[0])
    return refs


def _kubernetes_subject_refs(values: Any) -> set[str]:
    refs: set[str] = set()

    def add_subject(value: Any) -> None:
        if isinstance(value, dict):
            name = value.get("name")
            namespace = value.get("namespace")
            refs.update(_value_reference_candidates(name))
            if name and namespace:
                refs.add(f"{namespace}/{name}".lower())
            for key in ("service_account", "serviceaccount", "service_account_name"):
                refs.update(_value_reference_candidates(value.get(key)))
        elif isinstance(value, list):
            for item in value:
                add_subject(item)

    if isinstance(values, dict):
        for key, value in values.items():
            key_l = str(key).lower()
            if key_l in {"subject", "subjects"}:
                add_subject(value)
            elif key_l in {"service_account", "serviceaccount", "service_account_name"}:
                refs.update(_value_reference_candidates(value))
            if isinstance(value, (dict, list)):
                refs.update(_kubernetes_subject_refs(value))
    elif isinstance(values, list):
        for item in values:
            refs.update(_kubernetes_subject_refs(item))
    return refs


def _max_referenced_exposure(candidates: set[str], exposure_by_ref: dict[str, str]) -> str:
    exposure = "unknown"
    for reference, level in exposure_by_ref.items():
        if _references_any(candidates, {reference}):
            exposure = max_exposure(exposure, level)
    return exposure


def _has_direct_public_address(values: Any) -> bool:
    if isinstance(values, dict):
        for key, value in values.items():
            key_l = str(key).lower()
            if key_l in {"associate_public_ip_address", "assign_public_ip", "map_public_ip_on_launch"} and bool(value):
                return True
            if key_l in {"public_ip", "public_ip_address", "public_ips", "nat_ip", "nat_ips"} and _has_truthy_public_value(value):
                return True
            if key_l == "access_config" and value not in (None, [], {}):
                return True
            if isinstance(value, (dict, list)) and _has_direct_public_address(value):
                return True
    elif isinstance(values, list):
        return any(_has_direct_public_address(item) for item in values)
    return False


def _has_truthy_public_value(value: Any) -> bool:
    if isinstance(value, list):
        return any(_has_truthy_public_value(item) for item in value)
    if isinstance(value, dict):
        return any(_has_truthy_public_value(item) for item in value.values())
    if value is None or value is False:
        return False
    text = str(value).strip().lower()
    return bool(text and text not in {"false", "none", "null", "0.0.0.0", "::"})


def _azure_has_private_frontend_only(values: dict[str, Any]) -> bool:
    frontends = values.get("frontend_ip_configuration") or values.get("frontend_ip_configurations")
    if isinstance(frontends, dict):
        frontends = [frontends]
    if not isinstance(frontends, list) or not frontends:
        return False
    saw_private = False
    for frontend in frontends:
        if not isinstance(frontend, dict):
            continue
        if frontend.get("public_ip_address_id") or frontend.get("public_ip_address"):
            return False
        if frontend.get("private_ip_address") or frontend.get("subnet_id"):
            saw_private = True
    return saw_private


def _has_private_network_attachment(values: Any) -> bool:
    private_keys = {
        "subnet",
        "subnets",
        "subnet_id",
        "subnet_ids",
        "vpc_id",
        "vpc_config",
        "network",
        "networks",
        "network_interface",
        "network_interfaces",
        "network_configuration",
        "security_group",
        "security_groups",
        "security_group_ids",
        "vpc_security_group_ids",
        "virtual_network_subnet_id",
        "private_endpoint",
        "private_ip_address",
        "private_ip_addresses",
        "private_cluster_config",
        "connector",
        "vpc_connector",
        "vpc_access",
    }
    if isinstance(values, dict):
        for key, value in values.items():
            key_l = str(key).lower()
            if key_l in private_keys and value not in (None, [], {}, ""):
                return True
            if isinstance(value, (dict, list)) and _has_private_network_attachment(value):
                return True
    elif isinstance(values, list):
        return any(_has_private_network_attachment(item) for item in values)
    return False


def _network_source_exposure(value: Any) -> str:
    if value is None:
        return "unknown"
    text = str(value).strip().strip('"').strip("'").lower()
    if not text:
        return "unknown"
    if text in PUBLIC_TOKEN_VALUES:
        return "public"
    if text in INTERNAL_TOKEN_VALUES or text.startswith("sg-"):
        return "internal"
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return "unknown"
    if network.version in {4, 6} and network.is_global:
        return "external"
    return "internal"


def _resource_identifiers(resource: TerraformResource) -> set[str]:
    identifiers = {
        resource.address,
        resource.name,
        f"{resource.type}.{resource.name}" if resource.name else "",
    }
    for key in ("id", "arn", "name", "function_name", "service_name", "family"):
        value = resource.values.get(key)
        if isinstance(value, str):
            identifiers.add(value)
    expanded: set[str] = set()
    for item in identifiers:
        if not item:
            continue
        text = str(item).strip()
        expanded.add(text.lower())
        if "." in text and not text.endswith((".id", ".arn", ".name")):
            expanded.add(f"{text}.id".lower())
            expanded.add(f"{text}.arn".lower())
            expanded.add(f"{text}.name".lower())
    return expanded


def _references_any(values: Any, references: set[str]) -> bool:
    if not references:
        return False
    candidates = _value_reference_candidates(values)
    for candidate in candidates:
        for reference in references:
            if reference and (candidate == reference or reference in candidate or candidate in reference):
                return True
    return False


def _value_reference_candidates(values: Any) -> set[str]:
    candidates: set[str] = set()

    def add(value: Any) -> None:
        if value is None:
            return
        text = str(value).strip().strip('"').strip("'")
        if not text:
            return
        lower = text.lower()
        candidates.add(lower)
        path_parts = [part for part in re.split(r"[/\\]", lower) if part]
        cloud_path_markers = (
            "/backendaddresspools/",
            "/networkinterfaces/",
            "/targetgroup/",
            "/services/",
            "/locations/",
            "/regions/",
            "/zones/",
        )
        if len(path_parts) > 1 and any(marker in lower for marker in cloud_path_markers):
            candidates.add(path_parts[-1])
        for token in re.findall(r"[A-Za-z0-9_:\-/]+(?:\.[A-Za-z0-9_\-]+)+|sg-[A-Za-z0-9]+|arn:[^\s,\]\}]+", text):
            candidates.add(token.strip().strip('"').strip("'").lower())

    if isinstance(values, dict):
        for value in values.values():
            candidates.update(_value_reference_candidates(value))
    elif isinstance(values, (list, tuple, set)):
        for value in values:
            candidates.update(_value_reference_candidates(value))
    else:
        add(values)
    return {candidate for candidate in candidates if candidate}


def _security_group_refs(values: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    for key in ("security_groups", "security_group_ids", "vpc_security_group_ids"):
        if key in values:
            refs.update(_value_reference_candidates(values.get(key)))
    network_configuration = values.get("network_configuration")
    if isinstance(network_configuration, dict):
        refs.update(_security_group_refs(network_configuration))
    elif isinstance(network_configuration, list):
        for item in network_configuration:
            if isinstance(item, dict):
                refs.update(_security_group_refs(item))
    return refs


def _network_interface_refs(values: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    for key in ("network_interface_id", "network_interface_ids", "network_interface", "network_interfaces"):
        if key in values:
            refs.update(_value_reference_candidates(values.get(key)))
    network_configuration = values.get("network_configuration")
    if isinstance(network_configuration, dict):
        refs.update(_network_interface_refs(network_configuration))
    elif isinstance(network_configuration, list):
        for item in network_configuration:
            if isinstance(item, dict):
                refs.update(_network_interface_refs(item))
    return refs


def _security_group_source_refs(values: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    rules: list[Any] = []
    for key in ("ingress", "ingress_with_source_security_group_id"):
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
        for key in ("security_groups", "source_security_group_id", "source_security_group_ids"):
            refs.update(_value_reference_candidates(rule.get(key)))
    return refs


def _target_group_refs(values: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    for key in ("target_group_arn", "target_group_arns", "target_group", "target_groups"):
        if key in values:
            refs.update(_value_reference_candidates(values.get(key)))
    for key in ("load_balancer", "default_action", "action"):
        item = values.get(key)
        if isinstance(item, dict):
            refs.update(_target_group_refs(item))
        elif isinstance(item, list):
            for subitem in item:
                if isinstance(subitem, dict):
                    refs.update(_target_group_refs(subitem))
    return refs


def _load_balancer_refs(values: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    for key in ("load_balancer_arn", "load_balancer_id", "load_balancer_name", "arn", "id"):
        if key in values:
            refs.update(_value_reference_candidates(values.get(key)))
    return refs


def _kubernetes_names_and_selectors(resource: TerraformResource) -> set[str]:
    names: set[str] = {resource.name.lower()} if resource.name else set()

    def walk(value: Any, key_hint: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                key_l = str(key).lower()
                if key_l in {"name", "app", "app.kubernetes.io/name", "app.kubernetes.io/instance"} and isinstance(item, str):
                    names.add(item.lower())
                elif key_l in {"metadata", "labels", "selector", "match_labels"}:
                    walk(item, key_l)
                elif key_hint in {"metadata", "labels", "selector", "match_labels"}:
                    walk(item, key_hint)
                elif key_l in {"spec", "template"}:
                    walk(item, key_l)
        elif isinstance(value, list):
            for item in value:
                walk(item, key_hint)

    walk(resource.values)
    return {name for name in names if name}


def privilege_for_resource(resource: TerraformResource) -> str:
    return iam_grant_for_resource(resource).privilege


def iam_grant_for_resource(resource: TerraformResource) -> IamGrant:
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
        return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), resource_refs=tuple(sorted(_value_reference_candidates(values.get("key_vault_id")))), evidence=_iam_grant_evidence(resource, privilege, impacts))
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
        resource_refs = _value_reference_candidates(values.get("project")) | _value_reference_candidates(values.get("secret_id")) | _value_reference_candidates(values.get("resource")) | _value_reference_candidates(values.get("name"))
        return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), resource_refs=tuple(sorted(resource_refs)), evidence=_iam_grant_evidence(resource, privilege, impacts))
    if rtype in {"kubernetes_role_binding", "kubernetes_cluster_role_binding", "kubernetes_role_binding_v1", "kubernetes_cluster_role_binding_v1", "kubernetes_role_v1", "kubernetes_cluster_role_v1"}:
        privilege, impacts = classify_role_text_details(values.get("role_ref") or values.get("metadata"))
        return IamGrant(privilege=privilege, impacts=tuple(sorted(impacts)), evidence=_iam_grant_evidence(resource, privilege, impacts))
    return IamGrant(privilege="unknown", evidence=f"unknown IAM on {resource.address}")


def _iam_grant_evidence(resource: TerraformResource, privilege: str, impacts: set[str]) -> str:
    impact_text = ",".join(sorted(impacts)) if impacts else "none"
    return f"{privilege} IAM on {resource.address} impact={impact_text}"


def classify_policy(policy: Any) -> str:
    return classify_policy_details(policy)[0]


def classify_policy_details(policy: Any) -> tuple[str, set[str], set[str]]:
    if not policy:
        return "unknown", set(), set()
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            privilege, impacts = classify_role_text_details(policy)
            return privilege, impacts, set()
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    best = "unknown"
    impacts: set[str] = set()
    resource_refs: set[str] = set()
    for statement in statements:
        if not isinstance(statement, dict) or str(statement.get("Effect", "Allow")).lower() != "allow":
            continue
        resource_refs.update(_value_reference_candidates(statement.get("Resource")))
        resource_refs.update(_value_reference_candidates(statement.get("NotResource")))
        if "NotAction" in statement:
            best = max_privilege(best, "admin")
            impacts.add("admin_control")
            continue
        actions = [str(action).lower() for action in _listify(statement.get("Action"))]
        if "*" in actions or any(action.endswith(":*") for action in actions):
            best = max_privilege(best, "admin")
            impacts.add("admin_control")
            for action in actions:
                impacts.update(_iam_action_impacts(action))
        else:
            for action in actions:
                impacts.update(_iam_action_impacts(action))
        if impacts & CRITICAL_IAM_IMPACTS and best != "admin":
            best = max_privilege(best, "sensitive")
        elif actions:
            best = max_privilege(best, "limited")
    return best, impacts, resource_refs


def _embedded_policy_details(value: Any) -> tuple[str, set[str], set[str]]:
    best = "unknown"
    impacts: set[str] = set()
    resource_refs: set[str] = set()
    for item in _listify(value):
        policy = item.get("policy") if isinstance(item, dict) else item
        privilege, policy_impacts, policy_refs = classify_policy_details(policy)
        best = max_privilege(best, privilege)
        impacts.update(policy_impacts)
        resource_refs.update(policy_refs)
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


def _iam_action_impacts(action: str) -> set[str]:
    action = action.lower()
    impacts: set[str] = set()
    if action in {"*", "*:*"}:
        impacts.add("admin_control")
        return impacts
    if _is_sensitive_action(action):
        impacts.add("data_access")
    if action.startswith("iam:") or action.startswith("sts:"):
        if any(token in action for token in ("passrole", "assumerole", "attach", "putrolepolicy", "createpolicyversion", "setdefaultpolicyversion", "updateassumerolepolicy", "createaccesskey", "serviceaccount")):
            impacts.add("iam_escalation")
    if action.startswith(("ec2:", "elasticloadbalancing:", "route53:")):
        if any(token in action for token in ("securitygroup", "authorize", "revoke", "route", "vpc", "subnet", "transitgateway", "vpn", "peering", "networkinterface", "loadbalancer", "listener", "targetgroup", "*")):
            impacts.add("network_control")
    if action.startswith(("lambda:", "ecs:", "eks:", "ssm:", "apprunner:", "run.", "cloudfunctions.", "container.")):
        if any(token in action for token in ("update", "create", "run", "execute", "sendcommand", "invoke", "admin", "*")):
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


def _network_iam_criticality(exposure: str, privilege: str, impacts: set[str]) -> str:
    critical_impacts = impacts & CRITICAL_IAM_IMPACTS
    if privilege == "admin":
        critical_impacts.add("admin_control")
    if not critical_impacts:
        return "medium" if privilege == "sensitive" and exposure in {"public", "external", "internal"} else "unknown"
    if exposure in {"public", "external", "internal"}:
        return "high"
    if exposure == "private":
        return "medium"
    return "medium" if critical_impacts - {"admin_control"} else "unknown"


def max_criticality(left: str, right: str) -> str:
    return left if criticality_rank(left) >= criticality_rank(right) else right


def criticality_rank(value: str) -> int:
    return {"unknown": 0, "low": 1, "medium": 2, "high": 3}.get(value, 0)


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
    visibility_gaps: list[dict[str, str]] = []
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
            gap = {
                "address": resource.address,
                "type": resource.type,
                "provider": resource.provider,
                "gap_type": "unclassified_resource",
                "reason": "resource type is accounted for but not semantically classified",
            }
            unsupported.append(gap)
            visibility_gaps.append(gap)
        elif resource.type in OPAQUE_MANIFEST_WRAPPER_TYPES:
            visibility_gaps.append(
                {
                    "address": resource.address,
                    "type": resource.type,
                    "provider": resource.provider,
                    "gap_type": "opaque_manifest_wrapper",
                    "reason": "resource is a Helm/Kubectl manifest wrapper; rendered Kubernetes child workloads, images, exposure, and RBAC are not inspected",
                }
            )
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
        "visibility_gaps": visibility_gaps,
        "notes": [
            "100% resource accounting means every Terraform resource in the plan is represented in this report.",
            "Semantic coverage is limited to the declared manifest; unclassified resources are visibility gaps.",
            "Opaque manifest wrappers such as Helm releases are classified as Kubernetes support resources but still require rendered manifest evidence for child workloads.",
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
    "OPAQUE_MANIFEST_WRAPPER_TYPES",
    "SUPPORTED_TYPE_TO_CLASS",
    "TerraformAnalysis",
    "TerraformAnalyzer",
    "TerraformContextError",
    "analyze_terraform_plan",
    "classify_policy",
    "classify_role_text",
    "coverage_report",
    "empty_coverage_report",
    "exposure_for_resource",
    "extract_resources",
    "find_image_references",
    "image_matches",
    "is_public_exposure",
    "manifest_report",
    "privilege_for_resource",
    "provider_for_type",
]
