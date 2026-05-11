"""Terraform resource support manifest and provider classification helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


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
            "aws_vpc_endpoint",
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


def normalized_arm_type(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip().strip('"').strip("'")
    if not text:
        return None
    return text.split("@", 1)[0].lower()


def azapi_arm_category(value: Any) -> str | None:
    """Return a semantic category for an AzAPI ARM resource type."""

    arm_type = normalized_arm_type(value)
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
    "AZAPI_ARM_TYPE_TO_CATEGORY",
    "OPAQUE_MANIFEST_WRAPPER_TYPES",
    "SENSITIVE_RESOURCE_TYPES",
    "SUPPORTED_TYPE_TO_CLASS",
    "TERRAFORM_COVERAGE_MANIFEST",
    "ResourceSupport",
    "azapi_arm_category",
    "classification_for_resource",
    "manifest_report",
    "normalized_arm_type",
    "provider_for_type",
    "resource_type_supported",
]
