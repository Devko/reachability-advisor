from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.models import Artifact
from reachability_advisor.terraform import (
    SUPPORTED_TYPE_TO_CLASS,
    TERRAFORM_COVERAGE_MANIFEST,
    TerraformAnalyzer,
    TerraformContextError,
    classification_for_resource,
    classify_policy,
    classify_role_text,
    coverage_report,
    empty_coverage_report,
    exposure_for_resource,
    extract_resources,
    find_image_references,
    image_matches,
    is_public_exposure,
    load_terraform_plan,
    manifest_report,
    privilege_for_resource,
    provider_for_type,
)
from reachability_advisor.terraform_iam import iam_grant_for_resource
from reachability_advisor.terraform_network_adapters import network_adapter_signals

ROOT = Path(__file__).resolve().parents[1]


def resource(address: str, rtype: str, values: dict | None = None, name: str | None = None) -> dict:
    return {"address": address, "type": rtype, "name": name or address.split(".")[-1], "values": values or {}}


def plan(resources: list[dict]) -> dict:
    return {"planned_values": {"root_module": {"resources": resources}}}


class TerraformManifestTests(unittest.TestCase):
    def test_manifest_has_aws_azure_gcp_kubernetes(self) -> None:
        providers = {support.provider for support in TERRAFORM_COVERAGE_MANIFEST}
        self.assertTrue({"aws", "azure", "gcp", "kubernetes"}.issubset(providers))

    def test_manifest_has_no_duplicate_resource_types(self) -> None:
        all_types = [rtype for support in TERRAFORM_COVERAGE_MANIFEST for rtype in support.types]
        self.assertEqual(len(all_types), len(set(all_types)))

    def test_manifest_report_counts(self) -> None:
        report = manifest_report()
        self.assertGreaterEqual(report["provider_count"], 4)
        self.assertGreater(report["resource_type_count"], 120)
        self.assertIn("aws", report["providers"])
        self.assertIn("azure", report["providers"])
        self.assertIn("gcp", report["providers"])

    def test_supported_type_map_contains_categories(self) -> None:
        self.assertEqual(SUPPORTED_TYPE_TO_CLASS["aws_ecs_task_definition"], ("aws", "workload"))
        self.assertEqual(SUPPORTED_TYPE_TO_CLASS["aws_alb"], ("aws", "exposure"))
        self.assertEqual(SUPPORTED_TYPE_TO_CLASS["azurerm_container_app"], ("azure", "workload"))
        self.assertEqual(SUPPORTED_TYPE_TO_CLASS["azurerm_container_app_environment_dapr_component"], ("azure", "supporting"))
        self.assertEqual(SUPPORTED_TYPE_TO_CLASS["google_compute_firewall"], ("gcp", "exposure"))
        self.assertEqual(classification_for_resource("azapi_resource", {"type": "Microsoft.App/containerApps@2023-05-01"}), ("azure", "workload"))


class TerraformParsingTests(unittest.TestCase):
    def test_provider_for_type(self) -> None:
        self.assertEqual(provider_for_type("aws_lambda_function"), "aws")
        self.assertEqual(provider_for_type("azurerm_container_app"), "azure")
        self.assertEqual(provider_for_type("azuread_application"), "azure")
        self.assertEqual(provider_for_type("azapi_resource"), "azure")
        self.assertEqual(provider_for_type("google_cloud_run_v2_service"), "gcp")
        self.assertEqual(provider_for_type("kubernetes_deployment"), "kubernetes")
        self.assertEqual(provider_for_type("helm_release"), "kubernetes")
        self.assertEqual(provider_for_type("kubectl_manifest"), "kubernetes")
        self.assertEqual(provider_for_type("random_pet"), "terraform")
        self.assertEqual(provider_for_type("docker_image"), "docker")

    def test_extract_resources_from_planned_values_and_changes(self) -> None:
        data = plan([resource("aws_lambda_function.a", "aws_lambda_function", {"image_uri": "repo/a:1"})])
        data["resource_changes"] = [
            {"address": "google_compute_firewall.public", "type": "google_compute_firewall", "name": "public", "change": {"after": {"source_ranges": ["0.0.0.0/0"]}}}
        ]
        resources = extract_resources(data)
        self.assertEqual({r.type for r in resources}, {"aws_lambda_function", "google_compute_firewall"})

    def test_extract_resources_deduplicates_by_address(self) -> None:
        data = plan([resource("aws_lambda_function.a", "aws_lambda_function", {"image_uri": "old"})])
        data["resource_changes"] = [
            {"address": "aws_lambda_function.a", "type": "aws_lambda_function", "name": "a", "change": {"after": {"image_uri": "new"}}}
        ]
        resources = extract_resources(data)
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].values["image_uri"], "new")

    def test_load_terraform_plan_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(TerraformContextError):
                load_terraform_plan(path)

    def test_load_terraform_plan_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(TerraformContextError):
                load_terraform_plan(path)


class TerraformImageTests(unittest.TestCase):
    def test_find_images_from_container_definitions_json(self) -> None:
        images = find_image_references({"container_definitions": "[{\"image\": \"ghcr.io/acme/payments-api:1.2.3\"}]"})
        self.assertEqual(images, ["ghcr.io/acme/payments-api:1.2.3"])

    def test_find_images_from_azure_linux_fx_version(self) -> None:
        images = find_image_references({"site_config": [{"linux_fx_version": "DOCKER|ghcr.io/acme/app:1"}]})
        self.assertEqual(images, ["ghcr.io/acme/app:1"])

    def test_find_images_from_nested_cloud_run_container(self) -> None:
        images = find_image_references({"template": [{"containers": [{"image": "gcr.io/acme/audit:2"}]}]})
        self.assertEqual(images, ["gcr.io/acme/audit:2"])

    def test_find_images_keeps_unresolved_terraform_expression(self) -> None:
        images = find_image_references({"image": "${var.image}"})
        self.assertEqual(images, ["${var.image}"])

    def test_image_matches_name_reference_and_property(self) -> None:
        artifact = Artifact(name="payments-api", reference="ghcr.io/acme/payments-api:1.2.3", properties={"container:image": "ghcr.io/acme/payments-api:1.2.3"})
        self.assertTrue(image_matches(artifact, "ghcr.io/acme/payments-api:1.2.3"))
        self.assertTrue(image_matches(artifact, "ghcr.io/acme/payments-api:latest"))
        self.assertTrue(image_matches(artifact, "payments-api"))
        self.assertFalse(image_matches(artifact, "ghcr.io/acme/other:1"))


class TerraformExposureTests(unittest.TestCase):
    def _tf_resource(self, rtype: str, values: dict) -> object:
        return extract_resources(plan([resource(f"{rtype}.x", rtype, values)]))[0]

    def test_aws_security_group_public(self) -> None:
        r = self._tf_resource("aws_security_group", {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]})
        self.assertTrue(is_public_exposure(r))

    def test_aws_security_group_private(self) -> None:
        r = self._tf_resource("aws_security_group", {"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]})
        self.assertFalse(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "internal")

    def test_aws_security_group_restricted_external_source(self) -> None:
        r = self._tf_resource("aws_security_group", {"ingress": [{"cidr_blocks": ["8.8.8.8/32"]}]})
        self.assertFalse(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "external")

    def test_aws_security_group_uses_highest_exposure_across_rules(self) -> None:
        r = self._tf_resource(
            "aws_security_group",
            {"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}, {"cidr_blocks": ["0.0.0.0/0"]}]},
        )
        self.assertTrue(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "public")

    def test_azure_nsg_public(self) -> None:
        r = self._tf_resource("azurerm_network_security_rule", {"source_address_prefix": "Internet", "direction": "Inbound", "access": "Allow"})
        self.assertTrue(is_public_exposure(r))

    def test_azure_nsg_uses_highest_exposure_across_rules(self) -> None:
        r = self._tf_resource(
            "azurerm_network_security_group",
            {"security_rule": [{"source_address_prefix": "VirtualNetwork"}, {"source_address_prefix": "8.8.8.8/32"}]},
        )
        self.assertFalse(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "external")

    def test_azure_nsg_deny_not_public(self) -> None:
        r = self._tf_resource("azurerm_network_security_rule", {"source_address_prefix": "*", "direction": "Inbound", "access": "Deny"})
        self.assertFalse(is_public_exposure(r))

    def test_private_application_gateway_is_internal_not_public(self) -> None:
        r = self._tf_resource("azurerm_application_gateway", {"frontend_ip_configuration": [{"private_ip_address": "10.0.1.5", "subnet_id": "subnet-appgw"}]})
        self.assertFalse(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "internal")

    def test_gcp_firewall_public(self) -> None:
        r = self._tf_resource("google_compute_firewall", {"source_ranges": ["0.0.0.0/0"], "direction": "INGRESS"})
        self.assertTrue(is_public_exposure(r))

    def test_gcp_firewall_disabled_not_public(self) -> None:
        r = self._tf_resource("google_compute_firewall", {"source_ranges": ["0.0.0.0/0"], "disabled": True})
        self.assertFalse(is_public_exposure(r))

    def test_gcp_internal_forwarding_rule_is_internal(self) -> None:
        r = self._tf_resource("google_compute_forwarding_rule", {"load_balancing_scheme": "INTERNAL"})
        self.assertFalse(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "internal")

    def test_lambda_function_url_public(self) -> None:
        r = self._tf_resource("aws_lambda_function_url", {"function_name": "fn", "authorization_type": "NONE"})
        self.assertTrue(is_public_exposure(r))

    def test_gcp_all_users_invoker_public(self) -> None:
        r = self._tf_resource("google_cloud_run_service_iam_member", {"service": "svc", "role": "roles/run.invoker", "member": "allUsers"})
        self.assertTrue(is_public_exposure(r))

    def test_kubernetes_load_balancer_public(self) -> None:
        r = self._tf_resource("kubernetes_service", {"type": "LoadBalancer"})
        self.assertTrue(is_public_exposure(r))

    def test_kubernetes_cluster_ip_internal(self) -> None:
        r = self._tf_resource("kubernetes_service", {"type": "ClusterIP", "metadata": [{"name": "api"}]})
        self.assertFalse(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "internal")

    def test_kubernetes_cluster_ip_inside_spec_internal(self) -> None:
        r = self._tf_resource("kubernetes_service", {"metadata": [{"name": "api"}], "spec": [{"type": "ClusterIP", "selector": {"app": "api"}}]})
        self.assertFalse(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "internal")

    def test_kubernetes_service_spec_dict_load_balancer_public(self) -> None:
        r = self._tf_resource("kubernetes_service", {"metadata": [{"name": "api"}], "spec": {"type": "LoadBalancer", "selector": {"app": "api"}}})
        self.assertTrue(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "public")

    def test_kubernetes_service_defaults_to_internal_when_selector_exists(self) -> None:
        r = self._tf_resource("kubernetes_service", {"metadata": [{"name": "api"}], "selector": {"app": "api"}})
        self.assertFalse(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "internal")

    def test_empty_kubernetes_service_is_unknown(self) -> None:
        r = self._tf_resource("kubernetes_service", {"metadata": [{"name": "api"}]})
        self.assertFalse(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "unknown")

    def test_empty_kubernetes_ingress_is_unknown(self) -> None:
        r = self._tf_resource("kubernetes_ingress_v1", {"metadata": [{"name": "api"}]})
        self.assertFalse(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "unknown")

    def test_kubernetes_ingress_annotation_is_public_from_metadata_dict(self) -> None:
        r = self._tf_resource("kubernetes_ingress_v1", {"metadata": {"name": "api", "annotations": {"kubernetes.io/ingress.class": "nginx"}}})
        self.assertTrue(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "public")

    def test_kubernetes_ingress_annotation_is_public_from_metadata_list(self) -> None:
        r = self._tf_resource("kubernetes_ingress_v1", {"metadata": [{"name": "api", "annotations": {"kubernetes.io/ingress.class": "nginx"}}]})
        self.assertTrue(is_public_exposure(r))
        self.assertEqual(exposure_for_resource(r), "public")


class TerraformPrivilegeTests(unittest.TestCase):
    def _tf_resource(self, rtype: str, values: dict) -> object:
        return extract_resources(plan([resource(f"{rtype}.x", rtype, values)]))[0]

    def test_classify_policy_admin_wildcard(self) -> None:
        self.assertEqual(classify_policy({"Statement": {"Effect": "Allow", "Action": "*"}}), "admin")

    def test_classify_policy_admin_notaction(self) -> None:
        self.assertEqual(classify_policy({"Statement": {"Effect": "Allow", "NotAction": "iam:*"}}), "admin")

    def test_classify_policy_sensitive_secret(self) -> None:
        self.assertEqual(classify_policy({"Statement": [{"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"]}]}), "sensitive")

    def test_classify_policy_limited_ecs(self) -> None:
        self.assertEqual(classify_policy({"Statement": [{"Effect": "Allow", "Action": ["ecs:DescribeTasks"]}]}), "limited")

    def test_classify_role_text_admin_and_sensitive(self) -> None:
        self.assertEqual(classify_role_text("Owner"), "admin")
        self.assertEqual(classify_role_text("roles/secretmanager.secretAccessor"), "sensitive")
        self.assertEqual(classify_role_text("roles/viewer"), "limited")
        self.assertEqual(classify_role_text("arn:aws:iam::aws:policy/IAMFullAccess"), "sensitive")
        self.assertEqual(classify_role_text("Network Contributor"), "sensitive")

    def test_policy_capabilities_preserve_resource_scope_and_conditions(self) -> None:
        r = self._tf_resource(
            "aws_iam_role_policy",
            {
                "policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "secretsmanager:GetSecretValue",
                            "Resource": "arn:aws:secretsmanager:eu:123:secret:db",
                            "Condition": {"StringEquals": {"aws:ResourceTag/env": "prod"}},
                        },
                        {"Effect": "Allow", "Action": "ec2:AuthorizeSecurityGroupIngress", "Resource": "*"},
                    ]
                }
            },
        )
        grant = iam_grant_for_resource(r)
        secret = next(capability for capability in grant.capabilities if capability.impact == "data_access")
        network = next(capability for capability in grant.capabilities if capability.impact == "network_control")
        self.assertEqual(secret.resource_scope, "scoped")
        self.assertIn("aws:ResourceTag/env", secret.condition_keys)
        self.assertEqual(network.resource_scope, "wildcard")
        self.assertEqual(network.provider, "aws")
        self.assertEqual(secret.to_json()["effective_risk"], "constrained_critical")
        self.assertLess(secret.to_json()["risk_multiplier"], 1.0)

    def test_policy_capabilities_preserve_explicit_deny(self) -> None:
        r = self._tf_resource(
            "aws_iam_role_policy",
            {
                "policy": {
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": "secretsmanager:GetSecretValue",
                            "Resource": "*",
                        }
                    ]
                }
            },
        )

        grant = iam_grant_for_resource(r)

        self.assertEqual(grant.privilege, "unknown")
        self.assertEqual(grant.capabilities[0].effect, "deny")
        self.assertEqual(grant.capabilities[0].impact, "data_access")

    def test_aws_role_policy_privilege(self) -> None:
        r = self._tf_resource("aws_iam_role_policy", {"policy": json.dumps({"Statement": {"Effect": "Allow", "Action": "*"}})})
        self.assertEqual(privilege_for_resource(r), "admin")

    def test_azure_role_assignment_privilege(self) -> None:
        r = self._tf_resource("azurerm_role_assignment", {"role_definition_name": "Key Vault Secrets User"})
        self.assertEqual(privilege_for_resource(r), "sensitive")

    def test_azure_key_vault_policy_privilege(self) -> None:
        r = self._tf_resource("azurerm_key_vault_access_policy", {"secret_permissions": ["Get", "List"]})
        self.assertEqual(privilege_for_resource(r), "sensitive")

    def test_gcp_project_iam_privilege(self) -> None:
        r = self._tf_resource("google_project_iam_member", {"role": "roles/owner"})
        self.assertEqual(privilege_for_resource(r), "admin")

    def test_unknown_resource_privilege_unknown(self) -> None:
        r = self._tf_resource("random_pet", {})
        self.assertEqual(privilege_for_resource(r), "unknown")


class TerraformAnalysisTests(unittest.TestCase):
    def test_multicloud_sample_matches_all_artifacts(self) -> None:
        artifacts = [
            Artifact(name="payments-api", reference="ghcr.io/acme/payments-api:1.2.3", properties={"environment": "prod"}),
            Artifact(name="notifier", reference="ghcr.io/acme/notifier:0.9.0", properties={"environment": "dev"}),
            Artifact(name="orders-api", reference="ghcr.io/acme/orders-api:3.4.0", properties={"environment": "prod"}),
            Artifact(name="audit-api", reference="ghcr.io/acme/audit-api:2.0.0", properties={"environment": "prod"}),
            Artifact(name="inventory-api", reference="ghcr.io/acme/inventory-api:1.0.0", properties={"environment": "prod"}),
            Artifact(name="batch-worker", reference="ghcr.io/acme/batch-worker:0.4.0", properties={"environment": "prod"}),
            Artifact(name="reports-api", reference="ghcr.io/acme/reports-api:2.1.0", properties={"environment": "prod"}),
        ]
        data = json.loads((ROOT / "samples/tfplan-multicloud.json").read_text(encoding="utf-8"))
        analysis = TerraformAnalyzer(data, artifacts, source_name="sample").analyze()
        self.assertEqual(set(analysis.contexts), {"payments-api", "notifier", "orders-api", "audit-api", "inventory-api", "batch-worker", "reports-api"})
        self.assertEqual(analysis.contexts["payments-api"].exposure, "public")
        self.assertEqual(analysis.contexts["inventory-api"].exposure, "internal")
        self.assertEqual(analysis.contexts["batch-worker"].exposure, "private")
        self.assertEqual(analysis.contexts["reports-api"].exposure, "internal")
        self.assertEqual(analysis.contexts["orders-api"].privilege, "admin")
        self.assertEqual(analysis.contexts["audit-api"].privilege, "sensitive")
        self.assertEqual(analysis.contexts["reports-api"].privilege, "limited")
        self.assertEqual(analysis.contexts["batch-worker"].privilege, "unknown")
        self.assertTrue(any("terraform network path: internal" in item for item in analysis.contexts["inventory-api"].evidence))
        self.assertTrue(any("terraform network path: internal" in item for item in analysis.contexts["reports-api"].evidence))
        self.assertTrue(analysis.contexts["payments-api"].network_paths)
        self.assertTrue(analysis.contexts["orders-api"].effective_access)
        self.assertIn("confidence", analysis.contexts["orders-api"].effective_access[0])
        self.assertEqual(analysis.coverage["summary"]["resource_accounting_coverage"], 1.0)
        self.assertEqual(analysis.coverage["summary"]["semantic_classification_coverage"], 1.0)
        self.assertEqual(analysis.coverage["summary"]["artifact_match_coverage"], 1.0)
        self.assertGreater(analysis.coverage["summary"]["network_paths_observed"], 0)
        self.assertGreater(analysis.coverage["summary"]["effective_access_records"], 0)

    def test_effective_access_applies_explicit_deny_precedence(self) -> None:
        artifacts = [Artifact(name="app", reference="repo/app:1")]
        data = plan(
            [
                resource("aws_lambda_function.app", "aws_lambda_function", {"function_name": "app", "image_uri": "repo/app:1", "role": "app-role"}),
                resource(
                    "aws_iam_role_policy.app",
                    "aws_iam_role_policy",
                    {
                        "role": "app-role",
                        "policy": {
                            "Statement": [
                                {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"},
                                {"Effect": "Deny", "Action": "secretsmanager:GetSecretValue", "Resource": "*"},
                            ]
                        },
                    },
                ),
            ]
        )

        analysis = TerraformAnalyzer(data, artifacts).analyze()
        records = analysis.contexts["app"].effective_access
        allow = next(record for record in records if record["effect"] == "allow")
        deny = next(record for record in records if record["effect"] == "deny")

        self.assertEqual(allow["decision"], "denied_by_explicit_deny")
        self.assertEqual(allow["decision_basis"], "explicit_deny_precedence")
        self.assertEqual(allow["policy_layer"], "identity_policy")
        self.assertEqual(allow["confidence"], "high")
        self.assertTrue(any(blocker["kind"] == "explicit_deny_precedence" for blocker in allow["blockers"]))
        self.assertEqual(deny["decision"], "denied")

    def test_unsupported_resources_are_reported_as_visibility_gaps(self) -> None:
        artifacts = [Artifact(name="app", reference="ghcr.io/acme/app:1")]
        data = plan([
            resource("azurerm_container_app.app", "azurerm_container_app", {"name": "app", "template": [{"container": [{"image": "ghcr.io/acme/app:1"}]}]}),
            resource("custom_resource.name", "custom_resource", {"length": 2}),
        ])
        analysis = TerraformAnalyzer(data, artifacts).analyze()
        self.assertEqual(analysis.coverage["summary"]["resource_accounting_coverage"], 1.0)
        self.assertLess(analysis.coverage["summary"]["semantic_classification_coverage"], 1.0)
        self.assertEqual(len(analysis.coverage["visibility_gaps"]), 1)

    def test_empty_coverage_report_is_complete(self) -> None:
        report = empty_coverage_report()
        self.assertEqual(report["summary"]["resource_accounting_coverage"], 1.0)
        self.assertEqual(report["summary"]["semantic_classification_coverage"], 1.0)

    def test_coverage_report_counts_unmatched_artifacts(self) -> None:
        resources = extract_resources(plan([resource("aws_lambda_function.a", "aws_lambda_function", {"image_uri": "repo/a:1"})]))
        report = coverage_report(resources, [Artifact(name="missing")], [])
        self.assertEqual(report["unmatched_artifacts"], ["missing"])
        self.assertEqual(report["summary"]["artifact_match_coverage"], 0.0)

    def test_cli_writes_terraform_coverage_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            code = main([
                "scan",
                "--sbom", str(ROOT / "samples/sboms/payments-api.cdx.json"),
                "--sbom", str(ROOT / "samples/sboms/orders-api.cdx.json"),
                "--vulns", str(ROOT / "samples/vulnerabilities.json"),
                "--terraform-plan", str(ROOT / "samples/tfplan-multicloud.json"),
                "--terraform-coverage-out", str(out / "coverage.json"),
                "--source-root", f"payments-api={ROOT / 'samples/source/payments-api'}",
                "--source-root", f"orders-api={ROOT / 'samples/source/orders-api'}",
                "--out", str(out / "findings.json"),
                "--no-table",
            ])
            self.assertEqual(code, 0)
            coverage = json.loads((out / "coverage.json").read_text(encoding="utf-8"))
            self.assertEqual(coverage["summary"]["resource_accounting_coverage"], 1.0)
            findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(findings["metadata"]["terraform_resources"], 26)

    def test_all_manifest_resource_types_can_be_accounted(self) -> None:
        resources = [resource(f"{rtype}.x{i}", rtype, {}) for i, rtype in enumerate(SUPPORTED_TYPE_TO_CLASS)]
        report = coverage_report(extract_resources(plan(resources)), [], [])
        self.assertEqual(report["summary"]["resource_accounting_coverage"], 1.0)
        self.assertEqual(report["summary"]["semantic_classification_coverage"], 1.0)
        self.assertEqual(report["summary"]["unsupported_or_unclassified_resources"], 0)

    def test_opaque_manifest_wrappers_are_supported_but_still_gaps(self) -> None:
        resources = extract_resources(
            plan(
                [
                    resource("helm_release.app", "helm_release", {"name": "app"}),
                    resource("kubectl_manifest.app", "kubectl_manifest", {"yaml_body": "kind: Deployment"}),
                ]
            )
        )
        report = coverage_report(resources, [], [])
        self.assertEqual(report["summary"]["semantic_classification_coverage"], 1.0)
        self.assertEqual(report["summary"]["unsupported_or_unclassified_resources"], 0)
        self.assertEqual({row["category"] for row in report["resources"]}, {"supporting"})
        self.assertEqual({gap["gap_type"] for gap in report["visibility_gaps"]}, {"opaque_manifest_wrapper"})

    def test_coverage_reports_provider_network_adapter_signals(self) -> None:
        resources = extract_resources(
            plan(
                [
                    resource("aws_route.private", "aws_route", {"route_table_id": "rtb-private", "transit_gateway_id": "tgw-1"}),
                    resource("google_compute_firewall.web", "google_compute_firewall", {"source_ranges": ["0.0.0.0/0"], "target_tags": ["web"]}),
                ]
            )
        )
        report = coverage_report(resources, [], [])
        rows = {row["address"]: row for row in report["resources"]}
        self.assertEqual(rows["aws_route.private"]["network_adapter_signals"][0]["kind"], "private_route_bridge")
        self.assertEqual(rows["google_compute_firewall.web"]["network_adapter_signals"][0]["kind"], "firewall_target")

    def test_provider_network_adapter_exposes_azure_deny_and_gcp_priority(self) -> None:
        azure = network_adapter_signals("azurerm_network_security_rule", {"access": "Deny", "direction": "Inbound", "source_address_prefix": "*"})
        gcp = network_adapter_signals("google_compute_firewall", {"source_ranges": ["0.0.0.0/0"], "target_tags": ["web"], "priority": 1000})
        azure_route = network_adapter_signals("azurerm_route", {"route_table_name": "rt-private", "next_hop_type": "VirtualNetworkGateway"})
        gcp_route = network_adapter_signals("google_compute_route", {"network": "vpc-private", "next_hop_vpn_tunnel": "vpn-1"})
        self.assertEqual(azure[0].kind, "deny_inbound")
        self.assertEqual(gcp[0].exposure, "public")
        self.assertIn("priority=1000", gcp[0].reason)
        self.assertEqual(azure_route[0].kind, "private_route_bridge")
        self.assertEqual(gcp_route[0].kind, "private_route_bridge")


if __name__ == "__main__":
    unittest.main()

class TerraformBranchCoverageTests(unittest.TestCase):
    def _tf_resource(self, rtype: str, values: dict, address: str | None = None) -> object:
        return extract_resources(plan([resource(address or f"{rtype}.x", rtype, values)]))[0]

    def test_load_terraform_plan_valid_and_empty_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tf.json"
            path.write_text(json.dumps(plan([])), encoding="utf-8")
            self.assertEqual(load_terraform_plan(path)["planned_values"]["root_module"]["resources"], [])
            from reachability_advisor.terraform import analyze_terraform_plan
            empty = analyze_terraform_plan(None, [])
            self.assertEqual(empty.contexts, {})

    def test_extract_resources_ignores_bad_shapes(self) -> None:
        data = {"planned_values": {"root_module": {"resources": ["bad", {"type": ""}], "child_modules": ["bad"]}}, "resource_changes": ["bad", {"type": "aws_lambda_function", "change": {"before": {}}}]}
        self.assertEqual(extract_resources(data), [])

    def test_find_image_references_invalid_json_and_docker_scheme(self) -> None:
        images = find_image_references({"container_definitions": "docker://repo/app:1", "image": ""})
        self.assertEqual(images, ["repo/app:1"])

    def test_image_matches_false_for_empty(self) -> None:
        self.assertFalse(image_matches(Artifact(name="app"), None))

    def test_workload_name_match_path(self) -> None:
        data = plan([resource("aws_lambda_function.orders", "aws_lambda_function", {"function_name": "orders-api"})])
        analysis = TerraformAnalyzer(data, [Artifact(name="orders-api")]).analyze()
        self.assertIn("orders-api", analysis.contexts)

    def test_sensitive_resource_without_linked_identity_does_not_raise_privilege(self) -> None:
        data = plan([
            resource("aws_lambda_function.app", "aws_lambda_function", {"function_name": "app", "image_uri": "repo/app:1"}),
            resource("aws_secretsmanager_secret.app", "aws_secretsmanager_secret", {"name": "secret"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].privilege, "unknown")

    def test_unlinked_public_api_does_not_mark_lambda_public(self) -> None:
        data = plan([
            resource("aws_lambda_function.app", "aws_lambda_function", {"function_name": "app", "image_uri": "repo/app:1"}),
            resource("aws_api_gateway_rest_api.api", "aws_api_gateway_rest_api", {"name": "api"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "unknown")

    def test_ecs_service_linked_to_public_security_group_is_public(self) -> None:
        data = plan([
            resource("aws_security_group.public", "aws_security_group", {"id": "sg-public", "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]}),
            resource("aws_ecs_service.app", "aws_ecs_service", {"name": "app", "network_configuration": [{"security_groups": ["sg-public"]}]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "public")

    def test_ecs_service_linked_to_restricted_external_security_group_is_external(self) -> None:
        data = plan([
            resource("aws_security_group.external", "aws_security_group", {"id": "sg-external", "ingress": [{"cidr_blocks": ["8.8.8.8/32"]}]}),
            resource("aws_ecs_service.app", "aws_ecs_service", {"name": "app", "network_configuration": [{"security_groups": ["sg-external"]}]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "external")

    def test_ecs_service_linked_to_private_security_group_is_internal(self) -> None:
        data = plan([
            resource("aws_security_group.internal", "aws_security_group", {"id": "sg-internal", "ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]}),
            resource("aws_ecs_service.app", "aws_ecs_service", {"name": "app", "network_configuration": [{"security_groups": ["sg-internal"]}]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")

    def test_ecs_service_uses_security_group_rule_exposure(self) -> None:
        cases = [
            ("public", "0.0.0.0/0", "public"),
            ("external", "8.8.8.8/32", "external"),
            ("internal", "10.0.0.0/8", "internal"),
        ]
        for name, cidr, expected in cases:
            with self.subTest(name=name):
                data = plan([
                    resource(f"aws_security_group_rule.{name}", "aws_security_group_rule", {"type": "ingress", "security_group_id": f"sg-{name}", "cidr_blocks": [cidr]}),
                    resource("aws_ecs_service.app", "aws_ecs_service", {"name": "app", "network_configuration": [{"security_groups": [f"sg-{name}"]}]}),
                ])
                analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
                self.assertEqual(analysis.contexts["app"].exposure, expected)

    def test_ecs_service_uses_public_and_internal_target_groups(self) -> None:
        cases = [
            ("public", False, "public"),
            ("internal", True, "internal"),
        ]
        for name, internal, expected in cases:
            with self.subTest(name=name):
                data = plan([
                    resource(f"aws_lb.{name}", "aws_lb", {"name": f"lb-{name}", "arn": f"lb-{name}", "internal": internal}),
                    resource(f"aws_lb_target_group.{name}", "aws_lb_target_group", {"name": f"tg-{name}", "arn": f"tg-{name}"}),
                    resource(f"aws_lb_listener.{name}", "aws_lb_listener", {"load_balancer_arn": f"lb-{name}", "default_action": [{"target_group_arn": f"tg-{name}"}]}),
                    resource("aws_ecs_service.app", "aws_ecs_service", {"name": "app", "load_balancer": [{"target_group_arn": f"tg-{name}"}]}),
                ])
                analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
                self.assertEqual(analysis.contexts["app"].exposure, expected)

    def test_public_lb_reaches_instance_through_target_group_attachment(self) -> None:
        data = plan([
            resource("aws_lb.public", "aws_lb", {"name": "lb-public", "arn": "lb-public", "internal": False}),
            resource("aws_lb_target_group.app", "aws_lb_target_group", {"name": "tg-app", "arn": "tg-app"}),
            resource("aws_lb_listener.app", "aws_lb_listener", {"load_balancer_arn": "lb-public", "default_action": [{"target_group_arn": "tg-app"}]}),
            resource("aws_lb_target_group_attachment.app", "aws_lb_target_group_attachment", {"target_group_arn": "tg-app", "target_id": "i-app"}),
            resource("aws_instance.app", "aws_instance", {"id": "i-app", "ami": "ami-1", "subnet_id": "subnet-private", "private_ip": "10.0.1.10"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "public")
        self.assertTrue(any("terraform network path: public" in item for item in analysis.contexts["app"].evidence))

    def test_lambda_function_url_marks_matching_lambda_public(self) -> None:
        data = plan([
            resource("aws_lambda_function.app", "aws_lambda_function", {"function_name": "app", "image_uri": "repo/app:1"}),
            resource("aws_lambda_function_url.app", "aws_lambda_function_url", {"function_name": "app", "authorization_type": "NONE"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "public")
        self.assertTrue(any("aws_lambda_function_url.app" in item for item in analysis.contexts["app"].evidence))

    def test_kubernetes_selector_path_does_not_expose_same_named_cloud_workload(self) -> None:
        data = plan([
            resource("kubernetes_service.shared", "kubernetes_service", {"type": "LoadBalancer", "metadata": [{"name": "shared"}], "spec": [{"selector": {"app": "shared"}}]}),
            resource("aws_lambda_function.shared", "aws_lambda_function", {"function_name": "shared", "image_uri": "repo/lambda-app:1"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="lambda-app", reference="repo/lambda-app:1")]).analyze()
        context = analysis.contexts["lambda-app"]
        self.assertEqual(context.exposure, "unknown")
        self.assertFalse(any("kubernetes_service.shared" in item for item in context.evidence))

    def test_app_runner_false_public_access_is_internal(self) -> None:
        data = plan([resource("aws_apprunner_service.app", "aws_apprunner_service", {"service_name": "app", "publicly_accessible": False})])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")

    def test_app_runner_default_public_access_is_public(self) -> None:
        data = plan([resource("aws_apprunner_service.app", "aws_apprunner_service", {"service_name": "app"})])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "public")

    def test_private_instance_with_vpc_peering_is_internal_lateral(self) -> None:
        data = plan([
            resource("aws_vpc_peering_connection.peer", "aws_vpc_peering_connection", {"id": "pcx-1"}),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-1", "subnet_id": "subnet-private", "private_ip": "10.0.1.10"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")

    def test_private_instance_with_vpn_or_transit_is_internal_lateral(self) -> None:
        for bridge_type in ("aws_vpn_connection", "aws_ec2_transit_gateway_vpc_attachment"):
            with self.subTest(bridge_type=bridge_type):
                data = plan([
                    resource(f"{bridge_type}.bridge", bridge_type, {"id": "bridge-1"}),
                    resource("aws_instance.app", "aws_instance", {"ami": "ami-1", "subnet_id": "subnet-private", "private_ip": "10.0.1.10"}),
                ])
                analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
                self.assertEqual(analysis.contexts["app"].exposure, "internal")

    def test_private_instance_without_bridge_stays_private(self) -> None:
        data = plan([
            resource("aws_instance.app", "aws_instance", {"ami": "ami-1", "subnet_id": "subnet-private", "private_ip": "10.0.1.10"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "private")

    def test_unlinked_private_security_group_does_not_raise_private_instance(self) -> None:
        data = plan([
            resource("aws_security_group.internal", "aws_security_group", {"id": "sg-internal", "ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]}),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-1", "subnet_id": "subnet-private", "private_ip": "10.0.1.10"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "private")

    def test_security_group_hop_from_public_host_is_internal_lateral(self) -> None:
        data = plan([
            resource("aws_security_group.web", "aws_security_group", {"id": "sg-web", "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]}),
            resource("aws_security_group.db", "aws_security_group", {"id": "sg-db", "ingress": [{"source_security_group_id": "sg-web"}]}),
            resource("aws_instance.web", "aws_instance", {"ami": "ami-1", "associate_public_ip_address": True, "security_group_ids": ["sg-web"]}),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-2", "security_group_ids": ["sg-db"]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")
        self.assertTrue(any("terraform network path: internal" in item for item in analysis.contexts["app"].evidence))

    def test_public_admin_workload_can_raise_private_peer_to_internal(self) -> None:
        data = plan([
            resource("aws_iam_role.admin", "aws_iam_role", {"name": "admin-role", "managed_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"]}),
            resource("aws_instance.bastion", "aws_instance", {"ami": "ami-1", "associate_public_ip_address": True, "iam_instance_profile": "admin-role"}),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-2", "subnet_id": "subnet-private", "private_ip": "10.0.1.20"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")
        self.assertTrue(any("IAM impact admin_control can alter provider network reachability" in item for item in analysis.contexts["app"].evidence))

    def test_public_workload_with_limited_secret_read_is_critical_data_access(self) -> None:
        data = plan([
            resource("aws_secretsmanager_secret.db", "aws_secretsmanager_secret", {"name": "db", "arn": "arn:aws:secretsmanager:eu:123:secret:db"}),
            resource("aws_iam_role.app", "aws_iam_role", {"name": "app-role"}),
            resource(
                "aws_iam_role_policy.secret",
                "aws_iam_role_policy",
                {
                    "role": "app-role",
                    "policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "secretsmanager:GetSecretValue",
                                "Resource": "arn:aws:secretsmanager:eu:123:secret:db",
                            }
                        ]
                    },
                },
            ),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-1", "associate_public_ip_address": True, "iam_instance_profile": "app-role"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        context = analysis.contexts["app"]
        self.assertEqual(context.exposure, "public")
        self.assertEqual(context.privilege, "sensitive")
        self.assertEqual(context.criticality, "high")
        self.assertIn("data_access", context.iam_impacts)
        self.assertTrue(any(capability["impact"] == "data_access" and capability["access"] == "sensitive_data" for capability in context.iam_capabilities))
        self.assertTrue(any("targets aws_secretsmanager_secret.db" in item for item in context.evidence))

    def test_attached_customer_policy_inherits_per_resource_secret_access(self) -> None:
        data = plan([
            resource("aws_secretsmanager_secret.db", "aws_secretsmanager_secret", {"name": "db", "arn": "arn:aws:secretsmanager:eu:123:secret:db"}),
            resource(
                "aws_iam_policy.secret",
                "aws_iam_policy",
                {
                    "name": "secret-read",
                    "arn": "arn:aws:iam::123:policy/secret-read",
                    "policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "secretsmanager:GetSecretValue",
                                "Resource": "arn:aws:secretsmanager:eu:123:secret:db",
                            }
                        ]
                    },
                },
            ),
            resource("aws_iam_role.app", "aws_iam_role", {"name": "app-role"}),
            resource("aws_iam_role_policy_attachment.secret", "aws_iam_role_policy_attachment", {"role": "app-role", "policy_arn": "arn:aws:iam::123:policy/secret-read"}),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-1", "associate_public_ip_address": True, "iam_instance_profile": "app-role"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        context = analysis.contexts["app"]
        self.assertEqual(context.privilege, "sensitive")
        self.assertEqual(context.criticality, "high")
        self.assertTrue(any("aws_iam_policy.secret" in item and "targets aws_secretsmanager_secret.db" in item for item in context.evidence))

    def test_effective_access_graph_records_deny_decisions_without_raising_privilege(self) -> None:
        data = plan([
            resource("aws_iam_role.app", "aws_iam_role", {"name": "app-role"}),
            resource(
                "aws_iam_role_policy.deny_secret",
                "aws_iam_role_policy",
                {
                    "role": "app-role",
                    "policy": {
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "secretsmanager:GetSecretValue",
                                "Resource": "*",
                            }
                        ]
                    },
                },
            ),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-1", "iam_instance_profile": "app-role"}),
        ])

        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        context = analysis.contexts["app"]

        self.assertEqual(context.privilege, "unknown")
        self.assertTrue(any(item["effect"] == "deny" for item in context.iam_capabilities))
        denied = next(item for item in context.effective_access if item["effect"] == "deny")
        self.assertEqual(denied["decision"], "denied")
        self.assertTrue(any(blocker["kind"] == "explicit_deny" for blocker in denied["blockers"]))

    def test_inferred_public_workload_path_records_auth_and_waf_blockers(self) -> None:
        data = plan([
            resource(
                "azurerm_linux_web_app.app",
                "azurerm_linux_web_app",
                {
                    "name": "app",
                    "site_config": [{"linux_fx_version": "DOCKER|repo/app:1"}],
                    "auth_settings": [{"enabled": True}],
                    "web_application_firewall_policy_link_id": "/subscriptions/1/resourceGroups/rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf",
                },
            )
        ])

        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        path = analysis.contexts["app"].network_paths[0]
        blocker_kinds = {blocker["kind"] for blocker in path["blockers"]}

        self.assertEqual(path["exposure"], "public")
        self.assertEqual(path["path_type"], "direct_public")
        self.assertEqual(path["confidence"], "low")
        self.assertIn("auth_required", blocker_kinds)
        self.assertIn("waf_or_firewall_policy", blocker_kinds)
        self.assertTrue(path["unknowns"])

    def test_limited_network_control_identity_creates_internal_pivot(self) -> None:
        data = plan([
            resource("aws_iam_role.net", "aws_iam_role", {"name": "net-role"}),
            resource(
                "aws_iam_role_policy.net",
                "aws_iam_role_policy",
                {
                    "role": "net-role",
                    "policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "ec2:AuthorizeSecurityGroupIngress",
                                "Resource": "*",
                            }
                        ]
                    },
                },
            ),
            resource("aws_instance.bastion", "aws_instance", {"ami": "ami-1", "associate_public_ip_address": True, "iam_instance_profile": "net-role"}),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-2", "subnet_id": "subnet-private", "private_ip": "10.0.1.20"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="bastion"), Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["bastion"].privilege, "sensitive")
        self.assertEqual(analysis.contexts["bastion"].criticality, "high")
        self.assertIn("network_control", analysis.contexts["bastion"].iam_impacts)
        self.assertTrue(any(capability["impact"] == "network_control" for capability in analysis.contexts["bastion"].iam_capabilities))
        self.assertEqual(analysis.contexts["app"].exposure, "internal")
        self.assertTrue(any("IAM impact network_control can alter provider network reachability" in item for item in analysis.contexts["app"].evidence))

    def test_sts_assume_role_expands_target_role_blast_radius(self) -> None:
        admin_role_arn = "arn:aws:iam::123:role/admin-role"
        data = plan([
            resource("aws_iam_role.admin", "aws_iam_role", {"name": "admin-role", "arn": admin_role_arn, "managed_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"]}),
            resource("aws_iam_role.app", "aws_iam_role", {"name": "app-role"}),
            resource(
                "aws_iam_role_policy.assume_admin",
                "aws_iam_role_policy",
                {
                    "role": "app-role",
                    "policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRole",
                                "Resource": admin_role_arn,
                            }
                        ]
                    },
                },
            ),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-1", "associate_public_ip_address": True, "iam_instance_profile": "app-role"}),
        ])

        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        context = analysis.contexts["app"]
        self.assertEqual(context.privilege, "admin")
        self.assertIn("admin_control", context.iam_impacts)
        self.assertTrue(any("can assume" in item for item in context.evidence))

    def test_private_subnet_route_bridge_creates_internal_context(self) -> None:
        data = plan([
            resource("aws_route_table.private", "aws_route_table", {"id": "rtb-private"}),
            resource("aws_route.private_to_tgw", "aws_route", {"route_table_id": "rtb-private", "destination_cidr_block": "10.20.0.0/16", "transit_gateway_id": "tgw-123"}),
            resource("aws_route_table_association.private", "aws_route_table_association", {"route_table_id": "rtb-private", "subnet_id": "subnet-private"}),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-2", "subnet_id": "subnet-private", "private_ip": "10.0.1.20"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")
        self.assertTrue(any("private route table bridge" in item for item in analysis.contexts["app"].evidence))

    def test_azure_route_table_id_links_to_named_private_route_bridge(self) -> None:
        subnet_id = "/subscriptions/123/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/app"
        route_table_id = "/subscriptions/123/resourceGroups/rg/providers/Microsoft.Network/routeTables/rt-private"
        data = plan([
            resource("azurerm_route.private", "azurerm_route", {"route_table_name": "rt-private", "next_hop_type": "VirtualNetworkGateway"}),
            resource("azurerm_subnet_route_table_association.private", "azurerm_subnet_route_table_association", {"route_table_id": route_table_id, "subnet_id": subnet_id}),
            resource("azurerm_linux_virtual_machine.app", "azurerm_linux_virtual_machine", {"name": "app", "network_interface": [{"virtual_network_subnet_id": subnet_id}]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")
        self.assertTrue(any("azurerm_route.private" in item and "private route bridge" in item for item in analysis.contexts["app"].evidence))

    def test_gcp_vpn_route_network_links_to_instance_network(self) -> None:
        network = "https://www.googleapis.com/compute/v1/projects/demo/global/networks/private"
        data = plan([
            resource("google_compute_route.private", "google_compute_route", {"network": network, "next_hop_vpn_tunnel": "vpn-1"}),
            resource("google_compute_instance.app", "google_compute_instance", {"name": "app", "network_interface": [{"network": network}]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")
        self.assertTrue(any("google_compute_route.private" in item and "private route bridge" in item for item in analysis.contexts["app"].evidence))

    def test_gcp_firewall_target_tag_links_to_tagged_workload(self) -> None:
        data = plan([
            resource("google_compute_firewall.internal", "google_compute_firewall", {"source_ranges": ["10.0.0.0/8"], "target_tags": ["api"]}),
            resource("google_compute_instance.app", "google_compute_instance", {"name": "app", "tags": ["api"]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")
        self.assertTrue(any("firewall target api" in item for item in analysis.contexts["app"].evidence))

    def test_azure_application_gateway_reaches_vm_through_backend_pool_and_nic(self) -> None:
        data = plan([
            resource("azurerm_application_gateway.public", "azurerm_application_gateway", {"name": "gw", "backend_address_pool": [{"name": "pool-app"}]}),
            resource(
                "azurerm_network_interface_application_gateway_backend_address_pool_association.app",
                "azurerm_network_interface_application_gateway_backend_address_pool_association",
                {
                    "backend_address_pool_id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw/backendAddressPools/pool-app",
                    "network_interface_id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-app",
                },
            ),
            resource("azurerm_linux_virtual_machine.app", "azurerm_linux_virtual_machine", {"name": "app", "network_interface_ids": ["/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-app"]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "public")

    def test_gcp_global_forwarding_rule_reaches_cloud_run_through_backend_and_neg(self) -> None:
        data = plan([
            resource("google_compute_global_forwarding_rule.public", "google_compute_global_forwarding_rule", {"name": "fr", "target": "google_compute_backend_service.app"}),
            resource("google_compute_backend_service.app", "google_compute_backend_service", {"name": "backend-app", "id": "google_compute_backend_service.app", "backend": [{"group": "google_compute_region_network_endpoint_group.app"}]}),
            resource("google_compute_region_network_endpoint_group.app", "google_compute_region_network_endpoint_group", {"name": "neg-app", "id": "google_compute_region_network_endpoint_group.app", "cloud_run": {"service": "app"}}),
            resource("google_cloud_run_v2_service.app", "google_cloud_run_v2_service", {"name": "app", "template": [{"containers": [{"image": "repo/app:1"}]}]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "public")

    def test_azure_workload_identity_links_role_assignment_privilege(self) -> None:
        data = plan([
            resource("azurerm_linux_web_app.app", "azurerm_linux_web_app", {"name": "app", "identity": [{"type": "SystemAssigned", "principal_id": "pid-app"}]}),
            resource("azurerm_role_assignment.app", "azurerm_role_assignment", {"principal_id": "pid-app", "role_definition_name": "Key Vault Secrets User"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].privilege, "sensitive")
        self.assertTrue(any("terraform identity path" in item for item in analysis.contexts["app"].evidence))

    def test_unlinked_identity_resource_name_does_not_grant_workload(self) -> None:
        data = plan([
            resource("azurerm_linux_web_app.owner", "azurerm_linux_web_app", {"name": "owner", "public_network_access_enabled": True}),
            resource("azurerm_role_assignment.owner", "azurerm_role_assignment", {"role_definition_name": "Owner"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="owner")]).analyze()
        self.assertEqual(analysis.contexts["owner"].privilege, "unknown")
        self.assertEqual(analysis.contexts["owner"].criticality, "unknown")

    def test_aws_role_name_without_policy_does_not_grant_workload(self) -> None:
        data = plan([
            resource("aws_iam_role.admin", "aws_iam_role", {"name": "AdministratorAccess"}),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-1", "associate_public_ip_address": True, "iam_instance_profile": "AdministratorAccess"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].privilege, "unknown")
        self.assertEqual(analysis.contexts["app"].criticality, "unknown")

    def test_aws_role_inline_policy_grants_workload(self) -> None:
        data = plan([
            resource(
                "aws_iam_role.app",
                "aws_iam_role",
                {
                    "name": "app-role",
                    "inline_policy": [
                        {
                            "name": "secret-read",
                            "policy": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "secretsmanager:GetSecretValue",
                                        "Resource": "*",
                                    }
                                ]
                            },
                        }
                    ],
                },
            ),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-1", "associate_public_ip_address": True, "iam_instance_profile": "app-role"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].privilege, "sensitive")
        self.assertIn("data_access", analysis.contexts["app"].iam_impacts)

    def test_kubernetes_role_binding_name_without_subject_does_not_grant_workload(self) -> None:
        data = plan([
            resource(
                "kubernetes_deployment.app",
                "kubernetes_deployment",
                {"metadata": [{"name": "app"}], "spec": [{"template": [{"spec": [{"container": [{"name": "app", "image": "repo/app:1"}]}]}]}]},
            ),
            resource(
                "kubernetes_cluster_role_binding.app",
                "kubernetes_cluster_role_binding",
                {"metadata": [{"name": "app"}], "role_ref": {"name": "cluster-admin"}},
            ),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].privilege, "unknown")
        self.assertEqual(analysis.contexts["app"].criticality, "unknown")

    def test_azure_key_vault_policy_links_object_identity_and_target(self) -> None:
        data = plan([
            resource("azurerm_key_vault.vault", "azurerm_key_vault", {"name": "vault", "id": "/kv/vault"}),
            resource("azurerm_linux_web_app.app", "azurerm_linux_web_app", {"name": "app", "identity": [{"type": "SystemAssigned", "principal_id": "pid-app"}], "public_network_access_enabled": True}),
            resource(
                "azurerm_key_vault_access_policy.app",
                "azurerm_key_vault_access_policy",
                {"object_id": "pid-app", "key_vault_id": "/kv/vault", "secret_permissions": ["Get"]},
            ),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        context = analysis.contexts["app"]
        self.assertEqual(context.privilege, "sensitive")
        self.assertEqual(context.criticality, "high")
        self.assertIn("data_access", context.iam_impacts)
        self.assertTrue(any("targets azurerm_key_vault.vault" in item for item in context.evidence))

    def test_instance_with_public_ip_is_public(self) -> None:
        data = plan([
            resource("aws_instance.app", "aws_instance", {"ami": "ami-1", "associate_public_ip_address": True, "subnet_id": "subnet-public"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "public")

    def test_instance_linked_to_private_security_group_is_internal(self) -> None:
        data = plan([
            resource("aws_security_group.internal", "aws_security_group", {"id": "sg-internal", "ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]}),
            resource("aws_instance.app", "aws_instance", {"ami": "ami-1", "security_group_ids": ["sg-internal"]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")

    def test_launch_template_linked_to_restricted_external_security_group(self) -> None:
        data = plan([
            resource("aws_security_group.external", "aws_security_group", {"id": "sg-external", "ingress": [{"cidr_blocks": ["8.8.8.8/32"]}]}),
            resource("aws_launch_template.app", "aws_launch_template", {"name": "app", "vpc_security_group_ids": ["sg-external"]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "external")

    def test_ecs_task_definition_uses_linked_public_service(self) -> None:
        data = plan([
            resource("aws_security_group.public", "aws_security_group", {"id": "sg-public", "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]}),
            resource("aws_ecs_task_definition.app", "aws_ecs_task_definition", {"family": "app", "container_definitions": "[{\"name\":\"app\",\"image\":\"repo/app:1\"}]"}),
            resource("aws_ecs_service.app", "aws_ecs_service", {"name": "service", "task_definition": "app", "network_configuration": [{"security_groups": ["sg-public"]}]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "public")

    def test_ecs_task_definition_uses_linked_internal_service(self) -> None:
        data = plan([
            resource("aws_security_group.internal", "aws_security_group", {"id": "sg-internal", "ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]}),
            resource("aws_ecs_task_definition.app", "aws_ecs_task_definition", {"family": "app", "container_definitions": "[{\"name\":\"app\",\"image\":\"repo/app:1\"}]"}),
            resource("aws_ecs_service.app", "aws_ecs_service", {"name": "service", "task_definition": "app", "network_configuration": [{"security_groups": ["sg-internal"]}]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")

    def test_aws_lb_internal_and_public(self) -> None:
        public = self._tf_resource("aws_lb", {"internal": False})
        private = self._tf_resource("aws_lb", {"internal": True})
        self.assertTrue(is_public_exposure(public))
        self.assertFalse(is_public_exposure(private))

    def test_aws_alb_alias_public(self) -> None:
        self.assertTrue(is_public_exposure(self._tf_resource("aws_alb", {"internal": False})))

    def test_api_gateway_and_cloudfront_public(self) -> None:
        for rtype in ("aws_apigatewayv2_api", "aws_api_gateway_rest_api", "aws_cloudfront_distribution"):
            self.assertTrue(is_public_exposure(self._tf_resource(rtype, {})))

    def test_kubernetes_ingress_annotation_public(self) -> None:
        r = self._tf_resource("kubernetes_ingress", {"annotations": {"nginx.ingress.kubernetes.io/rewrite-target": "/"}})
        self.assertTrue(is_public_exposure(r))

    def test_kubernetes_ingress_rule_public(self) -> None:
        r = self._tf_resource("kubernetes_ingress_v1", {"rules": [{"host": "example.com"}]})
        self.assertTrue(is_public_exposure(r))

    def test_kubernetes_public_service_requires_workload_name_or_selector_match(self) -> None:
        public_service = resource("kubernetes_service.web_public", "kubernetes_service", {"type": "LoadBalancer", "metadata": [{"name": "web"}]})
        api = resource(
            "kubernetes_deployment.api",
            "kubernetes_deployment",
            {"metadata": [{"name": "api"}], "spec": [{"template": [{"spec": [{"container": [{"name": "api", "image": "repo/api:1"}]}]}]}]},
        )
        worker = resource(
            "kubernetes_deployment.worker",
            "kubernetes_deployment",
            {"metadata": [{"name": "worker"}], "spec": [{"template": [{"spec": [{"container": [{"name": "worker", "image": "repo/worker:1"}]}]}]}]},
        )
        analysis = TerraformAnalyzer(plan([public_service, api, worker]), [Artifact(name="api", reference="repo/api:1"), Artifact(name="worker", reference="repo/worker:1")]).analyze()
        self.assertEqual(analysis.contexts["api"].exposure, "unknown")
        self.assertEqual(analysis.contexts["worker"].exposure, "unknown")

    def test_kubernetes_cluster_ip_service_marks_matching_workload_internal(self) -> None:
        service = resource("kubernetes_service.api", "kubernetes_service", {"type": "ClusterIP", "metadata": [{"name": "api"}], "selector": {"app": "api"}})
        deployment = resource(
            "kubernetes_deployment.api",
            "kubernetes_deployment",
            {"metadata": [{"name": "api"}], "spec": [{"template": [{"spec": [{"container": [{"name": "api", "image": "repo/api:1"}]}]}]}]},
        )
        analysis = TerraformAnalyzer(plan([service, deployment]), [Artifact(name="api", reference="repo/api:1")]).analyze()
        self.assertEqual(analysis.contexts["api"].exposure, "internal")

    def test_azure_public_resources(self) -> None:
        for rtype in ("azurerm_public_ip", "azurerm_application_gateway", "azurerm_frontdoor_endpoint", "azurerm_cdn_frontdoor_endpoint"):
            self.assertTrue(is_public_exposure(self._tf_resource(rtype, {})))

    def test_azure_container_app_ingress_dict_public(self) -> None:
        data = plan([resource("azurerm_container_app.app", "azurerm_container_app", {"name": "app", "template": [{"container": [{"image": "repo/app:1"}]}], "ingress": {"external_enabled": True}})])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "public")

    def test_azure_container_app_internal_ingress(self) -> None:
        data = plan([resource("azurerm_container_app.app", "azurerm_container_app", {"name": "app", "template": [{"container": [{"image": "repo/app:1"}]}], "ingress": {"external_enabled": False}})])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")

    def test_azure_container_app_list_ingress_and_no_ingress(self) -> None:
        cases = [
            ("list", {"ingress": [{"external_enabled": False}]}, "internal"),
            ("none", {"virtual_network_subnet_id": "subnet-private"}, "private"),
        ]
        for name, extra_values, expected in cases:
            with self.subTest(name=name):
                values = {"name": "app", "template": [{"container": [{"image": "repo/app:1"}]}]}
                values.update(extra_values)
                data = plan([resource("azurerm_container_app.app", "azurerm_container_app", values)])
                analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
                self.assertEqual(analysis.contexts["app"].exposure, expected)

    def test_azapi_container_app_classifies_and_scores_context(self) -> None:
        data = plan(
            [
                resource(
                    "azapi_resource.app",
                    "azapi_resource",
                    {"type": "Microsoft.App/containerApps@2023-05-01", "name": "app", "properties": {"template": {"containers": [{"image": "repo/app:1"}]}, "configuration": {"ingress": {"external": True}}}, "ingress": {"external": True}},
                )
            ]
        )
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.coverage["summary"]["unsupported_or_unclassified_resources"], 0)
        self.assertEqual(analysis.contexts["app"].exposure, "public")

    def test_azapi_container_app_internal_ingress(self) -> None:
        data = plan(
            [
                resource(
                    "azapi_resource.app",
                    "azapi_resource",
                    {"type": "Microsoft.App/containerApps@2023-05-01", "name": "app", "properties": {"template": {"containers": [{"image": "repo/app:1"}]}}, "ingress": {"external": False}},
                )
            ]
        )
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")

    def test_azapi_container_app_without_ingress_is_unknown_without_network_hint(self) -> None:
        data = plan(
            [
                resource(
                    "azapi_resource.app",
                    "azapi_resource",
                    {"type": "Microsoft.App/containerApps@2023-05-01", "name": "app", "properties": {"template": {"containers": [{"image": "repo/app:1"}]}}},
                )
            ]
        )
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "unknown")

    def test_azure_vm_public_and_private(self) -> None:
        cases = [
            ("public", {"name": "app", "public_ip_address": "52.1.1.1"}, "public"),
            ("private", {"name": "app", "virtual_network_subnet_id": "subnet-1"}, "private"),
        ]
        for name, values, expected in cases:
            with self.subTest(name=name):
                data = plan([resource("azurerm_linux_virtual_machine.app", "azurerm_linux_virtual_machine", values)])
                analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
                self.assertEqual(analysis.contexts["app"].exposure, expected)

    def test_azure_web_app_private_when_public_access_disabled_without_bridge(self) -> None:
        data = plan([resource("azurerm_linux_web_app.app", "azurerm_linux_web_app", {"name": "app", "public_network_access_enabled": False})])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "private")

    def test_azure_web_app_internal_when_public_access_disabled_with_vnet_peering(self) -> None:
        data = plan([
            resource("azurerm_virtual_network_peering.peer", "azurerm_virtual_network_peering", {"name": "peer"}),
            resource("azurerm_linux_web_app.app", "azurerm_linux_web_app", {"name": "app", "public_network_access_enabled": False}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")

    def test_gcp_cloud_run_ingress_external(self) -> None:
        data = plan([resource("google_cloud_run_v2_service.app", "google_cloud_run_v2_service", {"name": "app", "template": [{"containers": [{"image": "repo/app:1"}]}], "ingress": "INGRESS_TRAFFIC_ALL"})])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "external")

    def test_gcp_cloud_run_ingress_internal(self) -> None:
        data = plan([resource("google_cloud_run_v2_service.app", "google_cloud_run_v2_service", {"name": "app", "template": [{"containers": [{"image": "repo/app:1"}]}], "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"})])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")

    def test_gcp_cloud_run_public_invoker_and_private_fallback(self) -> None:
        public_data = plan([
            resource("google_cloud_run_v2_service.app", "google_cloud_run_v2_service", {"name": "app", "template": [{"containers": [{"image": "repo/app:1"}]}]}),
            resource("google_cloud_run_v2_service_iam_member.app", "google_cloud_run_v2_service_iam_member", {"service": "app", "role": "roles/run.invoker", "member": "allUsers"}),
        ])
        public_analysis = TerraformAnalyzer(public_data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(public_analysis.contexts["app"].exposure, "public")

        private_data = plan([resource("google_cloud_run_v2_service.app", "google_cloud_run_v2_service", {"name": "app", "template": [{"containers": [{"image": "repo/app:1"}]}], "vpc_access": {"connector": "projects/p/locations/r/connectors/c"}})])
        private_analysis = TerraformAnalyzer(private_data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(private_analysis.contexts["app"].exposure, "private")

    def test_gcp_cloud_run_links_service_account_iam_privilege(self) -> None:
        data = plan([
            resource("google_cloud_run_v2_service.app", "google_cloud_run_v2_service", {"name": "app", "template": [{"service_account": "svc@example.iam.gserviceaccount.com", "containers": [{"image": "repo/app:1"}]}]}),
            resource("google_project_iam_member.secret", "google_project_iam_member", {"role": "roles/secretmanager.secretAccessor", "member": "serviceAccount:svc@example.iam.gserviceaccount.com"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].privilege, "sensitive")
        self.assertTrue(any("terraform identity path" in item for item in analysis.contexts["app"].evidence))

    def test_gcp_compute_instance_public_and_private(self) -> None:
        cases = [
            ("public", {"name": "app", "boot_disk": [], "network_interface": [{"access_config": [{}]}]}, "public"),
            ("private", {"name": "app", "network_interface": [{"network": "default"}]}, "private"),
        ]
        for name, values, expected in cases:
            with self.subTest(name=name):
                data = plan([resource("google_compute_instance.app", "google_compute_instance", values)])
                analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
                self.assertEqual(analysis.contexts["app"].exposure, expected)

    def test_gcp_function_and_cluster_private_fallback(self) -> None:
        function_data = plan([resource("google_cloudfunctions2_function.app", "google_cloudfunctions2_function", {"name": "app", "docker_repository": "repo/app:1", "vpc_connector": "connector-1"})])
        function_analysis = TerraformAnalyzer(function_data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(function_analysis.contexts["app"].exposure, "private")

        cluster_data = plan([resource("google_container_cluster.app", "google_container_cluster", {"name": "app", "network": "default"})])
        cluster_analysis = TerraformAnalyzer(cluster_data, [Artifact(name="app")]).analyze()
        self.assertEqual(cluster_analysis.contexts["app"].exposure, "private")

    def test_gcp_cloud_function_public_name(self) -> None:
        data = plan([
            resource("google_cloudfunctions_function.fn", "google_cloudfunctions_function", {"name": "fn", "docker_repository": "repo/fn:1"}),
            resource("google_cloudfunctions_function_iam_member.fn_public", "google_cloudfunctions_function_iam_member", {"cloud_function": "fn", "role": "roles/cloudfunctions.invoker", "member": "allUsers"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="fn", reference="repo/fn:1")]).analyze()
        self.assertEqual(analysis.contexts["fn"].exposure, "public")

    def test_privilege_branches_for_identity_resources(self) -> None:
        cases = [
            ("aws_iam_role_policy_attachment", {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}, "admin"),
            ("aws_iam_role", {"managed_policy_arns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]}, "limited"),
            ("google_service_account_iam_binding", {"role": "roles/storage.admin"}, "sensitive"),
            ("kubernetes_cluster_role_binding", {"role_ref": {"name": "cluster-admin"}}, "admin"),
        ]
        for rtype, values, expected in cases:
            with self.subTest(rtype=rtype):
                self.assertEqual(privilege_for_resource(self._tf_resource(rtype, values)), expected)

    def test_classify_policy_string_and_none(self) -> None:
        self.assertEqual(classify_policy(None), "unknown")
        self.assertEqual(classify_policy("AdministratorAccess"), "admin")
        self.assertEqual(classify_policy("roles/viewer"), "limited")

    def test_classify_policy_deny_and_non_dict_statement(self) -> None:
        self.assertEqual(classify_policy({"Statement": [{"Effect": "Deny", "Action": "*"}, "bad"]}), "unknown")

    def test_classify_role_text_empty_and_plain(self) -> None:
        self.assertEqual(classify_role_text(None), "unknown")
        self.assertEqual(classify_role_text("plain text"), "unknown")

    def test_azure_key_vault_admin_and_unknown(self) -> None:
        self.assertEqual(privilege_for_resource(self._tf_resource("azurerm_key_vault_access_policy", {"secret_permissions": ["Set"]})), "admin")
        self.assertEqual(privilege_for_resource(self._tf_resource("azurerm_key_vault_access_policy", {"secret_permissions": []})), "unknown")

    def test_tag_or_label_from_labels_list(self) -> None:
        from reachability_advisor.terraform import tag_or_label
        values = {"labels": [{"app.kubernetes.io/owner": "@team"}, {"environment": "stage"}]}
        self.assertEqual(tag_or_label(values, "owner"), "@team")
        self.assertEqual(tag_or_label(values, "environment"), "stage")
        self.assertEqual(tag_or_label(values, "missing", "fallback"), "fallback")

    def test_resource_without_provider_is_accounted(self) -> None:
        report = coverage_report(extract_resources(plan([resource("custom_resource.x", "custom_resource", {})])), [], [])
        self.assertEqual(report["summary"]["resource_accounting_coverage"], 1.0)
        self.assertEqual(report["resources"][0]["provider"], "unknown")

    def test_artifact_accumulator_unknown_provider_context_path(self) -> None:
        data = plan([resource("random_workload.app", "random_workload", {"name": "app"})])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts, {})
