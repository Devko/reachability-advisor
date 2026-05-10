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
    extract_resources,
    find_image_references,
    image_matches,
    is_public_exposure,
    load_terraform_plan,
    manifest_report,
    privilege_for_resource,
    provider_for_type,
)

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

    def test_azure_nsg_public(self) -> None:
        r = self._tf_resource("azurerm_network_security_rule", {"source_address_prefix": "Internet", "direction": "Inbound", "access": "Allow"})
        self.assertTrue(is_public_exposure(r))

    def test_azure_nsg_deny_not_public(self) -> None:
        r = self._tf_resource("azurerm_network_security_rule", {"source_address_prefix": "*", "direction": "Inbound", "access": "Deny"})
        self.assertFalse(is_public_exposure(r))

    def test_gcp_firewall_public(self) -> None:
        r = self._tf_resource("google_compute_firewall", {"source_ranges": ["0.0.0.0/0"], "direction": "INGRESS"})
        self.assertTrue(is_public_exposure(r))

    def test_gcp_firewall_disabled_not_public(self) -> None:
        r = self._tf_resource("google_compute_firewall", {"source_ranges": ["0.0.0.0/0"], "disabled": True})
        self.assertFalse(is_public_exposure(r))

    def test_lambda_function_url_public(self) -> None:
        r = self._tf_resource("aws_lambda_function_url", {"function_name": "fn", "authorization_type": "NONE"})
        self.assertTrue(is_public_exposure(r))

    def test_gcp_all_users_invoker_public(self) -> None:
        r = self._tf_resource("google_cloud_run_service_iam_member", {"service": "svc", "role": "roles/run.invoker", "member": "allUsers"})
        self.assertTrue(is_public_exposure(r))

    def test_kubernetes_load_balancer_public(self) -> None:
        r = self._tf_resource("kubernetes_service", {"type": "LoadBalancer"})
        self.assertTrue(is_public_exposure(r))


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
        ]
        data = json.loads((ROOT / "samples/tfplan-multicloud.json").read_text(encoding="utf-8"))
        analysis = TerraformAnalyzer(data, artifacts, source_name="sample").analyze()
        self.assertEqual(set(analysis.contexts), {"payments-api", "notifier", "orders-api", "audit-api"})
        self.assertEqual(analysis.contexts["payments-api"].exposure, "public")
        self.assertEqual(analysis.contexts["orders-api"].privilege, "admin")
        self.assertEqual(analysis.contexts["audit-api"].privilege, "sensitive")
        self.assertEqual(analysis.coverage["summary"]["resource_accounting_coverage"], 1.0)
        self.assertEqual(analysis.coverage["summary"]["semantic_classification_coverage"], 1.0)
        self.assertEqual(analysis.coverage["summary"]["artifact_match_coverage"], 1.0)

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
            self.assertEqual(findings["metadata"]["terraform_resources"], 15)

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

    def test_sensitive_resource_sets_limited_when_no_privilege_policy(self) -> None:
        data = plan([
            resource("aws_lambda_function.app", "aws_lambda_function", {"function_name": "app", "image_uri": "repo/app:1"}),
            resource("aws_secretsmanager_secret.app", "aws_secretsmanager_secret", {"name": "secret"}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].privilege, "limited")

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

    def test_ecs_task_definition_uses_linked_public_service(self) -> None:
        data = plan([
            resource("aws_security_group.public", "aws_security_group", {"id": "sg-public", "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]}),
            resource("aws_ecs_task_definition.app", "aws_ecs_task_definition", {"family": "app", "container_definitions": "[{\"name\":\"app\",\"image\":\"repo/app:1\"}]"}),
            resource("aws_ecs_service.app", "aws_ecs_service", {"name": "service", "task_definition": "app", "network_configuration": [{"security_groups": ["sg-public"]}]}),
        ])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "public")

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

    def test_azure_public_resources(self) -> None:
        for rtype in ("azurerm_public_ip", "azurerm_application_gateway", "azurerm_frontdoor_endpoint", "azurerm_cdn_frontdoor_endpoint"):
            self.assertTrue(is_public_exposure(self._tf_resource(rtype, {})))

    def test_azure_container_app_ingress_dict_public(self) -> None:
        data = plan([resource("azurerm_container_app.app", "azurerm_container_app", {"name": "app", "template": [{"container": [{"image": "repo/app:1"}]}], "ingress": {"external_enabled": True}})])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "public")

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

    def test_azure_web_app_internal_when_public_access_disabled(self) -> None:
        data = plan([resource("azurerm_linux_web_app.app", "azurerm_linux_web_app", {"name": "app", "public_network_access_enabled": False})])
        analysis = TerraformAnalyzer(data, [Artifact(name="app")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "internal")

    def test_gcp_cloud_run_ingress_external(self) -> None:
        data = plan([resource("google_cloud_run_v2_service.app", "google_cloud_run_v2_service", {"name": "app", "template": [{"containers": [{"image": "repo/app:1"}]}], "ingress": "INGRESS_TRAFFIC_ALL"})])
        analysis = TerraformAnalyzer(data, [Artifact(name="app", reference="repo/app:1")]).analyze()
        self.assertEqual(analysis.contexts["app"].exposure, "external")

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
