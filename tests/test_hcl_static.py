from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.hcl_static import HclAuditError, analyze_terraform_source, audit_hcl_project, hcl_blocks_to_plan, render_hcl_audit_markdown
from reachability_advisor.models import Artifact
from reachability_advisor.terraform import extract_resources, find_image_references, is_public_exposure


class HclStaticAuditTests(unittest.TestCase):
    def test_audit_gcp_cloud_run_module_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(
                '''
                resource "google_cloud_run_service" "main" {
                  name = "audit-api"
                  template { spec { containers { image = "gcr.io/acme/audit-api:1" } } }
                }
                resource "google_cloud_run_service_iam_member" "authorize" {
                  service = google_cloud_run_service.main.name
                  role = "roles/run.invoker"
                  member = "allUsers"
                }
                resource "google_cloud_run_domain_mapping" "domain" { name = "audit.example.com" }
                ''',
                encoding="utf-8",
            )
            audit = audit_hcl_project(root)
        report = audit.to_json()
        self.assertEqual(report["summary"]["resource_blocks"], 3)
        self.assertIn("google_cloud_run_service", report["resource_types_seen"])
        self.assertEqual(report["coverage"]["summary"]["resource_accounting_coverage"], 1.0)
        self.assertEqual(report["coverage"]["summary"]["semantic_classification_coverage"], 1.0)
        self.assertEqual(report["summary"]["literal_image_references"], 1)

    def test_audit_reports_unresolved_image_and_module_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(
                '''
                module "cloud_run" {
                  source = "GoogleCloudPlatform/cloud-run/google"
                  image  = var.image
                }
                resource "azurerm_container_app" "app" {
                  name = "orders-api"
                  template { container { image = each.value.image } }
                  ingress { external_enabled = true }
                }
                ''',
                encoding="utf-8",
            )
            audit = audit_hcl_project(root)
        report = audit.to_json()
        self.assertEqual(report["summary"]["module_blocks"], 1)
        self.assertEqual(report["summary"]["unresolved_image_references"], 1)
        reasons = "\n".join(gap["reason"] for gap in report["coverage"]["visibility_gaps"])
        self.assertIn("module child resources", reasons)
        self.assertIn("unresolved expression", reasons)

    def test_hcl_audit_ignores_line_commented_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(
                '''
                # resource "aws_ecs_task_definition" "old" {
                #   family = "commented"
                # }
                resource "aws_ecs_service" "service" {
                  name = "petclinic"
                }
                ''',
                encoding="utf-8",
            )
            audit = audit_hcl_project(root)
        self.assertEqual([block.address for block in audit.resources], ["aws_ecs_service.service"])

    def test_hcl_blocks_to_plan_extracts_public_exposure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(
                '''
                resource "aws_security_group" "public" {
                  ingress { cidr_blocks = ["0.0.0.0/0"] }
                }
                ''',
                encoding="utf-8",
            )
            audit = audit_hcl_project(root)
        resources = extract_resources(audit.synthetic_plan)
        self.assertEqual(resources[0].type, "aws_security_group")
        self.assertTrue(is_public_exposure(resources[0]))

    def test_hcl_source_can_feed_scan_context_with_literal_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(
                '''
                resource "azurerm_container_app" "orders" {
                  name = "orders-api"
                  template { container { image = "mcr.microsoft.com/acme/orders-api:2" } }
                  ingress { external_enabled = true }
                }
                resource "azurerm_role_assignment" "owner" {
                  role_definition_name = "Contributor"
                }
                ''',
                encoding="utf-8",
            )
            analysis = analyze_terraform_source(root, [Artifact(name="orders-api", reference="mcr.microsoft.com/acme/orders-api:2")])
        self.assertIn("orders-api", analysis.contexts)
        self.assertEqual(analysis.contexts["orders-api"].exposure, "public")
        self.assertEqual(analysis.contexts["orders-api"].privilege, "admin")
        self.assertEqual(analysis.coverage["source_mode"], "hcl_static")

    def test_hcl_audit_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "tf"
            root.mkdir()
            (root / "main.tf").write_text('resource "kubernetes_service" "web" { type = "LoadBalancer" }', encoding="utf-8")
            out = Path(tmp) / "audit.json"
            md = Path(tmp) / "audit.md"
            code = main(["hcl-audit", "--path", str(root), "--out", str(out), "--markdown-out", str(md)])
            self.assertEqual(code, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["resource_blocks"], 1)
            self.assertIn("Terraform HCL Static Audit", md.read_text(encoding="utf-8"))

    def test_hcl_audit_errors_without_tf_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(HclAuditError):
                audit_hcl_project(tmp)

    def test_render_markdown_includes_visibility_gap(self) -> None:
        report = {
            "root": "/x",
            "summary": {"tf_files": 1, "resource_blocks": 0, "module_blocks": 1, "data_blocks": 0, "literal_image_references": 0, "unresolved_image_references": 0},
            "resource_types_seen": [],
            "coverage": {"summary": {"resource_accounting_coverage": 1.0, "semantic_classification_coverage": 1.0}, "visibility_gaps": [{"address": "module.x", "reason": "module expansion"}]},
        }
        md = render_hcl_audit_markdown(report)
        self.assertIn("module expansion", md)

    def test_hcl_extracted_image_is_visible_to_terraform_image_finder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text('resource "google_cloud_run_v2_service" "app" { template { containers { image = "gcr.io/acme/app:1" } } }', encoding="utf-8")
            audit = audit_hcl_project(root)
        resources = extract_resources(audit.synthetic_plan)
        self.assertEqual(find_image_references(resources[0].values), ["gcr.io/acme/app:1"])

    def test_hcl_static_handles_json_style_image_and_azapi_external(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(
                '''
                resource "azapi_resource" "app" {
                  type = "Microsoft.App/containerApps@2023-05-01"
                  body = jsonencode({
                    properties = {
                      template = { containers = [{ image: "repo/app:1" }] }
                      configuration = { ingress = { external = true } }
                    }
                  })
                }
                ''',
                encoding="utf-8",
            )
            audit = audit_hcl_project(root)
        resources = extract_resources(audit.synthetic_plan)
        self.assertEqual(resources[0].provider, "azure")
        self.assertEqual(resources[0].category, "workload")
        self.assertIn("repo/app:1", find_image_references(resources[0].values))


if __name__ == "__main__":
    unittest.main()

class HclStaticCoverageBoostTests(unittest.TestCase):
    def test_nonexistent_path_errors(self) -> None:
        with self.assertRaises(HclAuditError):
            audit_hcl_project("/definitely/not/here")

    def test_single_file_and_data_block_are_accounted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "single.tf"
            path.write_text(
                'data "google_project" "current" {}\nresource "google_compute_firewall" "public" { source_ranges = ["0.0.0.0/0"] direction = "INGRESS" }',
                encoding="utf-8",
            )
            audit = audit_hcl_project(path)
        report = audit.to_json()
        self.assertEqual(report["summary"]["tf_files"], 1)
        self.assertEqual(report["summary"]["data_blocks"], 1)
        self.assertEqual(report["data"][0]["address"], "data.google_project.current")
        resources = extract_resources(audit.synthetic_plan)
        self.assertTrue(is_public_exposure(resources[0]))

    def test_invalid_utf8_file_is_decoded_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.tf"
            path.write_bytes(b'resource "random_string" "x" { length = 4 }\xff')
            audit = audit_hcl_project(path)
        self.assertTrue(audit.warnings)
        self.assertEqual(audit.to_json()["summary"]["resource_blocks"], 1)

    def test_hcl_static_handles_aws_ipv6_and_container_definitions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(
                '''
                resource "aws_security_group" "public" {
                  ingress { ipv6_cidr_blocks = ["::/0"] }
                }
                resource "aws_ecs_task_definition" "task" {
                  container_definitions = jsonencode([{ image = "ghcr.io/acme/app:1" }])
                }
                ''',
                encoding="utf-8",
            )
            audit = audit_hcl_project(root)
        resources = extract_resources(audit.synthetic_plan)
        self.assertTrue(is_public_exposure(resources[0]))
        self.assertIn("ghcr.io/acme/app:1", find_image_references(resources[1].values))

    def test_hcl_static_preserves_security_group_reference_for_exposure_linking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(
                '''
                resource "aws_security_group" "alb" {
                  ingress { cidr_blocks = ["0.0.0.0/0"] }
                }
                resource "aws_security_group" "task" {
                  ingress { security_groups = [aws_security_group.alb.id] }
                }
                resource "aws_ecs_service" "app" {
                  name = "app"
                  network_configuration { security_groups = [aws_security_group.task.id] }
                }
                ''',
                encoding="utf-8",
            )
            analysis = analyze_terraform_source(root, [Artifact(name="app")])
        self.assertEqual(analysis.contexts["app"].exposure, "public")

    def test_hcl_static_preserves_interpolated_image_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(
                '''
                resource "aws_ecs_task_definition" "task" {
                  container_definitions = <<DEFINITION
                  [{"image": "${aws_ecr_repository.image_repo.repository_url}"}]
                  DEFINITION
                }
                ''',
                encoding="utf-8",
            )
            audit = audit_hcl_project(root)
        self.assertIn("${aws_ecr_repository.image_repo.repository_url}", audit.resources[0].body)
        resources = extract_resources(audit.synthetic_plan)
        self.assertIn("${aws_ecr_repository.image_repo.repository_url}", find_image_references(resources[0].values))

    def test_hcl_static_resolves_simple_variable_defaults_and_tfvars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "variables.tf").write_text(
                '''
                variable "family" {
                  default = "petclinic"
                }
                variable "stack" {
                  default = "dev"
                }
                ''',
                encoding="utf-8",
            )
            (root / "terraform.tfvars").write_text('stack = "prod"', encoding="utf-8")
            (root / "main.tf").write_text(
                '''
                resource "aws_ecs_task_definition" "task" {
                  family = var.family
                }
                resource "aws_ecs_service" "service" {
                  name = "${var.stack}-service"
                  container_name = var.family
                }
                ''',
                encoding="utf-8",
            )
            audit = audit_hcl_project(root)
        resources = {resource.address: resource for resource in extract_resources(audit.synthetic_plan)}
        self.assertEqual(resources["aws_ecs_task_definition.task"].values["family"], "petclinic")
        self.assertEqual(resources["aws_ecs_service.service"].values["name"], "prod-service")
        self.assertEqual(audit.to_json()["summary"]["resolved_variable_values"], 2)

    def test_hcl_static_handles_azure_nsg_and_private_container_app(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(
                '''
                resource "azurerm_network_security_rule" "web" {
                  source_address_prefix = "Internet"
                  direction = "Inbound"
                  access = "Allow"
                }
                resource "azurerm_container_app" "private" {
                  ingress { external_enabled = false }
                }
                ''',
                encoding="utf-8",
            )
            audit = audit_hcl_project(root)
        resources = extract_resources(audit.synthetic_plan)
        self.assertTrue(is_public_exposure(resources[0]))
        self.assertFalse(resources[1].values["ingress"][0]["external_enabled"])

    def test_hcl_static_handles_kubernetes_load_balancer_and_module_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(
                '''
                module "child" {
                  source  = "example/module"
                  version = "1.2.3"
                  image_url = var.image_url
                }
                resource "kubernetes_service" "web" { type = "LoadBalancer" }
                ''',
                encoding="utf-8",
            )
            report = audit_hcl_project(root).to_json()
        self.assertEqual(report["modules"][0]["source"], "example/module")
        self.assertEqual(report["modules"][0]["version"], "1.2.3")
        self.assertEqual(report["modules"][0]["address"], "module.child")
        self.assertIn("image_url", report["modules"][0]["image_like_arguments"][0]["key"])

    def test_hcl_static_classifies_opaque_manifest_wrappers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text(
                '''
                resource "helm_release" "api" {
                  name = "api"
                }
                resource "kubectl_manifest" "api" {
                  yaml_body = "kind: Deployment"
                }
                ''',
                encoding="utf-8",
            )
            report = audit_hcl_project(root).to_json()
        self.assertEqual(report["coverage"]["summary"]["semantic_classification_coverage"], 1.0)
        self.assertEqual(report["coverage"]["summary"]["unsupported_or_unclassified_resources"], 0)
        self.assertEqual({gap["gap_type"] for gap in report["coverage"]["visibility_gaps"]}, {"opaque_manifest_wrapper"})

    def test_hcl_blocks_to_plan_skips_non_resource_like_block_without_type(self) -> None:
        from reachability_advisor.hcl_static import HclBlock

        block = HclBlock(kind="module", type=None, name="x", body="", file="x.tf", line=1)
        plan = hcl_blocks_to_plan([block])
        self.assertEqual(plan["planned_values"]["root_module"]["resources"], [])

    def test_analyze_terraform_source_none_returns_empty_report(self) -> None:
        analysis = analyze_terraform_source(None, [])
        self.assertEqual(analysis.coverage["summary"]["total_resources"], 0)

    def test_hcl_audit_cli_stdout_and_fail_on_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.tf").write_text('module "x" { source = "example/module" image = var.image }', encoding="utf-8")
            ok_code = main(["hcl-audit", "--path", str(root)])
            fail_code = main(["hcl-audit", "--path", str(root), "--fail-on-gaps"])
        self.assertEqual(ok_code, 0)
        self.assertEqual(fail_code, 10)

    def test_scan_rejects_plan_and_source_together(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = root / "tfplan.json"
            plan.write_text('{"planned_values":{"root_module":{"resources":[]}}}', encoding="utf-8")
            tf = root / "tf"
            tf.mkdir()
            (tf / "main.tf").write_text('resource "random_string" "x" { length = 4 }', encoding="utf-8")
            code = main(
                [
                    "scan",
                    "--sbom",
                    str(Path("samples/sboms/audit-api.cdx.json")),
                    "--vulns",
                    str(Path("samples/vulnerabilities.json")),
                    "--terraform-plan",
                    str(plan),
                    "--terraform-source",
                    str(tf),
                    "--no-table",
                ]
            )
        self.assertEqual(code, 2)
