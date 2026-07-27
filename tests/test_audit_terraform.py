"""Regression tests for audit findings in the Terraform / HCL analysis group."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from reachability_advisor.hcl_static import (
    _values_from_body,
    analyze_terraform_source,
    audit_hcl_project,
)
from reachability_advisor.models import Artifact
from reachability_advisor.terraform import (
    TerraformAnalyzer,
    TerraformNetworkGraph,
    _aws_security_group_ingress_exposure,
    _gcp_firewall_exposure,
    _security_group_source_refs,
    analyze_terraform_plan,
    exposure_for_resource,
    extract_resources,
    is_public_exposure,
)
from reachability_advisor.terraform_exposure import (
    cap_exposure,
    exposure_rank,
    max_exposure,
    network_source_exposure,
)
from reachability_advisor.terraform_manifest import resource_type_supported
from reachability_advisor.terraform_network_adapters import network_adapter_signals
from reachability_advisor.terraform_resources import flatten_unknown_paths

ROOT = Path(__file__).resolve().parents[1]

PAYMENTS_IMAGE = "ghcr.io/acme/payments-api:1.2.3"
CONTAINER_DEFINITIONS = json.dumps([{"name": "payments-api", "image": PAYMENTS_IMAGE}])


def _resource(address: str, rtype: str, values: dict[str, Any]) -> dict[str, Any]:
    return {"address": address, "type": rtype, "name": address.split(".")[-1], "values": values}


def _plan(resources: list[dict[str, Any]]) -> dict[str, Any]:
    return {"planned_values": {"root_module": {"resources": resources}}}


def _payments_artifact() -> Artifact:
    return Artifact(name="payments-api", reference=PAYMENTS_IMAGE)


def _analyze(plan: dict[str, Any]) -> Any:
    return TerraformAnalyzer(plan, [_payments_artifact()], source_name="plan").analyze()


def _ecs_workload(security_group_id: str = "sg-web") -> list[dict[str, Any]]:
    return [
        _resource(
            "aws_ecs_task_definition.app",
            "aws_ecs_task_definition",
            {"family": "payments-api", "container_definitions": CONTAINER_DEFINITIONS},
        ),
        _resource(
            "aws_ecs_service.app",
            "aws_ecs_service",
            {
                "name": "payments-api",
                "task_definition": "payments-api",
                "network_configuration": [{"security_groups": [security_group_id]}],
            },
        ),
    ]


class ModernAwsSecurityGroupRuleTests(unittest.TestCase):
    """Finding 1: aws_vpc_security_group_{ingress,egress}_rule were unsupported."""

    def test_modern_ingress_rule_open_to_the_internet_is_public(self) -> None:
        plan = _plan(
            [
                _resource("aws_security_group.web", "aws_security_group", {"id": "sg-web"}),
                _resource(
                    "aws_vpc_security_group_ingress_rule.web_all",
                    "aws_vpc_security_group_ingress_rule",
                    {"security_group_id": "sg-web", "cidr_ipv4": "0.0.0.0/0", "ip_protocol": "-1"},
                ),
                *_ecs_workload(),
            ]
        )
        analysis = _analyze(plan)
        # Before the fix this was "private": the modern rule resource was never
        # read, so the ECS service fell through to the private default.
        self.assertEqual(analysis.contexts["payments-api"].exposure, "public")

    def test_modern_egress_rule_to_the_internet_is_not_ingress(self) -> None:
        plan = _plan(
            [
                _resource("aws_security_group.web", "aws_security_group", {"id": "sg-web"}),
                _resource(
                    "aws_vpc_security_group_ingress_rule.private",
                    "aws_vpc_security_group_ingress_rule",
                    {"security_group_id": "sg-web", "cidr_ipv4": "10.0.0.0/8", "ip_protocol": "tcp"},
                ),
                _resource(
                    "aws_vpc_security_group_egress_rule.all",
                    "aws_vpc_security_group_egress_rule",
                    {"security_group_id": "sg-web", "cidr_ipv4": "0.0.0.0/0", "ip_protocol": "-1"},
                ),
                *_ecs_workload(),
            ]
        )
        analysis = _analyze(plan)
        # The allow-all egress rule is present on virtually every modern SG; it
        # must never be read as public ingress.
        self.assertEqual(analysis.contexts["payments-api"].exposure, "internal")

    def test_egress_rule_type_never_yields_ingress_exposure(self) -> None:
        values = {"security_group_id": "sg-web", "cidr_ipv4": "0.0.0.0/0", "ip_protocol": "-1"}
        self.assertEqual(_aws_security_group_ingress_exposure(values, "aws_vpc_security_group_egress_rule"), "unknown")
        self.assertEqual(_aws_security_group_ingress_exposure(values, "aws_vpc_security_group_ingress_rule"), "public")
        egress = extract_resources(_plan([_resource("aws_vpc_security_group_egress_rule.all", "aws_vpc_security_group_egress_rule", values)]))[0]
        self.assertFalse(is_public_exposure(egress))
        self.assertEqual(exposure_for_resource(egress), "unknown")

    def test_modern_rule_source_security_group_forms_a_lateral_edge(self) -> None:
        values = {"security_group_id": "sg-app", "referenced_security_group_id": "sg-lb"}
        self.assertEqual(_security_group_source_refs(values, "aws_vpc_security_group_ingress_rule"), {"sg-lb"})
        self.assertEqual(_security_group_source_refs(values, "aws_vpc_security_group_egress_rule"), set())

    def test_modern_rule_types_are_declared_in_the_coverage_manifest(self) -> None:
        for rtype in ("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"):
            self.assertTrue(resource_type_supported(rtype, {}), rtype)


class AfterUnknownTests(unittest.TestCase):
    """Finding 2: plan `after_unknown` was never read."""

    @staticmethod
    def _first_apply_plan() -> dict[str, Any]:
        service_values = {
            "name": "payments-api",
            "desired_count": 2,
            "network_configuration": [{"assign_public_ip": False}],
        }
        task_values = {"family": "payments-api", "container_definitions": CONTAINER_DEFINITIONS}
        sg_values = {"name": "payments-public", "ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 443, "to_port": 443}]}
        return {
            "planned_values": {
                "root_module": {
                    "resources": [
                        _resource("aws_security_group.web", "aws_security_group", sg_values),
                        _resource("aws_ecs_task_definition.payments", "aws_ecs_task_definition", task_values),
                        _resource("aws_ecs_service.payments", "aws_ecs_service", service_values),
                    ]
                }
            },
            "resource_changes": [
                {
                    "address": "aws_security_group.web",
                    "type": "aws_security_group",
                    "name": "web",
                    "change": {"actions": ["create"], "after": sg_values, "after_unknown": {"id": True, "arn": True}},
                },
                {
                    "address": "aws_ecs_task_definition.payments",
                    "type": "aws_ecs_task_definition",
                    "name": "payments",
                    "change": {"actions": ["create"], "after": task_values, "after_unknown": {"id": True, "arn": True}},
                },
                {
                    "address": "aws_ecs_service.payments",
                    "type": "aws_ecs_service",
                    "name": "payments",
                    "change": {
                        "actions": ["create"],
                        "after": service_values,
                        "after_unknown": {"id": True, "network_configuration": [{"security_groups": True, "subnets": True}]},
                    },
                },
            ],
        }

    def test_flatten_unknown_paths_walks_nested_mirrors(self) -> None:
        mirror = {"id": True, "network_configuration": [{"security_groups": True, "subnets": False}], "tags": {}}
        self.assertEqual(flatten_unknown_paths(mirror), frozenset({"id", "network_configuration.security_groups"}))
        self.assertEqual(flatten_unknown_paths(None), frozenset())

    def test_unknown_paths_are_carried_onto_the_resource(self) -> None:
        resources = {res.address: res for res in extract_resources(self._first_apply_plan())}
        self.assertIn("network_configuration.security_groups", resources["aws_ecs_service.payments"].unknown_paths)
        self.assertEqual(resources["aws_security_group.web"].unknown_paths, frozenset({"id", "arn"}))

    def test_unknown_network_attachment_is_not_reported_as_private(self) -> None:
        analysis = _analyze(self._first_apply_plan())
        # Before the fix this asserted exposure "private" (decision "isolated",
        # basis network:no_observed_ingress) from data the plan calls unknown.
        self.assertEqual(analysis.contexts["payments-api"].exposure, "unknown")

    def test_unknown_network_attachment_raises_a_visibility_gap(self) -> None:
        analysis = _analyze(self._first_apply_plan())
        gaps = [gap for gap in analysis.coverage["visibility_gaps"] if gap.get("gap_type") == "unknown_after_apply"]
        self.assertEqual([gap["address"] for gap in gaps], ["aws_ecs_service.payments"])
        self.assertIn("network_configuration.security_groups", gaps[0]["reason"])

    def test_known_attachment_still_classifies_normally(self) -> None:
        plan = self._first_apply_plan()
        plan["planned_values"]["root_module"]["resources"][2]["values"]["network_configuration"] = [{"security_groups": ["sg-web"]}]
        for change in plan["resource_changes"]:
            if change["address"] == "aws_ecs_service.payments":
                change["change"]["after"]["network_configuration"] = [{"security_groups": ["sg-web"]}]
                change["change"]["after_unknown"] = {"id": True}
        plan["planned_values"]["root_module"]["resources"][0]["values"]["id"] = "sg-web"
        for change in plan["resource_changes"]:
            if change["address"] == "aws_security_group.web":
                change["change"]["after"]["id"] = "sg-web"
        analysis = _analyze(plan)
        self.assertEqual(analysis.contexts["payments-api"].exposure, "public")
        self.assertEqual([gap for gap in analysis.coverage["visibility_gaps"] if gap.get("gap_type") == "unknown_after_apply"], [])


class HclStaticSecurityGroupDirectionTests(unittest.TestCase):
    """Finding 3: HCL static mode scraped CIDRs from the whole resource body."""

    @staticmethod
    def _write(tmp: str, body: str) -> Path:
        root = Path(tmp)
        (root / "main.tf").write_text(body, encoding="utf-8")
        return root

    PRIVATE_SG_PROJECT = '''
        resource "aws_security_group" "private_only" {
          name   = "payments-private"
          vpc_id = "vpc-1"

          ingress {
            from_port   = 443
            to_port     = 443
            protocol    = "tcp"
            cidr_blocks = ["10.0.0.0/8"]
          }

          egress {
            from_port   = 0
            to_port     = 0
            protocol    = "-1"
            cidr_blocks = ["0.0.0.0/0"]
          }
        }

        resource "aws_ecs_service" "payments" {
          name            = "payments-api"
          task_definition = "payments-api"
          network_configuration {
            security_groups = [aws_security_group.private_only.id]
            subnets         = ["subnet-1"]
          }
        }

        resource "aws_ecs_task_definition" "payments" {
          family                = "payments-api"
          container_definitions = "[{\\"name\\":\\"payments-api\\",\\"image\\":\\"ghcr.io/acme/payments-api:1.2.3\\"}]"
        }
        '''

    def test_egress_cidrs_are_not_scraped_as_ingress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._write(tmp, self.PRIVATE_SG_PROJECT)
            audit = audit_hcl_project(root)
            values = next(res["values"] for res in audit.synthetic_plan["planned_values"]["root_module"]["resources"] if res["type"] == "aws_security_group")
            # Before the fix this was ["10.0.0.0/8", "0.0.0.0/0"].
            self.assertEqual(values["ingress"], [{"cidr_blocks": ["10.0.0.0/8"], "ipv6_cidr_blocks": [], "security_groups": []}])
            analysis = analyze_terraform_source(root, [_payments_artifact()])
            self.assertEqual(analysis.contexts["payments-api"].exposure, "internal")

    def test_egress_only_security_group_group_gets_no_synthetic_ingress(self) -> None:
        body = '''
            resource "aws_security_group" "egress_only" {
              name = "egress-only"
              egress {
                from_port   = 0
                to_port     = 0
                protocol    = "-1"
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
            '''
        with tempfile.TemporaryDirectory() as tmp:
            audit = audit_hcl_project(self._write(tmp, body))
        values = audit.synthetic_plan["planned_values"]["root_module"]["resources"][0]["values"]
        self.assertNotIn("ingress", values)
        resource = extract_resources(audit.synthetic_plan)[0]
        self.assertFalse(is_public_exposure(resource))
        self.assertEqual(exposure_for_resource(resource), "unknown")

    def test_standalone_egress_rule_is_not_synthesized_as_ingress(self) -> None:
        body = 'type = "egress"\ncidr_blocks = ["0.0.0.0/0"]\n'
        values = _values_from_body(body, "aws_security_group_rule", {})
        self.assertNotIn("ingress", values)
        self.assertEqual(_aws_security_group_ingress_exposure(values, "aws_security_group_rule"), "unknown")

    def test_standalone_ingress_rule_is_still_public(self) -> None:
        body = 'type = "ingress"\ncidr_blocks = ["0.0.0.0/0"]\n'
        values = _values_from_body(body, "aws_security_group_rule", {})
        self.assertEqual(_aws_security_group_ingress_exposure(values, "aws_security_group_rule"), "public")

    def test_unattributable_direction_still_reports_and_records_a_gap(self) -> None:
        body = '''
            resource "aws_security_group" "dynamic_rules" {
              name = "dynamic"
              dynamic "ingress" {
                for_each = var.rules
                content {
                  cidr_blocks = ["0.0.0.0/0"]
                }
              }
              egress {
                cidr_blocks = ["10.9.0.0/16"]
              }
            }
            '''
        with tempfile.TemporaryDirectory() as tmp:
            audit = audit_hcl_project(self._write(tmp, body))
        values = audit.synthetic_plan["planned_values"]["root_module"]["resources"][0]["values"]
        # Absence of an attributable ingress block must not downgrade exposure,
        # but the verdict has to be caveated rather than asserted.
        self.assertEqual(values["ingress"][0]["cidr_blocks"], ["0.0.0.0/0"])
        reasons = [gap["reason"] for gap in audit.coverage["visibility_gaps"] if gap["address"] == "aws_security_group.dynamic_rules"]
        self.assertTrue(any("direction could not be attributed" in reason for reason in reasons), reasons)

    def test_synthetic_plan_values_carry_no_direction_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = audit_hcl_project(self._write(tmp, self.PRIVATE_SG_PROJECT))
        for res in audit.synthetic_plan["planned_values"]["root_module"]["resources"]:
            self.assertEqual([key for key in res["values"] if key.startswith("__hcl_sg")], [])


class NetworkSourceExposureTests(unittest.TestCase):
    """Finding 4: the private-CIDR branch was never executed by the suite."""

    CASES = (
        (None, "unknown"),
        ("", "unknown"),
        ("   ", "unknown"),
        ('"10.1.0.0/16"', "internal"),
        ("'10.1.0.0/16'", "internal"),
        ("  10.1.0.0/16  ", "internal"),
        ("10.1.0.0/16", "internal"),
        ("172.31.0.0/16", "internal"),
        ("172.20.5.0/24", "internal"),
        ("192.168.4.0/22", "internal"),
        ("fd00::/8", "internal"),
        ("127.0.0.1/32", "internal"),
        ("169.254.1.0/24", "internal"),
        ("100.64.0.0/10", "internal"),
        ("203.0.113.0/24", "internal"),
        ("2001:db8::/32", "internal"),
        ("sg-123", "internal"),
        ("VPC", "internal"),
        ("VirtualNetwork", "internal"),
        ("8.8.8.0/24", "external"),
        ("8.8.8.8/32", "external"),
        ("2001:4860::/32", "external"),
        ("2600::/16", "external"),
        ("0.0.0.0/0", "public"),
        ("::/0", "public"),
        ("*", "public"),
        ("Internet", "public"),
        ("allUsers", "public"),
        ("garbage", "unknown"),
    )

    def test_network_source_exposure_table(self) -> None:
        for value, expected in self.CASES:
            with self.subTest(value=value):
                self.assertEqual(network_source_exposure(value), expected)

    def test_unparseable_source_is_unknown_and_never_benign(self) -> None:
        for value in ("garbage", "${var.cidr}", "10.0.0.0/33"):
            with self.subTest(value=value):
                result = network_source_exposure(value)
                self.assertEqual(result, "unknown")
                self.assertNotEqual(result, "none")
                self.assertNotEqual(result, "private")

    def test_exposure_rank_is_strictly_ordered(self) -> None:
        order = ["unknown", "none", "private", "internal", "external", "public"]
        self.assertEqual([exposure_rank(value) for value in order], [0, 1, 2, 3, 4, 5])

    def test_unrecognized_exposure_cannot_outrank_a_known_one(self) -> None:
        self.assertEqual(exposure_rank("bogus"), 0)
        self.assertEqual(max_exposure("bogus", "none"), "none")
        self.assertEqual(max_exposure("bogus", "public"), "public")

    def test_cap_exposure_clamps_downward_only(self) -> None:
        self.assertEqual(cap_exposure("public", "internal"), "internal")
        self.assertEqual(cap_exposure("internal", None), "internal")
        self.assertEqual(cap_exposure("private", "public"), "private")


class GcpFirewallDenyTests(unittest.TestCase):
    """Finding 5: google_compute_firewall deny rules were read as ingress allows."""

    DENY = {"direction": "INGRESS", "priority": 900, "source_ranges": ["0.0.0.0/0"], "target_tags": ["web"], "deny": [{"protocol": "all"}]}
    ALLOW = {"direction": "INGRESS", "priority": 900, "source_ranges": ["0.0.0.0/0"], "target_tags": ["web"], "allow": [{"protocol": "all"}]}

    def test_deny_rule_is_not_ingress_exposure(self) -> None:
        self.assertEqual(_gcp_firewall_exposure(self.DENY), "unknown")
        self.assertEqual(_gcp_firewall_exposure(self.ALLOW), "public")

    def test_firewall_values_without_either_block_still_classify(self) -> None:
        bare = {"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "target_tags": ["web"]}
        self.assertEqual(_gcp_firewall_exposure(bare), "public")

    def test_deny_rule_emits_a_non_exposing_adapter_signal(self) -> None:
        signals = network_adapter_signals("google_compute_firewall", self.DENY)
        self.assertEqual([signal.kind for signal in signals], ["deny_ingress"])
        self.assertEqual(signals[0].exposure, "none")
        self.assertEqual(signals[0].refs, ())

    def test_deny_firewall_does_not_make_a_tagged_instance_public(self) -> None:
        plan = _plan(
            [
                _resource("google_compute_firewall.baseline", "google_compute_firewall", self.DENY),
                _resource(
                    "google_compute_instance.api",
                    "google_compute_instance",
                    {
                        "name": "payments-api",
                        "tags": ["web"],
                        "network_interface": [{"subnetwork": "private"}],
                        "boot_disk": [{"initialize_params": [{"image": PAYMENTS_IMAGE}]}],
                    },
                ),
            ]
        )
        analysis = _analyze(plan)
        self.assertNotEqual(analysis.contexts["payments-api"].exposure, "public")

    def test_allow_firewall_still_makes_a_tagged_instance_public(self) -> None:
        plan = _plan(
            [
                _resource("google_compute_firewall.baseline", "google_compute_firewall", self.ALLOW),
                _resource(
                    "google_compute_instance.api",
                    "google_compute_instance",
                    {
                        "name": "payments-api",
                        "tags": ["web"],
                        "network_interface": [{"subnetwork": "private"}],
                        "boot_disk": [{"initialize_params": [{"image": PAYMENTS_IMAGE}]}],
                    },
                ),
            ]
        )
        analysis = _analyze(plan)
        self.assertEqual(analysis.contexts["payments-api"].exposure, "public")


class EffectiveAccessDeterminismTests(unittest.TestCase):
    """Finding 6: effective_access ordering depended on set iteration order."""

    def test_effective_access_order_does_not_follow_set_iteration_order(self) -> None:
        """Pin the sort at the call site, independent of PYTHONHASHSEED.

        `_workload_identity_refs` returns a set built from randomized string
        hashes. Feeding the call site a deliberately reverse-ordered sequence
        proves the consumer normalizes the order instead of inheriting it.
        """

        original = TerraformNetworkGraph._workload_identity_refs

        def reversed_refs(self: Any, resource: Any) -> Any:
            return sorted(original(self, resource), reverse=True)

        path = str(ROOT / "samples" / "tfplan-multicloud.json")
        TerraformNetworkGraph._workload_identity_refs = reversed_refs  # type: ignore[method-assign]
        try:
            identities = [str(record.get("identity") or "") for record in analyze_terraform_plan(path, [Artifact(name="audit-api")]).contexts["audit-api"].effective_access]
        finally:
            TerraformNetworkGraph._workload_identity_refs = original  # type: ignore[method-assign]
        self.assertTrue(identities)
        self.assertEqual(identities, sorted(identities))

    def test_effective_access_identities_are_emitted_in_sorted_order(self) -> None:
        analysis = analyze_terraform_plan(str(ROOT / "samples" / "tfplan-multicloud.json"), [Artifact(name="audit-api")])
        identities = [str(record.get("identity") or "") for record in analysis.contexts["audit-api"].effective_access]
        self.assertTrue(identities)
        self.assertEqual(identities, sorted(identities))

    def test_effective_access_is_stable_across_repeated_analyses(self) -> None:
        path = str(ROOT / "samples" / "tfplan-multicloud.json")
        runs = [
            [json.dumps(record, sort_keys=True) for record in analyze_terraform_plan(path, [Artifact(name="audit-api")]).contexts["audit-api"].effective_access]
            for _ in range(3)
        ]
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[1], runs[2])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
