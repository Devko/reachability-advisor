"""Regression tests for confirmed audit findings in the provider evaluators.

Each test pins the exact value that changed, so it fails against the pre-fix behaviour.
"""

from __future__ import annotations

import unittest
from typing import Any

from reachability_advisor.effective_exposure import evaluate_effective_exposure
from reachability_advisor.models import Confidence, ContextEvidence
from reachability_advisor.provider_evaluators.network_engine import (
    _record_has_deny,
    evaluate_provider_network_graph,
)
from reachability_advisor.provider_evaluators.policy_engine import (
    _pattern_set_applies,
    evaluate_aws_policy_records,
    evaluate_azure_policy_records,
    evaluate_gcp_policy_records,
)


def _blocker_kinds(record: dict[str, Any]) -> set[str]:
    blockers = record.get("blockers")
    if not isinstance(blockers, list):
        return set()
    return {str(item.get("kind")) for item in blockers if isinstance(item, dict)}


def _policy_blocker_kinds(record: dict[str, Any]) -> set[str]:
    policy = record.get("policy_evaluation") if isinstance(record.get("policy_evaluation"), dict) else {}
    blockers: list[Any] = []
    if isinstance(record.get("blockers"), list):
        blockers.extend(record["blockers"])
    if isinstance(policy, dict) and isinstance(policy.get("blockers"), list):
        blockers.extend(policy["blockers"])
    return {str(item.get("kind")) for item in blockers if isinstance(item, dict)}


class NetworkEngineIdentifierTextTests(unittest.TestCase):
    """Finding 1: blocking verdicts must not come from author-controlled identifier text."""

    def test_gcp_network_tag_named_egress_does_not_flip_ingress_path_to_blocked(self) -> None:
        network = {
            "provider": "gcp",
            "exposure": "public",
            "entry": "internet",
            "target": "google_compute_instance.api",
            "source": "terraform-plan",
            "steps": [
                "internet",
                "google_compute_firewall.allow_http public firewall target egress-proxy",
                "google_compute_instance.api",
            ],
        }

        record = evaluate_provider_network_graph("gcp", network, "public")

        # Pre-fix: "blocked" with a "egress_firewall" blocker, purely because the network tag
        # name contains the substring "egress".
        self.assertEqual(record["decision"], "reachable")
        self.assertEqual(_blocker_kinds(record), set())

    def test_gcp_firewall_resource_named_deny_does_not_flip_allow_path_to_blocked(self) -> None:
        network = {
            "provider": "gcp",
            "exposure": "public",
            "entry": "internet",
            "target": "google_compute_instance.api",
            "source": "terraform-plan",
            "steps": ["internet", "google_compute_firewall.deny_internet public firewall", "google_compute_instance.api"],
        }

        record = evaluate_provider_network_graph("gcp", network, "public")

        # Pre-fix: "blocked" with "firewall_deny".
        self.assertEqual(record["decision"], "reachable")
        self.assertEqual(_blocker_kinds(record), set())

    def test_azure_nsg_verdict_ignores_a_route_resource_named_deny(self) -> None:
        network = {
            "provider": "azure",
            "exposure": "public",
            "entry": "internet",
            "target": "azurerm_linux_web_app.api",
            "routes": [{"id": "azurerm_route.deny_partner_legacy", "address_prefix": "0.0.0.0/0", "next_hop_type": "Internet"}],
            "network_security_rules": [
                {"id": "azurerm_network_security_rule.allow", "direction": "Inbound", "access": "Allow", "priority": 100, "source_address_prefix": "*"}
            ],
        }

        record = evaluate_provider_network_graph("azure", network, "public")

        # Pre-fix: "blocked" with "nsg_deny" -- the NSG edge inherited the route resource name
        # through the chained edge text.
        self.assertEqual(record["decision"], "reachable")
        self.assertEqual(_blocker_kinds(record), set())

    def test_aws_nacl_allow_rule_named_deny_is_not_treated_as_a_deny(self) -> None:
        network = {
            "provider": "aws",
            "exposure": "public",
            "entry": "internet",
            "target": "aws_instance.api",
            "routes": [{"id": "aws_route.default", "destination_cidr_block": "0.0.0.0/0", "gateway_id": "igw-1"}],
            "network_acl_rules": [
                {"id": "aws_network_acl_rule.deny_legacy_backup", "rule_number": 100, "rule_action": "allow", "cidr_block": "0.0.0.0/0"}
            ],
        }

        record = evaluate_provider_network_graph("aws", network, "public")

        # Pre-fix: "blocked" with "network_acl_deny".
        self.assertEqual(record["decision"], "reachable")
        self.assertEqual(_blocker_kinds(record), set())

    def test_record_has_deny_reads_typed_fields_only(self) -> None:
        # Pre-fix each of these returned True because "deny" appeared in the serialized record.
        self.assertFalse(_record_has_deny({"id": "fw-deny-legacy", "action": "allow"}))
        self.assertFalse(_record_has_deny({"name": "deny_internet", "allow": [{"protocol": "tcp"}]}))
        self.assertFalse(_record_has_deny({"deny": []}))
        # Typed deny evidence still counts.
        self.assertTrue(_record_has_deny({"deny": [{"protocol": "tcp"}]}))
        self.assertTrue(_record_has_deny({"access": "Deny"}))
        self.assertTrue(_record_has_deny({"rule_action": "deny"}))
        self.assertTrue(_record_has_deny({"action": "DENY"}))


class GcpFirewallSerializedKeyTests(unittest.TestCase):
    """Finding 2: a wide-open ingress allow must not be reported as blocked."""

    def _evaluate(self, rule: dict[str, Any]) -> dict[str, Any]:
        network = {
            "provider": "gcp",
            "exposure": "public",
            "entry": "internet",
            "target": "vm",
            "firewall_rules": [rule],
        }
        return evaluate_provider_network_graph("gcp", network, "public")

    def test_enabled_firewall_carrying_disabled_false_stays_reachable(self) -> None:
        record = self._evaluate(
            {
                "name": "allow-http-world",
                "direction": "INGRESS",
                "priority": 1000,
                "disabled": False,
                "source_ranges": ["0.0.0.0/0"],
                "allow": [{"protocol": "tcp", "ports": ["80", "443"]}],
            }
        )

        # Pre-fix: "blocked" with "disabled_firewall" because the key "disabled" was serialized.
        self.assertEqual(record["decision"], "reachable")
        self.assertEqual(_blocker_kinds(record), set())

    def test_disabled_true_still_blocks(self) -> None:
        record = self._evaluate(
            {
                "name": "allow-http-world",
                "direction": "INGRESS",
                "priority": 1000,
                "disabled": True,
                "source_ranges": ["0.0.0.0/0"],
                "allow": [{"protocol": "tcp"}],
            }
        )

        self.assertEqual(record["decision"], "blocked")
        self.assertIn("disabled_firewall", _blocker_kinds(record))

    def test_empty_deny_list_does_not_block_but_a_populated_one_does(self) -> None:
        allow_rule = {
            "name": "allow-http-world",
            "direction": "INGRESS",
            "priority": 1000,
            "deny": [],
            "source_ranges": ["0.0.0.0/0"],
            "allow": [{"protocol": "tcp"}],
        }
        deny_rule = {
            "name": "deny-partner",
            "direction": "INGRESS",
            "priority": 900,
            "deny": [{"protocol": "tcp"}],
            "source_ranges": ["0.0.0.0/0"],
        }

        # Pre-fix: the empty deny list produced "blocked" with "firewall_deny".
        self.assertEqual(self._evaluate(allow_rule)["decision"], "reachable")
        blocked = self._evaluate(deny_rule)
        self.assertEqual(blocked["decision"], "blocked")
        self.assertIn("firewall_deny", _blocker_kinds(blocked))

    def test_ingress_rule_whose_description_mentions_egress_stays_reachable(self) -> None:
        record = self._evaluate(
            {
                "name": "allow-http-world",
                "description": "paired with the egress firewall for the proxy tier",
                "direction": "INGRESS",
                "priority": 1000,
                "source_ranges": ["0.0.0.0/0"],
                "allow": [{"protocol": "tcp"}],
            }
        )

        # Pre-fix: "blocked" with "egress_firewall".
        self.assertEqual(record["decision"], "reachable")
        self.assertEqual(_blocker_kinds(record), set())

    def test_explicit_edge_direction_egress_still_blocks_even_with_a_type_label(self) -> None:
        record = evaluate_provider_network_graph(
            "gcp",
            {"edges": [{"from": "internet", "to": "vm", "type": "firewall", "direction": "EGRESS"}]},
            "public",
        )

        self.assertEqual(record["decision"], "blocked")
        self.assertIn("egress_firewall", _blocker_kinds(record))


class UnresolvedRoleDefinitionTests(unittest.TestCase):
    """Finding 3: an unexpandable role reference is a visibility gap, never an explicit deny."""

    GCP_RECORD = {
        "action": "storage.objects.delete",
        "resource": "projects/p/buckets/b",
        "principal": "serviceAccount:a@p.iam.gserviceaccount.com",
    }

    def _gcp(self, role: str) -> dict[str, Any]:
        record = dict(self.GCP_RECORD)
        record["iam_policy"] = {"bindings": [{"role": role, "members": ["serviceAccount:a@p.iam.gserviceaccount.com"]}]}
        return evaluate_gcp_policy_records([record])[0]

    def test_gcp_binding_with_uncatalogued_role_reports_unknown_not_denied(self) -> None:
        evaluated = self._gcp("roles/storage.objectAdmin")

        # Pre-fix: decision "denied", basis "policy_engine:denied:implicit_deny".
        self.assertEqual(evaluated["decision"], "unknown")
        self.assertEqual(evaluated["decision_basis"], "policy_engine:unknown:iam_policy")
        self.assertEqual(evaluated["effect"], "allow")
        self.assertIn("unresolved_role_definition", _policy_blocker_kinds(evaluated))
        self.assertNotIn("implicit_deny", _policy_blocker_kinds(evaluated))
        self.assertIn("role definition roles/storage.objectAdmin was not expanded to permissions", evaluated["unknowns"])

    def test_gcp_binding_with_catalogued_role_still_resolves_to_an_allow(self) -> None:
        evaluated = self._gcp("roles/storage.admin")

        self.assertEqual(evaluated["decision"], "constrained_allow")
        self.assertNotIn("unresolved_role_definition", _policy_blocker_kinds(evaluated))

    def test_gcp_binding_with_explicit_permissions_that_miss_still_implicit_denies(self) -> None:
        record = dict(self.GCP_RECORD)
        record["iam_policy"] = {
            "bindings": [
                {
                    "role": "projects/p/roles/customReader",
                    "permissions": ["storage.objects.get"],
                    "members": ["serviceAccount:a@p.iam.gserviceaccount.com"],
                }
            ]
        }

        evaluated = evaluate_gcp_policy_records([record])[0]

        self.assertEqual(evaluated["decision"], "denied")
        self.assertIn("implicit_deny", _policy_blocker_kinds(evaluated))

    def test_azure_role_assignment_with_uncatalogued_role_reports_unknown_not_denied(self) -> None:
        evaluated = evaluate_azure_policy_records(
            [
                {
                    "action": "microsoft.storage/storageaccounts/blobservices/containers/blobs/delete",
                    "resource": "/subscriptions/s/resourceGroups/rg/prod",
                    "role_assignment": {"roleDefinitionName": "Storage Blob Data Owner", "scope": "/subscriptions/s"},
                }
            ]
        )[0]

        # Pre-fix: decision "denied" with a "role_assignment_missing_allow" blocker.
        self.assertEqual(evaluated["decision"], "unknown")
        self.assertEqual(evaluated["effect"], "allow")
        self.assertIn("unresolved_role_definition", _policy_blocker_kinds(evaluated))
        self.assertNotIn("role_assignment_missing_allow", _policy_blocker_kinds(evaluated))
        self.assertIn("role definition Storage Blob Data Owner was not expanded to permissions", evaluated["unknowns"])

    def test_azure_catalogued_role_with_principal_mismatch_still_implicit_denies(self) -> None:
        evaluated = evaluate_azure_policy_records(
            [
                {
                    "action": "Microsoft.KeyVault/vaults/secrets/read",
                    "principal": "principal-other",
                    "resource": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/v/secrets/api",
                    "role_assignment": {
                        "roleDefinitionName": "Key Vault Secrets User",
                        "principalId": "principal-api",
                        "scope": "/subscriptions/sub-a/resourceGroups/rg-a",
                    },
                }
            ]
        )[0]

        self.assertEqual(evaluated["decision"], "denied")
        self.assertIn("role_assignment_missing_allow", _policy_blocker_kinds(evaluated))

    def test_effective_exposure_does_not_claim_an_explicit_deny_for_an_unexpanded_role(self) -> None:
        context = ContextEvidence(
            exposure="public",
            confidence=Confidence.HIGH,
            network_paths=[
                {
                    "provider": "gcp",
                    "exposure": "public",
                    "path_type": "public_ingress",
                    "entry": "internet",
                    "steps": ["internet", "google_cloud_run_v2_service.api"],
                    "confidence": "high",
                }
            ],
            effective_access=[
                {
                    "provider": "gcp",
                    "identity": "serviceAccount:a@p.iam.gserviceaccount.com",
                    "principal": "serviceAccount:a@p.iam.gserviceaccount.com",
                    "action": "storage.objects.delete",
                    "impact": "data_access",
                    "resource": "projects/p/buckets/b",
                    "confidence": "high",
                    "iam_policy": {"bindings": [{"role": "roles/storage.objectAdmin", "members": ["serviceAccount:a@p.iam.gserviceaccount.com"]}]},
                }
            ],
        )

        record = evaluate_effective_exposure("api", context)[0]
        identity = record["identity"]
        identity_kinds = {str(item.get("kind")) for item in identity["blockers"]}

        # Pre-fix: decision "reachable_without_effective_identity" and
        # provider_decision_basis "blocked_by:explicit_deny,implicit_deny".
        self.assertEqual(identity["decision"], "constrained_allow")
        self.assertEqual(record["decision"], "constrained")
        self.assertNotIn("explicit_deny", identity_kinds)
        self.assertNotIn("implicit_deny", identity_kinds)
        self.assertIn("unresolved_role_definition", identity_kinds)


class NotActionAndNotResourceTests(unittest.TestCase):
    """Finding 4: NotAction / NotResource select everything outside the list, not inside it."""

    def _aws(self, action: str, resource: str, statements: list[dict[str, Any]]) -> dict[str, Any]:
        return evaluate_aws_policy_records(
            [{"action": action, "resource": resource, "identity_policy": {"Statement": statements}}]
        )[0]

    def test_allow_not_action_grants_every_action_outside_the_not_list(self) -> None:
        allow_except_iam = [{"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"}]

        granted = self._aws("s3:deleteobject", "arn:aws:s3:::prod/*", allow_except_iam)
        excluded = self._aws("iam:createuser", "*", allow_except_iam)

        # Pre-fix: granted was "denied" with basis "policy_engine:denied:implicit_deny".
        self.assertEqual(granted["decision"], "allowed")
        self.assertEqual(granted["decision_basis"], "policy_engine:allowed:identity_policy")
        self.assertEqual(excluded["decision"], "denied")

    def test_deny_not_action_denies_every_action_outside_the_not_list(self) -> None:
        statements = [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "NotAction": ["s3:*"], "Resource": "*"},
        ]

        denied = self._aws("iam:createuser", "*", statements)
        allowed = self._aws("s3:getobject", "arn:aws:s3:::x", statements)

        # Pre-fix: denied was "allowed" -- the Deny statement was silently dropped.
        self.assertEqual(denied["decision"], "denied")
        self.assertEqual(allowed["decision"], "allowed")

    def test_deny_not_resource_denies_every_resource_outside_the_not_list(self) -> None:
        statements = [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:*", "NotResource": ["arn:aws:s3:::public/*"]},
        ]

        denied = self._aws("s3:getobject", "arn:aws:s3:::secrets/creds", statements)
        allowed = self._aws("s3:getobject", "arn:aws:s3:::public/x", statements)

        # Pre-fix: denied was "allowed".
        self.assertEqual(denied["decision"], "denied")
        self.assertEqual(allowed["decision"], "allowed")

    def test_allow_not_resource_grants_every_resource_outside_the_not_list(self) -> None:
        statements = [{"Effect": "Allow", "Action": "s3:*", "NotResource": ["arn:aws:s3:::locked/*"]}]

        self.assertEqual(self._aws("s3:getobject", "arn:aws:s3:::open/x", statements)["decision"], "allowed")
        self.assertEqual(self._aws("s3:getobject", "arn:aws:s3:::locked/x", statements)["decision"], "denied")

    def test_statement_with_neither_action_nor_not_action_still_applies(self) -> None:
        # Guard against over-correcting: Azure/GCP role documents carry no action list and rely
        # on the vacuous match. This was True before the fix and must stay True.
        self.assertTrue(_pattern_set_applies((), (), "s3:getobject"))
        self.assertTrue(_pattern_set_applies((), ("iam:*",), "s3:getobject"))
        self.assertFalse(_pattern_set_applies((), ("iam:*",), "iam:createuser"))


if __name__ == "__main__":
    unittest.main()
