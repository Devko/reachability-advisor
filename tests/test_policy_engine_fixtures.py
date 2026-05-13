from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from reachability_advisor.provider_evaluators.policy_engine import (
    evaluate_aws_policy_records,
    evaluate_azure_policy_records,
    evaluate_gcp_policy_records,
    evaluate_kubernetes_policy_records,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "policies" / "provider-policy-examples.json"


EVALUATORS = {
    "aws": evaluate_aws_policy_records,
    "azure": evaluate_azure_policy_records,
    "gcp": evaluate_gcp_policy_records,
    "kubernetes": evaluate_kubernetes_policy_records,
}


class ProviderPolicyFixtureTests(unittest.TestCase):
    def test_provider_policy_examples_exercise_ast_matching(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

        for case in fixture["cases"]:
            with self.subTest(case=case["name"]):
                provider = str(case["provider"])
                expected = case["expected"]
                evaluated = EVALUATORS[provider]([case["record"]])[0]
                policy = evaluated["policy_evaluation"]
                matched = policy["matched_statements"]
                blocker_kinds = _blocker_kinds(evaluated)

                self.assertEqual(policy["decision"], expected["decision"])
                self.assertEqual(evaluated["decision"], expected["decision"])
                self.assertEqual(policy["policy_layer"], expected["policy_layer"])
                if expected.get("required_blocker"):
                    self.assertIn(expected["required_blocker"], blocker_kinds)
                if expected.get("required_blockers"):
                    self.assertTrue(set(expected["required_blockers"]).issubset(blocker_kinds), blocker_kinds)
                if "matched_statements" in expected:
                    self.assertEqual(len(matched), expected["matched_statements"])
                if "decision_basis_contains" in expected:
                    self.assertIn(expected["decision_basis_contains"], policy["decision_basis"])
                if expected.get("principal_matched"):
                    self.assertTrue(all(item["matched"]["principal"] for item in matched))
                    self.assertTrue(all(item["principals"] for item in matched))
                if isinstance(expected.get("effective_permission"), dict):
                    permission = expected["effective_permission"]
                    self.assertEqual(policy["decision"], permission["decision"])
                    self.assertEqual(not str(evaluated["decision"]).startswith("denied"), permission["allowed"])

    def test_aws_policy_engine_handles_raw_documents_conditions_boundaries_and_trust(self) -> None:
        records = evaluate_aws_policy_records(
            [
                {
                    "principal": "arn:aws:iam::123456789012:role/api-prod",
                    "action": "s3:GetObject",
                    "resource": "arn:aws:s3:::tenant-data/key",
                    "identity_policy": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:Get*",
                            "Resource": "arn:aws:s3:::tenant-data/*",
                            "Condition": {
                                "StringLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/api-*"},
                                "Bool": {"aws:SecureTransport": "true"},
                            },
                        }
                    ],
                    "condition_context": {"aws:SecureTransport": "true"},
                    "condition_keys": ["existing"],
                },
                {
                    "action": "s3:PutObject",
                    "resource": "arn:aws:s3:::tenant-data/key",
                    "identity_policy": {"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*", "Condition": {"StringEquals": {"aws:Missing": "yes"}}}]},
                },
                {
                    "action": "s3:GetObject",
                    "resource": "arn:aws:s3:::tenant-data/key",
                    "policy_document": "{not-json",
                },
                {
                    "action": "s3:PutObject",
                    "resource": "arn:aws:s3:::tenant-data/key",
                    "identity_policy": {"Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}]},
                    "permissions_boundary": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
                },
                {
                    "action": "sts:AssumeRole",
                    "resource": "arn:aws:iam::123456789012:role/target",
                    "trust_policy": {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "arn:aws:iam::123456789012:role/other"}}]},
                    "principal": "arn:aws:iam::123456789012:role/api-prod",
                },
            ]
        )

        allowed, conditional_deny, malformed, boundary, trust = records

        self.assertEqual(allowed["decision"], "constrained_allow")
        self.assertIn("existing", allowed["condition_keys"])
        self.assertIn("Bool", allowed["condition_keys"])
        self.assertTrue(all(item["condition_state"] == "satisfied" for item in allowed["policy_evaluation"]["matched_statements"]))
        self.assertEqual(conditional_deny["decision"], "denied")
        self.assertIn("conditional_explicit_deny", _blocker_kinds(conditional_deny))
        self.assertIn("implicit_deny", _blocker_kinds(conditional_deny))
        self.assertIn("condition aws:Missing was not fully evaluated", conditional_deny["unknowns"])
        self.assertEqual(malformed["decision"], "denied")
        self.assertIn("implicit_deny", _blocker_kinds(malformed))
        self.assertEqual(boundary["decision"], "denied")
        self.assertIn("permission_boundary", _blocker_kinds(boundary))
        self.assertEqual(trust["decision"], "denied")
        self.assertIn("trust_policy_deny", _blocker_kinds(trust))

    def test_azure_gcp_and_kubernetes_policy_engines_cover_scope_and_boundary_cases(self) -> None:
        azure_records = evaluate_azure_policy_records(
            [
                {
                    "action": "Microsoft.KeyVault/vaults/secrets/read",
                    "resource": "/subscriptions/123/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v/secrets/s",
                    "principal": "user-1",
                    "role_definition": {
                        "permissions": [{"actions": ["Microsoft.KeyVault/vaults/secrets/read"]}],
                        "scope": "/subscriptions/123/resourceGroups/rg",
                        "principal": "user-1",
                        "eligible": "pim",
                    },
                },
                {
                    "action": "Microsoft.KeyVault/vaults/secrets/read",
                    "resource": "/subscriptions/123/providers/Microsoft.KeyVault/vaults/v/secrets/s",
                    "deny_assignment": {
                        "actions": ["Microsoft.KeyVault/*"],
                        "scope": "/subscriptions/123",
                        "condition": {"StringEquals": {"missing": "yes"}},
                    },
                },
            ]
        )
        gcp_records = evaluate_gcp_policy_records(
            [
                {
                    "principal": "serviceaccount:api@example.iam.gserviceaccount.com",
                    "action": "secretmanager.versions.access",
                    "resource": "projects/p/secrets/s",
                    "iam_policy": {
                        "bindings": [
                            {
                                "role": "roles/secretmanager.secretaccessor",
                                "members": ["serviceAccount:api@example.iam.gserviceaccount.com"],
                                "condition": {"expression": "resource.name.startsWith('projects/p/secrets/')"},
                            }
                        ]
                    },
                    "annotations": {"iam.gke.io/gcp-service-account": "api@example.iam.gserviceaccount.com"},
                },
                {
                    "action": "storage.objects.get",
                    "resource": "projects/p/buckets/b/objects/o",
                    "principal_access_boundary": {"rules": [{"permissions": ["storage.objects.list"], "resources": ["projects/other"]}]},
                },
                {
                    "action": "iam.serviceAccounts.actAs",
                    "resource": "projects/p/serviceAccounts/api@example.iam.gserviceaccount.com",
                    "deny_policy": {"rules": [{"deniedPermissions": ["iam.serviceAccounts.actAs"], "condition": {"expression": "request.time < timestamp('2026-06-01T00:00:00Z')"}}]},
                },
            ]
        )
        kubernetes_records = evaluate_kubernetes_policy_records(
            [
                {
                    "action": "get secrets",
                    "principal": "system:serviceaccount:default:api",
                    "namespace": "default",
                    "cluster_role": {
                        "aggregationRule": {"clusterRoleSelectors": [{"matchLabels": {"rbac.example/aggregate": "true"}}]},
                        "subjects": [{"kind": "ServiceAccount", "namespace": "default", "name": "api"}],
                        "rules": [{"verbs": ["get"], "resources": ["secrets"], "resourceNames": ["api-secret"]}],
                    },
                },
                {
                    "action": "get",
                    "resource": "/metrics",
                    "principal": "ops",
                    "role": [{"verbs": ["get"], "nonResourceURLs": ["/metrics"], "users": ["ops"]}],
                },
                {
                    "action": "delete secrets",
                    "principal": "system:serviceaccount:default:api",
                    "role": {"rules": [{"verbs": ["get"], "resources": ["configmaps"]}]},
                },
            ]
        )

        self.assertIn("pim_eligible_only", _blocker_kinds(azure_records[0]))
        self.assertIn("resource_group_scope", _blocker_kinds(azure_records[0]))
        self.assertIn("conditional_deny_assignment", _blocker_kinds(azure_records[1]))
        self.assertIn("subscription_scope", _blocker_kinds(azure_records[1]))
        self.assertEqual(gcp_records[0]["decision"], "constrained_allow")
        self.assertIn("conditional_iam_binding", _blocker_kinds(gcp_records[0]))
        self.assertIn("workload_identity_condition", _blocker_kinds(gcp_records[0]))
        self.assertEqual(gcp_records[1]["decision"], "denied")
        self.assertIn("principal_access_boundary_deny", _blocker_kinds(gcp_records[1]))
        self.assertIn("conditional_deny_policy", _blocker_kinds(gcp_records[2]))
        self.assertIn("service_account_impersonation", _blocker_kinds(gcp_records[2]))
        self.assertIn("rbac_resource_names", _blocker_kinds(kubernetes_records[0]))
        self.assertIn("aggregation_rule_scope", _blocker_kinds(kubernetes_records[0]))
        self.assertIn("service_account_scope", _blocker_kinds(kubernetes_records[0]))
        self.assertIn("non_resource_url_scope", _blocker_kinds(kubernetes_records[1]))
        self.assertEqual(kubernetes_records[2]["decision"], "denied")
        self.assertIn("rbac_deny", _blocker_kinds(kubernetes_records[2]))


def _blocker_kinds(record: dict[str, Any]) -> set[str]:
    policy = record.get("policy_evaluation") if isinstance(record.get("policy_evaluation"), dict) else {}
    blockers = []
    if isinstance(record.get("blockers"), list):
        blockers.extend(record["blockers"])
    if isinstance(policy, dict) and isinstance(policy.get("blockers"), list):
        blockers.extend(policy["blockers"])
    return {str(item.get("kind")) for item in blockers if isinstance(item, dict)}


if __name__ == "__main__":
    unittest.main()
