"""Regression tests for audited Kubernetes manifest defects."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.kubernetes import (
    KubernetesManifestError,
    analyze_kubernetes_manifests,
    load_kubernetes_resources,
)
from reachability_advisor.models import Artifact

WORKLOAD = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  labels:
    app: payments-api
spec:
  selector:
    matchLabels:
      app: payments-api
  template:
    metadata:
      labels:
        app: payments-api
    spec:
      containers:
        - name: payments-api
          image: ghcr.io/acme/payments-api:1.2.3
---
apiVersion: v1
kind: Service
metadata:
  name: payments-api
spec:
  type: LoadBalancer
  selector:
    app: payments-api
""".strip()

ARTIFACT = Artifact(name="payments-api", reference="ghcr.io/acme/payments-api:1.2.3")


def _policy(name: str, selector_block: str, *, ingress: str = "") -> str:
    return f"""
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {name}
spec:
  podSelector:
{selector_block}
  policyTypes: ["Ingress"]{ingress}
""".rstrip()


def _analyze(manifest_text: str) -> tuple[str, list[str]]:
    with tempfile.TemporaryDirectory() as tmp:
        manifest = Path(tmp) / "k8s.yaml"
        manifest.write_text(manifest_text, encoding="utf-8")
        analysis = analyze_kubernetes_manifests([manifest], [ARTIFACT])
    context = analysis.contexts["payments-api"]
    return context.exposure, list(context.evidence)


class NetworkPolicyPodSelectorTests(unittest.TestCase):
    def test_match_expressions_for_other_pods_do_not_downgrade_exposure(self) -> None:
        exposure, evidence = _analyze(
            WORKLOAD
            + _policy(
                "db-lockdown",
                """    matchExpressions:
      - key: app
        operator: In
        values: ["database"]""",
            )
        )

        self.assertEqual(exposure, "public")
        self.assertFalse(any("deny all ingress" in item for item in evidence))

    def test_match_expressions_that_select_the_workload_still_deny_all_ingress(self) -> None:
        for operator, values in (
            ("In", '\n        values: ["payments-api", "checkout"]'),
            ("NotIn", '\n        values: ["database"]'),
            ("Exists", ""),
        ):
            with self.subTest(operator=operator):
                exposure, evidence = _analyze(
                    WORKLOAD
                    + _policy(
                        "lockdown",
                        f"""    matchExpressions:
      - key: app
        operator: {operator}{values}""",
                    )
                )
                self.assertEqual(exposure, "private")
                self.assertTrue(any("deny all ingress" in item for item in evidence))

    def test_does_not_exist_expression_selects_workload_without_the_label(self) -> None:
        exposure, _ = _analyze(
            WORKLOAD
            + _policy(
                "lockdown",
                """    matchExpressions:
      - key: tier
        operator: DoesNotExist""",
            )
        )
        self.assertEqual(exposure, "private")

    def test_match_expressions_are_anded_with_match_labels(self) -> None:
        exposure, _ = _analyze(
            WORKLOAD
            + _policy(
                "lockdown",
                """    matchLabels:
      app: payments-api
    matchExpressions:
      - key: tier
        operator: Exists""",
            )
        )
        self.assertEqual(exposure, "public")

    def test_empty_pod_selector_selects_every_pod_in_the_namespace(self) -> None:
        exposure, evidence = _analyze(WORKLOAD + _policy("namespace-lockdown", "    {}"))

        self.assertEqual(exposure, "private")
        self.assertTrue(any("deny all ingress" in item for item in evidence))

    def test_unevaluable_pod_selector_records_an_unknown_and_keeps_exposure(self) -> None:
        exposure, evidence = _analyze(
            WORKLOAD
            + _policy(
                "weird-lockdown",
                """    matchExpressions:
      - key: app
        operator: Matches
        values: ["payments-api"]""",
            )
        )

        self.assertEqual(exposure, "public")
        self.assertTrue(any("podSelector could not be evaluated" in item for item in evidence))
        self.assertFalse(any("deny all ingress" in item for item in evidence))

    def test_unknown_pod_selector_key_is_not_treated_as_namespace_wide(self) -> None:
        exposure, evidence = _analyze(WORKLOAD + _policy("weird-lockdown", "    matchSomething:\n      app: payments-api"))

        self.assertEqual(exposure, "public")
        self.assertTrue(any("podSelector could not be evaluated" in item for item in evidence))

    def test_unevaluable_ingress_policy_suppresses_an_otherwise_proven_deny_all(self) -> None:
        manifest = (
            WORKLOAD
            + _policy(
                "api-deny-all",
                """    matchLabels:
      app: payments-api""",
                ingress="\n  ingress: []",
            )
            + _policy(
                "unparseable-allow",
                """    matchExpressions:
      - key: app
        operator: Matches
        values: ["payments-api"]""",
            )
        )

        exposure, evidence = _analyze(manifest)

        self.assertEqual(exposure, "public")
        self.assertTrue(any("podSelector could not be evaluated" in item for item in evidence))
        self.assertFalse(any("deny all ingress" in item for item in evidence))

    def test_deny_all_still_applies_when_every_selector_is_evaluable(self) -> None:
        manifest = (
            WORKLOAD
            + _policy(
                "api-deny-all",
                """    matchLabels:
      app: payments-api""",
                ingress="\n  ingress: []",
            )
            + _policy(
                "db-allow",
                """    matchExpressions:
      - key: app
        operator: In
        values: ["database"]""",
                ingress="\n  ingress:\n    - from: []",
            )
        )

        exposure, evidence = _analyze(manifest)

        self.assertEqual(exposure, "private")
        self.assertTrue(any("deny all ingress" in item for item in evidence))


class ManifestNestingDepthTests(unittest.TestCase):
    def test_inline_flow_nesting_is_rejected_instead_of_overflowing_the_stack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "inline.yaml"
            manifest.write_text(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata:\n  v: " + "[" * 1000 + "]" * 1000 + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(KubernetesManifestError) as error:
                load_kubernetes_resources(manifest)
        self.assertIn("manifest nesting exceeds supported depth", str(error.exception))

    def test_block_nesting_is_rejected_instead_of_overflowing_the_stack(self) -> None:
        lines = ["apiVersion: v1", "kind: ConfigMap", "metadata:", "  name: y", "data:"]
        lines.extend(" " * (level + 1) + f"k{level}:" for level in range(700))
        lines.append(" " * 701 + "leaf: 1")
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "block.yaml"
            manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaises(KubernetesManifestError) as error:
                load_kubernetes_resources(manifest)
        self.assertIn("manifest nesting exceeds supported depth", str(error.exception))

    def test_deeply_nested_json_manifest_is_rejected_before_recursive_walks(self) -> None:
        document: dict[str, object] = {"kind": "Deployment", "metadata": {"name": "z"}, "spec": {}}
        current: dict[str, object] = document["spec"]  # type: ignore[assignment]
        for _ in range(1500):
            child: dict[str, object] = {}
            current["n"] = child
            current = child
        current["image"] = "ghcr.io/acme/x:1"
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "deep.json"
            manifest.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(KubernetesManifestError) as load_error:
                load_kubernetes_resources(manifest)
            with self.assertRaises(KubernetesManifestError):
                analyze_kubernetes_manifests([manifest], [Artifact(name="x", reference="ghcr.io/acme/x:1")])
        self.assertIn("manifest nesting exceeds supported depth", str(load_error.exception))

    def test_realistic_manifest_nesting_is_still_accepted(self) -> None:
        sample = Path(__file__).resolve().parents[1] / "samples" / "demo" / "kubernetes.yaml"
        resources = load_kubernetes_resources(sample)
        self.assertTrue(resources)
        self.assertTrue(any(resource.kind == "Ingress" for resource in resources))


if __name__ == "__main__":
    unittest.main()
