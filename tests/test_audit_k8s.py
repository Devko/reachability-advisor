"""Regression tests for audited Kubernetes manifest defects."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reachability_advisor.kubernetes import (
    MAX_MANIFEST_DEPTH,
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
        # PyYAML's own parser recurses per nesting level and hits RecursionError while
        # *parsing* this input, before yaml_loader's node-count/depth bound ever runs.
        # yaml_loader converts that into a controlled YamlError, which this module wraps.
        self.assertIn("nesting too deep for the YAML parser", str(error.exception))

    def test_block_nesting_is_rejected_instead_of_overflowing_the_stack(self) -> None:
        lines = ["apiVersion: v1", "kind: ConfigMap", "metadata:", "  name: y", "data:"]
        lines.extend(" " * (level + 1) + f"k{level}:" for level in range(700))
        lines.append(" " * 701 + "leaf: 1")
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "block.yaml"
            manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaises(KubernetesManifestError) as error:
                load_kubernetes_resources(manifest)
        # Same RecursionError-during-parse path as the inline flow case above.
        self.assertIn("nesting too deep for the YAML parser", str(error.exception))

    @staticmethod
    def _nested_json_manifest(depth: int) -> str:
        # Built as text, not as a Python object graph: an attacker sends bytes, and
        # `json.dumps` of a deep object is itself recursive, so constructing the input
        # would blow the stack before the loader under test is ever reached.
        nested = '{"image": "ghcr.io/acme/x:1"}'
        for _ in range(depth):
            nested = '{"n": ' + nested + "}"
        return '{"kind": "Deployment", "metadata": {"name": "z"}, "spec": ' + nested + "}"

    def test_json_nesting_past_the_supported_depth_is_rejected(self) -> None:
        # Just past MAX_MANIFEST_DEPTH: shallow enough that `yaml.safe_load` (JSON is
        # valid YAML, so JSON manifests go through the same loader as YAML ones) parses
        # it successfully on every supported interpreter, so this deterministically
        # exercises the shared loader's node-walking depth bound (MAX_YAML_DEPTH, which
        # is numerically equal to MAX_MANIFEST_DEPTH) rather than CPython's stack limit.
        document = self._nested_json_manifest(MAX_MANIFEST_DEPTH + 50)
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "deep.json"
            manifest.write_text(document, encoding="utf-8")
            with self.assertRaises(KubernetesManifestError) as load_error:
                load_kubernetes_resources(manifest)
        self.assertIn("nesting exceeds the supported depth of 100", str(load_error.exception))

    def test_pathological_json_nesting_never_escapes_as_a_recursion_error(self) -> None:
        # Deep enough that `json.loads` may hit its own recursion limit first. Which
        # limit trips varies by interpreter version, so assert the invariant that
        # actually matters: the caller always sees a controlled KubernetesManifestError,
        # never an uncaught RecursionError.
        document = self._nested_json_manifest(1500)
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "deep.json"
            manifest.write_text(document, encoding="utf-8")
            with self.assertRaises(KubernetesManifestError):
                load_kubernetes_resources(manifest)
            with self.assertRaises(KubernetesManifestError):
                analyze_kubernetes_manifests([manifest], [Artifact(name="x", reference="ghcr.io/acme/x:1")])

    def test_realistic_manifest_nesting_is_still_accepted(self) -> None:
        sample = Path(__file__).resolve().parents[1] / "samples" / "demo" / "kubernetes.yaml"
        resources = load_kubernetes_resources(sample)
        self.assertTrue(resources)
        self.assertTrue(any(resource.kind == "Ingress" for resource in resources))


class SharedYamlLoaderTests(unittest.TestCase):
    """Manifests must go through the shared bounded loader, not a private parser."""

    def test_kubernetes_module_keeps_no_private_yaml_parser(self) -> None:
        from reachability_advisor import kubernetes as k8s

        for name in ("_parse_yaml_document", "_parse_yaml_block", "_parse_yaml_mapping",
                     "_parse_yaml_list", "_yaml_lines"):
            self.assertFalse(
                hasattr(k8s, name),
                f"kubernetes.{name} still exists; manifests must use yaml_loader",
            )

    def test_anchor_aliases_are_supported_now(self) -> None:
        # The hand-rolled parser silently mis-parsed anchors: `selector: &sel` followed by
        # an indented block was read as the scalar string "&sel", and the nested
        # `app: payments-api` / `ports: []` lines were silently dropped rather than
        # attached anywhere. Assert the resolved structure, not just `.kind`, so this
        # test actually fails against that bug instead of passing either way.
        # Anchors are scoped to a single YAML document, so the alias must be used in the
        # same document as the anchor -- the realistic case is reusing one label mapping
        # for both the selector and a second field within one manifest.
        text = (
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: a\n"
            "spec:\n  selector: &sel\n    app: payments-api\n"
            "  altSelector: *sel\n"
            "  ports: []\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "svc.yaml"
            manifest.write_text(text, encoding="utf-8")
            resources = load_kubernetes_resources(manifest)
        self.assertEqual(resources[0].kind, "Service")
        self.assertEqual(resources[0].values["spec"]["selector"], {"app": "payments-api"})
        self.assertEqual(resources[0].values["spec"]["ports"], [])
        # The alias must resolve to the same mapping the anchor captured, proving aliases
        # -- not just anchors -- are handled correctly.
        self.assertEqual(resources[0].values["spec"]["altSelector"], {"app": "payments-api"})


if __name__ == "__main__":
    unittest.main()
