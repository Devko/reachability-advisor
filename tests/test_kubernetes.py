from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.kubernetes import (
    KubernetesManifestError,
    analyze_kubernetes_manifests,
    empty_kubernetes_coverage_report,
    load_kubernetes_resources,
    merge_context_maps,
)
from reachability_advisor.models import Artifact, Confidence, ContextEvidence

ROOT = Path(__file__).resolve().parents[1]


class KubernetesManifestTests(unittest.TestCase):
    def test_rendered_manifest_context_covers_public_internal_private_and_rbac(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "k8s.yaml"
            manifest.write_text(
                """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  labels:
    app: frontend
spec:
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      serviceAccountName: frontend-admin
      containers:
        - name: frontend
          image: ghcr.io/acme/frontend:1.0.0
---
apiVersion: v1
kind: Service
metadata:
  name: frontend
spec:
  type: LoadBalancer
  selector:
    app: frontend
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  labels:
    app: api
spec:
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      serviceAccountName: secret-reader
      containers:
        - name: api
          image: ghcr.io/acme/api:2.0.0
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: ClusterIP
  selector:
    app: api
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
  labels:
    app: worker
spec:
  selector:
    matchLabels:
      app: worker
  template:
    metadata:
      labels:
        app: worker
    spec:
      serviceAccountName: read-only
      containers:
        - name: worker
          image: ghcr.io/acme/worker:3.0.0
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: frontend-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: frontend-admin
    namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secret-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader
subjects:
  - kind: ServiceAccount
    name: secret-reader
    namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-only
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
  - kind: ServiceAccount
    name: read-only
    namespace: default
""".strip(),
                encoding="utf-8",
            )
            analysis = analyze_kubernetes_manifests(
                [manifest],
                [
                    Artifact(name="frontend", reference="ghcr.io/acme/frontend:1.0.0"),
                    Artifact(name="api", reference="ghcr.io/acme/api:2.0.0"),
                    Artifact(name="worker", reference="ghcr.io/acme/worker:3.0.0"),
                ],
                infer_lateral_from_public_entry=True,
            )

        self.assertEqual(analysis.contexts["frontend"].exposure, "public")
        self.assertEqual(analysis.contexts["frontend"].privilege, "admin")
        self.assertEqual(analysis.contexts["frontend"].criticality, "high")
        self.assertEqual(analysis.contexts["api"].exposure, "internal")
        self.assertEqual(analysis.contexts["api"].privilege, "sensitive")
        self.assertIn("data_access", analysis.contexts["api"].iam_impacts)
        self.assertTrue(any("frontend" in item for item in analysis.contexts["api"].evidence))
        self.assertEqual(analysis.contexts["worker"].exposure, "private")
        self.assertEqual(analysis.contexts["worker"].privilege, "limited")
        self.assertEqual(analysis.coverage["summary"]["artifacts_matched"], 3)

    def test_network_policy_deny_all_ingress_overrides_service_exposure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "k8s.yaml"
            manifest.write_text(
                """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  labels:
    app: api
spec:
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:1.0.0
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: LoadBalancer
  selector:
    app: api
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-deny-all
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes: ["Ingress"]
  ingress: []
""".strip(),
                encoding="utf-8",
            )
            analysis = analyze_kubernetes_manifests([manifest], [Artifact(name="api", reference="ghcr.io/acme/api:1.0.0")])

        self.assertEqual(analysis.contexts["api"].exposure, "private")
        self.assertTrue(any("NetworkPolicy resources deny all ingress" in item for item in analysis.contexts["api"].evidence))
        self.assertEqual(analysis.coverage["summary"]["network_policy_resources"], 1)

    def test_json_list_manifest_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "kind": "List",
                        "items": [
                            {
                                "kind": "Deployment",
                                "metadata": {"name": "api"},
                                "spec": {
                                    "selector": {"matchLabels": {"app": "api"}},
                                    "template": {"metadata": {"labels": {"app": "api"}}, "spec": {"containers": [{"image": "ghcr.io/acme/api:1"}]}},
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            resources = load_kubernetes_resources(manifest)
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].address, "kubernetes_deployment.api")

    def test_manifest_errors_and_empty_coverage_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unsupported = root / "manifest.txt"
            invalid_json = root / "manifest.json"
            unsupported.write_text("kind: Pod\nmetadata:\n  name: bad\n", encoding="utf-8")
            invalid_json.write_text("{", encoding="utf-8")

            with self.assertRaises(KubernetesManifestError):
                analyze_kubernetes_manifests([root / "missing.yaml"], [])
            with self.assertRaises(KubernetesManifestError):
                analyze_kubernetes_manifests([unsupported], [])
            with self.assertRaises(KubernetesManifestError):
                load_kubernetes_resources(invalid_json)

        empty = empty_kubernetes_coverage_report()
        self.assertEqual(empty["summary"]["artifact_match_coverage"], 1.0)
        self.assertEqual(empty["resources"], [])

    def test_directory_scan_and_yaml_edge_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifests = root / "manifests"
            manifests.mkdir()
            (manifests / "ignored.txt").write_text("not a manifest", encoding="utf-8")
            manifest = manifests / "manifest.yaml"
            manifest.write_text(
                """
# empty first document
---
apiVersion: v1
kind: Pod
metadata:
  name: direct-pod
  namespace: "prod"
  labels: {app: direct-pod, quoted: "value,with,comma", ignored}
spec:
  serviceAccountName: direct-reader
  restartPolicy: Never
  automountServiceAccountToken: true
  containers:
    - name: direct-pod
      image: ghcr.io/acme/direct-pod:1
      args: ["--flag", "value,with,comma", null, false]
    -
      name: sidecar
      image: ghcr.io/acme/sidecar:1
    - null
---
kind: Service
metadata:
  name: direct-pod # service name fallback targets Pod name
  namespace: prod
spec:
  type: NodePort
---
kind: RoleBinding
metadata:
  name: direct-reader
  namespace: prod
roleRef:
  kind: ClusterRole
  name: read-only
subjects:
  - kind: User
    name: ignored
  - kind: ServiceAccount
    name: direct-reader
""".strip(),
                encoding="utf-8",
            )

            analysis = analyze_kubernetes_manifests([manifests], [Artifact(name="direct-pod")])

        self.assertEqual(analysis.coverage["summary"]["manifest_files_scanned"], 1)
        self.assertEqual(analysis.contexts["direct-pod"].exposure, "public")
        self.assertEqual(analysis.contexts["direct-pod"].privilege, "limited")

    def test_ingress_exposure_supports_public_internal_and_legacy_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "ingress.yaml"
            manifest.write_text(
                """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  labels: {app: web}
spec:
  selector:
    matchLabels: {app: web}
  template:
    metadata:
      labels: {app: web}
    spec:
      containers:
        - image: ghcr.io/acme/web:1
---
kind: Service
metadata:
  name: web
spec:
  selector: {app: web}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-web
spec:
  rules:
    - http:
        paths:
          - path: /
            backend:
              service:
                name: web
                port:
                  number: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: legacy
  labels: {app: legacy}
spec:
  selector:
    matchLabels: {app: legacy}
  template:
    metadata:
      labels: {app: legacy}
    spec:
      containers:
        - image: ghcr.io/acme/legacy:1
---
kind: Service
metadata:
  name: legacy
spec:
  selector: {app: legacy}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: internal-legacy
  annotations:
    alb.ingress.kubernetes.io/scheme: internal
spec:
  backend:
    serviceName: legacy
""".strip(),
                encoding="utf-8",
            )

            analysis = analyze_kubernetes_manifests(
                [manifest],
                [Artifact(name="web"), Artifact(name="legacy")],
            )

        self.assertEqual(analysis.contexts["web"].exposure, "public")
        self.assertTrue(any("kubernetes_ingress.public-web" in item for item in analysis.contexts["web"].evidence))
        self.assertEqual(analysis.contexts["legacy"].exposure, "internal")
        self.assertTrue(any("kubernetes_ingress.internal-legacy" in item for item in analysis.contexts["legacy"].evidence))

    def test_external_service_and_named_rbac_classes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "named-rbac.yaml"
            manifest.write_text(
                """
kind: Deployment
metadata:
  name: external-api
  labels: {app: external-api}
spec:
  selector:
    matchLabels: {app: external-api}
  template:
    metadata:
      labels: {app: external-api}
    spec:
      serviceAccountName: editor
      containers:
        - image: ghcr.io/acme/external-api:1
---
kind: Service
metadata:
  name: external-api
spec:
  type: ExternalName
  selector: {app: external-api}
---
kind: Deployment
metadata:
  name: admin-api
spec:
  template:
    spec:
      serviceAccountName: named-admin
      containers:
        - image: ghcr.io/acme/admin-api:1
---
kind: ClusterRoleBinding
metadata:
  name: editor
roleRef:
  kind: ClusterRole
  name: edit
subjects:
  - kind: ServiceAccount
    name: editor
---
kind: RoleBinding
metadata:
  name: named-admin
roleRef:
  kind: Role
  name: namespace-admin
subjects:
  - kind: ServiceAccount
    name: named-admin
""".strip(),
                encoding="utf-8",
            )

            analysis = analyze_kubernetes_manifests(
                [manifest],
                [Artifact(name="external-api"), Artifact(name="admin-api")],
            )

        self.assertEqual(analysis.contexts["external-api"].exposure, "external")
        self.assertEqual(analysis.contexts["external-api"].privilege, "sensitive")
        self.assertIn("compute_control", analysis.contexts["external-api"].iam_impacts)
        self.assertEqual(analysis.contexts["admin-api"].exposure, "private")
        self.assertIn("iam_escalation", analysis.contexts["admin-api"].iam_impacts)

    def test_rbac_rule_impacts_are_merged_per_service_account(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "rbac.yaml"
            manifest.write_text(
                """
kind: Deployment
metadata:
  name: ops-api
  labels: {app: ops-api}
spec:
  selector:
    matchLabels: {app: ops-api}
  template:
    metadata:
      labels: {app: ops-api}
    spec:
      serviceAccountName: ops
      containers:
        - image: ghcr.io/acme/ops-api:1
---
kind: Service
metadata:
  name: ops-api
spec:
  selector: {app: ops-api}
---
kind: Role
metadata:
  name: ops-network
rules:
  - resources: ["services", "ingresses"]
    verbs: ["patch"]
  - resources: ["deployments"]
    verbs: ["update"]
  - resources: ["roles", "rolebindings"]
    verbs: ["create"]
  - resources: ["configmaps"]
    verbs: ["get"]
  - "plain"
---
kind: RoleBinding
metadata:
  name: ops-network
roleRef:
  kind: Role
  name: ops-network
subjects:
  - kind: ServiceAccount
    name: ops
---
kind: Deployment
metadata:
  name: wildcard-api
spec:
  template:
    spec:
      serviceAccountName: wildcard
      containers:
        - image: ghcr.io/acme/wildcard-api:1
---
kind: Role
metadata:
  name: wildcard
rules:
  - resources: ["*"]
    verbs: ["get"]
---
kind: RoleBinding
metadata:
  name: wildcard
roleRef:
  kind: Role
  name: wildcard
subjects:
  - kind: ServiceAccount
    name: wildcard
""".strip(),
                encoding="utf-8",
            )

            analysis = analyze_kubernetes_manifests(
                [manifest],
                [Artifact(name="ops-api"), Artifact(name="wildcard-api")],
            )

        self.assertEqual(analysis.contexts["ops-api"].exposure, "internal")
        self.assertEqual(analysis.contexts["ops-api"].privilege, "sensitive")
        self.assertEqual(
            analysis.contexts["ops-api"].iam_impacts,
            ["compute_control", "iam_escalation", "network_control"],
        )
        self.assertEqual(analysis.contexts["wildcard-api"].privilege, "admin")
        self.assertIn("admin_control", analysis.contexts["wildcard-api"].iam_impacts)

    def test_merge_context_maps_combines_strongest_context(self) -> None:
        existing = {
            "api": ContextEvidence(
                environment="prod",
                exposure="internal",
                privilege="limited",
                criticality="medium",
                iam_impacts=["data_access"],
                owner="team-a",
                source="terraform",
                confidence=Confidence.LOW,
                evidence=["terraform evidence"],
            )
        }
        update = {
            "api": ContextEvidence(
                environment="unknown",
                exposure="public",
                privilege="admin",
                criticality="high",
                iam_impacts=["admin_control"],
                source="kubernetes-manifest",
                confidence=Confidence.HIGH,
                evidence=["kubernetes evidence"],
            ),
            "worker": ContextEvidence(source="kubernetes-manifest"),
        }

        merged = merge_context_maps(existing, update)

        self.assertEqual(merged["api"].environment, "prod")
        self.assertEqual(merged["api"].exposure, "public")
        self.assertEqual(merged["api"].privilege, "admin")
        self.assertEqual(merged["api"].criticality, "high")
        self.assertEqual(merged["api"].iam_impacts, ["admin_control", "data_access"])
        self.assertEqual(merged["api"].owner, "team-a")
        self.assertEqual(merged["api"].source, "terraform+kubernetes-manifest")
        self.assertEqual(merged["api"].confidence, Confidence.HIGH)
        self.assertEqual(merged["api"].evidence, ["terraform evidence", "kubernetes evidence"])
        self.assertIn("worker", merged)

    def test_cli_scan_accepts_kubernetes_manifest_and_writes_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            code = main(
                [
                    "scan",
                    "--sbom",
                    str(ROOT / "samples/sboms/payments-api.cdx.json"),
                    "--vulns",
                    str(ROOT / "samples/vulnerabilities.json"),
                    "--source-root",
                    f"payments-api={ROOT / 'samples/source/payments-api'}",
                    "--kubernetes-manifest",
                    str(ROOT / "samples/kubernetes-manifest.yaml"),
                    "--kubernetes-coverage-out",
                    str(out / "kubernetes-coverage.json"),
                    "--out",
                    str(out / "findings.json"),
                    "--no-table",
                ]
            )
            findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            coverage = json.loads((out / "kubernetes-coverage.json").read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertEqual(coverage["summary"]["manifest_files_scanned"], 1)
        self.assertEqual(coverage["summary"]["artifacts_matched"], 1)
        self.assertTrue(any(finding["context"]["exposure"] == "public" for finding in findings["findings"]))

    def test_validate_command_checks_kubernetes_manifest_paths(self) -> None:
        self.assertEqual(
            main(
                [
                    "validate",
                    "--sbom",
                    str(ROOT / "samples/sboms/payments-api.cdx.json"),
                    "--kubernetes-manifest",
                    "missing.yaml",
                ]
            ),
            2,
        )


if __name__ == "__main__":
    unittest.main()
