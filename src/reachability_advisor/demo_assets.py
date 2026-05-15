"""Built-in no-cloud demo inputs for the installed CLI."""

from __future__ import annotations

import json
from pathlib import Path

DEMO_SOURCE = """const express = require("express");
const app = express();

app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.send(`<h1>${q}</h1>`);
});

app.post("/debug", (req, res) => {
  console.log(req.body);
  res.json({ok: true});
});

module.exports = app;
"""

DEMO_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "name": "demo-api",
            "version": "1.0.0",
            "properties": [
                {"name": "container:image", "value": "registry.example.test/demo-api:1.0.0"},
                {"name": "container:digest", "value": "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
                {"name": "environment", "value": "prod"},
                {"name": "owner", "value": "@team-demo"},
            ],
        }
    },
    "components": [
        {"type": "library", "name": "express", "version": "4.17.1", "purl": "pkg:npm/express@4.17.1", "scope": "runtime"},
        {"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20", "scope": "runtime"},
    ],
}

DEMO_VULNERABILITIES = {
    "vulnerabilities": [
        {
            "id": "GHSA-demo-express",
            "package": {"name": "express", "purl": "pkg:npm/express@4.17.1"},
            "affected_versions": ["4.17.1"],
            "severity": "high",
            "cvss": 7.5,
            "summary": "Demo dependency vulnerability with source and deployment context.",
            "fixed_versions": ["4.18.2"],
        },
        {
            "id": "GHSA-demo-lodash",
            "package": {"name": "lodash", "purl": "pkg:npm/lodash@4.17.20"},
            "affected_versions": ["4.17.20"],
            "severity": "medium",
            "cvss": 6.1,
            "summary": "Demo dependency vulnerability without proven source usage.",
            "fixed_versions": ["4.17.21"],
        },
    ]
}

DEMO_DAST_ZAP = {
    "site": [
        {
            "@name": "https://demo.example.test",
            "@host": "demo.example.test",
            "alerts": [
                {
                    "pluginid": "40012",
                    "alert": "Cross Site Scripting (Reflected)",
                    "riskdesc": "High (Medium)",
                    "confidence": "high",
                    "cweid": "79",
                    "desc": "Reflected payload was observed in the response.",
                    "solution": "Encode reflected output and set a restrictive content security policy.",
                    "reference": "https://example.test/security/xss",
                    "instances": [
                        {
                            "uri": "https://demo.example.test/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                            "method": "GET",
                            "param": "q",
                            "attack": "<script>alert(1)</script>",
                            "evidence": "<script>alert(1)</script>",
                        }
                    ],
                },
                {
                    "pluginid": "10098",
                    "alert": "Informational header observation",
                    "riskdesc": "Informational",
                    "confidence": "medium",
                    "desc": "A non-critical response header observation.",
                    "instances": [{"uri": "https://unmapped.example.test/status", "method": "GET", "evidence": "Server: demo"}],
                },
            ],
        }
    ]
}

DEMO_NUCLEI = {
    "template-id": "demo-missing-security-header",
    "info": {
        "name": "Missing security header",
        "severity": "low",
        "classification": {"cwe-id": "CWE-693"},
        "description": "A low-severity runtime observation.",
    },
    "matched-at": "https://demo.example.test/",
    "matcher-name": "missing-header",
    "type": "http",
}

DEMO_KUBERNETES = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-api
  labels:
    app: demo-api
spec:
  selector:
    matchLabels:
      app: demo-api
  template:
    metadata:
      labels:
        app: demo-api
    spec:
      serviceAccountName: demo-api
      containers:
        - name: demo-api
          image: registry.example.test/demo-api:1.0.0
---
apiVersion: v1
kind: Service
metadata:
  name: demo-api
spec:
  type: ClusterIP
  selector:
    app: demo-api
  ports:
    - port: 80
      targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: demo-api
spec:
  rules:
    - host: demo.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: demo-api
                port:
                  number: 80
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: demo-reader
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: demo-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: demo-reader
subjects:
  - kind: ServiceAccount
    name: demo-api
    namespace: default
"""


def write_demo_inputs(root: str | Path) -> dict[str, str]:
    demo_root = Path(root)
    source_root = demo_root / "source"
    source_root.mkdir(parents=True, exist_ok=True)
    source_path = source_root / "app.js"
    source_path.write_text(DEMO_SOURCE, encoding="utf-8")

    sast = {
        "security_evidence": [
            {
                "scanner_type": "sast",
                "tool": "semgrep",
                "rule_id": "js.express.reflected-xss",
                "weakness": "Reflected XSS",
                "severity": "high",
                "confidence": "high",
                "artifact": "demo-api",
                "component": "GET /search",
                "cwe": "CWE-79",
                "message": "Request parameter q reaches HTML response.",
                "route": "/search",
                "source": {
                    "path": str(source_path),
                    "line": 7,
                    "column": 15,
                    "snippet": "res.send(`<h1>${q}</h1>`);",
                },
                "evidence": {"dataflow": "req.query.q -> res.send"},
                "remediation": "Encode untrusted output before writing HTML.",
            },
            {
                "scanner_type": "sast",
                "tool": "semgrep",
                "rule_id": "js.demo.location-only",
                "weakness": "Location-only static finding",
                "severity": "medium",
                "confidence": "medium",
                "artifact": "demo-api",
                "component": "background job",
                "cwe": "CWE-20",
                "message": "Input validation warning without data-flow trace.",
                "source": {"path": str(source_path), "line": 13, "column": 3, "snippet": "console.log(req.body);"},
            },
        ]
    }

    paths = {
        "sbom": demo_root / "sbom.cdx.json",
        "vulnerabilities": demo_root / "vulnerabilities.json",
        "sast": demo_root / "sast-semgrep.json",
        "dast_zap": demo_root / "dast-zap.json",
        "dast_nuclei": demo_root / "dast-nuclei.jsonl",
        "kubernetes": demo_root / "kubernetes.yaml",
        "source_root": source_root,
    }
    paths["sbom"].write_text(json.dumps(DEMO_SBOM, indent=2), encoding="utf-8")
    paths["vulnerabilities"].write_text(json.dumps(DEMO_VULNERABILITIES, indent=2), encoding="utf-8")
    paths["sast"].write_text(json.dumps(sast, indent=2), encoding="utf-8")
    paths["dast_zap"].write_text(json.dumps(DEMO_DAST_ZAP, indent=2), encoding="utf-8")
    paths["dast_nuclei"].write_text(json.dumps(DEMO_NUCLEI, separators=(",", ":")) + "\n", encoding="utf-8")
    paths["kubernetes"].write_text(DEMO_KUBERNETES, encoding="utf-8")
    return {key: str(value) for key, value in paths.items()}
