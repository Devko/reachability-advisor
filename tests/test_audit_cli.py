"""Regression tests for audit findings in the `cli` group.

Covers fixture-pack output containment, the previously untested CI quality gates,
security-profile coverage scoping, and the silent exit-10 release gates.
"""

from __future__ import annotations

import io
import json
import math
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from reachability_advisor.cli import main
from reachability_advisor.cli_quality import _profile_minimum
from reachability_advisor.fixtures import (
    FixtureError,
    _fixture_output_root,
    discover_fixture_packs,
    load_fixture_pack,
    run_fixture_pack,
    validate_fixture_pack,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "terraform"
SBOM = ROOT / "samples" / "sboms" / "payments-api.cdx.json"
VULNS = ROOT / "samples" / "vulnerabilities.json"


def _write(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _run(argv: list[str]) -> tuple[int, str]:
    err = io.StringIO()
    with patch("sys.stderr", err):
        code = main(argv)
    return code, err.getvalue()


class FixturePackOutputContainmentTests(unittest.TestCase):
    """A community fixture.json must not be able to steer writes out of --output-dir."""

    def test_load_fixture_pack_rejects_traversal_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = _write(Path(tmp) / "fixture.json", {"id": "../../../../PWNED", "sboms": []})
            with self.assertRaises(FixtureError) as raised:
                load_fixture_pack(manifest)
            self.assertIn("invalid fixture id", str(raised.exception))

    def test_load_fixture_pack_rejects_absolute_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = _write(Path(tmp) / "fixture.json", {"id": str(Path(tmp) / "ABS_PWNED"), "sboms": []})
            with self.assertRaises(FixtureError):
                load_fixture_pack(manifest)

    def test_load_fixture_pack_rejects_blank_and_dot_ids(self) -> None:
        for bad_id in ("   ", ".", "..", "a/b", "-leading-dash"):
            with self.subTest(fixture_id=bad_id), tempfile.TemporaryDirectory() as tmp:
                manifest = _write(Path(tmp) / "fixture.json", {"id": bad_id, "sboms": []})
                with self.assertRaises(FixtureError):
                    load_fixture_pack(manifest)

    def test_shipped_fixture_ids_still_load(self) -> None:
        packs = [load_fixture_pack(path) for path in discover_fixture_packs(FIXTURES)]
        self.assertGreaterEqual(len(packs), 9)
        self.assertTrue(all(pack.id for pack in packs))

    def test_fixture_output_root_rejects_ids_that_escape_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "outputs"
            out.mkdir()
            self.assertEqual(_fixture_output_root(out, "gcp-cloud-run"), out.resolve() / "gcp-cloud-run")
            for bad_id in ("../escape", "..", "/tmp/absolute-escape", ""):
                with self.subTest(fixture_id=bad_id), self.assertRaises(FixtureError):
                    _fixture_output_root(out, bad_id)

    def test_run_fixture_pack_with_unsafe_id_writes_nothing_outside_output_dir(self) -> None:
        pack = load_fixture_pack(FIXTURES / "packs" / "gcp-cloud-run")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            out = base / "requested"
            out.mkdir()
            escape_target = base / "PWNED"
            hostile = replace(pack, id="../PWNED")
            report = run_fixture_pack(hostile, output_dir=out)
            self.assertEqual(report["status"], "failed")
            self.assertFalse(escape_target.exists())
            self.assertEqual(list(out.iterdir()), [])

    def test_validate_fixture_pack_flags_unsafe_id(self) -> None:
        pack = replace(load_fixture_pack(FIXTURES / "packs" / "gcp-cloud-run"), id="../PWNED")
        messages = [issue.message for issue in validate_fixture_pack(pack)]
        self.assertTrue(any("not a safe directory name" in message for message in messages))

    def test_fixtures_run_cli_refuses_hostile_pack_and_leaves_output_dir_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "packs-root"
            _write(root / "packs" / "evil" / "fixture.json", {"id": "../../../PWNED", "sboms": []})
            out = base / "requested"
            out.mkdir()
            escape_target = base / "PWNED"

            code, err = _run(["fixtures", "run", "--root", str(root), "--output-dir", str(out)])

            self.assertEqual(code, 2)
            self.assertIn("invalid fixture id", err)
            self.assertFalse(escape_target.exists())
            self.assertEqual(list(out.iterdir()), [])

    def test_fixture_output_root_refuses_a_symlinked_pack_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            out = base / "outputs"
            out.mkdir()
            elsewhere = base / "elsewhere"
            elsewhere.mkdir()
            (out / "gcp-cloud-run").symlink_to(elsewhere, target_is_directory=True)
            with self.assertRaises(FixtureError) as raised:
                _fixture_output_root(out, "gcp-cloud-run")
            self.assertIn("resolves outside the requested output directory", str(raised.exception))

    def test_discover_fixture_packs_rejects_index_path_escaping_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "fixtures"
            _write(root / "index.json", {"packs": [{"id": "evil", "path": "../../escape"}]})
            with self.assertRaises(FixtureError) as raised:
                discover_fixture_packs(root)
            self.assertIn("escapes the fixtures root", str(raised.exception))

    def test_discover_fixture_packs_still_accepts_relative_index_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "fixtures"
            _write(root / "index.json", {"packs": [{"id": "demo", "path": "packs/demo"}]})
            paths = discover_fixture_packs(root)
            self.assertEqual(paths[0].parts[-3:], ("packs", "demo", "fixture.json"))


class MappingWarningGateTests(unittest.TestCase):
    """`--fail-on-mapping-warnings` had no test; a disabled branch survived mutation."""

    def test_fail_on_mapping_warnings_exits_10_and_names_the_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mapping_out = Path(tmp) / "mapping.json"
            code, err = _run([
                "scan",
                "--sbom", str(SBOM),
                "--vuln-in", str(VULNS),
                "--mapping-out", str(mapping_out),
                "--fail-on-mapping-warnings",
                "--no-table",
            ])
            report = json.loads(mapping_out.read_text(encoding="utf-8"))
            warnings = int(report["summary"]["mapping_warnings_count"])

            self.assertEqual(code, 10)
            self.assertGreater(warnings, 0)
            self.assertIn(f"mapping report contains {warnings} warning(s)", err)

    def test_same_scan_without_the_flag_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, _ = _run([
                "scan",
                "--sbom", str(SBOM),
                "--vuln-in", str(VULNS),
                "--mapping-out", str(Path(tmp) / "mapping.json"),
                "--no-table",
            ])
            self.assertEqual(code, 0)


class ProductionProfileTerraformSourceGateTests(unittest.TestCase):
    """`--analysis-profile production` must reject advisory-only Terraform source input."""

    def test_production_profile_rejects_terraform_source_without_a_rendered_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            coverage_out = Path(tmp) / "source-coverage.json"
            code, err = _run([
                "scan",
                "--sbom", str(SBOM),
                "--vuln-in", str(VULNS),
                "--terraform-source", str(ROOT / "samples" / "terraform-source"),
                "--source-coverage-out", str(coverage_out),
                "--analysis-profile", "production",
                "--no-table",
            ])
            blockers = json.loads(coverage_out.read_text(encoding="utf-8"))["production_readiness"]["blockers"]

            self.assertEqual(code, 10)
            self.assertIn("Production profile treats --terraform-source as advisory only", err)
            self.assertIn("Terraform source mode is advisory only; use a rendered Terraform plan for production gates.", blockers)

    def test_advisory_profile_accepts_terraform_source(self) -> None:
        code, err = _run([
            "scan",
            "--sbom", str(SBOM),
            "--vuln-in", str(VULNS),
            "--terraform-source", str(ROOT / "samples" / "terraform-source"),
            "--no-table",
        ])
        self.assertEqual(code, 0)
        self.assertNotIn("advisory only", err)


class ProfileMinimumTests(unittest.TestCase):
    """Production floors must raise a user minimum, never lower it."""

    def test_production_floor_wins_over_a_lower_user_minimum(self) -> None:
        self.assertEqual(_profile_minimum(0.5, 1.0), 1.0)
        self.assertEqual(_profile_minimum(1.0, 0.8), 1.0)
        self.assertEqual(_profile_minimum(None, 0.8), 0.8)
        self.assertEqual(_profile_minimum(0.3, None), 0.3)
        self.assertTrue(math.isnan(_profile_minimum(math.nan, 1.0) or 0.0))


class ArtifactProvenanceGateTests(unittest.TestCase):
    """`--require-artifact-provenance` had no test; the whole block survived mutation."""

    def _strong_manifest(self, root: Path) -> Path:
        digest = "sha256:" + "a" * 64
        code = main([
            "artifact-manifest", "init",
            "--artifact", "payments-api",
            "--sbom", str(SBOM),
            "--image", "ghcr.io/acme/payments-api:1.0.0",
            "--digest", digest,
            "--registry-ref", f"ghcr.io/acme/payments-api@{digest}",
            "--git-sha", "b" * 40,
            "--signed",
            "--out", str(root / "strong.json"),
        ])
        self.assertEqual(code, 0)
        return root / "strong.json"

    def test_require_provenance_without_any_manifest_exits_10(self) -> None:
        code, err = _run([
            "scan",
            "--sbom", str(SBOM),
            "--vuln-in", str(VULNS),
            "--require-artifact-provenance",
            "--no-table",
        ])
        self.assertEqual(code, 10)
        self.assertIn("Strict artifact provenance requires at least one --artifact-manifest", err)

    def test_require_provenance_with_unsigned_manifest_exits_10_and_counts_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            weak = _write(
                Path(tmp) / "weak.json",
                {"artifacts": [{"name": "payments-api", "image": "ghcr.io/acme/payments-api:1.0.0", "sbom": str(SBOM), "git_sha": "a" * 16}]},
            )
            code, err = _run([
                "scan",
                "--sbom", str(SBOM),
                "--vuln-in", str(VULNS),
                "--artifact-manifest", str(weak),
                "--require-artifact-provenance",
                "--no-table",
            ])
            self.assertEqual(code, 10)
            self.assertRegex(err, r"artifact provenance has [1-9]\d* blocker\(s\)")

            without_flag, _ = _run([
                "scan",
                "--sbom", str(SBOM),
                "--vuln-in", str(VULNS),
                "--artifact-manifest", str(weak),
                "--no-table",
            ])
            self.assertEqual(without_flag, 0)

    def test_require_provenance_passes_for_a_signed_digest_pinned_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._strong_manifest(Path(tmp))
            code, err = _run([
                "scan",
                "--sbom", str(SBOM),
                "--vuln-in", str(VULNS),
                "--artifact-manifest", str(manifest),
                "--require-artifact-provenance",
                "--no-table",
            ])
            self.assertEqual(code, 0)
            self.assertNotIn("artifact provenance", err)


class PolicyExceptionThresholdTests(unittest.TestCase):
    """Locks the `policy_status != "excepted"` filter in `_findings_fail`."""

    def _policy(self, root: Path, *, with_exception: bool) -> Path:
        exceptions = (
            [{
                "vulnerability": "CVE-2021-44228",
                "artifact": "payments-api",
                "component": "log4j-core",
                "expires": "2099-12-31",
                "reason": "Accepted while the upgrade is validated.",
            }]
            if with_exception
            else []
        )
        return _write(root / "policy.json", {"schema_version": "1.0", "fail_on_tier": "medium", "exceptions": exceptions})

    def test_excepted_finding_does_not_trip_the_tier_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with_exception, _ = _run([
                "scan", "--sbom", str(SBOM), "--vuln-in", str(VULNS),
                "--policy", str(self._policy(root / "a", with_exception=True)),
                "--fail-on-tier", "medium", "--no-table",
            ])
            without_exception, err = _run([
                "scan", "--sbom", str(SBOM), "--vuln-in", str(VULNS),
                "--policy", str(self._policy(root / "b", with_exception=False)),
                "--fail-on-tier", "medium", "--no-table",
            ])

            self.assertEqual(with_exception, 0)
            self.assertEqual(without_exception, 10)
            self.assertIn("reached priority medium", err)


class SecurityProfileCoverageScopeTests(unittest.TestCase):
    """Self-generated posture records must not be scored as missing SAST/DAST profiles."""

    def test_production_profile_is_satisfiable_with_rendered_deployment_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            coverage_out = Path(tmp) / "source-coverage.json"
            _, err = _run([
                "scan",
                "--sbom", str(SBOM),
                "--vuln-in", str(VULNS),
                "--terraform-plan", str(ROOT / "samples" / "tfplan-multicloud.json"),
                "--kubernetes-manifest", str(ROOT / "samples" / "kubernetes-manifest.yaml"),
                "--source-evidence-in", str(ROOT / "samples" / "source-evidence.json"),
                "--source-root", f"payments-api={ROOT / 'samples' / 'source' / 'payments-api'}",
                "--source-coverage-out", str(coverage_out),
                "--analysis-profile", "production",
                "--no-table",
            ])
            summary = json.loads(coverage_out.read_text(encoding="utf-8"))["security_evidence"]["summary"]

            self.assertNotIn("critical security profile coverage", err)
            self.assertGreater(int(summary["native_posture_records"]), 0)
            self.assertEqual(int(summary["native_posture_records"]), int(summary["records_outside_profile_catalog"]))
            self.assertGreater(int(summary["critical_records_outside_profile_catalog"]), 0)
            self.assertEqual(int(summary["critical_records"]), 0)
            self.assertEqual(summary["critical_profile_coverage"], 1.0)
            self.assertEqual(summary["profiled_scanner_types"], ["dast", "sast"])
            posture_rows = [row for row in json.loads(coverage_out.read_text(encoding="utf-8"))["security_evidence"]["profile_records"] if row["scanner_type"] == "cspm"]
            self.assertTrue(posture_rows)
            self.assertTrue(all(row["profile_status"] == "not_applicable" for row in posture_rows))

    def test_imported_cspm_records_stay_visible_without_blocking_the_sast_dast_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cspm = _write(
                Path(tmp) / "checkov.json",
                {"security_evidence": [{
                    "scanner_type": "cspm",
                    "tool": "checkov",
                    "rule_id": "CKV_AWS_20",
                    "weakness": "S3 bucket allows public read",
                    "severity": "high",
                    "cwe": "CWE-284",
                    "artifact": "payments-api",
                    "resource_id": "aws_s3_bucket.public",
                    "resource_type": "aws_s3_bucket",
                    "provider": "aws",
                    "message": "public read acl",
                }]},
            )
            coverage_out = Path(tmp) / "source-coverage.json"
            code, err = _run([
                "scan",
                "--sbom", str(SBOM),
                "--vuln-in", str(VULNS),
                "--cspm-in", str(cspm),
                "--source-coverage-out", str(coverage_out),
                "--min-critical-security-profile-coverage", "1.0",
                "--no-table",
            ])
            report = json.loads(coverage_out.read_text(encoding="utf-8"))["security_evidence"]

            self.assertEqual(code, 0)
            self.assertNotIn("critical security profile coverage", err)
            self.assertEqual(int(report["records"]), 1)
            self.assertEqual(int(report["summary"]["records_outside_profile_catalog"]), 1)
            self.assertEqual(int(report["summary"]["critical_records_outside_profile_catalog"]), 1)
            self.assertEqual(int(report["summary"]["native_posture_records"]), 0)
            self.assertEqual(report["profile_records"][0]["profile_status"], "not_applicable")

    def test_imported_critical_sast_record_without_a_profile_still_fails_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sast = _write(
                Path(tmp) / "sast.json",
                {"security_evidence": [{
                    "scanner_type": "sast",
                    "tool": "semgrep",
                    "rule_id": "custom.unknown-weakness",
                    "weakness": "Undocumented custom weakness",
                    "severity": "critical",
                    "artifact": "payments-api",
                    "component": "app",
                    "message": "custom rule with no maintained profile",
                }]},
            )
            coverage_out = Path(tmp) / "source-coverage.json"
            code, err = _run([
                "scan",
                "--sbom", str(SBOM),
                "--vuln-in", str(VULNS),
                "--sast-in", str(sast),
                "--source-coverage-out", str(coverage_out),
                "--min-critical-security-profile-coverage", "1.0",
                "--no-table",
            ])
            summary = json.loads(coverage_out.read_text(encoding="utf-8"))["security_evidence"]["summary"]

            self.assertEqual(code, 10)
            self.assertIn("critical security profile coverage is 0.0000", err)
            self.assertEqual(int(summary["critical_records"]), 1)
            self.assertEqual(int(summary["critical_records_missing_profile"]), 1)


class MissingSecurityEvidenceGateTests(unittest.TestCase):
    """A scan that imports no security evidence must not report fabricated 0.0 coverage."""

    def test_dependency_only_scan_passes_the_security_profile_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            coverage_out = Path(tmp) / "source-coverage.json"
            code, err = _run([
                "scan",
                "--sbom", str(SBOM),
                "--vuln-in", str(VULNS),
                "--source-coverage-out", str(coverage_out),
                "--min-critical-security-profile-coverage", "1.0",
                "--no-table",
            ])
            report = json.loads(coverage_out.read_text(encoding="utf-8"))["security_evidence"]

            self.assertEqual(code, 0)
            self.assertNotIn("critical security profile coverage", err)
            self.assertEqual(int(report["records"]), 0)
            self.assertEqual(report["summary"]["critical_profile_coverage"], 1.0)

    def test_dependency_only_readiness_reports_the_metric_instead_of_null(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            readiness_out = Path(tmp) / "readiness.json"
            _run([
                "scan",
                "--sbom", str(SBOM),
                "--vuln-in", str(VULNS),
                "--readiness-out", str(readiness_out),
                "--no-table",
            ])
            readiness = json.loads(readiness_out.read_text(encoding="utf-8"))

            self.assertEqual(readiness["summary"]["critical_security_profile_coverage"], 1.0)
            self.assertNotIn("critical_security_profile_coverage", [blocker["kind"] for blocker in readiness["blockers"]])


class SilentReleaseGateMessageTests(unittest.TestCase):
    """Exit 10 with `--out` used to emit nothing at all on stdout or stderr."""

    def test_artifact_manifest_validate_explains_the_blockers_when_out_is_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = _write(
                Path(tmp) / "artifacts.json",
                {"artifacts": [{"name": "payments-api", "image": "ghcr.io/acme/payments-api:1.0.0", "sbom": str(SBOM), "git_sha": "c" * 40}]},
            )
            report_out = Path(tmp) / "validation.json"
            code, err = _run([
                "artifact-manifest", "validate",
                "--manifest", str(manifest),
                "--out", str(report_out),
                "--strict-provenance",
                "--fail-on-warning",
            ])
            report = json.loads(report_out.read_text(encoding="utf-8"))

            self.assertEqual(code, 10)
            self.assertEqual(report["status"], "blocked")
            self.assertIn("artifact manifest gate failed", err)
            self.assertIn("payments-api", err)
            self.assertIn("signature", err)
            self.assertIn("Next step:", err)
            self.assertIn(str(report_out), err)

    def test_artifact_manifest_validate_names_weak_identity_without_strict_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = _write(Path(tmp) / "artifacts.json", {"artifacts": [{"name": "payments-api", "sbom": str(SBOM)}]})
            code, err = _run([
                "artifact-manifest", "validate",
                "--manifest", str(manifest),
                "--out", str(Path(tmp) / "validation.json"),
                "--fail-on-warning",
            ])
            self.assertEqual(code, 10)
            self.assertIn("payments-api: no image digest or exact registry reference", err)

    def test_artifact_manifest_validate_reports_an_empty_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = _write(Path(tmp) / "artifacts.json", {"artifacts": []})
            code, err = _run([
                "artifact-manifest", "validate",
                "--manifest", str(manifest),
                "--out", str(Path(tmp) / "validation.json"),
                "--fail-on-warning",
            ])
            self.assertEqual(code, 10)
            self.assertIn("the manifest declares no artifacts", err)

    def test_artifact_manifest_validate_stays_silent_when_the_manifest_is_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            digest = "sha256:" + "a" * 64
            manifest = _write(
                Path(tmp) / "artifacts.json",
                {"artifacts": [{
                    "name": "payments-api",
                    "image": "ghcr.io/acme/payments-api:1.0.0",
                    "digest": digest,
                    "registry_ref": f"ghcr.io/acme/payments-api@{digest}",
                    "sbom": str(SBOM),
                    "git_sha": "b" * 40,
                    "signed": True,
                }]},
            )
            code, err = _run([
                "artifact-manifest", "validate",
                "--manifest", str(manifest),
                "--out", str(Path(tmp) / "validation.json"),
                "--strict-provenance",
                "--fail-on-warning",
            ])
            self.assertEqual(code, 0)
            self.assertEqual(err, "")

    def test_benchmark_snapshots_explains_the_regression_when_out_is_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            benchmark = _write(root / "benchmark.json", {"aggregate": {"finding_count": 1, "tier_counts": {"urgent": 1}}, "cases": []})
            expectations = _write(
                root / "expectations.json",
                {"schema_version": "1.0", "snapshots": [{
                    "id": "aggregate",
                    "expected_tier_counts": {"urgent": 0, "high": 0, "medium": 1, "low": 0, "informational": 0},
                    "regression_limits": {"max_count_by_tier": {"urgent": 0}, "allowed_count_delta_by_tier": {"urgent": 0}},
                }]},
            )
            report_out = root / "report.json"
            code, err = _run([
                "benchmark-snapshots",
                "--benchmark", str(benchmark),
                "--expectations", str(expectations),
                "--out", str(report_out),
            ])

            self.assertEqual(code, 10)
            self.assertEqual(json.loads(report_out.read_text(encoding="utf-8"))["status"], "failed")
            self.assertIn("benchmark snapshot gate failed", err)
            self.assertIn("aggregate", err)
            self.assertIn("urgent", err)
            self.assertIn("Next step:", err)
            self.assertIn(str(report_out), err)

    def test_benchmark_snapshots_warn_only_stays_quiet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            benchmark = _write(root / "benchmark.json", {"aggregate": {"finding_count": 1, "tier_counts": {"urgent": 1}}, "cases": []})
            expectations = _write(
                root / "expectations.json",
                {"schema_version": "1.0", "snapshots": [{
                    "id": "aggregate",
                    "expected_tier_counts": {"urgent": 0},
                    "regression_limits": {"max_count_by_tier": {"urgent": 0}},
                }]},
            )
            code, err = _run([
                "benchmark-snapshots",
                "--benchmark", str(benchmark),
                "--expectations", str(expectations),
                "--out", str(root / "report.json"),
                "--warn-only",
            ])
            self.assertEqual(code, 0)
            self.assertEqual(err, "")


if __name__ == "__main__":  # pragma: no cover - unittest entry point
    unittest.main()
