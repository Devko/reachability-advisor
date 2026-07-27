"""Regression tests for audited defects in the built-in source analyzer.

Every test here pins behaviour that was wrong before the `source` audit fixes:
catastrophic regex backtracking on untrusted repo files, an unbounded recursive
walk that aborted the whole scan, silently swallowed analysis failures reported
as "no link exists", package-name matching that never matched, custom rule
patterns that were accepted and then discarded, and untrusted scanner values
coerced with a bare `int()`.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from reachability_advisor.models import Component, Reachability
from reachability_advisor.source import (
    MAX_CALL_NAME_SEGMENTS,
    _file_segments,
    _function_segments,
    _generic_patterns,
    _python_function_segments,
    analyze_component_source,
    build_source_index,
    load_external_source_evidence,
    load_reachability_rules,
)

# Pathological inputs run at 100k characters. Before the fix the Java pattern
# needed ~14 s at 400 characters and grew roughly as n**3.8, so anything that
# finishes inside this budget cannot be running the old pattern.
REDOS_BUDGET_SECONDS = 5.0
REDOS_PADDING = 100_000


def _write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class SourceSegmentationRedosTests(unittest.TestCase):
    """Untrusted repo files must not be able to stall the scanner."""

    def _assert_fast(self, filename: str, text: str) -> None:
        started = time.monotonic()
        _function_segments(Path(filename), text)
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            REDOS_BUDGET_SECONDS,
            f"{filename} segmentation took {elapsed:.2f}s on {len(text)} bytes of padded input",
        )

    def test_java_whitespace_padding_does_not_blow_up(self) -> None:
        self._assert_fast("Evil.java", "class A {\n" + " " * REDOS_PADDING + "!\n}\n")
        self._assert_fast("Evil.java", "public " + " " * REDOS_PADDING + "a\n")

    def test_javascript_whitespace_padding_does_not_blow_up(self) -> None:
        self._assert_fast("evil.js", "const a = " + " " * REDOS_PADDING + "!\n")
        self._assert_fast("evil.js", "a(" + " " * REDOS_PADDING + "!\n")
        self._assert_fast("evil.js", 'app.get("/a", ' + " " * REDOS_PADDING + "!\n")

    def test_typescript_return_annotation_padding_does_not_blow_up(self) -> None:
        self._assert_fast("evil.ts", "x(): " + " " * REDOS_PADDING + "!\n")

    def test_java_signature_shapes_still_segment(self) -> None:
        cases = {
            "  void plain() {\n  }\n": "plain",
            "  public static final void go() {\n  }\n": "go",
            "  public Map<String, Object> handle(String a) {\n  }\n": "handle",
            "  public Map<String, List<Integer>> nested(int a) {\n  }\n": "nested",
            "  protected List<String> names(int x) throws IOException {\n  }\n": "names",
            "  <T> T generic(T a) {\n  }\n": "generic",
            "  String[] arrayReturn(int x) {\n  }\n": "arrayReturn",
            "class C { void f(@RequestBody String b){ }}\n": "f",
        }
        for text, expected in cases.items():
            with self.subTest(text=text.strip()):
                names = [segment.name for segment in _function_segments(Path("A.java"), text)]
                self.assertIn(expected, names)

    def test_java_anonymous_class_body_is_not_a_function(self) -> None:
        text = "class C {\n  void run() {\n    Object o = new Runnable(x) {\n      int y = 1;\n    };\n  }\n}\n"
        names = [segment.name for segment in _function_segments(Path("C.java"), text)]
        self.assertIn("run", names)
        self.assertNotIn("Runnable", names)

    def test_javascript_arrow_shapes_still_segment(self) -> None:
        cases = {
            "const add = (a, b) => a + b;\n": "add",
            "const one = x => x;\n": "one",
            "const none = () => 1;\n": "none",
            "const later = async (a) => a;\n": "later",
            "exports.handler = (event) => event;\n": "handler",
        }
        for text, expected in cases.items():
            with self.subTest(text=text.strip()):
                names = [segment.name for segment in _function_segments(Path("a.js"), text)]
                self.assertIn(expected, names)

    def test_typescript_annotated_method_still_segments(self) -> None:
        text = "class C {\n  handle(a: string): Promise<void> {\n    return use(a);\n  }\n}\n"
        names = [segment.name for segment in _function_segments(Path("a.ts"), text)]
        self.assertIn("handle", names)


class DeepAttributeChainTests(unittest.TestCase):
    """A crafted `.py` file must degrade itself, not abort the scan."""

    def test_deep_dotted_call_does_not_raise_and_is_bounded(self) -> None:
        text = "def f():\n    return a" + ".b" * 2000 + "()\n"
        segments = _python_function_segments(text)
        self.assertEqual([segment.name for segment in segments], ["f"])
        self.assertLessEqual(len(segments[0].calls), MAX_CALL_NAME_SEGMENTS)
        # The leaf attribute must survive the cap so realistic matching still works.
        self.assertIn("b", segments[0].calls)

    def test_short_dotted_call_keeps_every_suffix(self) -> None:
        segments = _python_function_segments("def f():\n    return a.b.c()\n")
        self.assertEqual(segments[0].calls, frozenset({"a.b.c", "b.c", "c"}))

    def test_scan_survives_a_file_that_exhausts_the_parser(self) -> None:
        # 20k levels defeats ast.parse itself; the file must degrade alone.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "app.py", "import yaml\n\ndef handler():\n    return yaml.load('x')\n")
            _write(root, "deep.py", "def g():\n    return a" + ".b" * 20000 + "()\n")
            evidence = analyze_component_source(
                Component(name="PyYAML", version="5.1", purl="pkg:pypi/pyyaml@5.1"), root
            )
        self.assertEqual(evidence.reachability, Reachability.FUNCTION_REACHABLE)

    def test_recursion_failure_is_recorded_on_the_index_not_raised(self) -> None:
        # Whether a given chain depth actually exhausts the parser varies by
        # interpreter version, so raise the RecursionError directly instead. The unit
        # under test is the handler in `_file_segments` -- a pathological file must
        # degrade to a recorded visibility gap, never propagate and abort the scan.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = _write(root, "deep.py", "def g():\n    return a.b()\n")
            text = path.read_text(encoding="utf-8")
            with mock.patch(
                "reachability_advisor.source._function_segments", side_effect=RecursionError
            ):
                result = _file_segments(build_source_index(root), path, text)
        self.assertEqual(result.segments, ())
        self.assertEqual(result.error_code, "source_analysis_failed")
        self.assertIn("recursion", result.error_message)


class ParseFailureHonestyTests(unittest.TestCase):
    """A failed parse is a visibility gap, never a lower-reachability claim."""

    CLEAN = "import yaml\nfrom flask import request\n\ndef handler():\n    return yaml.load(request.args['x'])\n"
    COMPONENT = Component(name="PyYAML", version="5.1", purl="pkg:pypi/pyyaml@5.1")

    def test_unparseable_evidence_file_reports_the_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "app.py", self.CLEAN + "\ndef broken(:\n    pass\n")
            evidence = analyze_component_source(self.COMPONENT, root)
        codes = [str(diagnostic.get("code")) for diagnostic in evidence.diagnostics]
        self.assertIn("source_parse_failed", codes)
        self.assertNotIn("unlinked_attacker_input", codes)
        parse_diagnostic = next(d for d in evidence.diagnostics if d["code"] == "source_parse_failed")
        self.assertEqual(parse_diagnostic["severity"], "warning")
        self.assertIn("app.py", str(parse_diagnostic["detail"]["files"]))
        # The old reason positively asserted the negative.
        self.assertNotIn("no same-function or bounded call-path link was inferred", evidence.reason)
        self.assertIn("incomplete", evidence.reason)

    def test_clean_source_is_unaffected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "app.py", self.CLEAN)
            evidence = analyze_component_source(self.COMPONENT, root)
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertEqual(evidence.diagnostics, [])

    def test_unparseable_sibling_file_does_not_taint_a_clean_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "app.py", self.CLEAN)
            _write(root, "other.py", "def broken(:\n")
            evidence = analyze_component_source(self.COMPONENT, root)
        self.assertEqual(evidence.reachability, Reachability.ATTACKER_CONTROLLED)
        self.assertEqual(evidence.diagnostics, [])


class GenericPatternTests(unittest.TestCase):
    def test_hyphenated_pypi_name_matches_the_underscored_module(self) -> None:
        component = Component(name="django-allauth", version="1.0", purl="pkg:pypi/django-allauth@1.0")
        import_pattern, from_pattern = _generic_patterns(component)
        self.assertNotIn(r"\[", import_pattern)
        self.assertEqual(import_pattern, r"^\s*import\s+django[-_.]+allauth\b")
        self.assertEqual(from_pattern, r"^\s*from\s+django[-_.]+allauth(?:\.[\w.]+)?\s+import\s+")

    def test_hyphenated_pypi_component_is_imported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "app.py", "import django_allauth\n\ndef h():\n    return django_allauth.x()\n")
            evidence = analyze_component_source(
                Component(name="django-allauth", version="1.0", purl="pkg:pypi/django-allauth@1.0"), root
            )
        self.assertEqual(evidence.reachability, Reachability.IMPORTED)

    def test_generic_pypi_submodule_import_is_observed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "app.py", "from urllib3.util.retry import Retry\n\ndef h():\n    return Retry()\n")
            evidence = analyze_component_source(
                Component(name="urllib3", version="1.26.5", purl="pkg:pypi/urllib3@1.26.5"), root
            )
        self.assertEqual(evidence.reachability, Reachability.IMPORTED)

    def test_builtin_pypi_rule_submodule_import_is_observed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "app.py", "from lxml.etree import fromstring\n\ndef h(request):\n    return fromstring(request.data)\n")
            evidence = analyze_component_source(
                Component(name="lxml", version="4.6.0", purl="pkg:pypi/lxml@4.6.0"), root
            )
        self.assertEqual(evidence.reachability, Reachability.IMPORTED)

    def test_scoped_npm_patterns_use_the_full_specifier(self) -> None:
        component = Component(name="traverse", group="@babel", version="7.23.2", purl="pkg:npm/%40babel/traverse@7.23.2")
        patterns = _generic_patterns(component)
        self.assertTrue(all("@babel/traverse" in pattern for pattern in patterns), patterns)

    def test_scoped_npm_require_is_imported(self) -> None:
        component = Component(name="traverse", group="@babel", version="7.23.2", purl="pkg:npm/%40babel/traverse@7.23.2")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "a.js", "const t = require('@babel/traverse');\n")
            self.assertEqual(analyze_component_source(component, root).reachability, Reachability.IMPORTED)

    def test_unrelated_same_suffix_package_is_not_credited(self) -> None:
        component = Component(name="traverse", group="@babel", version="7.23.2", purl="pkg:npm/%40babel/traverse@7.23.2")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "a.js", "const t = require('traverse');\n")
            self.assertNotEqual(analyze_component_source(component, root).reachability, Reachability.IMPORTED)

    def test_prejoined_scoped_name_is_not_double_scoped(self) -> None:
        component = Component(name="@nestjs/platform-express", version="10.0.0", purl="pkg:npm/%40nestjs/platform-express@10.0.0")
        self.assertNotIn("@nestjs/@nestjs", _generic_patterns(component)[0])

    def test_unscoped_npm_patterns_are_unchanged(self) -> None:
        component = Component(name="left-pad", version="1.0.0", purl="pkg:npm/left-pad@1.0.0")
        self.assertEqual(_generic_patterns(component)[0], r"require\(['\"]left\-pad(?:/[^'\"]+)?['\"]\)")


class ReachabilityRuleValidationTests(unittest.TestCase):
    def _rules_file(self, tmp: str, rules: list[dict[str, object]]) -> Path:
        path = Path(tmp) / "rules.json"
        path.write_text(json.dumps({"rules": rules}), encoding="utf-8")
        return path

    def test_invalid_import_pattern_is_rejected_at_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._rules_file(tmp, [{"ecosystem": "pypi", "package": "acme", "import_patterns": [r"^\s*import\s+acme(\b"]}])
            with self.assertRaises(ValueError) as caught:
                load_reachability_rules(path)
        message = str(caught.exception)
        self.assertIn("import_patterns", message)
        self.assertIn("is not a valid regex", message)

    def test_invalid_function_and_attacker_patterns_are_rejected(self) -> None:
        for field in ("function_patterns", "attacker_patterns"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                path = self._rules_file(
                    tmp,
                    [{"ecosystem": "pypi", "package": "acme", "import_patterns": [r"^\s*import\s+acme\b"], field: ["("]}],
                )
                with self.assertRaises(ValueError) as caught:
                    load_reachability_rules(path)
                self.assertIn(field, str(caught.exception))

    def test_vulnerability_ids_are_not_treated_as_regexes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._rules_file(
                tmp,
                [{"ecosystem": "pypi", "package": "acme", "import_patterns": [r"^\s*import\s+acme\b"], "vulnerabilities": ["CVE-2021-4(4228"]}],
            )
            rules = load_reachability_rules(path)
        self.assertEqual(rules[0].vulnerability_ids, ("CVE-2021-4(4228",))

    def test_valid_rules_still_load_and_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._rules_file(tmp, [{"ecosystem": "pypi", "package": "acme", "import_patterns": [r"^\s*import\s+acme\b"]}])
            rules = load_reachability_rules(path)
            root = Path(tmp) / "src"
            _write(root, "app.py", "import acme\n\ndef h():\n    acme.run(1)\n")
            evidence = analyze_component_source(
                Component(name="acme", version="1.0", purl="pkg:pypi/acme@1.0"), root, custom_rules=rules
            )
        self.assertEqual(evidence.reachability, Reachability.IMPORTED)


class SourceIndexHardeningTests(unittest.TestCase):
    def test_non_regular_files_are_skipped_with_a_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "real.py", "import yaml\n")
            os.symlink("/dev/zero", root / "device.py")
            os.mkfifo(root / "pipe.py")
            index = build_source_index(root)
        self.assertEqual(sorted(item.path.name for item in index.files), ["real.py"])
        skipped = {Path(item["path"]).name: item["reason"] for item in index.skipped_files}
        self.assertEqual(skipped.get("device.py"), "not a regular file")
        self.assertEqual(skipped.get("pipe.py"), "not a regular file")

    def test_symlink_to_a_regular_file_is_still_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = _write(root, "real.py", "import yaml\n")
            os.symlink(target, root / "link.py")
            index = build_source_index(root)
        self.assertEqual(sorted(item.path.name for item in index.files), ["link.py", "real.py"])

    def test_oversized_file_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "big.py", "# pad\n" * 200_000)
            index = build_source_index(root)
        self.assertEqual(index.files, [])
        self.assertEqual([item["reason"] for item in index.skipped_files], ["file exceeds source scan size limit"])


class SegmentCacheTests(unittest.TestCase):
    def test_segments_are_computed_once_per_file_per_index(self) -> None:
        import reachability_advisor.source as source_module

        calls: list[Path] = []
        original = source_module._function_segments

        def counting(path: Path, text: str) -> list[object]:
            calls.append(path)
            return original(path, text)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index_number in range(5):
                _write(root, f"m{index_number}.py", "import yaml\n\ndef h():\n    return yaml.load('x')\n")
            index = build_source_index(root)
            source_module._function_segments = counting  # type: ignore[assignment]
            try:
                results = [
                    analyze_component_source(
                        Component(name="PyYAML", version="5.1", purl="pkg:pypi/pyyaml@5.1"),
                        None,
                        source_index=index,
                    ).reachability
                    for _ in range(4)
                ]
            finally:
                source_module._function_segments = original  # type: ignore[assignment]
        # Without the cache this was 5 files x 4 analyses = 20 segmentations.
        self.assertEqual(len(calls), 5)
        self.assertEqual(len(set(results)), 1)


class ExternalEvidenceCoercionTests(unittest.TestCase):
    def _load(self, tmp: str, name: str, payload: dict[str, object]) -> list[tuple[int, int]]:
        path = Path(tmp) / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        store = load_external_source_evidence([path])
        return [(location.line, location.column) for record in store.records for location in record.evidence.locations]

    def test_non_numeric_plain_location_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {"evidence": [{"component": "lodash", "state": "imported", "locations": [{"path": "a.js", "line": {"x": 1}, "column": ["nope"]}]}]}
            self.assertEqual(self._load(tmp, "ev.json", payload), [(1, 1)])

    def test_non_numeric_string_location_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {"evidence": [{"component": "lodash", "state": "imported", "locations": [{"path": "a.js", "line": "n/a"}]}]}
            self.assertEqual(self._load(tmp, "ev.json", payload), [(1, 1)])

    def test_sarif_region_with_non_numeric_start_line_does_not_crash(self) -> None:
        payload = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "codeql"}},
                    "results": [
                        {
                            "ruleId": "js/x",
                            "message": {"text": "m"},
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": "a.js"}, "region": {"startLine": {"bad": 1}, "startColumn": [2]}}}
                            ],
                        }
                    ],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._load(tmp, "ev.sarif", payload), [(1, 1)])

    def test_valid_locations_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {"evidence": [{"component": "lodash", "state": "imported", "locations": [{"path": "a.js", "line": 7, "column": 3}]}]}
            self.assertEqual(self._load(tmp, "ev.json", payload), [(7, 3)])

    def test_out_of_spec_line_numbers_are_clamped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {"evidence": [{"component": "lodash", "state": "imported", "locations": [{"path": "a.js", "line": -5, "column": -2}]}]}
            self.assertEqual(self._load(tmp, "ev.json", payload), [(1, 1)])


if __name__ == "__main__":
    unittest.main()
