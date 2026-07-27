# tests/test_yaml_loader.py
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reachability_advisor.yaml_loader import (
    MAX_YAML_DEPTH,
    YamlError,
    load_yaml_documents,
    load_yaml_mapping,
    load_yaml_text,
)

# yaml.safe_load's own recursive-descent parser raises a raw RecursionError on documents
# this deep, before `_check_bounds` (which only runs on the returned value) ever sees them.
# 50,000 is well past where CPython's default recursion limit gives out for both flow and
# block styles; keep it well above that line rather than tuned to the exact threshold.
RECURSION_DEPTH = 50_000


def _deep_flow_sequence(depth: int = RECURSION_DEPTH) -> str:
    return "root: " + "[" * depth + "1" + "]" * depth


def _deep_block_mapping(depth: int = RECURSION_DEPTH) -> str:
    return "".join(f"{'  ' * i}k:\n" for i in range(depth)) + f"{'  ' * depth}leaf: 1\n"


def _write(text: str) -> Path:
    tmp = tempfile.mkdtemp()
    path = Path(tmp) / "doc.yml"
    path.write_text(text, encoding="utf-8")
    return path


class LoadYamlMappingTests(unittest.TestCase):
    def test_parses_a_mapping_with_comments(self) -> None:
        path = _write("# why this gate\ngate:\n  fail_on: high\n")
        self.assertEqual(load_yaml_mapping(path, "config"), {"gate": {"fail_on": "high"}})

    def test_rejects_a_non_mapping_document(self) -> None:
        path = _write("- one\n- two\n")
        with self.assertRaises(YamlError) as error:
            load_yaml_mapping(path, "config")
        self.assertIn("must be a mapping", str(error.exception))

    def test_rejects_malformed_yaml_with_the_label_and_path(self) -> None:
        path = _write("gate: [unclosed\n")
        with self.assertRaises(YamlError) as error:
            load_yaml_mapping(path, "config")
        self.assertIn(str(path), str(error.exception))

    def test_rejects_nesting_past_the_depth_cap(self) -> None:
        # safe_load blocks object construction but not deep nesting.
        deep = "".join(f"{' ' * i}k{i}:\n" for i in range(MAX_YAML_DEPTH + 5))
        path = _write(deep + f"{' ' * (MAX_YAML_DEPTH + 5)}leaf: 1\n")
        with self.assertRaises(YamlError) as error:
            load_yaml_mapping(path, "config")
        self.assertIn("nesting exceeds", str(error.exception))

    def test_rejects_an_alias_expansion_bomb(self) -> None:
        # safe_load happily expands aliases; this is the billion-laughs shape. Six levels of
        # 9-way branching (~9**6 leaf visits) are needed to clear the 200,000-node budget --
        # four levels only reaches ~8k visits and would not exercise the guard.
        bomb = "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
        bomb += "c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
        bomb += "e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\nf: [*e,*e,*e,*e,*e,*e,*e,*e,*e]\n"
        path = _write(bomb)
        with self.assertRaises(YamlError):
            load_yaml_mapping(path, "config")

    def test_never_constructs_arbitrary_objects(self) -> None:
        path = _write("value: !!python/object/apply:os.system ['echo pwned']\n")
        with self.assertRaises(YamlError):
            load_yaml_mapping(path, "config")


class DeeplyNestedYamlTests(unittest.TestCase):
    """`yaml.safe_load` recurses while parsing, so pure structural nesting can raise a raw
    `RecursionError` before `_check_bounds` ever runs -- `_check_bounds` only inspects the
    value `safe_load` returns, not the document text. These regression tests cover both the
    single-document and multi-document loaders, and both flow-style and block-style nesting.
    """

    def test_load_yaml_text_rejects_deep_flow_nesting_without_recursion_error(self) -> None:
        with self.assertRaises(YamlError) as caught:
            load_yaml_text(_deep_flow_sequence(), "config")
        self.assertIn("nesting", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, RecursionError)

    def test_load_yaml_text_rejects_deep_block_nesting_without_recursion_error(self) -> None:
        with self.assertRaises(YamlError) as caught:
            load_yaml_text(_deep_block_mapping(), "config")
        self.assertIn("nesting", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, RecursionError)

    def test_load_yaml_documents_rejects_deep_flow_nesting_without_recursion_error(self) -> None:
        with self.assertRaises(YamlError) as caught:
            load_yaml_documents(_deep_flow_sequence(), "config")
        self.assertIn("nesting", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, RecursionError)

    def test_load_yaml_documents_rejects_deep_block_nesting_without_recursion_error(self) -> None:
        with self.assertRaises(YamlError) as caught:
            load_yaml_documents(_deep_block_mapping(), "config")
        self.assertIn("nesting", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, RecursionError)

    def test_load_yaml_mapping_rejects_deep_flow_nesting_through_a_file(self) -> None:
        # End-to-end through the file-reading entry point malicious configs and manifests
        # actually go through, not just the in-memory parse helpers.
        path = _write(_deep_flow_sequence())
        with self.assertRaises(YamlError) as caught:
            load_yaml_mapping(path, "config")
        self.assertIn("nesting", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
