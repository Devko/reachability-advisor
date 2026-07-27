# Config File and Onboarding Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 49-flag `scan` invocation with a layered `.reachability.yml`, and add `init` and `doctor` so a platform team gets from an unconfigured repo to a passing gate in three commands.

**Architecture:** A new config subsystem loads YAML through a hardened `safe_load` wrapper, merges four precedence layers (defaults → org baseline via `extends:` → repo file → CLI flags), and feeds resolved values into the existing argparse defaults so every current flag keeps working. `init` writes a config from repo detection; `doctor` reports what evidence is missing and the exact command that produces it.

**Tech Stack:** Python 3.10+, PyYAML (first runtime dependency), stdlib `unittest`, argparse, `importlib.resources`.

## Global Constraints

- Tests are **`unittest`**, not pytest. Run with `PYTHONPATH=src .venv/bin/python -m unittest tests.<module> -v`. The suite runs via `PYTHONPATH=src .venv/bin/python scripts/run_tests.py`.
- Every module starts with `from __future__ import annotations`.
- `mypy --strict` must stay clean: `PYTHONPATH=src .venv/bin/python -m mypy src`.
- `ruff` must stay clean: `.venv/bin/python -m ruff check src tests scripts`. Line length 100.
- Error classes subclass `ValueError` so `cli.py`'s existing top-level handler maps them to `error: ...` and exit code 2.
- `yaml.safe_load` **only**. `yaml.load` is arbitrary object construction. Never use it.
- Untrusted input: every config/manifest read goes through `input_limits.read_text_limited` and the depth guard. Fail closed.
- Unknown keys are **rejected, not ignored** — a typo'd gate key must fail loudly.
- No network at runtime. `extends:` resolves from a path or an installed package only.
- The full suite (905 tests at plan time) must stay green on Python 3.10, 3.11, 3.12 and 3.13.
- Verify all four interpreters before pushing: `/tmp/.../venv3.10/bin/python` etc., or `uv venv --python 3.N`.

---

### Task 1: Hardened YAML loader and the PyYAML dependency

**Files:**
- Create: `src/reachability_advisor/yaml_loader.py`
- Create: `tests/test_yaml_loader.py`
- Modify: `pyproject.toml` (add `dependencies`)
- Modify: `README.md`, `docs/threat_model.md` (correct zero-dependency claims)

**Interfaces:**
- Consumes: `input_limits.read_text_limited`, `input_limits.InputSizeError`
- Produces: `YamlError(ValueError)`, `load_yaml_mapping(path: str | Path, label: str) -> dict[str, Any]`, `load_yaml_documents(text: str, label: str) -> list[Any]`, `MAX_YAML_DEPTH: int`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_yaml_loader.py
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reachability_advisor.yaml_loader import MAX_YAML_DEPTH, YamlError, load_yaml_mapping


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
        # safe_load happily expands aliases; this is the billion-laughs shape.
        bomb = "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
        bomb += "c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
        path = _write(bomb)
        with self.assertRaises(YamlError):
            load_yaml_mapping(path, "config")

    def test_never_constructs_arbitrary_objects(self) -> None:
        path = _write("value: !!python/object/apply:os.system ['echo pwned']\n")
        with self.assertRaises(YamlError):
            load_yaml_mapping(path, "config")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_yaml_loader -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'reachability_advisor.yaml_loader'`

- [ ] **Step 3: Add PyYAML to the project dependencies**

In `pyproject.toml`, directly after the `license-files` line's block and before `keywords`, add:

```toml
dependencies = [
  # First runtime dependency. Config and Kubernetes manifests are YAML, and a hand-written
  # parser for a security tool's untrusted input is a liability -- an audit found a stack
  # overflow in the previous one. Only `yaml.safe_load` is ever used.
  "PyYAML>=6",
]
```

Install it: `.venv/bin/pip install -q -e ".[dev]"`

- [ ] **Step 4: Write the loader**

```python
# src/reachability_advisor/yaml_loader.py
"""Bounded, non-constructing YAML loading for untrusted documents."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .input_limits import InputSizeError, read_text_limited

MAX_YAML_DEPTH = 100
MAX_YAML_NODES = 200_000


class YamlError(ValueError):
    """Raised when a YAML document is unreadable or exceeds a safety bound.

    Subclasses ``ValueError`` so the CLI's top-level handler maps it to exit code 2
    without this module importing from ``cli``.
    """


def _check_bounds(value: Any, label: str, depth: int = 0, budget: list[int] | None = None) -> None:
    """Reject documents that are too deep or that expand to too many nodes.

    ``safe_load`` refuses to construct arbitrary Python objects, but it will happily
    expand anchors and aliases, so a small file can produce an enormous structure.
    The node budget is what stops that; the depth cap stops unbounded recursion.
    """
    if budget is None:
        budget = [MAX_YAML_NODES]
    if depth > MAX_YAML_DEPTH:
        raise YamlError(f"{label}: nesting exceeds the supported depth of {MAX_YAML_DEPTH}")
    budget[0] -= 1
    if budget[0] < 0:
        raise YamlError(
            f"{label}: document expands to more than {MAX_YAML_NODES} nodes. "
            "Anchors and aliases can expand a small file into an enormous structure."
        )
    if isinstance(value, dict):
        for key, item in value.items():
            _check_bounds(key, label, depth + 1, budget)
            _check_bounds(item, label, depth + 1, budget)
    elif isinstance(value, list):
        for item in value:
            _check_bounds(item, label, depth + 1, budget)


def load_yaml_text(text: str, label: str) -> Any:
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise YamlError(f"{label}: invalid YAML: {exc}") from None
    _check_bounds(parsed, label)
    return parsed


def load_yaml_documents(text: str, label: str) -> list[Any]:
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise YamlError(f"{label}: invalid YAML: {exc}") from None
    for document in documents:
        _check_bounds(document, label)
    return documents


def load_yaml_mapping(path: str | Path, label: str) -> dict[str, Any]:
    file_path = Path(path)
    try:
        text = read_text_limited(file_path, label)
    except InputSizeError:
        raise
    except OSError as exc:
        raise YamlError(f"{file_path}: {label} could not be read: {exc}") from None
    parsed = load_yaml_text(text, f"{file_path}: {label}")
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise YamlError(f"{file_path}: {label} must be a mapping, got {type(parsed).__name__}")
    return parsed
```

- [ ] **Step 5: Run test to verify it passes**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_yaml_loader -v`
Expected: PASS, 6 tests

- [ ] **Step 6: Correct the zero-dependency claims**

Grep for the claims and fix each: `grep -rn "no dependencies\|zero dependencies\|dependency-free\|stdlib only" README.md docs/`

In `docs/threat_model.md`, under "Security controls", add:

```markdown
- The only runtime dependency is PyYAML, used exclusively through `yaml.safe_load`, which does not construct arbitrary Python objects. YAML input is additionally bounded by a document size limit, a nesting-depth cap, and a node budget that stops anchor/alias expansion attacks.
```

- [ ] **Step 7: Run the gates and commit**

```bash
.venv/bin/python -m ruff check src tests scripts
PYTHONPATH=src .venv/bin/python -m mypy src
PYTHONPATH=src .venv/bin/python scripts/run_tests.py
git add src/reachability_advisor/yaml_loader.py tests/test_yaml_loader.py pyproject.toml README.md docs/threat_model.md
git commit -m "feat: add bounded safe_load YAML loader and PyYAML dependency"
```

---

### Task 2: Replace the hand-rolled Kubernetes YAML parser

**Files:**
- Modify: `src/reachability_advisor/kubernetes.py` (delete `_parse_yaml_document`, `_yaml_lines`, `_parse_yaml_block`, `_parse_yaml_mapping`, `_parse_yaml_list` and their helpers; rewrite `_parse_manifest_documents`)
- Modify: `tests/test_audit_k8s.py` (the depth-guard tests now assert the shared loader's message)

**Interfaces:**
- Consumes: `yaml_loader.load_yaml_documents`, `yaml_loader.YamlError`, `yaml_loader.MAX_YAML_DEPTH`
- Produces: unchanged public API — `load_kubernetes_resources`, `KubernetesManifestError`, `MAX_MANIFEST_DEPTH`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_audit_k8s.py`:

```python
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
        # The hand-rolled parser silently mis-parsed anchors; a real loader resolves them.
        text = (
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: a\n"
            "spec:\n  selector: &sel\n    app: payments-api\n"
            "  ports: []\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "svc.yaml"
            manifest.write_text(text, encoding="utf-8")
            resources = load_kubernetes_resources(manifest)
        self.assertEqual(resources[0].kind, "Service")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_audit_k8s.SharedYamlLoaderTests -v`
Expected: FAIL — `kubernetes._parse_yaml_document still exists`

- [ ] **Step 3: Rewrite the parse entry point**

In `src/reachability_advisor/kubernetes.py`, add to the imports:

```python
from .yaml_loader import YamlError, load_yaml_documents
```

Replace the body of `_parse_manifest_documents` with:

```python
def _parse_manifest_documents(text: str, path: Path) -> list[Any]:
    """Parse a multi-document manifest through the shared bounded loader.

    The depth and node bounds live in ``yaml_loader``; ``MAX_MANIFEST_DEPTH`` still applies
    to the parsed structure because a manifest that deep is not something this tool models,
    regardless of whether the loader could hold it.
    """
    try:
        documents = load_yaml_documents(text, f"{path}: manifest")
    except YamlError as exc:
        raise KubernetesManifestError(str(exc)) from None
    return [document for document in documents if isinstance(document, dict)]
```

Then delete `_parse_yaml_document`, `_yaml_lines`, `_parse_yaml_block`, `_parse_yaml_mapping`,
`_parse_yaml_list`, and any helper that is now unreferenced. Verify none remain referenced:
`grep -n "_parse_yaml\|_yaml_lines" src/reachability_advisor/kubernetes.py`

Keep `_check_depth` / `MAX_MANIFEST_DEPTH` and the call site that walks the parsed structure.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_audit_k8s -v`
Expected: PASS. If a depth-guard test now reports the loader's `nesting exceeds the supported
depth` instead of `manifest nesting exceeds supported depth`, update that assertion — both are
controlled domain errors; record which layer now fires.

- [ ] **Step 5: Run the full suite and commit**

```bash
PYTHONPATH=src .venv/bin/python scripts/run_tests.py
.venv/bin/python -m ruff check src tests scripts && PYTHONPATH=src .venv/bin/python -m mypy src
git add src/reachability_advisor/kubernetes.py tests/test_audit_k8s.py
git commit -m "refactor: parse Kubernetes manifests with the shared YAML loader"
```

---

### Task 3: Config schema and validation

**Files:**
- Create: `src/reachability_advisor/config_schema.py`
- Create: `tests/test_config_schema.py`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces: `ConfigError(ValueError)`, `ArtifactConfig`, `GateConfig`, `OutputConfig`, `ReachabilityConfig`, `validate_config(raw: dict[str, Any], source: str) -> ReachabilityConfig`, `TOP_LEVEL_KEYS: frozenset[str]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config_schema.py
from __future__ import annotations

import unittest

from reachability_advisor.config_schema import ConfigError, validate_config

MINIMAL = {
    "version": 1,
    "artifacts": {"payments-api": {"sbom": "sboms/p.cdx.json", "source": "src/p"}},
}


class ValidateConfigTests(unittest.TestCase):
    def test_accepts_a_minimal_config(self) -> None:
        config = validate_config(MINIMAL, "test.yml")
        self.assertEqual(config.artifacts["payments-api"].sbom, "sboms/p.cdx.json")
        self.assertEqual(config.gate.fail_on, "high")  # documented default

    def test_rejects_an_unknown_top_level_key(self) -> None:
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "artifcats": {}}, "test.yml")
        message = str(error.exception)
        self.assertIn("artifcats", message)
        self.assertIn("test.yml", message)

    def test_rejects_an_unknown_gate_key(self) -> None:
        # A typo'd gate key must fail loudly: silently defaulting is how a gate stops gating.
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "gate": {"fial_on": "high"}}, "test.yml")
        self.assertIn("fial_on", str(error.exception))

    def test_rejects_an_out_of_range_fail_on_tier(self) -> None:
        with self.assertRaises(ConfigError) as error:
            validate_config({**MINIMAL, "gate": {"fail_on": "bad"}}, "test.yml")
        self.assertIn("fail_on", str(error.exception))

    def test_rejects_a_missing_version(self) -> None:
        with self.assertRaises(ConfigError):
            validate_config({"artifacts": {}}, "test.yml")

    def test_rejects_an_unsupported_version(self) -> None:
        with self.assertRaises(ConfigError):
            validate_config({**MINIMAL, "version": 99}, "test.yml")

    def test_rejects_a_wrongly_typed_artifact_block(self) -> None:
        with self.assertRaises(ConfigError):
            validate_config({"version": 1, "artifacts": {"a": "not-a-mapping"}}, "test.yml")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_config_schema -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'reachability_advisor.config_schema'`

- [ ] **Step 3: Write the schema**

```python
# src/reachability_advisor/config_schema.py
"""Typed schema and strict validation for .reachability.yml."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SUPPORTED_VERSIONS = frozenset({1})
TIERS = ("informational", "low", "medium", "high", "urgent")
PROFILES = ("advisory", "production")

TOP_LEVEL_KEYS = frozenset({"version", "extends", "artifacts", "evidence", "iac", "gate", "output"})
ARTIFACT_KEYS = frozenset({"sbom", "source", "image", "manifest"})
EVIDENCE_KEYS = frozenset({"vulnerabilities", "sast", "dast", "cspm", "posture", "source"})
IAC_KEYS = frozenset({"terraform", "terraform_source", "kubernetes"})
GATE_KEYS = frozenset({"profile", "fail_on", "fail_on_new", "thresholds"})
OUTPUT_KEYS = frozenset({"dir", "formats"})
FORMATS = ("json", "sarif", "markdown", "html", "diagnostics", "annotations", "baseline")


class ConfigError(ValueError):
    """Raised when a configuration document is malformed.

    Subclasses ``ValueError`` so the CLI's existing handler maps it to exit code 2.
    A malformed config must stop the run: every silent coercion here widens a gate.
    """


@dataclass(frozen=True)
class ArtifactConfig:
    sbom: str | None = None
    source: str | None = None
    image: str | None = None
    manifest: str | None = None


@dataclass(frozen=True)
class GateConfig:
    profile: str = "advisory"
    fail_on: str = "high"
    fail_on_new: str | None = None
    thresholds: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class OutputConfig:
    dir: str = "outputs"
    formats: tuple[str, ...] = ("json", "markdown")


@dataclass(frozen=True)
class ReachabilityConfig:
    version: int = 1
    artifacts: dict[str, ArtifactConfig] = field(default_factory=dict)
    evidence: dict[str, tuple[str, ...]] = field(default_factory=dict)
    iac: dict[str, str] = field(default_factory=dict)
    gate: GateConfig = field(default_factory=GateConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


def _reject_unknown(block: dict[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = sorted(str(key) for key in block if key not in allowed)
    if unknown:
        raise ConfigError(
            f"{label}: unknown key(s) {', '.join(repr(key) for key in unknown)}; "
            f"allowed keys are {', '.join(sorted(allowed))}"
        )


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{label}: must be a mapping, got {type(value).__name__}")
    return value


def _string_list(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{label}: must be a string or a list of strings")
    return tuple(value)


def _optional_string(block: dict[str, Any], key: str, label: str) -> str | None:
    if key not in block or block[key] is None:
        return None
    value = block[key]
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label}: {key!r} must be a non-empty string, got {value!r}")
    return value


def _gate(value: Any, label: str) -> GateConfig:
    block = _mapping(value, f"{label}: gate")
    _reject_unknown(block, GATE_KEYS, f"{label}: gate")
    profile = block.get("profile", "advisory")
    if profile not in PROFILES:
        raise ConfigError(f"{label}: gate.profile must be one of {', '.join(PROFILES)}, got {profile!r}")
    fail_on = block.get("fail_on", "high")
    if fail_on not in TIERS:
        raise ConfigError(f"{label}: gate.fail_on must be one of {', '.join(TIERS)}, got {fail_on!r}")
    fail_on_new = block.get("fail_on_new")
    if fail_on_new is not None and fail_on_new not in TIERS:
        raise ConfigError(f"{label}: gate.fail_on_new must be one of {', '.join(TIERS)}, got {fail_on_new!r}")
    raw_thresholds = _mapping(block.get("thresholds"), f"{label}: gate.thresholds")
    thresholds: dict[str, float] = {}
    for key, item in raw_thresholds.items():
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ConfigError(f"{label}: gate.thresholds.{key} must be a number, got {item!r}")
        thresholds[str(key)] = float(item)
    return GateConfig(profile=profile, fail_on=fail_on, fail_on_new=fail_on_new, thresholds=thresholds)


def _output(value: Any, label: str) -> OutputConfig:
    block = _mapping(value, f"{label}: output")
    _reject_unknown(block, OUTPUT_KEYS, f"{label}: output")
    directory = block.get("dir", "outputs")
    if not isinstance(directory, str) or not directory.strip():
        raise ConfigError(f"{label}: output.dir must be a non-empty string")
    formats = _string_list(block.get("formats", ["json", "markdown"]), f"{label}: output.formats")
    unsupported = [item for item in formats if item not in FORMATS]
    if unsupported:
        raise ConfigError(
            f"{label}: output.formats has unsupported value(s) {', '.join(unsupported)}; "
            f"supported are {', '.join(FORMATS)}"
        )
    return OutputConfig(dir=directory, formats=formats)


def validate_config(raw: dict[str, Any], source: str) -> ReachabilityConfig:
    """Validate a fully merged config mapping into a typed object."""
    _reject_unknown(raw, TOP_LEVEL_KEYS, source)

    if "version" not in raw:
        raise ConfigError(f"{source}: 'version' is required; write `version: 1`")
    version = raw["version"]
    if version not in SUPPORTED_VERSIONS:
        raise ConfigError(
            f"{source}: unsupported version {version!r}; "
            f"this build supports {', '.join(str(item) for item in sorted(SUPPORTED_VERSIONS))}"
        )

    artifacts: dict[str, ArtifactConfig] = {}
    for name, block in _mapping(raw.get("artifacts"), f"{source}: artifacts").items():
        label = f"{source}: artifacts.{name}"
        mapping = _mapping(block, label)
        _reject_unknown(mapping, ARTIFACT_KEYS, label)
        artifacts[str(name)] = ArtifactConfig(
            sbom=_optional_string(mapping, "sbom", label),
            source=_optional_string(mapping, "source", label),
            image=_optional_string(mapping, "image", label),
            manifest=_optional_string(mapping, "manifest", label),
        )

    evidence_block = _mapping(raw.get("evidence"), f"{source}: evidence")
    _reject_unknown(evidence_block, EVIDENCE_KEYS, f"{source}: evidence")
    evidence = {
        str(key): _string_list(value, f"{source}: evidence.{key}")
        for key, value in evidence_block.items()
    }

    iac_block = _mapping(raw.get("iac"), f"{source}: iac")
    _reject_unknown(iac_block, IAC_KEYS, f"{source}: iac")
    iac: dict[str, str] = {}
    for key in iac_block:
        value = _optional_string(iac_block, key, f"{source}: iac")
        if value is not None:
            iac[str(key)] = value

    return ReachabilityConfig(
        version=int(version),
        artifacts=artifacts,
        evidence=evidence,
        iac=iac,
        gate=_gate(raw.get("gate"), source),
        output=_output(raw.get("output"), source),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_config_schema -v`
Expected: PASS, 7 tests

- [ ] **Step 5: Commit**

```bash
.venv/bin/python -m ruff check src tests scripts && PYTHONPATH=src .venv/bin/python -m mypy src
git add src/reachability_advisor/config_schema.py tests/test_config_schema.py
git commit -m "feat: add strict schema validation for .reachability.yml"
```

---

### Task 4: Config discovery, `extends` layering and precedence

**Files:**
- Create: `src/reachability_advisor/config.py`
- Create: `tests/test_config.py`

**Interfaces:**
- Consumes: `yaml_loader.load_yaml_mapping`, `yaml_loader.YamlError`, `config_schema.validate_config`, `config_schema.ConfigError`, `config_schema.ReachabilityConfig`
- Produces: `MAX_EXTENDS_DEPTH: int`, `CONFIG_FILENAME: str`, `discover_config_path(start: Path) -> Path | None`, `merge_layers(layers: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]`, `resolve_layers(path: Path) -> list[tuple[str, dict[str, Any]]]`, `load_config(path: str | Path | None, start: Path | None = None) -> LoadedConfig`, `LoadedConfig` dataclass with `.config: ReachabilityConfig`, `.provenance: dict[str, str]`, `.path: Path | None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reachability_advisor.config import (
    CONFIG_FILENAME,
    discover_config_path,
    load_config,
    merge_layers,
)
from reachability_advisor.config_schema import ConfigError


def _tree(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


BASE = "version: 1\ngate:\n  fail_on: high\n  profile: production\n"


class MergeLayersTests(unittest.TestCase):
    def test_maps_deep_merge_and_scalars_override(self) -> None:
        merged = merge_layers([
            ("org", {"gate": {"fail_on": "high", "profile": "production"}}),
            ("repo", {"gate": {"fail_on": "low"}}),
        ])
        self.assertEqual(merged["gate"], {"fail_on": "low", "profile": "production"})

    def test_lists_replace_rather_than_append(self) -> None:
        # Appending would make it impossible for a repo to remove an inherited entry.
        merged = merge_layers([
            ("org", {"evidence": {"sast": ["org.json"]}}),
            ("repo", {"evidence": {"sast": ["repo.json"]}}),
        ])
        self.assertEqual(merged["evidence"]["sast"], ["repo.json"])


class DiscoveryTests(unittest.TestCase):
    def test_walks_up_to_the_git_root_and_no_further(self) -> None:
        root = _tree({CONFIG_FILENAME: BASE, ".git/HEAD": "ref: refs/heads/main\n",
                      "services/api/.keep": ""})
        self.assertEqual(discover_config_path(root / "services" / "api"), root / CONFIG_FILENAME)

    def test_returns_none_when_no_config_exists(self) -> None:
        root = _tree({".git/HEAD": "ref: refs/heads/main\n"})
        self.assertIsNone(discover_config_path(root))


class ExtendsTests(unittest.TestCase):
    def test_extends_a_relative_path_and_repo_wins(self) -> None:
        root = _tree({
            "shared/base.yml": BASE,
            CONFIG_FILENAME: "version: 1\nextends: ./shared/base.yml\ngate:\n  fail_on: medium\n",
        })
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertEqual(loaded.config.gate.fail_on, "medium")
        self.assertEqual(loaded.config.gate.profile, "production")  # inherited

    def test_records_which_layer_set_each_value(self) -> None:
        root = _tree({
            "shared/base.yml": BASE,
            CONFIG_FILENAME: "version: 1\nextends: ./shared/base.yml\ngate:\n  fail_on: medium\n",
        })
        loaded = load_config(root / CONFIG_FILENAME)
        self.assertIn("shared/base.yml", loaded.provenance["gate.profile"])
        self.assertIn(CONFIG_FILENAME, loaded.provenance["gate.fail_on"])

    def test_rejects_an_extends_cycle(self) -> None:
        root = _tree({
            "a.yml": "version: 1\nextends: ./b.yml\n",
            "b.yml": "version: 1\nextends: ./a.yml\n",
        })
        with self.assertRaises(ConfigError) as error:
            load_config(root / "a.yml")
        self.assertIn("cycle", str(error.exception).lower())

    def test_rejects_a_missing_extends_target(self) -> None:
        root = _tree({CONFIG_FILENAME: "version: 1\nextends: ./nope.yml\n"})
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("nope.yml", str(error.exception))

    def test_rejects_a_url_extends_target(self) -> None:
        # extends must never reach the network.
        root = _tree({CONFIG_FILENAME: "version: 1\nextends: https://example.test/base.yml\n"})
        with self.assertRaises(ConfigError) as error:
            load_config(root / CONFIG_FILENAME)
        self.assertIn("path or an installed package", str(error.exception))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_config -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'reachability_advisor.config'`

- [ ] **Step 3: Write the loader**

```python
# src/reachability_advisor/config.py
"""Discovery, layering and resolution for .reachability.yml."""

from __future__ import annotations

import importlib.resources
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config_schema import ConfigError, ReachabilityConfig, validate_config
from .yaml_loader import YamlError, load_yaml_mapping

CONFIG_FILENAME = ".reachability.yml"
MAX_EXTENDS_DEPTH = 8
_URL_PREFIXES = ("http://", "https://", "git://", "ssh://", "ftp://")


@dataclass(frozen=True)
class LoadedConfig:
    config: ReachabilityConfig
    path: Path | None = None
    provenance: dict[str, str] = field(default_factory=dict)


def discover_config_path(start: Path) -> Path | None:
    """Find the nearest config, walking up no further than the git root.

    A config outside the repository is not reviewable in that repository's pull requests,
    so the search stops at the repo boundary rather than reaching into the home directory.
    """
    current = start.resolve()
    for directory in (current, *current.parents):
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        if (directory / ".git").exists():
            break
    return None


def _resolve_extends(target: str, source: Path) -> Path:
    if target.startswith(_URL_PREFIXES):
        raise ConfigError(
            f"{source}: extends {target!r} is not local. `extends` must name a relative path "
            "or an installed package; configuration is never fetched over the network."
        )
    if target.startswith((".", "/")) or target.endswith((".yml", ".yaml")):
        candidate = (source.parent / target).resolve()
        if not candidate.is_file():
            raise ConfigError(f"{source}: extends target {target!r} does not exist at {candidate}")
        return candidate
    try:
        package = importlib.resources.files(target)
    except (ModuleNotFoundError, TypeError):
        raise ConfigError(
            f"{source}: extends target {target!r} is not an installed package and not a path. "
            "Install the package that provides your organization baseline, or use a relative path."
        ) from None
    candidate = Path(str(package)) / CONFIG_FILENAME
    if not candidate.is_file():
        raise ConfigError(f"{source}: package {target!r} does not contain {CONFIG_FILENAME}")
    return candidate


def resolve_layers(path: Path) -> list[tuple[str, dict[str, Any]]]:
    """Return layers lowest-precedence first, following `extends` with cycle detection."""
    layers: list[tuple[str, dict[str, Any]]] = []
    seen: set[Path] = set()
    current: Path | None = path.resolve()
    while current is not None:
        if current in seen:
            raise ConfigError(f"{path}: extends cycle detected at {current}")
        if len(seen) >= MAX_EXTENDS_DEPTH:
            raise ConfigError(f"{path}: extends chain exceeds {MAX_EXTENDS_DEPTH} levels")
        seen.add(current)
        try:
            raw = load_yaml_mapping(current, "configuration")
        except YamlError as exc:
            raise ConfigError(str(exc)) from None
        layers.append((str(current), raw))
        target = raw.get("extends")
        if target is None:
            current = None
            continue
        if not isinstance(target, str) or not target.strip():
            raise ConfigError(f"{current}: 'extends' must be a non-empty string")
        current = _resolve_extends(target.strip(), current)
    layers.reverse()
    return layers


def merge_layers(layers: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for _, raw in layers:
        _merge_into(merged, raw)
    merged.pop("extends", None)
    return merged


def _merge_into(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _merge_into(target[key], value)
        else:
            # Lists replace: appending would make removing an inherited entry impossible.
            target[key] = value


def _provenance(layers: list[tuple[str, dict[str, Any]]]) -> dict[str, str]:
    trail: dict[str, str] = {}
    for name, raw in layers:
        for dotted in _flatten(raw):
            trail[dotted] = name
    return trail


def _flatten(block: dict[str, Any], prefix: str = "") -> list[str]:
    keys: list[str] = []
    for key, value in block.items():
        if key == "extends":
            continue
        dotted = f"{prefix}{key}"
        if isinstance(value, dict):
            keys.extend(_flatten(value, f"{dotted}."))
        else:
            keys.append(dotted)
    return keys


def load_config(path: str | Path | None, start: Path | None = None) -> LoadedConfig:
    """Load and validate configuration, or return defaults when none exists."""
    if path is None:
        found = discover_config_path(start or Path.cwd())
        if found is None:
            return LoadedConfig(config=validate_config({"version": 1}, "defaults"))
        path = found
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"{config_path}: configuration file does not exist")
    layers = resolve_layers(config_path)
    merged = merge_layers(layers)
    return LoadedConfig(
        config=validate_config(merged, str(config_path)),
        path=config_path,
        provenance=_provenance(layers),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_config -v`
Expected: PASS, 9 tests

- [ ] **Step 5: Commit**

```bash
.venv/bin/python -m ruff check src tests scripts && PYTHONPATH=src .venv/bin/python -m mypy src
git add src/reachability_advisor/config.py tests/test_config.py
git commit -m "feat: resolve layered .reachability.yml with offline extends"
```

---

### Task 5: Wire config into `scan`, and add `config explain`

**Files:**
- Modify: `src/reachability_advisor/cli_parser.py` (add `--config` to `scan`; add the `config` subcommand)
- Modify: `src/reachability_advisor/cli.py` (apply config as argparse defaults; add `cmd_config`)
- Create: `tests/test_config_cli.py`

**Interfaces:**
- Consumes: `config.load_config`, `config.LoadedConfig`, `config_schema.ReachabilityConfig`
- Produces: `cli.apply_config_defaults(args: argparse.Namespace, loaded: LoadedConfig) -> argparse.Namespace`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config_cli.py
from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from reachability_advisor.cli import main

CONFIG = """version: 1
artifacts:
  demo-api:
    sbom: samples/sboms/audit-api.cdx.json
gate:
  fail_on: medium
  profile: production
"""


class ConfigExplainTests(unittest.TestCase):
    def test_explain_prints_each_value_and_its_layer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text(CONFIG, encoding="utf-8")
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["config", "explain", "--config", str(path)])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("gate.fail_on", output)
        self.assertIn("medium", output)
        self.assertIn(str(path), output)

    def test_explain_reports_a_malformed_config_and_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text("version: 1\ngate:\n  fial_on: high\n", encoding="utf-8")
            code = main(["config", "explain", "--config", str(path)])
        self.assertEqual(code, 2)


class ScanUsesConfigTests(unittest.TestCase):
    def test_a_cli_flag_overrides_the_config_value(self) -> None:
        from argparse import Namespace

        from reachability_advisor.cli import apply_config_defaults
        from reachability_advisor.config import load_config

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".reachability.yml"
            path.write_text(CONFIG, encoding="utf-8")
            loaded = load_config(path)

        explicit = Namespace(fail_on_tier="urgent", sbom=[], _explicit={"fail_on_tier"})
        self.assertEqual(apply_config_defaults(explicit, loaded).fail_on_tier, "urgent")

        implicit = Namespace(fail_on_tier=None, sbom=[], _explicit=set())
        self.assertEqual(apply_config_defaults(implicit, loaded).fail_on_tier, "medium")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_config_cli -v`
Expected: FAIL — `invalid choice: 'config'`

- [ ] **Step 3: Add the parser entries**

In `cli_parser.py`, add `--config` to the `scan` parser:

```python
    scan.add_argument(
        "--config",
        help=f"Path to {CONFIG_FILENAME}. Defaults to the nearest one up to the git root.",
    )
```

Import `CONFIG_FILENAME` from `.config` at the top of the module, and register the new command:

```python
    config_cmd = subparsers.add_parser("config", help="Inspect resolved configuration.")
    config_sub = config_cmd.add_subparsers(dest="config_command", required=True)
    explain = config_sub.add_parser("explain", help="Print each resolved value and its source layer.")
    explain.add_argument("--config", help=f"Path to {CONFIG_FILENAME}.")
    validate_cmd = config_sub.add_parser("validate", help="Validate configuration and exit.")
    validate_cmd.add_argument("--config", help=f"Path to {CONFIG_FILENAME}.")
```

- [ ] **Step 4: Apply config as argparse defaults**

In `cli.py`, add:

```python
def apply_config_defaults(args: argparse.Namespace, loaded: LoadedConfig) -> argparse.Namespace:
    """Fill unset arguments from configuration. An explicitly passed flag always wins."""
    explicit = getattr(args, "_explicit", set())
    config = loaded.config

    def fill(attribute: str, value: Any) -> None:
        if attribute in explicit or value in (None, (), []):
            return
        current = getattr(args, attribute, None)
        if current in (None, [], ()):
            setattr(args, attribute, value)

    fill("fail_on_tier", config.gate.fail_on)
    fill("analysis_profile", config.gate.profile)
    fill("sbom", [item.sbom for item in config.artifacts.values() if item.sbom])
    fill("source_root", [f"{name}={item.source}" for name, item in config.artifacts.items() if item.source])
    fill("artifact_alias", [f"{name}={item.image}" for name, item in config.artifacts.items() if item.image])
    fill("vuln_in", list(config.evidence.get("vulnerabilities", ())))
    fill("sast_in", list(config.evidence.get("sast", ())))
    fill("dast_in", list(config.evidence.get("dast", ())))
    fill("cspm_in", list(config.evidence.get("cspm", ())))
    fill("terraform_plan", config.iac.get("terraform"))
    fill("terraform_source", config.iac.get("terraform_source"))
    fill("kubernetes_manifest", config.iac.get("kubernetes"))
    return args
```

Record which flags were passed explicitly. In `main`, immediately after parsing:

```python
    args._explicit = {
        action.dest
        for action in parser._actions
        if action.dest != "help" and any(option in argv for option in action.option_strings)
    }
```

Then, in the `scan` branch before the scan runs:

```python
    loaded = load_config(getattr(args, "config", None))
    args = apply_config_defaults(args, loaded)
```

Add `cmd_config`:

```python
def cmd_config(args: argparse.Namespace) -> int:
    loaded = load_config(getattr(args, "config", None))
    if args.config_command == "validate":
        print(f"Configuration valid: {loaded.path or 'defaults (no config file found)'}")
        return 0
    width = max((len(key) for key in loaded.provenance), default=20)
    for key in sorted(loaded.provenance):
        print(f"{key.ljust(width)}  <- {loaded.provenance[key]}")
    if not loaded.provenance:
        print("No configuration file found; built-in defaults are in effect.")
    return 0
```

Register `"config": cmd_config` in the existing command dispatch table, and confirm the
top-level handler already maps `ValueError` to exit code 2 — `ConfigError` and `YamlError`
both subclass it.

- [ ] **Step 5: Run test to verify it passes**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_config_cli -v`
Expected: PASS, 3 tests

- [ ] **Step 6: Verify a real scan runs with no flags**

```bash
cd /tmp && mkdir -p cfgdemo && cd cfgdemo
cat > .reachability.yml <<'YAML'
version: 1
artifacts:
  audit-api:
    sbom: SAMPLES/sboms/audit-api.cdx.json
evidence:
  vulnerabilities: [SAMPLES/vulnerabilities.json]
YAML
sed -i "s|SAMPLES|/home/roland/Dev/reachabilty-advisor/samples|g" .reachability.yml
PYTHONPATH=/home/roland/Dev/reachabilty-advisor/src \
  /home/roland/Dev/reachabilty-advisor/.venv/bin/python -m reachability_advisor scan --no-table
```
Expected: a scan completes using only the config; no `--sbom` or `--vuln-in` passed.

- [ ] **Step 7: Commit**

```bash
cd /home/roland/Dev/reachabilty-advisor
.venv/bin/python -m ruff check src tests scripts && PYTHONPATH=src .venv/bin/python -m mypy src
PYTHONPATH=src .venv/bin/python scripts/run_tests.py
git add src/reachability_advisor/cli.py src/reachability_advisor/cli_parser.py tests/test_config_cli.py
git commit -m "feat: read scan options from .reachability.yml with flags overriding"
```

---

### Task 6: Repo detection

**Files:**
- Create: `src/reachability_advisor/config_detect.py`
- Create: `tests/test_config_detect.py`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces: `DetectedArtifact` dataclass (`name: str`, `sbom: str | None`, `source: str | None`, `image: str | None`, `ecosystem: str | None`), `Detection` dataclass (`artifacts: list[DetectedArtifact]`, `vulnerabilities: list[str]`, `terraform: str | None`, `terraform_source: str | None`, `kubernetes: str | None`, `notes: list[str]`), `detect_repo(root: Path) -> Detection`, `SBOM_COMMANDS: dict[str, str]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config_detect.py
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reachability_advisor.config_detect import detect_repo


def _tree(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


class DetectRepoTests(unittest.TestCase):
    def test_detects_an_existing_cyclonedx_sbom(self) -> None:
        root = _tree({"sboms/api.cdx.json": '{"bomFormat":"CycloneDX","components":[]}'})
        detection = detect_repo(root)
        self.assertEqual([item.sbom for item in detection.artifacts], ["sboms/api.cdx.json"])

    def test_detects_an_ecosystem_from_a_lockfile_and_names_the_sbom_command(self) -> None:
        root = _tree({"services/api/package-lock.json": "{}"})
        detection = detect_repo(root)
        artifact = detection.artifacts[0]
        self.assertEqual(artifact.source, "services/api")
        self.assertEqual(artifact.ecosystem, "npm")
        self.assertIsNone(artifact.sbom)
        self.assertTrue(any("syft" in note for note in detection.notes))

    def test_detects_terraform_and_kubernetes(self) -> None:
        root = _tree({
            "infra/main.tf": 'resource "aws_instance" "a" {}\n',
            "k8s/deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\n",
        })
        detection = detect_repo(root)
        self.assertEqual(detection.terraform_source, "infra")
        self.assertEqual(detection.kubernetes, "k8s")

    def test_does_not_invent_paths_that_do_not_exist(self) -> None:
        detection = detect_repo(_tree({"README.md": "# empty\n"}))
        self.assertEqual(detection.artifacts, [])
        self.assertIsNone(detection.terraform)
        self.assertIsNone(detection.kubernetes)

    def test_ignores_vendor_and_dependency_directories(self) -> None:
        root = _tree({"node_modules/pkg/package-lock.json": "{}", "app/package-lock.json": "{}"})
        detection = detect_repo(root)
        self.assertEqual([item.source for item in detection.artifacts], ["app"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_config_detect -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'reachability_advisor.config_detect'`

- [ ] **Step 3: Write the detector**

```python
# src/reachability_advisor/config_detect.py
"""Detect what evidence a repository already has, for `init` and `doctor`."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRECTORIES = frozenset({
    ".git", ".venv", "venv", "node_modules", "vendor", "__pycache__", "dist", "build",
    ".mypy_cache", ".ruff_cache", ".tox", "target", "outputs",
})

LOCKFILE_ECOSYSTEMS: dict[str, str] = {
    "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "poetry.lock": "python", "requirements.txt": "python", "Pipfile.lock": "python",
    "go.sum": "go", "Cargo.lock": "rust", "Gemfile.lock": "ruby", "pom.xml": "java",
    "build.gradle": "java", "composer.lock": "php",
}

SBOM_COMMANDS: dict[str, str] = {
    "npm": "syft dir:{path} -o cyclonedx-json > {out}",
    "python": "syft dir:{path} -o cyclonedx-json > {out}",
    "go": "syft dir:{path} -o cyclonedx-json > {out}",
    "rust": "syft dir:{path} -o cyclonedx-json > {out}",
    "ruby": "syft dir:{path} -o cyclonedx-json > {out}",
    "java": "syft dir:{path} -o cyclonedx-json > {out}",
    "php": "syft dir:{path} -o cyclonedx-json > {out}",
}

SBOM_SUFFIXES = (".cdx.json", ".spdx.json")


@dataclass(frozen=True)
class DetectedArtifact:
    name: str
    sbom: str | None = None
    source: str | None = None
    image: str | None = None
    ecosystem: str | None = None


@dataclass
class Detection:
    artifacts: list[DetectedArtifact] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    terraform: str | None = None
    terraform_source: str | None = None
    kubernetes: str | None = None
    notes: list[str] = field(default_factory=list)


def _walk(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRECTORIES for part in path.relative_to(root).parts):
            continue
        if path.is_file():
            found.append(path)
    return found


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def detect_repo(root: Path) -> Detection:
    """Inspect a repository and report only what is actually present."""
    root = root.resolve()
    detection = Detection()
    files = _walk(root)

    sboms = [path for path in files if path.name.endswith(SBOM_SUFFIXES)]
    for path in sorted(sboms):
        name = path.name.split(".")[0]
        detection.artifacts.append(DetectedArtifact(name=name, sbom=_relative(path, root)))

    claimed = {item.name for item in detection.artifacts}
    for path in sorted(files):
        ecosystem = LOCKFILE_ECOSYSTEMS.get(path.name)
        if ecosystem is None:
            continue
        source_dir = path.parent
        name = source_dir.name if source_dir != root else root.name
        if name in claimed:
            continue
        claimed.add(name)
        detection.artifacts.append(
            DetectedArtifact(name=name, source=_relative(source_dir, root), ecosystem=ecosystem)
        )
        command = SBOM_COMMANDS.get(ecosystem, SBOM_COMMANDS["python"])
        detection.notes.append(
            f"{name}: no SBOM found. Generate one with: "
            + command.format(path=_relative(source_dir, root), out=f"sboms/{name}.cdx.json")
        )

    terraform_files = [path for path in files if path.suffix == ".tf"]
    if terraform_files:
        detection.terraform_source = _relative(sorted(terraform_files)[0].parent, root)
        detection.notes.append(
            "Terraform source found. A plan gives far better exposure evidence: "
            "terraform show -json plan.tfout > tf-plan.json"
        )

    for path in sorted(files):
        if path.suffix in {".yaml", ".yml"} and path.parent != root:
            head = path.read_text(encoding="utf-8", errors="ignore")[:400]
            if "kind:" in head and "apiVersion:" in head:
                detection.kubernetes = _relative(path.parent, root)
                break

    for path in sorted(files):
        if path.name in {"grype.json", "trivy.json", "osv.json", "vulnerabilities.json"}:
            detection.vulnerabilities.append(_relative(path, root))
    if not detection.vulnerabilities:
        detection.notes.append(
            "No vulnerability report found. Generate one with: "
            "grype sbom:sboms/<artifact>.cdx.json -o json > grype.json"
        )
    return detection
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_config_detect -v`
Expected: PASS, 5 tests

- [ ] **Step 5: Commit**

```bash
.venv/bin/python -m ruff check src tests scripts && PYTHONPATH=src .venv/bin/python -m mypy src
git add src/reachability_advisor/config_detect.py tests/test_config_detect.py
git commit -m "feat: detect repository evidence for config scaffolding"
```

---

### Task 7: The `init` command

**Files:**
- Modify: `src/reachability_advisor/cli_parser.py` (register `init`)
- Modify: `src/reachability_advisor/cli.py` (add `cmd_init`)
- Create: `src/reachability_advisor/config_render.py`
- Create: `tests/test_config_init.py`

**Interfaces:**
- Consumes: `config_detect.detect_repo`, `config_detect.Detection`, `config.CONFIG_FILENAME`
- Produces: `config_render.render_config(detection: Detection) -> str`, `cli.cmd_init(args) -> int`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config_init.py
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.config import CONFIG_FILENAME, load_config


def _repo(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


class InitTests(unittest.TestCase):
    def test_writes_a_config_that_loads_back(self) -> None:
        root = _repo({"sboms/api.cdx.json": '{"bomFormat":"CycloneDX","components":[]}'})
        self.assertEqual(main(["init", "--root", str(root)]), 0)
        written = root / CONFIG_FILENAME
        self.assertTrue(written.is_file())
        loaded = load_config(written)
        self.assertIn("api", loaded.config.artifacts)

    def test_records_missing_evidence_as_todo_comments(self) -> None:
        root = _repo({"app/package-lock.json": "{}"})
        main(["init", "--root", str(root)])
        text = (root / CONFIG_FILENAME).read_text(encoding="utf-8")
        self.assertIn("# TODO", text)
        self.assertIn("syft", text)

    def test_refuses_to_overwrite_an_existing_config(self) -> None:
        root = _repo({CONFIG_FILENAME: "version: 1\n"})
        self.assertEqual(main(["init", "--root", str(root)]), 2)
        self.assertEqual((root / CONFIG_FILENAME).read_text(encoding="utf-8"), "version: 1\n")

    def test_refresh_writes_a_side_file_instead_of_overwriting(self) -> None:
        root = _repo({
            CONFIG_FILENAME: "version: 1\n# keep this comment\n",
            "sboms/api.cdx.json": "{}",
        })
        self.assertEqual(main(["init", "--root", str(root), "--refresh"]), 0)
        self.assertIn("# keep this comment", (root / CONFIG_FILENAME).read_text(encoding="utf-8"))
        self.assertTrue((root / ".reachability.detected.yml").is_file())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_config_init -v`
Expected: FAIL — `invalid choice: 'init'`

- [ ] **Step 3: Write the renderer**

```python
# src/reachability_advisor/config_render.py
"""Render a detected repository into a commented .reachability.yml."""

from __future__ import annotations

from .config_detect import Detection

HEADER = """# Reachability Advisor configuration.
# Written by `reachability-advisor init` from what was found in this repository.
# Values here are defaults; any CLI flag overrides them.
# Run `reachability-advisor doctor` to see what is still missing.
"""


def render_config(detection: Detection) -> str:
    lines = [HEADER, "version: 1", ""]

    if detection.notes:
        lines.append("# TODO: this repository is not fully covered yet.")
        lines.extend(f"# TODO: {note}" for note in detection.notes)
        lines.append("")

    lines.append("artifacts:")
    if not detection.artifacts:
        lines.append("  # TODO: no artifacts detected. Add one, for example:")
        lines.append("  #   my-service:")
        lines.append("  #     sbom: sboms/my-service.cdx.json")
        lines.append("  #     source: src/my-service")
    for artifact in detection.artifacts:
        lines.append(f"  {artifact.name}:")
        if artifact.sbom:
            lines.append(f"    sbom: {artifact.sbom}")
        else:
            lines.append(f"    # TODO: no SBOM found for {artifact.name}")
        if artifact.source:
            lines.append(f"    source: {artifact.source}")
        if artifact.image:
            lines.append(f"    image: {artifact.image}")
    lines.append("")

    lines.append("evidence:")
    if detection.vulnerabilities:
        joined = ", ".join(detection.vulnerabilities)
        lines.append(f"  vulnerabilities: [{joined}]")
    else:
        lines.append("  # TODO: no vulnerability report found.")
        lines.append("  vulnerabilities: []")
    lines.append("")

    if detection.terraform or detection.terraform_source or detection.kubernetes:
        lines.append("iac:")
        if detection.terraform:
            lines.append(f"  terraform: {detection.terraform}")
        if detection.terraform_source:
            lines.append(f"  terraform_source: {detection.terraform_source}")
        if detection.kubernetes:
            lines.append(f"  kubernetes: {detection.kubernetes}")
        lines.append("")

    lines.append("gate:")
    lines.append("  profile: advisory   # switch to `production` once doctor reports ready")
    lines.append("  fail_on: high")
    lines.append("")
    return "\n".join(lines)
```

- [ ] **Step 4: Wire the command**

In `cli_parser.py`:

```python
    init = subparsers.add_parser("init", help=f"Detect repository evidence and write {CONFIG_FILENAME}.")
    init.add_argument("--root", default=".", help="Repository root to inspect. Defaults to the working directory.")
    init.add_argument("--refresh", action="store_true",
                      help="Write newly detected values to .reachability.detected.yml instead of failing.")
```

In `cli.py`:

```python
def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    if not root.is_dir():
        raise ValueError(f"{root}: --root is not a directory")
    target = root / CONFIG_FILENAME
    rendered = render_config(detect_repo(root))

    if target.exists() and not args.refresh:
        # PyYAML does not round-trip comments, so rewriting in place would silently strip
        # every comment justifying a gate. Refuse rather than destroy the user's work.
        raise ValueError(
            f"{target} already exists. `init` never rewrites it, because doing so would drop "
            "your comments. Re-run with --refresh to write .reachability.detected.yml instead."
        )
    if target.exists():
        side = root / ".reachability.detected.yml"
        side.write_text(rendered, encoding="utf-8")
        print(f"Wrote {side}. Merge anything you want into {target} by hand.")
        return 0

    target.write_text(rendered, encoding="utf-8")
    print(f"Wrote {target}")
    print("Next: reachability-advisor doctor")
    return 0
```

Register `"init": cmd_init` in the dispatch table, and import `CONFIG_FILENAME`,
`detect_repo` and `render_config`.

- [ ] **Step 5: Run test to verify it passes**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_config_init -v`
Expected: PASS, 4 tests

- [ ] **Step 6: Commit**

```bash
.venv/bin/python -m ruff check src tests scripts && PYTHONPATH=src .venv/bin/python -m mypy src
git add src/reachability_advisor/config_render.py src/reachability_advisor/cli.py src/reachability_advisor/cli_parser.py tests/test_config_init.py
git commit -m "feat: add init command that scaffolds .reachability.yml from repo detection"
```

---

### Task 8: The `doctor` command

**Files:**
- Create: `src/reachability_advisor/doctor.py`
- Create: `tests/test_doctor.py`
- Modify: `src/reachability_advisor/cli_parser.py`, `src/reachability_advisor/cli.py`
- Modify: `docs/quickstart.md`, `README.md`, `action.yml`

**Interfaces:**
- Consumes: `config.load_config`, `config.LoadedConfig`, `config_detect.detect_repo`
- Produces: `Readiness` dataclass (`ready: bool`, `artifacts: list[ArtifactReadiness]`, `blockers: list[str]`, `next_actions: list[str]`), `ArtifactReadiness` dataclass (`name: str`, `present: dict[str, bool]`, `missing: list[str]`), `diagnose(loaded: LoadedConfig, root: Path) -> Readiness`, `render_text(readiness: Readiness) -> str`, `readiness_to_dict(readiness: Readiness) -> dict[str, Any]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_doctor.py
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reachability_advisor.cli import main
from reachability_advisor.config import CONFIG_FILENAME, load_config
from reachability_advisor.doctor import diagnose, render_text


def _repo(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


COMPLETE = """version: 1
artifacts:
  api:
    sbom: sboms/api.cdx.json
    source: src/api
evidence:
  vulnerabilities: [grype.json]
gate:
  profile: advisory
  fail_on: high
"""


class DiagnoseTests(unittest.TestCase):
    def test_reports_a_missing_sbom_file_as_a_blocker(self) -> None:
        root = _repo({CONFIG_FILENAME: COMPLETE, "grype.json": "{}"})
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertFalse(readiness.ready)
        self.assertTrue(any("sboms/api.cdx.json" in item for item in readiness.blockers))

    def test_names_the_exact_command_for_missing_evidence(self) -> None:
        root = _repo({CONFIG_FILENAME: COMPLETE, "sboms/api.cdx.json": "{}"})
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertTrue(any("grype" in item for item in readiness.next_actions))

    def test_is_ready_when_every_declared_input_exists(self) -> None:
        root = _repo({CONFIG_FILENAME: COMPLETE, "sboms/api.cdx.json": "{}", "grype.json": "{}",
                      "src/api/.keep": ""})
        readiness = diagnose(load_config(root / CONFIG_FILENAME), root)
        self.assertTrue(readiness.ready, render_text(readiness))


class DoctorCommandTests(unittest.TestCase):
    def test_exits_non_zero_when_not_ready(self) -> None:
        root = _repo({CONFIG_FILENAME: COMPLETE})
        self.assertEqual(main(["doctor", "--config", str(root / CONFIG_FILENAME), "--root", str(root)]), 1)

    def test_exits_zero_and_emits_json_when_ready(self) -> None:
        root = _repo({CONFIG_FILENAME: COMPLETE, "sboms/api.cdx.json": "{}", "grype.json": "{}",
                      "src/api/.keep": ""})
        out = root / "readiness.json"
        code = main(["doctor", "--config", str(root / CONFIG_FILENAME), "--root", str(root),
                     "--json", str(out)])
        self.assertEqual(code, 0)
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertTrue(payload["ready"])
        self.assertIn("artifacts", payload)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_doctor -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'reachability_advisor.doctor'`

- [ ] **Step 3: Write the diagnosis**

```python
# src/reachability_advisor/doctor.py
"""Report what evidence is present, what is missing, and the command that produces it."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import LoadedConfig

GRYPE_COMMAND = "grype sbom:{sbom} -o json > {out}"
SYFT_COMMAND = "syft dir:{path} -o cyclonedx-json > {out}"
TERRAFORM_COMMAND = "terraform show -json plan.tfout > {out}"


@dataclass(frozen=True)
class ArtifactReadiness:
    name: str
    present: dict[str, bool] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)


@dataclass
class Readiness:
    ready: bool = False
    artifacts: list[ArtifactReadiness] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)


def diagnose(loaded: LoadedConfig, root: Path) -> Readiness:
    """Check every declared input actually exists on disk."""
    readiness = Readiness()
    config = loaded.config
    root = root.resolve()

    if not config.artifacts:
        readiness.blockers.append("No artifacts declared. Run `reachability-advisor init`.")

    for name, artifact in sorted(config.artifacts.items()):
        present: dict[str, bool] = {}
        missing: list[str] = []
        for label, value in (("sbom", artifact.sbom), ("source", artifact.source)):
            if value is None:
                present[label] = False
                missing.append(label)
                continue
            exists = (root / value).exists()
            present[label] = exists
            if not exists:
                missing.append(label)
                readiness.blockers.append(f"{name}: declared {label} {value!r} does not exist")
        if artifact.sbom is None:
            readiness.next_actions.append(
                f"{name}: " + SYFT_COMMAND.format(
                    path=artifact.source or ".", out=f"sboms/{name}.cdx.json"
                )
            )
        readiness.artifacts.append(ArtifactReadiness(name=name, present=present, missing=missing))

    vulnerabilities = config.evidence.get("vulnerabilities", ())
    if not vulnerabilities:
        readiness.blockers.append("No vulnerability report declared under evidence.vulnerabilities")
        first = next(iter(sorted(config.artifacts)), None)
        sbom = config.artifacts[first].sbom if first else "sboms/<artifact>.cdx.json"
        readiness.next_actions.append(
            GRYPE_COMMAND.format(sbom=sbom or "sboms/<artifact>.cdx.json", out="grype.json")
        )
    for item in vulnerabilities:
        if not (root / item).exists():
            readiness.blockers.append(f"declared vulnerability report {item!r} does not exist")
            readiness.next_actions.append(GRYPE_COMMAND.format(sbom="sboms/<artifact>.cdx.json", out=item))

    terraform = config.iac.get("terraform")
    if terraform and not (root / terraform).exists():
        readiness.blockers.append(f"declared Terraform plan {terraform!r} does not exist")
        readiness.next_actions.append(TERRAFORM_COMMAND.format(out=terraform))

    if config.gate.profile == "production" and readiness.blockers:
        readiness.blockers.append(
            "gate.profile is `production`, which requires complete evidence. "
            "Resolve the items above or set `profile: advisory` while onboarding."
        )

    readiness.ready = not readiness.blockers
    return readiness


def render_text(readiness: Readiness) -> str:
    lines: list[str] = []
    for artifact in readiness.artifacts:
        marks = "  ".join(
            f"{label} {'ok' if ok else 'missing'}" for label, ok in sorted(artifact.present.items())
        )
        lines.append(f"{artifact.name}    {marks}")
    if readiness.blockers:
        lines.append("")
        lines.append("Blockers:")
        lines.extend(f"  - {item}" for item in readiness.blockers)
    if readiness.next_actions:
        lines.append("")
        lines.append("Next:")
        lines.extend(f"  {item}" for item in readiness.next_actions)
    lines.append("")
    lines.append("gate: ready" if readiness.ready else "gate: not ready")
    return "\n".join(lines)


def readiness_to_dict(readiness: Readiness) -> dict[str, Any]:
    return {
        "ready": readiness.ready,
        "artifacts": [
            {"name": item.name, "present": item.present, "missing": item.missing}
            for item in readiness.artifacts
        ],
        "blockers": list(readiness.blockers),
        "next_actions": list(readiness.next_actions),
    }
```

- [ ] **Step 4: Wire the command**

In `cli_parser.py`:

```python
    doctor = subparsers.add_parser(
        "doctor", help="Report missing evidence and the exact command that produces it."
    )
    doctor.add_argument("--config", help=f"Path to {CONFIG_FILENAME}.")
    doctor.add_argument("--root", default=".", help="Repository root. Defaults to the working directory.")
    doctor.add_argument("--json", dest="json_out", help="Write the readiness report as JSON to this path.")
```

In `cli.py`:

```python
def cmd_doctor(args: argparse.Namespace) -> int:
    loaded = load_config(getattr(args, "config", None))
    readiness = diagnose(loaded, Path(args.root))
    print(render_text(readiness))
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(readiness_to_dict(readiness), indent=2) + "\n", encoding="utf-8")
    return 0 if readiness.ready else 1
```

Register `"doctor": cmd_doctor` in the dispatch table.

- [ ] **Step 5: Run test to verify it passes**

Run: `PYTHONPATH=src .venv/bin/python -m unittest tests.test_doctor -v`
Expected: PASS, 5 tests

- [ ] **Step 6: Document the three-command flow**

Replace the "Common Workflows" opening of `docs/quickstart.md` with:

````markdown
## Set Up Your Own Repository

Three commands, in order:

```bash
reachability-advisor init      # writes .reachability.yml from what is in the repo
reachability-advisor doctor    # what is missing, and the command that produces it
reachability-advisor scan      # no flags; reads the config
```

`init` only declares what it finds, and marks everything else with `# TODO`. `doctor` is
re-runnable: work through its output until it reports `gate: ready`. It exits non-zero until
then, so CI can use it directly, and `--json` gives a machine-readable report for tracking
onboarding across many repositories.

Configuration layers, lowest precedence first: built-in defaults, an organization baseline via
`extends:`, the repository's `.reachability.yml`, then any CLI flag. `reachability-advisor
config explain` prints each resolved value and the layer that set it.
````

Add a `config` input to `action.yml` alongside the existing inputs:

```yaml
  config:
    description: "Path to .reachability.yml. When set, other inputs override individual values."
    required: false
```

- [ ] **Step 7: Verify the whole flow end to end**

```bash
cd /tmp && rm -rf flowtest && mkdir flowtest && cd flowtest
cp -r /home/roland/Dev/reachabilty-advisor/samples/sboms .
RA="PYTHONPATH=/home/roland/Dev/reachabilty-advisor/src /home/roland/Dev/reachabilty-advisor/.venv/bin/python -m reachability_advisor"
eval "$RA init"        # expect: writes .reachability.yml, prints "Next: ... doctor"
eval "$RA doctor"      # expect: exit 1, names the grype command
eval "$RA config explain"
```

- [ ] **Step 8: Run every gate on all four interpreters and commit**

```bash
cd /home/roland/Dev/reachabilty-advisor
.venv/bin/python -m ruff check src tests scripts
PYTHONPATH=src .venv/bin/python -m mypy src
for V in 3.10 3.11 3.12 3.13; do
  .venv/bin/uv venv --python $V /tmp/v$V >/dev/null 2>&1
  /tmp/v$V/bin/python -m pip install -q -e ".[dev]" 2>/dev/null
  echo -n "$V: "; PYTHONPATH=src /tmp/v$V/bin/python scripts/run_tests.py 2>&1 | tail -2 | head -1
done
PYTHON=.venv/bin/python make quality
git add -A
git commit -m "feat: add doctor command and document the init/doctor/scan flow"
```

---

## Self-Review

**Spec coverage.** Config format and precedence → Tasks 4, 5. `extends` offline resolution and
cycle detection → Task 4. Merge semantics (lists replace) → Task 4. Discovery stopping at the
git root → Task 4. `config explain` → Task 5. Schema → Task 3. `init` detection → Tasks 6, 7.
`init` never rewriting in place → Task 7. `doctor` with exit codes and `--json` → Task 8.
`safe_load` only, size/depth/node bounds, unknown-key rejection → Tasks 1, 3. PyYAML dependency
and doc honesty → Task 1. Kubernetes parser replacement → Task 2. Testing → every task.

**Deferred, as the spec states:** gate flag renaming, subcommand regrouping, gate locking.

**Type consistency.** `LoadedConfig.config/.path/.provenance` defined in Task 4 and consumed in
Tasks 5 and 8. `Detection`/`DetectedArtifact` defined in Task 6, consumed in Task 7
(`render_config`) and referenced in Task 8. `ConfigError` defined in Task 3 and raised in
Task 4. `YamlError` defined in Task 1 and caught in Tasks 2 and 4. `CONFIG_FILENAME` defined in
Task 4, used in Tasks 5, 7, 8.

**Known ordering constraint.** Task 5's `_explicit` set is computed from `argv` in `main`; the
`apply_config_defaults` tests construct it directly, so Task 5 must land before Task 8's
end-to-end check.
