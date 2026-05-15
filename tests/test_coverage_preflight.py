from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("run_coverage", ROOT / "scripts" / "run_coverage.py")
assert SPEC is not None and SPEC.loader is not None
run_coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_coverage)


class CoveragePreflightTests(unittest.TestCase):
    def test_windows_missing_overlapped_gets_actionable_error(self) -> None:
        def missing_module(name: str) -> object:
            raise ModuleNotFoundError(name)

        error = run_coverage.coverage_preflight_error(
            platform="win32",
            executable="C:/Python313/python.exe",
            import_module=missing_module,
            find_spec=lambda name: object(),
            path_exists=lambda path: False,
        )

        self.assertIsNotNone(error)
        self.assertIn("_overlapped", str(error))
        self.assertIn("full Windows CPython runtime", str(error))

    def test_windows_embeddable_python_gets_actionable_error(self) -> None:
        error = run_coverage.coverage_preflight_error(
            platform="win32",
            executable="C:/repo/.tools/python/python.exe",
            import_module=lambda name: object(),
            find_spec=lambda name: object(),
            path_exists=lambda path: True,
        )

        self.assertIsNotNone(error)
        self.assertIn("embeddable Python runtime", str(error))
        self.assertIn("full interpreter", str(error))

    def test_missing_coverage_gets_install_hint(self) -> None:
        error = run_coverage.coverage_preflight_error(
            platform="linux",
            import_module=lambda name: object(),
            find_spec=lambda name: None,
        )

        self.assertIsNotNone(error)
        self.assertIn("pip install -e", str(error))


if __name__ == "__main__":
    unittest.main()
