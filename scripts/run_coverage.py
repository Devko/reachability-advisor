from __future__ import annotations

import importlib
import importlib.util
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path


def coverage_preflight_error(
    *,
    platform: str = sys.platform,
    executable: str = sys.executable,
    import_module: Callable[[str], object] = importlib.import_module,
    find_spec: Callable[[str], object | None] = importlib.util.find_spec,
    path_exists: Callable[[Path], bool] = Path.exists,
) -> str | None:
    if platform == "win32":
        pth_file = Path(executable).with_name(
            f"python{sys.version_info.major}{sys.version_info.minor}._pth"
        )
        if path_exists(pth_file):
            return (
                "coverage requires a full Windows CPython runtime. "
                f"The detected interpreter is an embeddable Python runtime ({pth_file.name}), "
                "which is known to fail under coverage while importing unittest.mock/asyncio. "
                "Install Python 3.10+ from python.org or set PYTHON to a full interpreter, then run "
                "`python scripts/run_coverage.py`."
            )
        try:
            import_module("_overlapped")
        except ModuleNotFoundError:
            return (
                "coverage requires a full Windows CPython runtime with the _overlapped extension. "
                "The bundled embeddable Python in this workspace is missing that module. "
                "Install Python 3.10+ from python.org or set PYTHON to a full interpreter, then run "
                "`python scripts/run_coverage.py`."
            )
        try:
            import_module("unittest.mock")
        except (ImportError, ModuleNotFoundError, NameError) as exc:
            return (
                "coverage requires a Windows CPython runtime that can import unittest.mock cleanly. "
                f"This interpreter failed that preflight with {type(exc).__name__}: {exc}. "
                "Install Python 3.10+ from python.org or set PYTHON to a full interpreter, then run "
                "`python scripts/run_coverage.py`."
            )
    if find_spec("coverage") is None:
        return "coverage is not installed. Run `python -m pip install -e .[dev]` before the coverage gate."
    return None


def main() -> int:
    if error := coverage_preflight_error():
        print(f"Coverage preflight failed: {error}", file=sys.stderr)
        return 2
    run = [sys.executable, "-m", "coverage", "run", "--source=src/reachability_advisor", "scripts/run_tests.py"]
    report = [sys.executable, "-m", "coverage", "report", "-m", "--fail-under=93"]
    first = subprocess.run(run, check=False)
    if first.returncode:
        return first.returncode
    return subprocess.run(report, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
