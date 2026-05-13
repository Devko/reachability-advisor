"""Validate real-app benchmark tier snapshots."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from reachability_advisor.benchmark_snapshots import validate_benchmark_snapshots  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate real-app benchmark tier distributions and over-prioritization limits.")
    parser.add_argument("--benchmark", default=str(ROOT / "outputs" / "external-complex" / "benchmark.json"))
    parser.add_argument("--expectations", default=str(ROOT / "fixtures" / "benchmarks" / "real-app-tier-snapshots.json"))
    parser.add_argument("--out")
    parser.add_argument("--warn-only", action="store_true")
    args = parser.parse_args(argv)

    report = validate_benchmark_snapshots(args.benchmark, args.expectations)
    text = json.dumps(report, indent=2)
    if args.out:
        output = Path(args.out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0 if args.warn_only or report["status"] == "passed" else 10


if __name__ == "__main__":
    raise SystemExit(main())
