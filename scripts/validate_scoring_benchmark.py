"""Validate the checked-in scoring benchmark corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from reachability_advisor.scoring_benchmark import run_scoring_benchmark  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate scoring benchmark expected tiers and score bands.")
    parser.add_argument("--benchmark", default=str(ROOT / "configs" / "scoring-benchmark.json"))
    parser.add_argument("--out")
    args = parser.parse_args(argv)

    report = run_scoring_benchmark(args.benchmark)
    text = json.dumps(report, indent=2)
    if args.out:
        output = Path(args.out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
