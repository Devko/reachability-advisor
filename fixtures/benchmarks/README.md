# Benchmark Snapshots

This directory contains checked-in regression expectations for scale runs against real open-source applications.

`real-app-tier-snapshots.json` is compared with `outputs/external-complex/benchmark.json` by:

```bash
reachability-advisor benchmark-snapshots \
  --benchmark outputs/external-complex/benchmark.json \
  --expectations fixtures/benchmarks/real-app-tier-snapshots.json
```

The gate is focused on over-prioritization. It fails when high or urgent tiers inflate beyond the configured limits, when per-case distributions drift too far, or when an expected case no longer passes.

Use `configs/scoring-benchmark.json` for labeled scoring decisions. That benchmark checks individual urgent, high, medium, and low cases with an expected reason, score band, and required evidence labels. The real-app snapshot in this directory checks release-to-release distribution drift.
