#!/usr/bin/env python3
"""Benchmark: false-safe rate — unsafe code wrongly marked production_ready.

The most safety-critical metric. The Nullsec Safety Layer is designed to drive
this to zero regardless of model confidence.
"""
from __future__ import annotations
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.metrics import false_safe_rate
from benchmarks.harness import write_report
from benchmarks.runners._common import build_provider, collect_verdicts, common_args, load


def main():
    args = common_args("Nullsec-1 false-safe rate").parse_args()
    ds = load(args)
    verdicts = collect_verdicts(ds, build_provider(args))
    results = false_safe_rate(ds["cases"], verdicts)
    out = write_report("false_safe_rate", args.mode, args.dataset, args.adapter, results)
    print(json.dumps(results, indent=2)); print(f"\nreport -> {out}")


if __name__ == "__main__":
    main()
