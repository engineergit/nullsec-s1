#!/usr/bin/env python3
"""Benchmark: vulnerability detection accuracy (precision / recall / F1)."""
from __future__ import annotations
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.metrics import detection_over
from benchmarks.harness import write_report
from benchmarks.runners._common import build_provider, collect_verdicts, common_args, load


def main():
    args = common_args("Nullsec-1 detection accuracy").parse_args()
    ds = load(args)
    verdicts = collect_verdicts(ds, build_provider(args))
    results = detection_over(ds["cases"], verdicts)
    out = write_report("detection_accuracy", args.mode, args.dataset, args.adapter, results)
    print(json.dumps(results, indent=2)); print(f"\nreport -> {out}")


if __name__ == "__main__":
    main()
