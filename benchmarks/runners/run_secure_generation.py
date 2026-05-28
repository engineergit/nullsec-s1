#!/usr/bin/env python3
"""Benchmark: secure code generation score — patches free of insecure signals."""
from __future__ import annotations
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.metrics import secure_generation_score
from benchmarks.harness import write_report
from benchmarks.runners._common import build_provider, collect_verdicts, common_args, load


def main():
    args = common_args("Nullsec-1 secure generation score").parse_args()
    ds = load(args)
    verdicts = collect_verdicts(ds, build_provider(args))
    results = secure_generation_score(ds["cases"], verdicts)
    out = write_report("secure_generation", args.mode, args.dataset, args.adapter, results)
    print(json.dumps(results, indent=2)); print(f"\nreport -> {out}")


if __name__ == "__main__":
    main()
