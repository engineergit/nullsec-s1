#!/usr/bin/env python3
"""Benchmark: OWASP coverage — detection recall per OWASP category."""
from __future__ import annotations
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.metrics import owasp_coverage
from benchmarks.harness import write_report
from benchmarks.runners._common import build_provider, collect_verdicts, common_args, load


def main():
    args = common_args("Nullsec-1 OWASP coverage").parse_args()
    ds = load(args)
    verdicts = collect_verdicts(ds, build_provider(args))
    results = owasp_coverage(ds["cases"], verdicts)
    out = write_report("owasp_coverage", args.mode, args.dataset, args.adapter, results)
    print(json.dumps(results, indent=2)); print(f"\nreport -> {out}")


if __name__ == "__main__":
    main()
