#!/usr/bin/env python3
"""Run the full Nullsec-1 benchmark suite and write a consolidated report.

Obtains real Nullsec-1 outputs once (model or replay), then computes every
metric family over them. Produces benchmarks/reports/SUITE.json plus the
individual reports.

Usage:
  # against the live model (GPU):
  python benchmarks/run_all.py --mode model --adapter outputs/nullsec-s1-qlora

  # against captured real outputs (no GPU):
  python benchmarks/run_all.py --mode replay --replay path/to/captured.jsonl
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.harness import write_report
from benchmarks.metrics import (
    detection_over,
    false_safe_rate,
    hallucination_rate,
    owasp_coverage,
    patch_correctness,
    secure_generation_score,
)
from benchmarks.runners._common import build_provider, collect_verdicts, common_args, load

FAMILIES = {
    "detection_accuracy": detection_over,
    "false_safe_rate": false_safe_rate,
    "hallucination_rate": hallucination_rate,
    "owasp_coverage": owasp_coverage,
    "patch_correctness": patch_correctness,
    "secure_generation": secure_generation_score,
}


def main():
    args = common_args("Nullsec-1 full benchmark suite").parse_args()
    ds = load(args)
    verdicts = collect_verdicts(ds, build_provider(args))

    suite = {name: fn(ds["cases"], verdicts) for name, fn in FAMILIES.items()}
    out = write_report("SUITE", args.mode, args.dataset, args.adapter, suite)
    print(json.dumps(suite, indent=2))
    print(f"\nconsolidated report -> {out}")


if __name__ == "__main__":
    main()
