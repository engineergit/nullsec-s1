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
    debug_report,
    detection_over,
    failed_case_ids,
    false_safe_rate,
    hallucination_rate,
    owasp_coverage,
    patch_correctness,
    per_category_recall,
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
    "per_category_recall": per_category_recall,
    "failed_cases": failed_case_ids,
}


def main():
    ap = common_args("Nullsec-1 full benchmark suite")
    ap.add_argument("--debug", action="store_true",
                    help="print per-case reason codes (failure triage)")
    ap.add_argument("--failed-only", action="store_true",
                    help="with --debug, show only cases that did not pass")
    args = ap.parse_args()
    ds = load(args)
    verdicts = collect_verdicts(ds, build_provider(args))

    suite = {name: fn(ds["cases"], verdicts) for name, fn in FAMILIES.items()}
    # Per-case explicit failure-triage records (recorded in the report; printed with --debug).
    dbg = debug_report(ds["cases"], verdicts, failed_only=bool(args.failed_only))
    suite["debug"] = dbg
    if args.debug:
        scope = "failed only" if args.failed_only else "all cases"
        print(f"Per-case detail ({scope}; {dbg['passed']}/{dbg['cases']} passed):\n")
        for cid, d in dbg["per_case"].items():
            flags = []
            if d["malformed_or_missing_output"]:
                flags.append("MALFORMED/MISSING")
            if d["hallucinated_clean_finding"]:
                flags.append("HALLUCINATED_CLEAN_FINDING")
            if d["false_positive"]:
                flags.append(f"FP={d['false_positive']}")
            if d["false_negative"]:
                flags.append(f"FN={d['false_negative']}")
            if d["weak_patch"]:
                flags.append(f"WEAK_PATCH={d['weak_patch']}")
            print(f"  {cid}")
            print(f"      expected : {d['expected_verdict']:6} {d['expected_categories']}")
            print(f"      predicted: {str(d['predicted_verdict']):6} {d['predicted_categories']}")
            print(f"      flags    : {', '.join(flags) or '-'}")
            print(f"      notes    : {d['notes']}")
        print()
    # Headline summary: total cases and how many produced an alignable output.
    produced = sum(1 for cid in (c["id"] for c in ds["cases"]) if verdicts.get(cid, (None, False))[1])
    suite["summary"] = {
        "total_cases": len(ds["cases"]),
        "total_outputs": produced,
        "detection_f1": suite["detection_accuracy"].get("detection_f1"),
        "detection_precision": suite["detection_accuracy"].get("detection_precision"),
        "detection_recall": suite["detection_accuracy"].get("detection_recall"),
        "false_safe_rate": suite["false_safe_rate"].get("false_safe_rate"),
        "hallucination_rate": suite["hallucination_rate"].get("hallucination_rate"),
        "patch_correctness": suite["patch_correctness"].get("patch_correctness"),
        "secure_generation_score": suite["secure_generation"].get("secure_generation_score"),
        "owasp_coverage": suite["owasp_coverage"].get("coverage"),
        "categories_below_full_recall": suite["per_category_recall"].get("categories_below_full_recall"),
        "failed_case_ids": [f["id"] for f in suite["failed_cases"].get("failed", [])],
    }
    out = write_report("SUITE", args.mode, args.dataset, args.adapter, suite)
    print(json.dumps(suite["summary"], indent=2))
    print(f"\nconsolidated report -> {out}  (run_mode={args.mode}, adapter={args.adapter})")


if __name__ == "__main__":
    main()
