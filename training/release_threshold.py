#!/usr/bin/env python3
"""Nullsec-1.0 training-readiness threshold.

Blocks a v1.0 training run unless the corpus is genuinely ready:

  - at least MIN_CURATED curated examples exist (default 500)
  - every taxonomy category has at least MIN_PER_CATEGORY curated examples (25)
  - the eval split has at least MIN_EVAL examples (100)
  - Safety Layer consistency is exactly 100%

"Curated" means hand-authored or curated-ingested — synthetic augmentation never
counts toward the curated thresholds (it is reported separately). This gate is the
data-side analogue of validate_claims: it tells the truth about whether the corpus
can back a real Nullsec-1.0 model, and it exits non-zero until it can.

  python training/release_threshold.py
  python training/release_threshold.py --include-synthetic   # counts synthetic toward EVAL/consistency only
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from corpus import is_curated, load_corpus, split
from training.dataset_stats import compute

MIN_CURATED = 500
MIN_PER_CATEGORY = 25
MIN_EVAL = 100


def evaluate(examples, eval_frac, seed, min_curated, min_per_cat, min_eval) -> dict:
    s = compute(examples, eval_frac, seed)
    curated = s["curated_total"]
    cat_curated = s["category_coverage_curated"]
    below = {c: n for c, n in cat_curated.items() if n < min_per_cat}
    eval_n = s["train_eval_split"]["eval"]
    consistency = s["safety_layer_consistency"]["pass_rate"]

    criteria = {
        f"curated >= {min_curated}": (curated >= min_curated, f"{curated}/{min_curated}"),
        f"every category >= {min_per_cat} curated": (not below, f"{len(below)} below" if below else "all categories met"),
        f"eval >= {min_eval}": (eval_n >= min_eval, f"{eval_n}/{min_eval}"),
        "safety layer consistency == 100%": (consistency == 1.0, f"{consistency}"),
    }
    return {
        "criteria": criteria,
        "below_categories": below,
        "passed": all(ok for ok, _ in criteria.values()),
        "stats_summary": {
            "curated_total": curated,
            "total": s["total_examples"],
            "provenance": s["provenance"],
            "eval": eval_n,
            "consistency": consistency,
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Nullsec-1.0 training-readiness threshold")
    ap.add_argument("--eval-split", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--include-synthetic", action="store_true")
    ap.add_argument("--include-ingested", action="store_true")
    ap.add_argument("--min-curated", type=int, default=MIN_CURATED)
    ap.add_argument("--min-per-category", type=int, default=MIN_PER_CATEGORY)
    ap.add_argument("--min-eval", type=int, default=MIN_EVAL)
    args = ap.parse_args()

    examples = load_corpus(include_synthetic=args.include_synthetic, include_ingested=args.include_ingested)
    r = evaluate(examples, args.eval_split, args.seed,
                 args.min_curated, args.min_per_category, args.min_eval)

    print("Nullsec-1.0 training-readiness threshold")
    print("=" * 60)
    for name, (ok, detail) in r["criteria"].items():
        print(f"[{'PASS' if ok else 'FAIL'}] {name:<40} {detail}")
    ss = r["stats_summary"]
    print("-" * 60)
    print(f"curated: {ss['curated_total']}  total: {ss['total']}  provenance: {ss['provenance']}")
    if r["below_categories"]:
        print(f"categories below {args.min_per_category} curated: {r['below_categories']}")
    print("=" * 60)
    if r["passed"]:
        print("RESULT: PASS — corpus meets the v1.0 training threshold.")
        sys.exit(0)
    gap = max(0, args.min_curated - ss["curated_total"])
    print(f"RESULT: BLOCKED — corpus is not yet v1.0-ready.")
    print(f"  Need {gap} more curated examples (and >= {args.min_per_category}/category, "
          f">= {args.min_eval} eval). Close the gap with real CVE/scanner ingestion "
          "(nullsec.ingest), real AI-generated failure cases, and continued authoring — "
          "not synthetic padding.")
    sys.exit(1)


if __name__ == "__main__":
    main()
