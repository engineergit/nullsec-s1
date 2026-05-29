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

# Release profiles. v1.0 is the SHIPPED gate and is never weakened. v1.1 (RC2) is
# a SEPARATE, stricter gate layered on top — it does not change v1.0 behavior.
PROFILES = {
    "v1.0": {
        "min_curated": 500, "min_per_category": 25, "min_eval": 100,
        "min_benchmark_cases": 0, "require_all_categories_benchmarked": False,
    },
    "v1.1": {
        "min_curated": 1000, "min_per_category": 60, "min_eval": 200,
        "min_benchmark_cases": 100, "require_all_categories_benchmarked": True,
    },
}
PROFILE_ALIASES = {"rc2": "v1.1", "1.0": "v1.0", "1.1": "v1.1"}


def benchmark_criteria(min_cases: int, require_all_categories: bool) -> dict:
    """Benchmark-side criteria for the RC2 profile (separate from corpus checks)."""
    crit: dict = {}
    try:
        from benchmarks.harness import load_dataset
        from taxonomy import load_taxonomy

        ds = load_dataset("detection.json")
        cases = ds.get("cases", [])
        n = len(cases)
        covered = set()
        for c in cases:
            covered.update(c.get("expected_categories", []))
        all_cats = {c["id"] for c in load_taxonomy()["categories"]}
        missing = sorted(all_cats - covered)
    except Exception as e:  # benchmark dataset missing/unreadable
        crit[f"benchmark cases >= {min_cases}"] = (False, f"could not load benchmark: {e}")
        return crit

    crit[f"benchmark cases >= {min_cases}"] = (n >= min_cases, f"{n}/{min_cases}")
    if require_all_categories:
        crit["benchmark covers all 16 categories"] = (
            not missing, "all 16 covered" if not missing else f"missing {len(missing)}: {missing}"
        )
    return crit


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
    ap = argparse.ArgumentParser(description="Nullsec training-readiness threshold")
    ap.add_argument("--eval-split", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--include-synthetic", action="store_true")
    ap.add_argument("--include-ingested", action="store_true")
    ap.add_argument("--profile", default="v1.0",
                    help="release profile: v1.0 (default, shipped gate) or v1.1/rc2 (stricter RC2 gate)")
    # Explicit overrides; default None means "use the profile value".
    ap.add_argument("--min-curated", type=int, default=None)
    ap.add_argument("--min-per-category", type=int, default=None)
    ap.add_argument("--min-eval", type=int, default=None)
    args = ap.parse_args()

    profile_key = PROFILE_ALIASES.get(args.profile, args.profile)
    if profile_key not in PROFILES:
        print(f"unknown profile '{args.profile}'. Choose from: {', '.join(PROFILES)} (alias rc2=v1.1).")
        sys.exit(2)
    prof = PROFILES[profile_key]

    min_curated = args.min_curated if args.min_curated is not None else prof["min_curated"]
    min_per_cat = args.min_per_category if args.min_per_category is not None else prof["min_per_category"]
    min_eval = args.min_eval if args.min_eval is not None else prof["min_eval"]

    examples = load_corpus(include_synthetic=args.include_synthetic, include_ingested=args.include_ingested)
    r = evaluate(examples, args.eval_split, args.seed, min_curated, min_per_cat, min_eval)

    criteria = dict(r["criteria"])
    if prof["min_benchmark_cases"] > 0:
        criteria.update(benchmark_criteria(prof["min_benchmark_cases"], prof["require_all_categories_benchmarked"]))
    passed = all(ok for ok, _ in criteria.values())

    print(f"Nullsec training-readiness threshold — profile {profile_key}")
    print("=" * 60)
    for name, (ok, detail) in criteria.items():
        print(f"[{'PASS' if ok else 'FAIL'}] {name:<40} {detail}")
    ss = r["stats_summary"]
    print("-" * 60)
    print(f"curated: {ss['curated_total']}  total: {ss['total']}  provenance: {ss['provenance']}")
    if r["below_categories"]:
        print(f"categories below {min_per_cat} curated: {r['below_categories']}")
    print("=" * 60)
    if passed:
        print(f"RESULT: PASS — corpus meets the {profile_key} training threshold.")
        sys.exit(0)
    gap = max(0, min_curated - ss["curated_total"])
    print(f"RESULT: BLOCKED — corpus is not yet {profile_key}-ready.")
    print(f"  Need {gap} more curated examples (and >= {min_per_cat}/category, "
          f">= {min_eval} eval). Close the gap with real CVE/scanner ingestion "
          "(nullsec.ingest), real AI-generated failure cases, and continued authoring — "
          "not synthetic padding.")
    sys.exit(1)


if __name__ == "__main__":
    main()
