#!/usr/bin/env python3
"""Nullsec-1 training corpus statistics.

    python training/dataset_stats.py
    python training/dataset_stats.py --include-synthetic --json

Reports total examples, train/eval split, category coverage, severity coverage,
language/framework coverage, the production_ready true/false ratio, the Safety
Layer consistency pass rate, and the curated/synthetic/ingested provenance
breakdown (so generated data is never mistaken for curated data).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from corpus import is_curated, load_corpus, split
from nullsec.safety import VerdictParseError, align_and_enforce
from taxonomy import load_taxonomy


def compute(examples: list[dict], eval_frac: float, seed: int) -> dict:
    categories = [c["id"] for c in load_taxonomy()["categories"]]
    cat = Counter()
    cat_curated = Counter()
    sev = Counter()
    lang = Counter()
    framework = Counter()
    provenance = Counter()
    pr_true = pr_false = 0
    consistent = 0
    checked = 0

    for e in examples:
        provenance[e.get("provenance", "unknown")] += 1
        lang[e.get("lang", "unknown")] += 1
        framework[e.get("framework", "unknown")] += 1
        v = e["verdict"]
        if e.get("expected_production_ready"):
            pr_true += 1
        else:
            pr_false += 1
        sev[v.get("severity", "?")] += 1
        for f in v.get("findings", []):
            cat[f["category"]] += 1
            if is_curated(e):
                cat_curated[f["category"]] += 1
        try:
            res = align_and_enforce(json.dumps(v))
            checked += 1
            if res.production_ready == e.get("expected_production_ready"):
                consistent += 1
        except VerdictParseError:
            pass

    train, ev = split(examples, eval_frac, seed)
    total = len(examples)
    return {
        "total_examples": total,
        "train_eval_split": {"train": len(train), "eval": len(ev), "eval_frac": eval_frac, "seed": seed},
        "provenance": dict(provenance),
        "curated_total": sum(1 for e in examples if is_curated(e)),
        "category_coverage": {c: cat.get(c, 0) for c in categories},
        "category_coverage_curated": {c: cat_curated.get(c, 0) for c in categories},
        "severity_coverage": dict(sorted(sev.items())),
        "language_coverage": dict(sorted(lang.items())),
        "framework_coverage": dict(sorted(framework.items())),
        "production_ready_ratio": {
            "true": pr_true, "false": pr_false,
            "true_pct": round(100 * pr_true / total, 1) if total else 0.0,
        },
        "safety_layer_consistency": {
            "checked": checked, "consistent": consistent,
            "pass_rate": round(consistent / checked, 4) if checked else None,
        },
    }


def render(s: dict) -> str:
    L = []
    L.append(f"Total examples:        {s['total_examples']}")
    sp = s["train_eval_split"]
    L.append(f"Train / eval split:    {sp['train']} train / {sp['eval']} eval (frac={sp['eval_frac']}, seed={sp['seed']})")
    L.append(f"Curated (hand/ingested): {s['curated_total']}")
    L.append(f"Provenance:            {s['provenance']}")
    L.append(f"production_ready ratio: {s['production_ready_ratio']['false']} false / "
             f"{s['production_ready_ratio']['true']} true ({s['production_ready_ratio']['true_pct']}% true)")
    slc = s["safety_layer_consistency"]
    L.append(f"Safety Layer consistency: {slc['consistent']}/{slc['checked']} "
             f"({'100%' if slc['pass_rate'] == 1.0 else slc['pass_rate']})")
    L.append("Severity coverage:     " + ", ".join(f"{k}:{v}" for k, v in s["severity_coverage"].items()))
    L.append("Language coverage:     " + ", ".join(f"{k}:{v}" for k, v in s["language_coverage"].items()))
    L.append("Framework coverage:    " + ", ".join(f"{k}:{v}" for k, v in s["framework_coverage"].items()))
    L.append("Category coverage (curated / total):")
    for c, n in s["category_coverage"].items():
        cu = s["category_coverage_curated"].get(c, 0)
        L.append(f"   {c:<24} {cu:>3} / {n}")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="Nullsec-1 corpus statistics")
    ap.add_argument("--eval-split", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--include-synthetic", action="store_true")
    ap.add_argument("--include-ingested", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    examples = load_corpus(include_synthetic=args.include_synthetic, include_ingested=args.include_ingested)
    s = compute(examples, args.eval_split, args.seed)
    print(json.dumps(s, indent=2) if args.json else render(s))


if __name__ == "__main__":
    main()
