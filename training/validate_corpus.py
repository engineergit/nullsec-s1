#!/usr/bin/env python3
"""Validate the Nullsec-1 training corpus.

Rejects any example that would poison training. An example is rejected if:

  - required fields are missing (id, lang, code, verdict)            [incomplete]
  - a vulnerable finding has no real secure_patch                    [missing patch]
  - a finding's check dimension is reported 'pass'                   [contradiction]
  - it is labeled production_ready True but the Safety Layer blocks  [false-ready]
    (or it is labeled production_ready but still carries findings)
  - the embedded verdict cannot be aligned to the contract          [malformed]

It also checks per-category minimum coverage. Exit code is non-zero if any
example is rejected or any category is below the minimum.

  python training/validate_corpus.py
  python training/validate_corpus.py --min-per-category 25 --include-synthetic
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from corpus import is_curated, load_corpus
from nullsec.core.models import REQUIRED_DIMENSIONS
from nullsec.safety import VerdictParseError, align_and_enforce
from taxonomy import check_dimension_for, load_taxonomy

REQUIRED_TOP = ("id", "lang", "code", "verdict")
_STUB_MARKERS = ("needs_curation", "todo", "tbd", "review:", "unfilled", "xxx")


def validate_example(e: dict) -> list[str]:
    issues: list[str] = []

    for k in REQUIRED_TOP:
        if not e.get(k):
            issues.append(f"missing field '{k}'")
    if issues:
        return issues  # can't go further without the basics

    v = e["verdict"]
    findings = v.get("findings", [])
    checks = v.get("checks_performed", {})

    # secure patches must be real on every vulnerable finding
    for f in findings:
        patch = (f.get("secure_patch") or "").strip()
        if len(patch) < 8:
            issues.append(f"finding '{f.get('category')}' has no real secure_patch")
        elif any(p in patch.lower() for p in _STUB_MARKERS):
            issues.append(f"finding '{f.get('category')}' secure_patch is an unfilled stub")
        if not (f.get("exploit_scenario") or "").strip():
            issues.append(f"finding '{f.get('category')}' has no exploit_scenario")

    # contradiction: a finding whose dimension is reported 'pass'
    for f in findings:
        dim = check_dimension_for(f.get("category", ""))
        if dim and isinstance(checks.get(dim), dict) and checks[dim].get("status") == "pass":
            issues.append(f"contradiction: finding '{f['category']}' but dimension '{dim}' marked pass")

    # every required dimension must be present
    for d in REQUIRED_DIMENSIONS:
        if d not in checks:
            issues.append(f"checks_performed missing dimension '{d}'")

    # alignment + Safety Layer consistency
    try:
        res = align_and_enforce(json.dumps(v))
    except VerdictParseError as ve:
        issues.append(f"verdict cannot be aligned: {ve}")
        return issues

    expected = e.get("expected_production_ready")
    if res.production_ready != expected:
        issues.append(
            f"Safety Layer inconsistency: enforced production_ready={res.production_ready}, "
            f"labeled expected={expected}"
        )
    # production_ready must never be True with findings present
    if expected is True and findings:
        issues.append("labeled production_ready True but findings are present (false-ready)")

    return issues


def run(min_per_category: int, include_synthetic: bool, include_ingested: bool) -> dict:
    examples = load_corpus(include_synthetic=include_synthetic, include_ingested=include_ingested)
    rejected: list[dict] = []
    accepted = 0
    cat_counts: Counter = Counter()
    cat_counts_curated: Counter = Counter()

    seen_ids = set()
    for e in examples:
        issues = validate_example(e)
        eid = e.get("id", "<no-id>")
        if eid in seen_ids:
            issues.append("duplicate id")
        seen_ids.add(eid)
        if issues:
            rejected.append({"id": eid, "issues": issues})
            continue
        accepted += 1
        for f in e["verdict"].get("findings", []):
            cat_counts[f["category"]] += 1
            if is_curated(e):
                cat_counts_curated[f["category"]] += 1

    categories = [c["id"] for c in load_taxonomy()["categories"]]
    below = {c: cat_counts.get(c, 0) for c in categories if cat_counts.get(c, 0) < min_per_category}

    return {
        "total": len(examples),
        "accepted": accepted,
        "rejected": rejected,
        "category_counts": dict(sorted(cat_counts.items())),
        "category_counts_curated": dict(sorted(cat_counts_curated.items())),
        "min_per_category": min_per_category,
        "below_minimum": below,
        "ok": (not rejected) and (not below),
    }


def main():
    ap = argparse.ArgumentParser(description="Validate the Nullsec-1 training corpus")
    ap.add_argument("--min-per-category", type=int, default=1)
    ap.add_argument("--include-synthetic", action="store_true")
    ap.add_argument("--include-ingested", action="store_true")
    args = ap.parse_args()

    r = run(args.min_per_category, args.include_synthetic, args.include_ingested)
    print(f"corpus: {r['total']} examples, {r['accepted']} accepted, {len(r['rejected'])} rejected")
    for rej in r["rejected"]:
        print(f"  REJECT {rej['id']}: {'; '.join(rej['issues'])}")
    if r["below_minimum"]:
        print(f"below minimum ({r['min_per_category']}/category): {r['below_minimum']}")
    print("RESULT:", "PASS" if r["ok"] else "FAIL")
    sys.exit(0 if r["ok"] else 1)


if __name__ == "__main__":
    main()
