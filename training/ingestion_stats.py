#!/usr/bin/env python3
"""Statistics for the curated ingestion workflow.

    python training/ingestion_stats.py
    python training/ingestion_stats.py --json

Shows how many findings are staged (raw imported), pending review, approved
(curated_ingested), and rejected; which categories the approved set covers; and
how many approved curated_ingested examples count toward the 500-curated release
threshold. Approved examples are counted only if they currently pass
training/validate_corpus.py.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from training._ingest_store import (  # noqa: E402
    CURATED_DIR,
    RAW_DIR,
    iter_candidates,
    iter_rejected,
)
from training.validate_corpus import validate_example  # noqa: E402


def _count_raw_staged() -> int:
    if not RAW_DIR.exists():
        return 0
    n = 0
    for fp in RAW_DIR.glob("*.jsonl"):
        n += sum(1 for line in fp.read_text(encoding="utf-8").splitlines() if line.strip())
    return n


def _load_curated_ingested() -> list[dict]:
    out = []
    if not CURATED_DIR.exists():
        return out
    for fp in sorted(CURATED_DIR.glob("*.jsonl")):
        for line in fp.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


def compute() -> dict:
    candidates = iter_candidates()
    rejected = iter_rejected() + [c for c in candidates if c.get("reviewer_status") == "rejected"]
    pending = [c for c in candidates if c.get("reviewer_status") == "pending"]

    curated = _load_curated_ingested()
    # how many of the approved curated examples actually pass validation right now
    counts_toward_threshold = 0
    cats = Counter()
    for ex in curated:
        if not validate_example(ex):
            counts_toward_threshold += 1
            for f in ex["verdict"].get("findings", []):
                cats[f["category"]] += 1

    return {
        "raw_imported_staged": _count_raw_staged(),
        "pending_review": len(pending),
        "approved_curated_ingested": len(curated),
        "rejected": len(rejected),
        "approved_categories_covered": dict(sorted(cats.items())),
        "counts_toward_500_curated": counts_toward_threshold,
        "note": ("Only validated curated_ingested examples count toward the 500-curated "
                 "threshold, and only when --include-ingested is passed to the threshold/stats."),
    }


def render(s: dict) -> str:
    L = [
        "Nullsec-1 ingestion pipeline",
        "=" * 50,
        f"raw imported (staged, not eligible): {s['raw_imported_staged']}",
        f"pending review:                      {s['pending_review']}",
        f"approved (curated_ingested):         {s['approved_curated_ingested']}",
        f"rejected (never trained):            {s['rejected']}",
        "-" * 50,
        f"counts toward 500-curated threshold: {s['counts_toward_500_curated']}",
    ]
    if s["approved_categories_covered"]:
        L.append("approved categories: " + ", ".join(
            f"{k}:{v}" for k, v in s["approved_categories_covered"].items()))
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="Ingestion pipeline statistics")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    s = compute()
    print(json.dumps(s, indent=2) if args.json else render(s))


if __name__ == "__main__":
    main()
