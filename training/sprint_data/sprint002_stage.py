"""Stage Sprint 002 cases as SKELETAL raw findings.

This is deliberately raw-first: the staged record has the vulnerable code and the
source/references, but NO secure patch, NO exploit scenario, and every check
dimension set to 'not_checked'. That mirrors what a real importer/scanner emits
and forces the work to happen in the review loop (sprint002_curate.py), not here.

  python -m training.sprint_data.sprint002_stage      # writes data/raw/sprint002.jsonl
"""
from __future__ import annotations

import json
from pathlib import Path

from nullsec.core.models import REQUIRED_DIMENSIONS
from taxonomy import check_dimension_for, default_severity

from training.sprint_data.sprint002_cases_p1 import CASES_P1
from training.sprint_data.sprint002_cases_p2 import CASES_P2
from training.sprint_data.sprint002_cases_p3 import CASES_P3
from training.sprint_data.sprint002_cases_sup import CASES_SUP

ALL_CASES = CASES_P1 + CASES_P2 + CASES_P3 + CASES_SUP
OUT = Path(__file__).resolve().parents[2] / "data" / "raw"


def skeleton_record(c: dict) -> dict:
    """A raw, uncurated finding: code + source + refs, but no remediation yet."""
    cat = c["category"]
    sev = c.get("completion", {}).get("severity") or default_severity(cat)
    # checks all not_checked except the obvious failing dimension flagged by the
    # scanner; everything else awaits human review.
    checks = {d: {"status": "not_checked", "note": "awaiting review"} for d in REQUIRED_DIMENSIONS}
    dim = check_dimension_for(cat)
    if dim:
        checks[dim] = {"status": "fail", "note": "flagged by source"}
    verdict = {
        "risk_score": 0,  # not scored until curated
        "production_ready": False,
        "severity": sev,
        "confidence": "MEDIUM",
        "reasoning_summary": f"[RAW] {cat} flagged by {c['source_type']} ({c['source_ref']}); needs review.",
        "exploit_scenario": None,        # to be filled in curation
        "affected_files": [c["filename"]],
        "checks_performed": checks,
        "findings": [{
            "category": cat, "severity": sev, "confidence": "MEDIUM",
            "file": c["filename"], "line": 1,
            "description": f"[RAW] {cat} candidate from {c['source_type']}",
            "exploit_scenario": None,
            "recommended_fix": None,
            "secure_patch": "",          # intentionally empty until curated
        }],
    }
    return {
        "source_type": c["source_type"],
        "source_reference": c["source_ref"],
        "references": c.get("references", {}),
        "filename": c["filename"], "lang": c["lang"], "framework": c["framework"],
        "code": c["code"], "verdict": verdict,
        "reviewer_notes": "",            # filled in curation
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    out = OUT / "sprint002.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for c in ALL_CASES:
            fh.write(json.dumps(skeleton_record(c)) + "\n")
    print(f"staged {len(ALL_CASES)} SKELETAL records -> {out}")
    print("These are raw: no patch, no exploit, checks not_checked. Curate before approval.")


if __name__ == "__main__":
    main()
