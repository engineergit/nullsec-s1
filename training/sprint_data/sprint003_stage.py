"""Stage Sprint 003 cases as SKELETAL raw findings (raw-first).

Writes data/raw/sprint003.jsonl with code + source + references only — no patch,
no exploit, all dimensions not_checked except the flagged one. Curate via
sprint003_curate.py, then approve.

  python -m training.sprint_data.sprint003_stage
"""
from __future__ import annotations

import json
from pathlib import Path

from nullsec.core.models import REQUIRED_DIMENSIONS
from taxonomy import check_dimension_for, default_severity

from training.sprint_data.sprint003_cases_p1 import CASES_P1
from training.sprint_data.sprint003_cases_p2 import CASES_P2
from training.sprint_data.sprint003_cases_p3 import CASES_P3
from training.sprint_data.sprint003_cases_sup import CASES_SUP

ALL_CASES = CASES_P1 + CASES_P2 + CASES_P3 + CASES_SUP
OUT = Path(__file__).resolve().parents[2] / "data" / "raw"


def skeleton_record(c: dict) -> dict:
    cat = c["category"]
    sev = c.get("completion", {}).get("severity") or default_severity(cat)
    checks = {d: {"status": "not_checked", "note": "awaiting review"} for d in REQUIRED_DIMENSIONS}
    dim = check_dimension_for(cat)
    if dim:
        checks[dim] = {"status": "fail", "note": "flagged by source"}
    verdict = {
        "risk_score": 0,
        "production_ready": False,
        "severity": sev,
        "confidence": "MEDIUM",
        "reasoning_summary": f"[RAW] {cat} flagged by {c['source_type']} ({c['source_ref']}); needs review.",
        "exploit_scenario": None,
        "affected_files": [c["filename"]],
        "checks_performed": checks,
        "findings": [{
            "category": cat, "severity": sev, "confidence": "MEDIUM",
            "file": c["filename"], "line": 1,
            "description": f"[RAW] {cat} candidate from {c['source_type']}",
            "exploit_scenario": None, "recommended_fix": None, "secure_patch": "",
        }],
    }
    return {
        "source_type": c["source_type"], "source_reference": c["source_ref"],
        "references": c.get("references", {}),
        "filename": c["filename"], "lang": c["lang"], "framework": c["framework"],
        "code": c["code"], "verdict": verdict, "reviewer_notes": "",
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    out = OUT / "sprint003.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for c in ALL_CASES:
            fh.write(json.dumps(skeleton_record(c)) + "\n")
    print(f"staged {len(ALL_CASES)} SKELETAL records -> {out}")


if __name__ == "__main__":
    main()
