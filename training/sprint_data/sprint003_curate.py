"""Apply Sprint 003 review completions to imported candidates (raw-first loop).

Mirrors sprint002_curate: matches pending candidates by
(source_type, source_reference, code), fills in patch/exploit/checks/verdict, and
saves them. Does NOT approve. Reject-test cases (_expect="reject") are left
incomplete so approval rejects them.

  python -m training.sprint_data.sprint003_curate
"""
from __future__ import annotations

from nullsec.core.models import REQUIRED_DIMENSIONS
from taxonomy import check_dimension_for, default_severity

from training import _ingest_store as store
from training.sprint_data.sprint003_cases_p1 import CASES_P1
from training.sprint_data.sprint003_cases_p2 import CASES_P2
from training.sprint_data.sprint003_cases_p3 import CASES_P3
from training.sprint_data.sprint003_cases_sup import CASES_SUP

ALL_CASES = CASES_P1 + CASES_P2 + CASES_P3 + CASES_SUP
_RISK = {"INFO": 0, "LOW": 10, "MEDIUM": 35, "HIGH": 70, "CRITICAL": 90}


def _key(st, ref, code):
    return (st, ref, code)


def _index():
    return {_key(c["source_type"], c["source_ref"], c["code"]): c for c in ALL_CASES}


def curate_candidate(cand: dict, case: dict) -> dict:
    comp = case.get("completion", {})
    cat = case["category"]
    sev = comp.get("severity") or default_severity(cat)

    checks = {d: {"status": "pass", "note": "reviewed, no issue"} for d in REQUIRED_DIMENSIONS}
    for d in comp.get("na_dims", ()):
        checks[d] = {"status": "not_applicable", "note": "n/a"}
    dim = check_dimension_for(cat)
    if dim:
        checks[dim] = {"status": "fail", "note": comp.get("exploit", cat)[:80]}
    for d in comp.get("fail_dims", ()):
        checks[d] = {"status": "fail", "note": "related failing control"}

    patch, exploit = comp["patch"], comp["exploit"]
    verdict = {
        "risk_score": _RISK[sev], "production_ready": False, "severity": sev, "confidence": "HIGH",
        "reasoning_summary": case.get("source_ref", cat), "exploit_scenario": exploit,
        "affected_files": [case["filename"]], "checks_performed": checks,
        "findings": [{
            "category": cat, "severity": sev, "confidence": "HIGH",
            "file": case["filename"], "line": 1,
            "description": comp.get("reviewer_notes", cat)[:200],
            "exploit_scenario": exploit, "recommended_fix": "see secure_patch", "secure_patch": patch,
        }],
    }
    cand.update({
        "proposed_verdict": verdict, "proposed_secure_patch": patch, "exploit_scenario": exploit,
        "severity_suggestion": sev, "checks_performed": checks, "category_suggestion": cat,
        "expected_production_ready": False, "reviewer_notes": comp.get("reviewer_notes", ""),
    })
    return cand


def main():
    idx = _index()
    curated = reject_left = skipped = 0
    for cand in store.iter_candidates():
        if cand.get("reviewer_status") != "pending":
            continue
        case = idx.get(_key(cand.get("source_type"), cand.get("source_reference"), cand.get("code")))
        if not case:
            skipped += 1
            continue
        if case.get("_expect") == "reject":
            reject_left += 1
            continue
        store.save_candidate(curate_candidate(cand, case))
        curated += 1
    print(f"curated {curated}; left {reject_left} reject-test(s) incomplete; {skipped} unmatched.")


if __name__ == "__main__":
    main()
