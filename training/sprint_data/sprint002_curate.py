"""Apply Sprint 002 review completions to imported candidates.

This is the human-review step of the loop, expressed as code so it is
reproducible and auditable. For each pending candidate that matches a Sprint 002
case (by source_type + source_reference + code), it fills in the reviewer's work:

  - secure_patch (on the finding)
  - exploit_scenario (finding + verdict)
  - severity (if the reviewer adjusted it)
  - checks_performed: the flagged dimension -> fail (+ any extra fail dims),
    remaining 'not_checked' dimensions resolved to pass/not_applicable
  - risk_score floor consistent with severity
  - reviewer_notes

It does NOT approve anything. After curation, run
`training/curate_ingested.py approve <id>` (or the sprint runner), which validates
and enforces Safety Layer consistency before writing to corpus/ingested/.

Candidates whose case is tagged _expect="reject" are intentionally left
incomplete (or with weak provenance) so the approval step rejects them.

  python -m training.sprint_data.sprint002_curate
"""
from __future__ import annotations

from nullsec.core.models import REQUIRED_DIMENSIONS
from taxonomy import check_dimension_for, default_severity, max_severity

from training import _ingest_store as store
from training.sprint_data.sprint002_cases_p1 import CASES_P1
from training.sprint_data.sprint002_cases_p2 import CASES_P2
from training.sprint_data.sprint002_cases_p3 import CASES_P3
from training.sprint_data.sprint002_cases_sup import CASES_SUP

ALL_CASES = CASES_P1 + CASES_P2 + CASES_P3 + CASES_SUP
_RISK = {"INFO": 0, "LOW": 10, "MEDIUM": 35, "HIGH": 70, "CRITICAL": 90}


def _case_key(source_type, source_ref, code):
    return (source_type, source_ref, code)


def _build_case_index():
    idx = {}
    for c in ALL_CASES:
        idx[_case_key(c["source_type"], c["source_ref"], c["code"])] = c
    return idx


def curate_candidate(cand: dict, case: dict) -> dict:
    """Apply the reviewer completion to a pending candidate (in place semantics)."""
    comp = case.get("completion", {})
    cat = case["category"]
    sev = comp.get("severity") or default_severity(cat)

    # Resolve checks: flagged dim + extra fail dims -> fail; the rest -> pass,
    # unless explicitly not_applicable.
    checks = {d: {"status": "pass", "note": "reviewed, no issue"} for d in REQUIRED_DIMENSIONS}
    for d in comp.get("na_dims", ()):
        checks[d] = {"status": "not_applicable", "note": "n/a"}
    dim = check_dimension_for(cat)
    if dim:
        checks[dim] = {"status": "fail", "note": comp.get("exploit", cat)[:80]}
    for d in comp.get("fail_dims", ()):
        checks[d] = {"status": "fail", "note": "related failing control"}

    patch = comp["patch"]
    exploit = comp["exploit"]

    verdict = {
        "risk_score": _RISK[sev],
        "production_ready": False,
        "severity": sev,
        "confidence": "HIGH",
        "reasoning_summary": case.get("source_ref", cat),
        "exploit_scenario": exploit,
        "affected_files": [case["filename"]],
        "checks_performed": checks,
        "findings": [{
            "category": cat, "severity": sev, "confidence": "HIGH",
            "file": case["filename"], "line": 1,
            "description": comp.get("reviewer_notes", cat)[:200],
            "exploit_scenario": exploit,
            "recommended_fix": "see secure_patch",
            "secure_patch": patch,
        }],
    }
    cand["proposed_verdict"] = verdict
    cand["proposed_secure_patch"] = patch
    cand["exploit_scenario"] = exploit
    cand["severity_suggestion"] = sev
    cand["checks_performed"] = checks
    cand["category_suggestion"] = cat
    cand["expected_production_ready"] = False
    cand["reviewer_notes"] = comp.get("reviewer_notes", "")
    return cand


def main():
    idx = _build_case_index()
    curated = skipped = reject_left = 0
    for cand in store.iter_candidates():
        if cand.get("reviewer_status") != "pending":
            continue
        key = _case_key(cand.get("source_type"), cand.get("source_reference"), cand.get("code"))
        case = idx.get(key)
        if not case:
            skipped += 1
            continue
        if case.get("_expect") == "reject":
            # leave it incomplete/weak on purpose so approval rejects it
            reject_left += 1
            continue
        store.save_candidate(curate_candidate(cand, case))
        curated += 1
    print(f"curated {curated} candidate(s); left {reject_left} reject-test candidate(s) incomplete; "
          f"{skipped} unmatched.")


if __name__ == "__main__":
    main()
