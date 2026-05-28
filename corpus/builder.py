"""Authoring helpers for the Nullsec-1 training corpus.

`vuln(...)` and `secure(...)` turn concise inputs into a full training example
whose embedded verdict is consistent with the Nullsec Safety Layer: vulnerable
examples are never production_ready and surface a failing check dimension;
secure examples pass every dimension with no findings. This removes verdict
boilerplate without faking anything — the vulnerable code, the exploit, and the
secure patch are all real and authored per example.

Every example records `provenance` ("hand_authored" by default). Synthetic and
ingested examples carry their own provenance and never count as curated.
"""
from __future__ import annotations

from nullsec.core.models import REQUIRED_DIMENSIONS
from taxonomy import check_dimension_for, default_severity, max_severity, severity_rank

_RISK_FLOOR = {"INFO": 0, "LOW": 10, "MEDIUM": 35, "HIGH": 70, "CRITICAL": 90}


def finding(category, file, line, description, exploit, fix, patch,
            severity=None, confidence="HIGH"):
    return {
        "category": category,
        "severity": severity or default_severity(category),
        "confidence": confidence,
        "file": file,
        "line": line,
        "description": description,
        "exploit_scenario": exploit,
        "recommended_fix": fix,
        "secure_patch": patch,
    }


def vuln(*, id, lang, framework, file, code, category, line, description, exploit,
         fix, patch, severity=None, extra_findings=None, fail_dims=(), na_dims=(),
         summary=None, provenance="hand_authored"):
    """A vulnerable example. production_ready is always False and the relevant
    check dimension(s) are marked fail."""
    findings = [finding(category, file, line, description, exploit, fix, patch, severity)]
    if extra_findings:
        findings.extend(extra_findings)

    checks = {d: {"status": "pass", "note": "reviewed"} for d in REQUIRED_DIMENSIONS}
    for d in na_dims:
        checks[d] = {"status": "not_applicable", "note": "not applicable to this code"}
    for f in findings:
        dim = check_dimension_for(f["category"])
        if dim:
            checks[dim] = {"status": "fail", "note": f["description"][:80]}
    for d in fail_dims:
        checks[d] = {"status": "fail", "note": "failed review"}

    sev = max_severity([f["severity"] for f in findings])
    verdict = {
        "risk_score": _RISK_FLOOR[sev],
        "production_ready": False,
        "severity": sev,
        "confidence": "HIGH",
        "reasoning_summary": summary or description,
        "exploit_scenario": exploit,
        "affected_files": [file],
        "checks_performed": checks,
        "findings": findings,
    }
    return {
        "id": id, "lang": lang, "framework": framework, "code": code,
        "verdict": verdict, "expected_production_ready": False,
        "provenance": provenance, "source": "authored",
    }


def secure(*, id, lang, framework, file, code, summary, na_dims=(),
           provenance="hand_authored"):
    """A clean example: every dimension passes, no findings, production_ready True.
    Teaches Nullsec-1 what acceptable code looks like so the corpus is not 100%
    positive."""
    checks = {d: {"status": "pass", "note": "reviewed, no issue"} for d in REQUIRED_DIMENSIONS}
    for d in na_dims:
        checks[d] = {"status": "not_applicable", "note": "not applicable to this code"}
    verdict = {
        "risk_score": 0,
        "production_ready": True,
        "severity": "INFO",
        "confidence": "HIGH",
        "reasoning_summary": summary,
        "exploit_scenario": None,
        "affected_files": [file],
        "checks_performed": checks,
        "findings": [],
    }
    return {
        "id": id, "lang": lang, "framework": framework, "code": code,
        "verdict": verdict, "expected_production_ready": True,
        "provenance": provenance, "source": "authored",
    }
