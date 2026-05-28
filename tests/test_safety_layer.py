"""Test suite for the Nullsec-1 deterministic security layers.

Run: pytest -q
These tests need NO GPU/ML stack — they exercise the Security Alignment Layer,
the Nullsec Safety Layer, the schema, metrics, taxonomy, and the seed dataset.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nullsec.core.models import Verdict  # noqa: E402
from nullsec.safety import (  # noqa: E402
    VerdictParseError,
    enforce,
    normalize_finding_severities,
    parse_verdict,
)
from taxonomy import REQUIRED_CHECK_DIMENSIONS, category_ids, severity_rank  # noqa: E402


def _checks(default="pass", **overrides):
    base = {d: {"status": default, "note": "ok"} for d in REQUIRED_CHECK_DIMENSIONS}
    for k, v in overrides.items():
        base[k] = v
    return base


def _verdict_dict(**kw):
    base = dict(
        risk_score=0,
        production_ready=True,
        severity="INFO",
        confidence="HIGH",
        reasoning_summary="clean",
        exploit_scenario=None,
        affected_files=[],
        checks_performed=_checks(),
        findings=[],
    )
    base.update(kw)
    return base


# ---------------- parser ----------------

def test_parser_strips_code_fence():
    raw = "```json\n" + json.dumps(_verdict_dict()) + "\n```"
    v = parse_verdict(raw)
    assert isinstance(v, Verdict)


def test_parser_handles_preamble_and_trailing_prose():
    raw = "Here is my verdict:\n" + json.dumps(_verdict_dict()) + "\nHope that helps."
    v = parse_verdict(raw)
    assert v.severity == "INFO"


def test_parser_rejects_garbage():
    with pytest.raises(VerdictParseError):
        parse_verdict("no json here at all")


def test_parser_rejects_unknown_category():
    d = _verdict_dict(
        findings=[{
            "category": "NOT_A_REAL_CATEGORY", "severity": "HIGH", "confidence": "HIGH",
            "file": "x.py", "line": 1, "description": "d", "exploit_scenario": "",
            "recommended_fix": "", "secure_patch": "",
        }]
    )
    with pytest.raises(VerdictParseError):
        parse_verdict(json.dumps(d))


def test_parser_rejects_missing_dimension():
    checks = _checks()
    del checks["auth"]
    d = _verdict_dict(checks_performed=checks)
    with pytest.raises(VerdictParseError):
        parse_verdict(json.dumps(d))


# ---------------- gate ----------------

def test_gate_blocks_not_checked():
    d = _verdict_dict(checks_performed=_checks(auth={"status": "not_checked", "note": ""}))
    res = enforce(parse_verdict(json.dumps(d)))
    assert not res.production_ready
    assert any("R1" in r for r in res.blocking_reasons)


def test_gate_blocks_failed_dimension():
    d = _verdict_dict(checks_performed=_checks(secrets={"status": "fail", "note": "leak"}))
    res = enforce(parse_verdict(json.dumps(d)))
    assert not res.production_ready
    assert any("R2" in r for r in res.blocking_reasons)


def test_gate_blocks_high_finding():
    d = _verdict_dict(
        findings=[{
            "category": "XSS", "severity": "HIGH", "confidence": "HIGH",
            "file": "x.js", "line": 1, "description": "xss", "exploit_scenario": "",
            "recommended_fix": "escape", "secure_patch": "+ escape()",
        }]
    )
    res = enforce(parse_verdict(json.dumps(d)))
    assert not res.production_ready
    assert any("R3" in r for r in res.blocking_reasons)


def test_gate_detects_contradiction():
    # finding says SQLi but input_validation marked pass
    d = _verdict_dict(
        severity="CRITICAL",
        risk_score=90,
        findings=[{
            "category": "SQL_INJECTION", "severity": "CRITICAL", "confidence": "HIGH",
            "file": "x.py", "line": 1, "description": "sqli", "exploit_scenario": "",
            "recommended_fix": "param", "secure_patch": "+ %s",
        }],
    )
    res = enforce(parse_verdict(json.dumps(d)))
    assert any("R5" in r for r in res.blocking_reasons)


def test_gate_overrides_model_optimism():
    # Nullsec-1 claims production_ready True with a CRITICAL finding
    d = _verdict_dict(
        production_ready=True,
        severity="INFO",
        risk_score=0,
        findings=[{
            "category": "COMMAND_INJECTION", "severity": "CRITICAL", "confidence": "HIGH",
            "file": "x.py", "line": 1, "description": "ci", "exploit_scenario": "",
            "recommended_fix": "execFile", "secure_patch": "+ execFile()",
        }],
    )
    v = parse_verdict(json.dumps(d))
    normalize_finding_severities(v)
    res = enforce(v)
    assert res.production_ready is False
    assert res.verdict.production_ready is False
    # severity and risk were floored up from findings
    assert res.verdict.severity == "CRITICAL"
    assert res.verdict.risk_score >= 90


def test_gate_passes_genuinely_clean():
    res = enforce(parse_verdict(json.dumps(_verdict_dict())))
    assert res.production_ready
    assert res.blocking_reasons == []


def test_normalize_raises_lax_finding_severity():
    # SQL_INJECTION labeled LOW should be floored to its taxonomy default
    d = _verdict_dict(
        severity="LOW", risk_score=10,
        checks_performed=_checks(input_validation={"status": "fail", "note": "sqli"}),
        findings=[{
            "category": "SQL_INJECTION", "severity": "LOW", "confidence": "HIGH",
            "file": "x.py", "line": 1, "description": "sqli", "exploit_scenario": "",
            "recommended_fix": "param", "secure_patch": "+ %s",
        }],
    )
    v = parse_verdict(json.dumps(d))
    normalize_finding_severities(v)
    assert v.findings[0].severity == "CRITICAL"


# ---------------- taxonomy ----------------

def test_all_categories_have_required_dimension():
    from taxonomy import check_dimension_for
    for cid in category_ids():
        assert check_dimension_for(cid) in set(REQUIRED_CHECK_DIMENSIONS)


def test_severity_ordering():
    assert severity_rank("CRITICAL") > severity_rank("HIGH") > severity_rank("LOW")


# ---------------- corpus consistency ----------------

def test_corpus_examples_all_valid_and_gated():
    from corpus import load_corpus
    for ex in load_corpus():
        v = parse_verdict(json.dumps(ex["verdict"]))
        normalize_finding_severities(v)
        res = enforce(v)
        assert res.production_ready == ex["expected_production_ready"], ex["id"]


# ---------------- metrics ----------------

def test_metrics_perfect_detection():
    from benchmarks.metrics import Aggregate, score_case
    case = {
        "id": "t", "expected_categories": ["SQL_INJECTION"],
        "expected_min_severity": "HIGH", "expected_production_ready": False,
    }
    d = _verdict_dict(
        severity="CRITICAL", risk_score=90,
        checks_performed=_checks(input_validation={"status": "fail", "note": "sqli"}),
        findings=[{
            "category": "SQL_INJECTION", "severity": "CRITICAL", "confidence": "HIGH",
            "file": "x.py", "line": 1, "description": "sqli", "exploit_scenario": "",
            "recommended_fix": "param", "secure_patch": "+ cur.execute(q, (u,))",
        }],
    )
    v = parse_verdict(json.dumps(d)); normalize_finding_severities(v); enforce(v)
    cs = score_case(case, v, True)
    assert cs.true_pos == 1 and cs.false_pos == 0 and cs.false_neg == 0
    assert cs.severity_ok and cs.verdict_ok
    agg = Aggregate(); agg.add(cs)
    rep = agg.report()
    assert rep["detection_f1"] == 1.0


# ---------------- extended benchmark metrics ----------------

def _v(**kw):
    """Build an aligned+enforced verdict from a dict for metric tests."""
    from nullsec.safety import align_and_enforce
    import json as _json
    return align_and_enforce(_json.dumps(_verdict_dict(**kw))).verdict


def test_false_safe_rate_flags_hidden_finding():
    from benchmarks.metrics import false_safe_rate
    # unsafe case, but model hid the finding and claimed all-pass -> genuine false-safe
    v = _v()  # clean-looking verdict, production_ready stays True after enforce
    cases = [{"id": "x", "expected_categories": ["SQL_INJECTION"],
              "expected_min_severity": "HIGH", "expected_production_ready": False}]
    r = false_safe_rate(cases, {"x": (v, True)})
    assert r["false_safe_count"] == 1 and r["false_safe_rate"] == 1.0


def test_false_safe_rate_zero_when_blocked():
    from benchmarks.metrics import false_safe_rate
    v = _v(checks_performed=_checks(input_validation={"status": "fail", "note": "sqli"}),
           findings=[{"category": "SQL_INJECTION", "severity": "CRITICAL", "confidence": "HIGH",
                      "file": "x.py", "line": 1, "description": "sqli", "exploit_scenario": "",
                      "recommended_fix": "param", "secure_patch": "+ %s"}])
    cases = [{"id": "x", "expected_categories": ["SQL_INJECTION"],
              "expected_min_severity": "HIGH", "expected_production_ready": False}]
    r = false_safe_rate(cases, {"x": (v, True)})
    assert r["false_safe_count"] == 0 and r["false_safe_rate"] == 0.0


def test_hallucination_rate_counts_invented_findings():
    from benchmarks.metrics import hallucination_rate
    v = _v(checks_performed=_checks(input_validation={"status": "fail", "note": "ghost"}),
           findings=[{"category": "SQL_INJECTION", "severity": "HIGH", "confidence": "HIGH",
                      "file": "ok.py", "line": 1, "description": "not real", "exploit_scenario": "",
                      "recommended_fix": "", "secure_patch": "+ x"}])
    cases = [{"id": "c", "expected_categories": [], "expected_min_severity": "INFO",
              "expected_production_ready": True}]
    r = hallucination_rate(cases, {"c": (v, True)})
    assert r["clean_cases_flagged"] == 1 and r["hallucination_rate"] == 1.0


def test_owasp_coverage_buckets_by_tag():
    from benchmarks.metrics import owasp_coverage
    v = _v(checks_performed=_checks(input_validation={"status": "fail", "note": "sqli"}),
           findings=[{"category": "SQL_INJECTION", "severity": "CRITICAL", "confidence": "HIGH",
                      "file": "x.py", "line": 1, "description": "sqli", "exploit_scenario": "",
                      "recommended_fix": "param", "secure_patch": "+ %s"}])
    cases = [{"id": "x", "owasp": "A03:2021-Injection", "expected_categories": ["SQL_INJECTION"],
              "expected_min_severity": "HIGH", "expected_production_ready": False}]
    r = owasp_coverage(cases, {"x": (v, True)})
    assert r["coverage"] == 1.0
    assert r["per_category"]["A03:2021-Injection"]["recall"] == 1.0


def test_missing_output_is_a_real_miss_not_fabricated():
    from benchmarks.metrics import detection_over
    cases = [{"id": "x", "expected_categories": ["SQL_INJECTION"],
              "expected_min_severity": "HIGH", "expected_production_ready": False}]
    # no verdict supplied for the case -> recorded as a miss
    r = detection_over(cases, {})
    assert r["false_negatives"] == 1 and r["detection_recall"] == 0.0


# ---------------- adversarial Safety Layer probes ----------------

def test_safety_probes_all_blocked():
    from benchmarks.safety_probes import run_safety_probes
    out = run_safety_probes()
    assert out["passed"] is True, f"Safety Layer bypassed by: {out['bypassed']}"
    assert out["total_probes"] >= 8


def test_underreported_severity_cannot_pass():
    # A SQLi labeled LOW must be normalized up and then blocked.
    from benchmarks.safety_probes import PROBES
    from nullsec.safety import align_and_enforce
    res = align_and_enforce(PROBES["underreported_severity"]())
    assert res.production_ready is False
