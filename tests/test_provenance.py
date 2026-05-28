"""Tests for provenance enforcement (Sprint 002)."""
from training.provenance import provenance_blockers


def _cand(source_type, references=None, source_reference="x", reviewer_notes=""):
    return {
        "source_type": source_type,
        "references": references or {},
        "source_reference": source_reference,
        "reviewer_notes": reviewer_notes,
    }


def test_cve_requires_real_cve_id_and_cwe():
    assert provenance_blockers(_cand("cve", {"cwe": "CWE-89"}, "no id"))
    assert provenance_blockers(_cand("cve", {"cve": "CVE-2021-44228"}))  # missing cwe
    assert not provenance_blockers(_cand("cve", {"cve": "CVE-2021-44228", "cwe": "CWE-502"}, "Log4Shell"))


def test_cve_rejects_malformed_id():
    assert provenance_blockers(_cand("cve", {"cve": "CVE-bogus", "cwe": "CWE-89"}, "bad"))


def test_semgrep_requires_rule_id():
    assert provenance_blockers(_cand("semgrep", {}, "some rule"))
    assert not provenance_blockers(_cand("semgrep", {"rule_id": "python.lang.security.x"}, "rule"))


def test_owasp_requires_category():
    assert provenance_blockers(_cand("owasp", {}, "OWASP thing"))
    assert not provenance_blockers(_cand("owasp", {"owasp": "A03:2021-Injection"}, "Injection"))


def test_sarif_requires_rule_id():
    assert provenance_blockers(_cand("sarif", {}, "finding"))
    assert not provenance_blockers(_cand("sarif", {"rule_id": "js/sql-injection"}, "finding"))


def test_vibecoded_requires_case_id_and_notes():
    assert provenance_blockers(_cand("vibecoded_failure", {}, "scan", ""))
    assert provenance_blockers(_cand("vibecoded_failure", {"case_id": "V-1"}, "scan", "short"))
    assert not provenance_blockers(
        _cand("vibecoded_failure", {"case_id": "V-1"}, "scan",
              "This is an AI-generated app failure observed in scanner output.")
    )


def test_vague_reference_rejected_without_stable_ref():
    for vague in ("internet", "blog", "known issue", "common vulnerability"):
        assert provenance_blockers(_cand("owasp", {}, vague)), f"{vague} should be rejected"


def test_vague_reference_allowed_with_stable_ref():
    # vague top-level text is fine if a stable reference is attached
    assert not provenance_blockers(
        _cand("owasp", {"owasp": "A03:2021-Injection", "url": "https://owasp.org/x"}, "blog")
    )
