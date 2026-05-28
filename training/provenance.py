"""Provenance enforcement for curated ingestion.

A `curated_ingested` example is only defensible if its claimed source can be
audited. This module enforces source-type-specific reference requirements and
rejects vague, unciteable references. It is consulted at approval time, so a
candidate with weak provenance cannot become curated.

Rules (Sprint 002):
  - source_type == cve       -> requires a real-looking CVE ID (CVE-YYYY-N+);
                                CWE required when available (we require it here).
  - source_type == semgrep   -> requires a rule_id or stable rule reference.
  - source_type == owasp     -> requires an OWASP category reference.
  - source_type == sarif/codeql -> requires a rule_id (the SARIF ruleId).
  - source_type == vibecoded_failure -> requires a local case_id AND reviewer
                                notes explaining why it is an AI-generated app failure.
  - Any source: a reference that is only a vague word ("internet", "blog",
    "known issue", "common vulnerability", ...) is rejected unless a stable
    reference (cve/cwe/rule_id/owasp/url/case_id) is also attached.
"""
from __future__ import annotations

import re

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)

# Vague terms that are not, by themselves, an auditable source.
VAGUE_TERMS = (
    "internet", "blog", "known issue", "common vulnerability", "common knowledge",
    "online", "various", "misc", "general", "somewhere", "a website", "forum",
    "stackoverflow", "stack overflow", "reddit", "tweet", "twitter",
)

# Accepted aliases for vibecoded source type.
VIBECODED_TYPES = ("vibecoded", "vibecoded_failure")

STABLE_REF_KEYS = ("cve", "cwe", "rule_id", "owasp", "url", "case_id", "swc", "ref_url")


def _has_stable_reference(refs: dict) -> bool:
    for k in STABLE_REF_KEYS:
        v = refs.get(k)
        if isinstance(v, str) and v.strip():
            return True
    return False


def _ref_is_vague(text: str) -> bool:
    t = (text or "").strip().lower()
    if not t:
        return True
    # exact or token match against vague terms
    return any(t == term or t.startswith(term + " ") or t == term + "s" for term in VAGUE_TERMS)


def provenance_blockers(candidate: dict) -> list[str]:
    """Return reasons the candidate's provenance is insufficient (empty == ok)."""
    issues: list[str] = []
    st = (candidate.get("source_type") or "").strip().lower()
    refs = candidate.get("references") or {}
    source_ref = candidate.get("source_reference") or ""
    notes = (candidate.get("reviewer_notes") or "").strip()

    if not st:
        issues.append("missing source_type")

    # Vague top-level reference with no stable identifier attached is rejected.
    if _ref_is_vague(source_ref) and not _has_stable_reference(refs):
        issues.append(
            f"vague source_reference '{source_ref}' with no stable reference "
            "(attach cve/cwe/rule_id/owasp/url/case_id)"
        )

    if st == "cve":
        cve = (refs.get("cve") or "").strip()
        if not CVE_RE.match(cve):
            issues.append(f"source_type=cve requires a real CVE ID (got '{cve or 'none'}')")
        cwe = (refs.get("cwe") or "").strip()
        if not CWE_RE.match(cwe):
            issues.append("source_type=cve requires a CWE id (e.g. CWE-89) where available")

    elif st == "semgrep":
        rule = (refs.get("rule_id") or "").strip()
        if not rule:
            issues.append("source_type=semgrep requires a rule_id / stable rule reference")

    elif st == "owasp":
        owasp = (refs.get("owasp") or "").strip()
        if not owasp:
            issues.append("source_type=owasp requires an OWASP category reference (e.g. A03:2021, LLM01:2025)")

    elif st in ("sarif", "codeql"):
        rule = (refs.get("rule_id") or "").strip()
        if not rule:
            issues.append(f"source_type={st} requires a rule_id (the SARIF ruleId)")

    elif st in VIBECODED_TYPES:
        case_id = (refs.get("case_id") or "").strip()
        if not case_id:
            issues.append("source_type=vibecoded_failure requires a local case_id in references")
        if len(notes) < 20 or "ai" not in notes.lower() and "generat" not in notes.lower() and "vibe" not in notes.lower():
            issues.append(
                "source_type=vibecoded_failure requires reviewer_notes explaining why this is an "
                "AI-generated app failure"
            )

    return issues
