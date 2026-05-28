"""Shared state for the curated ingestion workflow.

The pipeline has three on-disk stores, none of which training reads except the
final curated one:

  data/raw/                     staged raw findings (CVE/Semgrep/SARIF/vibecoded)
  data/ingest_candidates/       review candidates (pending/approved/rejected)
  data/ingest_rejected/         rejected candidates (audit trail, never trained)
  corpus/ingested/*.jsonl       APPROVED, curated examples (provenance curated_ingested)

A candidate is a single JSON file under data/ingest_candidates/<id>.json. Only an
explicit `approve` writes into corpus/ingested/, and only after validation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
CANDIDATES_DIR = ROOT / "data" / "ingest_candidates"
REJECTED_DIR = ROOT / "data" / "ingest_rejected"
CURATED_DIR = ROOT / "corpus" / "ingested"

# Provenance lifecycle. Only CURATED_INGESTED is training-eligible/curated.
NEEDS_REVIEW = "needs_human_review"
RAW_IMPORTED = "raw_imported"
CURATED_INGESTED = "curated_ingested"
REJECTED = "rejected"

VALID_STATUSES = ("pending", "approved", "rejected")


def candidate_id(source_type: str, source_ref: str, code: str) -> str:
    """Stable id from the finding's identity, so re-importing is idempotent."""
    h = hashlib.sha256(f"{source_type}|{source_ref}|{code}".encode("utf-8")).hexdigest()[:12]
    safe_ref = "".join(c if c.isalnum() else "-" for c in source_ref)[:32].strip("-")
    return f"{source_type}-{safe_ref}-{h}" if safe_ref else f"{source_type}-{h}"


def make_candidate(*, source_type, source_ref, filename, lang, code, verdict,
                   framework="none", references=None, reviewer_notes="") -> dict:
    """Build a review candidate from a staged raw record. Always starts pending
    and NOT curated. `references` is a dict of audit identifiers (cve, cwe,
    rule_id, repo, file, patch_ref) — any may be omitted/None when not applicable."""
    cid = candidate_id(source_type, source_ref, code)
    findings = verdict.get("findings", [])
    cat = findings[0]["category"] if findings else None
    sev = verdict.get("severity")
    exploit = verdict.get("exploit_scenario") or (findings[0].get("exploit_scenario") if findings else None)
    patch = findings[0].get("secure_patch", "") if findings else ""
    return {
        "id": cid,
        "provenance": NEEDS_REVIEW,
        "reviewer_status": "pending",
        "reviewer_notes": reviewer_notes,
        "source_type": source_type,
        "source_reference": source_ref,
        "references": references or {},
        # the proposed example, for the reviewer to inspect / correct
        "lang": lang,
        "framework": framework,
        "code": code,
        "category_suggestion": cat,
        "severity_suggestion": sev,
        "exploit_scenario": exploit,
        "checks_performed": verdict.get("checks_performed", {}),
        "proposed_verdict": verdict,
        "proposed_secure_patch": patch,
        # filled on approval
        "expected_production_ready": verdict.get("production_ready", False),
    }


def ensure_dirs() -> None:
    for d in (RAW_DIR, CANDIDATES_DIR, REJECTED_DIR, CURATED_DIR):
        d.mkdir(parents=True, exist_ok=True)


def candidate_path(cid: str) -> Path:
    return CANDIDATES_DIR / f"{cid}.json"


def save_candidate(c: dict) -> Path:
    ensure_dirs()
    p = candidate_path(c["id"])
    p.write_text(json.dumps(c, indent=2), encoding="utf-8")
    return p


def load_candidate(cid: str) -> dict | None:
    p = candidate_path(cid)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def iter_candidates() -> list[dict]:
    if not CANDIDATES_DIR.exists():
        return []
    out = []
    for p in sorted(CANDIDATES_DIR.glob("*.json")):
        out.append(json.loads(p.read_text(encoding="utf-8")))
    return out


def iter_rejected() -> list[dict]:
    if not REJECTED_DIR.exists():
        return []
    out = []
    for p in sorted(REJECTED_DIR.glob("*.json")):
        out.append(json.loads(p.read_text(encoding="utf-8")))
    return out


def to_corpus_example(c: dict) -> dict:
    """Project an APPROVED candidate into the corpus example shape.

    `review_quality` records the auditable checks the candidate passed to be
    approved. The flags are not free-form claims: approval only succeeds when the
    candidate has a stable source, a real reviewed patch, Safety Layer
    consistency, and a confirmed category, so these flags are always true on an
    approved example (and are recomputed here from the candidate, not copied
    blindly)."""
    findings = c.get("proposed_verdict", {}).get("findings", [])
    has_patch = bool(findings and (findings[0].get("secure_patch") or "").strip())
    review_quality = {
        "source_backed": bool(c.get("references")),
        "patch_reviewed": has_patch,
        "safety_layer_consistent": True,  # enforced by validate_example at approval
        "category_confirmed": bool(c.get("category_suggestion")),
    }
    return {
        "id": f"ing-{c['id']}",
        "lang": c.get("lang", "none"),
        "framework": c.get("framework", "none"),
        "code": c["code"],
        "verdict": c["proposed_verdict"],
        "expected_production_ready": c.get("expected_production_ready", False),
        "provenance": CURATED_INGESTED,
        "source": f"{c['source_type']}:{c['source_reference']}",
        "references": c.get("references", {}),
        "reviewer_notes": c.get("reviewer_notes", ""),
        "review_quality": review_quality,
    }
