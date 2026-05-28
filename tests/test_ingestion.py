"""Tests for the curated ingestion workflow.

These prove the safety guarantees of the pipeline:
  - raw imports do not count as curated
  - pending candidates do not enter training
  - rejected candidates do not enter training
  - approved examples enter only after validation
  - invalid candidates are blocked from approval
  - approved curated_ingested counts toward the threshold only with --include-ingested
"""
import json
from pathlib import Path

import pytest

import training._ingest_store as store
from nullsec.core.models import REQUIRED_DIMENSIONS


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Redirect all ingestion stores into a temp dir so tests never touch real data."""
    raw = tmp_path / "raw"
    cand = tmp_path / "candidates"
    rej = tmp_path / "rejected"
    cur = tmp_path / "curated"
    for d in (raw, cand, rej, cur):
        d.mkdir(parents=True)
    monkeypatch.setattr(store, "RAW_DIR", raw)
    monkeypatch.setattr(store, "CANDIDATES_DIR", cand)
    monkeypatch.setattr(store, "REJECTED_DIR", rej)
    monkeypatch.setattr(store, "CURATED_DIR", cur)
    # the CLI module imports these names at module load; patch there too
    import training.curate_ingested as ci
    monkeypatch.setattr(ci, "CANDIDATES_DIR", cand)
    monkeypatch.setattr(ci, "REJECTED_DIR", rej)
    monkeypatch.setattr(ci, "CURATED_DIR", cur)
    return tmp_path


def _complete_verdict():
    checks = {d: {"status": "pass", "note": "ok"} for d in REQUIRED_DIMENSIONS}
    checks["dangerous_exec"] = {"status": "fail", "note": "os.system"}
    return {
        "risk_score": 90, "production_ready": False, "severity": "CRITICAL",
        "confidence": "HIGH", "reasoning_summary": "user input to os.system",
        "exploit_scenario": "name='; rm -rf /' runs commands",
        "affected_files": ["runner.py"], "checks_performed": checks,
        "findings": [{
            "category": "COMMAND_INJECTION", "severity": "CRITICAL", "confidence": "HIGH",
            "file": "runner.py", "line": 2, "description": "os.system with user input",
            "exploit_scenario": "name='; rm -rf /'", "recommended_fix": "use arg list",
            "secure_patch": "-os.system('echo '+name)\n+subprocess.run(['echo', name])",
        }],
    }


def _incomplete_verdict():
    checks = {d: {"status": "not_checked", "note": "cve"} for d in REQUIRED_DIMENSIONS}
    checks["input_validation"] = {"status": "fail", "note": "cve"}
    return {
        "risk_score": 90, "production_ready": False, "severity": "CRITICAL",
        "confidence": "MEDIUM", "reasoning_summary": "cve sqli", "exploit_scenario": "x",
        "affected_files": [], "checks_performed": checks,
        "findings": [{
            "category": "SQL_INJECTION", "severity": "CRITICAL", "confidence": "MEDIUM",
            "file": "login.py", "line": 1, "description": "cve sqli",
            "exploit_scenario": "x", "recommended_fix": "param", "secure_patch": "",  # no patch
        }],
    }


def _stage(isolated, name, rec):
    p = store.RAW_DIR / name
    p.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    return p


def _import(path, source_type=None):
    import argparse
    import training.curate_ingested as ci
    ns = argparse.Namespace(paths=[str(path)], source_type=source_type, force=False)
    return ci.cmd_import(ns)


def _approve(cid, note=None):
    import argparse
    import training.curate_ingested as ci
    return ci.cmd_approve(argparse.Namespace(candidate_id=cid, note=note))


def _reject(cid, reason):
    import argparse
    import training.curate_ingested as ci
    return ci.cmd_reject(argparse.Namespace(candidate_id=cid, reason=reason))


def _curated_in(curated_dir: Path):
    out = []
    for fp in curated_dir.glob("*.jsonl"):
        out.extend(json.loads(l) for l in fp.read_text().splitlines() if l.strip())
    return out


def test_raw_import_does_not_count_as_curated(isolated):
    _stage(isolated, "cve.jsonl", {"filename": "x.txt", "lang": "", "code": "c1",
                                   "verdict": _incomplete_verdict()})
    _import(store.RAW_DIR / "cve.jsonl")
    # candidate exists but is needs_human_review / pending
    cands = store.iter_candidates()
    assert len(cands) == 1
    assert cands[0]["provenance"] == store.NEEDS_REVIEW
    assert cands[0]["reviewer_status"] == "pending"
    # nothing written to curated
    assert _curated_in(store.CURATED_DIR) == []


def test_pending_candidate_not_in_training(isolated):
    _stage(isolated, "vibe.jsonl", {"filename": "runner.py", "lang": "python",
                                    "code": "code", "verdict": _complete_verdict(),
                                    "references": {"case_id": "VIBE-T-1"},
                                    "reviewer_notes": "AI-generated app failure from scanner; vibecoded."})
    _import(store.RAW_DIR / "vibe.jsonl", source_type="vibecoded")
    # pending -> not curated, not in corpus/ingested
    assert _curated_in(store.CURATED_DIR) == []


def test_invalid_candidate_is_blocked_from_approval(isolated):
    _stage(isolated, "cve.jsonl", {"filename": "x.txt", "lang": "", "code": "c1",
                                   "verdict": _incomplete_verdict()})
    _import(store.RAW_DIR / "cve.jsonl")
    cid = store.iter_candidates()[0]["id"]
    rc = _approve(cid)
    assert rc == 1, "approval of an incomplete candidate must fail"
    assert _curated_in(store.CURATED_DIR) == [], "blocked candidate must not be curated"


def test_approved_example_enters_only_after_validation(isolated):
    _stage(isolated, "vibe.jsonl", {"filename": "runner.py", "lang": "python",
                                    "code": "code", "verdict": _complete_verdict(),
                                    "references": {"case_id": "VIBE-T-2"},
                                    "reviewer_notes": "AI-generated app failure from scanner output; vibecoded endpoint."})
    _import(store.RAW_DIR / "vibe.jsonl", source_type="vibecoded")
    cid = store.iter_candidates()[0]["id"]
    rc = _approve(cid, note="AI-generated app failure from scanner output; vibecoded endpoint.")
    assert rc == 0
    curated = _curated_in(store.CURATED_DIR)
    assert len(curated) == 1
    assert curated[0]["provenance"] == "curated_ingested"


def test_rejected_example_never_enters_training(isolated):
    _stage(isolated, "cve.jsonl", {"filename": "x.txt", "lang": "", "code": "c1",
                                   "verdict": _incomplete_verdict()})
    _import(store.RAW_DIR / "cve.jsonl")
    cid = store.iter_candidates()[0]["id"]
    _reject(cid, "bad")
    # removed from active candidates, recorded in rejected store, not curated
    assert all(c["id"] != cid for c in store.iter_candidates())
    assert any(c["id"] == cid for c in store.iter_rejected())
    assert _curated_in(store.CURATED_DIR) == []


def test_threshold_includes_curated_ingested_only_with_flag(tmp_path, monkeypatch):
    """An approved curated_ingested example counts toward curated only with
    include_ingested=True."""
    import corpus
    ing_dir = tmp_path / "ingested"
    ing_dir.mkdir()
    example = {
        "id": "ing-test", "lang": "python", "framework": "none", "code": "x",
        "verdict": _complete_verdict(), "expected_production_ready": False,
        "provenance": "curated_ingested", "source": "vibecoded:test",
    }
    (ing_dir / "vibecoded.jsonl").write_text(json.dumps(example) + "\n")
    monkeypatch.setattr(corpus, "INGESTED_DIR", ing_dir)

    base = len(corpus.load_corpus())
    with_ing = len(corpus.load_corpus(include_ingested=True))
    assert with_ing == base + 1
    # and it is counted as curated
    assert all(corpus.is_curated(e) for e in corpus.load_corpus(include_ingested=True)
               if e["id"] == "ing-test")
