#!/usr/bin/env python3
"""Curated ingestion workflow for Nullsec-1.

Turns staged raw security findings into real, human-reviewed curated training
examples. Nothing is auto-approved: import creates pending candidates, and only
an explicit `approve` — which validates the candidate — writes a curated example
into corpus/ingested/.

  # 1) stage raw findings (CVE/Semgrep/SARIF/vibecoded) into data/raw/*.jsonl
  python -m nullsec.ingest.import_cve --feed nvd.json --out data/raw/cve.jsonl

  # 2) build review candidates (all start pending / needs_human_review)
  python training/curate_ingested.py import data/raw/cve.jsonl
  python training/curate_ingested.py list --status pending
  python training/curate_ingested.py show <candidate_id>

  # 3) human review
  python training/curate_ingested.py approve <candidate_id>
  python training/curate_ingested.py reject  <candidate_id> --reason "duplicate of X"

Approval requires a real secure patch, complete checks_performed, and Safety
Layer consistency. Rejected candidates move to data/ingest_rejected/ and never
enter training.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from training._ingest_store import (  # noqa: E402
    CANDIDATES_DIR,
    CURATED_DIR,
    REJECTED_DIR,
    candidate_path,
    ensure_dirs,
    iter_candidates,
    load_candidate,
    make_candidate,
    save_candidate,
    to_corpus_example,
)
from training.provenance import provenance_blockers  # noqa: E402
from training.validate_corpus import validate_example  # noqa: E402


# --------------------------------------------------------------------------
# import: staged raw records -> pending candidates
# --------------------------------------------------------------------------
def _detect_source_type(path: Path) -> str:
    n = path.name.lower()
    if "cve" in n or "nvd" in n:
        return "cve"
    if "semgrep" in n:
        return "semgrep"
    if "sarif" in n or "codeql" in n:
        return "sarif"
    if "vibe" in n or "failure" in n:
        return "vibecoded"
    return "staged"


def cmd_import(args) -> int:
    ensure_dirs()
    created = skipped = 0
    for raw_path in args.paths:
        p = Path(raw_path)
        if not p.exists():
            print(f"  missing: {p}", file=sys.stderr)
            continue
        source_type = args.source_type or _detect_source_type(p)
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            verdict = rec.get("verdict", {})
            source_ref = (
                rec.get("source_reference")
                or (verdict.get("findings") or [{}])[0].get("description", "")[:40]
                or rec.get("filename", "unknown")
            )
            cand = make_candidate(
                source_type=rec.get("source_type") or source_type,
                source_ref=source_ref,
                filename=rec.get("filename", "input"),
                lang=rec.get("lang", ""),
                framework=rec.get("framework", "none"),
                code=rec.get("code", ""),
                verdict=verdict,
                references=rec.get("references"),
                reviewer_notes=rec.get("reviewer_notes", ""),
            )
            path = candidate_path(cand["id"])
            if path.exists() and not args.force:
                skipped += 1
                continue
            save_candidate(cand)
            created += 1
    print(f"import: {created} candidate(s) created, {skipped} already existed (pending review).")
    print("None of these count as curated until explicitly approved.")
    return 0


# --------------------------------------------------------------------------
# list / show
# --------------------------------------------------------------------------
def cmd_list(args) -> int:
    cands = iter_candidates()
    if args.status:
        cands = [c for c in cands if c.get("reviewer_status") == args.status]
    if not cands:
        print("(no candidates)")
        return 0
    for c in cands:
        print(f"{c['reviewer_status']:<8} {c['provenance']:<18} {c['id']:<40} "
              f"{c.get('category_suggestion')} / {c.get('severity_suggestion')}  [{c['source_type']}]")
    print(f"\n{len(cands)} candidate(s).")
    return 0


def cmd_show(args) -> int:
    c = load_candidate(args.candidate_id)
    if not c:
        print(f"no candidate '{args.candidate_id}'", file=sys.stderr)
        return 2
    print(json.dumps(c, indent=2))
    return 0


# --------------------------------------------------------------------------
# approve: validate -> write curated example
# --------------------------------------------------------------------------
def _approval_blockers(c: dict) -> list[str]:
    """Reasons this candidate may NOT be approved. Empty == approvable."""
    issues: list[str] = []
    patch = (c.get("proposed_secure_patch") or "").strip()
    findings = c.get("proposed_verdict", {}).get("findings", [])
    # require a real secure patch on each finding
    for f in findings:
        if len((f.get("secure_patch") or "").strip()) < 8:
            issues.append(f"finding '{f.get('category')}' has no real secure_patch")
    if findings and len(patch) < 8:
        issues.append("proposed_secure_patch is empty")
    # provenance must be auditable (source-type-specific reference requirements)
    issues.extend(provenance_blockers(c))
    # full validation through the same corpus validator (checks completeness,
    # contradictions, Safety Layer consistency, etc.)
    example = to_corpus_example(c)
    issues.extend(validate_example(example))
    return issues


def cmd_approve(args) -> int:
    c = load_candidate(args.candidate_id)
    if not c:
        print(f"no candidate '{args.candidate_id}'", file=sys.stderr)
        return 2
    if c.get("reviewer_status") == "rejected":
        print("candidate was rejected; re-import to reconsider", file=sys.stderr)
        return 1

    blockers = _approval_blockers(c)
    if blockers:
        print(f"APPROVAL BLOCKED for {c['id']}:")
        for b in blockers:
            print(f"  - {b}")
        print("Fix the candidate JSON (real secure patch, complete checks_performed, "
              "consistent verdict) and approve again.")
        return 1

    # promote
    ensure_dirs()
    c["reviewer_status"] = "approved"
    c["provenance"] = "curated_ingested"
    if args.note:
        c["reviewer_notes"] = args.note
    save_candidate(c)

    example = to_corpus_example(c)
    out_file = CURATED_DIR / f"{c['source_type']}.jsonl"
    # de-dup by example id within the shard
    existing = []
    if out_file.exists():
        existing = [json.loads(l) for l in out_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    if any(e.get("id") == example["id"] for e in existing):
        print(f"already curated: {example['id']}")
        return 0
    with out_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(example) + "\n")
    print(f"APPROVED {c['id']} -> {out_file} (provenance: curated_ingested)")
    print("It counts toward curated thresholds only via --include-ingested and after validate_corpus passes.")
    return 0


# --------------------------------------------------------------------------
# reject: move to rejected store
# --------------------------------------------------------------------------
def cmd_reject(args) -> int:
    c = load_candidate(args.candidate_id)
    if not c:
        print(f"no candidate '{args.candidate_id}'", file=sys.stderr)
        return 2
    ensure_dirs()
    c["reviewer_status"] = "rejected"
    c["provenance"] = "rejected"
    c["reviewer_notes"] = args.reason
    (REJECTED_DIR / f"{c['id']}.json").write_text(json.dumps(c, indent=2), encoding="utf-8")
    # remove from active candidates so it can never be approved/loaded into training
    cp = candidate_path(c["id"])
    if cp.exists():
        cp.unlink()
    print(f"REJECTED {c['id']} -> {REJECTED_DIR} (reason: {args.reason})")
    print("Rejected candidates are never read by training.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Nullsec-1 curated ingestion workflow")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("import", help="build pending candidates from staged raw records")
    pi.add_argument("paths", nargs="+", help="staged raw .jsonl files (e.g. data/raw/cve.jsonl)")
    pi.add_argument("--source-type", default=None, help="override detected source type")
    pi.add_argument("--force", action="store_true", help="overwrite existing candidates")
    pi.set_defaults(func=cmd_import)

    pl = sub.add_parser("list", help="list candidates")
    pl.add_argument("--status", choices=["pending", "approved", "rejected"], default=None)
    pl.set_defaults(func=cmd_list)

    ps = sub.add_parser("show", help="print a candidate")
    ps.add_argument("candidate_id")
    ps.set_defaults(func=cmd_show)

    pa = sub.add_parser("approve", help="validate and curate a candidate")
    pa.add_argument("candidate_id")
    pa.add_argument("--note", default=None, help="reviewer note")
    pa.set_defaults(func=cmd_approve)

    pr = sub.add_parser("reject", help="reject a candidate (never trained)")
    pr.add_argument("candidate_id")
    pr.add_argument("--reason", required=True)
    pr.set_defaults(func=cmd_reject)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
