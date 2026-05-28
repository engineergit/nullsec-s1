#!/usr/bin/env python3
"""Ingest real-world findings into Nullsec training examples.

Supports:
  - Semgrep JSON  (`semgrep --json`)
  - SARIF 2.1.0   (CodeQL, Semgrep, many scanners export this)

Each finding is mapped onto the Nullsec taxonomy via a rule->category table and
emitted as a raw example ({filename, lang, code, verdict}) into data/raw/. These
are then validated + gated by training/prepare_dataset.py before training.

IMPORTANT: auto-ingested verdicts are SINGLE-finding skeletons. They are a
scaling aid, not gold labels — review/augment them (especially the secure_patch
and checks_performed fields) before relying on them for production training.

Usage:
  python -m nullsec.ingest.import_scanners --semgrep results.json --out data/raw/semgrep.jsonl
  python -m nullsec.ingest.import_scanners --sarif codeql.sarif --out data/raw/codeql.jsonl

NOTE: ingestion output is RAW/uncurated staging. It is not training-eligible until validated and human-curated into corpus/ingested/ (provenance curated_ingested), per the curated data ingestion workflow.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from taxonomy import REQUIRED_CHECK_DIMENSIONS, default_severity  # noqa: E402

# Map scanner rule fragments -> Nullsec category. Extend freely.
RULE_MAP = {
    "sql": "SQL_INJECTION",
    "injection.sql": "SQL_INJECTION",
    "xss": "XSS",
    "command-injection": "COMMAND_INJECTION",
    "os-command": "COMMAND_INJECTION",
    "ssrf": "SSRF",
    "hardcoded": "EXPOSED_SECRET",
    "secret": "EXPOSED_SECRET",
    "credential": "EXPOSED_SECRET",
    "path-traversal": "UNSAFE_FILE_UPLOAD",
    "upload": "UNSAFE_FILE_UPLOAD",
    "auth": "BROKEN_AUTH",
    "rate": "MISSING_RATE_LIMIT",
    "reentrancy": "SMART_CONTRACT_RISK",
    "dependency": "DEPENDENCY_RISK",
    "vulnerable-dependency": "DEPENDENCY_RISK",
}

_EXT_LANG = {".py": "python", ".js": "javascript", ".ts": "typescript", ".sol": "solidity"}


def map_rule(rule_id: str) -> str:
    rid = rule_id.lower()
    for frag, cat in RULE_MAP.items():
        if frag in rid:
            return cat
    return "DEPENDENCY_RISK"  # conservative default; review before use


def _skeleton_verdict(filename: str, category: str, line: int, msg: str) -> dict:
    sev = default_severity(category)
    checks = {d: {"status": "not_checked", "note": "auto-ingested; review"}
              for d in REQUIRED_CHECK_DIMENSIONS}
    # mark the dimension this finding implicates as fail
    from taxonomy import check_dimension_for

    dim = check_dimension_for(category)
    if dim:
        checks[dim] = {"status": "fail", "note": f"scanner: {msg[:120]}"}
    return {
        "risk_score": 70 if sev in ("HIGH", "CRITICAL") else 40,
        "production_ready": False,
        "severity": sev,
        "confidence": "MEDIUM",
        "reasoning_summary": f"Scanner-reported {category}: {msg[:200]}",
        "exploit_scenario": None,
        "affected_files": [filename],
        "checks_performed": checks,
        "findings": [
            {
                "category": category,
                "severity": sev,
                "confidence": "MEDIUM",
                "file": filename,
                "line": line,
                "description": msg[:500],
                "exploit_scenario": "See scanner reference.",
                "recommended_fix": "NEEDS_CURATION: add remediation before training.",
                "secure_patch": "NEEDS_CURATION: add secure patch before training.",
            }
        ],
    }


def from_semgrep(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    out = []
    for r in data.get("results", []):
        fn = r.get("path", "unknown")
        line = (r.get("start") or {}).get("line", 0)
        cat = map_rule(r.get("check_id", ""))
        msg = (r.get("extra") or {}).get("message", r.get("check_id", ""))
        snippet = (r.get("extra") or {}).get("lines", "")
        out.append({
            "filename": Path(fn).name,
            "lang": _EXT_LANG.get(Path(fn).suffix, ""),
            "code": snippet or f"# {fn}:{line}",
            "verdict": _skeleton_verdict(Path(fn).name, cat, line, msg),
        })
    return out


def from_sarif(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    out = []
    for run in data.get("runs", []):
        for res in run.get("results", []):
            rule = res.get("ruleId", "")
            cat = map_rule(rule)
            msg = (res.get("message") or {}).get("text", rule)
            locs = res.get("locations", [])
            fn, line = "unknown", 0
            if locs:
                phys = locs[0].get("physicalLocation", {})
                fn = phys.get("artifactLocation", {}).get("uri", "unknown")
                line = phys.get("region", {}).get("startLine", 0)
            out.append({
                "filename": Path(fn).name,
                "lang": _EXT_LANG.get(Path(fn).suffix, ""),
                "code": f"# {fn}:{line} (snippet unavailable from SARIF)",
                "verdict": _skeleton_verdict(Path(fn).name, cat, line, msg),
            })
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep")
    ap.add_argument("--sarif")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    records = []
    if args.semgrep:
        records += from_semgrep(Path(args.semgrep))
    if args.sarif:
        records += from_sarif(Path(args.sarif))
    if not records:
        raise SystemExit("provide --semgrep and/or --sarif")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} raw examples -> {out}")
    print("NOTE: review recommended_fix / secure_patch / checks_performed before training.")


if __name__ == "__main__":
    main()
