#!/usr/bin/env python3
"""Ingest CVE records (NVD JSON 2.0 schema) into Nullsec raw examples.

CVEs rarely ship runnable vulnerable/fixed code, so this produces *description-
level* training examples: the CWE is mapped to a Nullsec category and the CVE
description becomes the finding. Pair these with real patch commits where
available (the --patch-dir option scans for before/after snippets you've saved).

This is a scaling scaffold. CVE text alone trains classification, not patching;
attach real code for patch-quality signal.

Usage:
  python -m nullsec.ingest.import_cve --feed nvdcve-2.0.json --out data/raw/cve.jsonl

NOTE: ingestion output is RAW/uncurated staging. It is not training-eligible until validated and human-curated into corpus/ingested/ (provenance curated_ingested), per the curated data ingestion workflow.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from taxonomy import REQUIRED_CHECK_DIMENSIONS, check_dimension_for, default_severity  # noqa: E402

# CWE -> Nullsec category.
CWE_MAP = {
    "CWE-89": "SQL_INJECTION",
    "CWE-79": "XSS",
    "CWE-78": "COMMAND_INJECTION",
    "CWE-77": "COMMAND_INJECTION",
    "CWE-918": "SSRF",
    "CWE-798": "EXPOSED_SECRET",
    "CWE-312": "EXPOSED_SECRET",
    "CWE-287": "BROKEN_AUTH",
    "CWE-306": "BROKEN_AUTH",
    "CWE-862": "BROKEN_AUTH",
    "CWE-285": "UNSAFE_ADMIN_ROUTE",
    "CWE-434": "UNSAFE_FILE_UPLOAD",
    "CWE-22": "UNSAFE_FILE_UPLOAD",
    "CWE-770": "MISSING_RATE_LIMIT",
    "CWE-841": "SMART_CONTRACT_RISK",
    "CWE-1104": "DEPENDENCY_RISK",
    "CWE-829": "DEPENDENCY_RISK",
}

_CVSS_TO_SEV = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "INFO"),
]


def cvss_to_sev(score: float) -> str:
    for thresh, sev in _CVSS_TO_SEV:
        if score >= thresh:
            return sev
    return "INFO"


def _verdict(cve_id: str, category: str, sev: str, desc: str) -> dict:
    checks = {d: {"status": "not_checked", "note": "CVE-derived; code review needed"}
              for d in REQUIRED_CHECK_DIMENSIONS}
    dim = check_dimension_for(category)
    if dim:
        checks[dim] = {"status": "fail", "note": cve_id}
    return {
        "risk_score": {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 20, "INFO": 5}[sev],
        "production_ready": False,
        "severity": sev,
        "confidence": "MEDIUM",
        "reasoning_summary": f"{cve_id}: {desc[:200]}",
        "exploit_scenario": desc[:500],
        "affected_files": [],
        "checks_performed": checks,
        "findings": [
            {
                "category": category,
                "severity": sev,
                "confidence": "MEDIUM",
                "file": "",
                "line": None,
                "description": f"{cve_id}: {desc[:400]}",
                "exploit_scenario": desc[:400],
                "recommended_fix": "NEEDS_CURATION: attach upstream patch.",
                "secure_patch": "NEEDS_CURATION: attach fixed code from patch commit.",
            }
        ],
    }


def from_nvd(feed: Path) -> list[dict]:
    data = json.loads(feed.read_text())
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "CVE-UNKNOWN")
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        # CWE
        category = None
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                category = CWE_MAP.get(d.get("value"))
                if category:
                    break
            if category:
                break
        if not category:
            continue
        # CVSS
        metrics = cve.get("metrics", {})
        score = 5.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0]["cvssData"]["baseScore"]
                break
        sev = cvss_to_sev(score)
        out.append({
            "filename": f"{cve_id}.txt",
            "lang": "",
            "code": desc[:1000] or cve_id,
            "verdict": _verdict(cve_id, category, sev, desc),
        })
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed", required=True, help="NVD JSON 2.0 feed")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    records = from_nvd(Path(args.feed))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} CVE-derived examples -> {out}")
    print("NOTE: attach real before/after code for patch-quality training signal.")


if __name__ == "__main__":
    main()
