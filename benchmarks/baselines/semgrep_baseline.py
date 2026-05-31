#!/usr/bin/env python3
"""Run a Semgrep baseline over the Nullsec-S1 benchmark dataset.

Semgrep is optional. If it is missing, this script exits with a clear install
message. Results are category-mapped conservatively and written under
benchmarks/reports/baselines/semgrep/SUITE.json.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.baselines.category_map import (  # noqa: E402
    PARTIAL_OR_UNSUPPORTED_CATEGORIES,
    SUPPORTED_CATEGORIES,
    category_for_rule,
)
from benchmarks.baselines.common import write_baseline_report  # noqa: E402
from benchmarks.harness import load_dataset  # noqa: E402
from nullsec.core.models import REQUIRED_DIMENSIONS, Verdict  # noqa: E402
from nullsec.safety import enforce  # noqa: E402
from taxonomy import check_dimension_for, default_severity  # noqa: E402


def _suffix(filename: str, lang: str) -> str:
    ext = Path(filename).suffix
    if ext:
        return ext
    return {
        "python": ".py",
        "javascript": ".js",
        "typescript": ".ts",
        "solidity": ".sol",
        "java": ".java",
        "php": ".php",
        "ruby": ".rb",
        "go": ".go",
        "json": ".json",
        "yaml": ".yml",
        "bash": ".sh",
    }.get(lang, ".txt")


def _semgrep(case: dict, config: Path) -> list[dict]:
    with tempfile.TemporaryDirectory() as td:
        fp = Path(td) / ("case" + _suffix(case.get("filename", "case.txt"), case.get("lang", "")))
        fp.write_text(case["code"], encoding="utf-8")
        proc = subprocess.run(
            ["semgrep", "--json", "--config", str(config), str(fp)],
            capture_output=True,
            text=True,
        )
        # Semgrep exits 1 on findings, 0 on none; other codes indicate failure.
        if proc.returncode not in (0, 1):
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
        data = json.loads(proc.stdout or "{}")
        return data.get("results", [])


def _verdict_from_hits(case: dict, hits: list[dict]):
    findings = []
    seen = set()
    for h in hits:
        rid = h.get("check_id") or h.get("extra", {}).get("metadata", {}).get("id", "")
        cat = category_for_rule(rid)
        if not cat or cat in seen:
            continue
        seen.add(cat)
        findings.append(
            {
                "category": cat,
                "severity": default_severity(cat),
                "confidence": "HIGH",
                "file": case.get("filename", "input"),
                "line": (h.get("start") or {}).get("line"),
                "description": h.get("extra", {}).get("message") or f"Semgrep rule {rid}",
                "exploit_scenario": "Static rule matched a pattern associated with this Nullsec category.",
                "recommended_fix": "Review the matched code and apply the category-specific secure pattern.",
                "secure_patch": "+ Review and remediate the Semgrep finding with a secure category-specific patch.",
            }
        )

    checks = {d: {"status": "pass", "note": "no Semgrep finding for this dimension"} for d in REQUIRED_DIMENSIONS}
    for f in findings:
        dim = check_dimension_for(f["category"])
        if dim:
            checks[dim] = {"status": "fail", "note": f["description"][:120]}

    if findings:
        severity = max((f["severity"] for f in findings), key=lambda s: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s))
        risk = {"LOW": 10, "MEDIUM": 35, "HIGH": 70, "CRITICAL": 90}.get(severity, 0)
        raw = {
            "risk_score": risk,
            "production_ready": False,
            "severity": severity,
            "confidence": "HIGH",
            "reasoning_summary": f"Semgrep matched {len(findings)} Nullsec-mapped rule(s).",
            "exploit_scenario": "See findings.",
            "affected_files": [case.get("filename", "input")],
            "checks_performed": checks,
            "findings": findings,
        }
    else:
        raw = {
            "risk_score": 0,
            "production_ready": True,
            "severity": "INFO",
            "confidence": "HIGH",
            "reasoning_summary": "Semgrep emitted no mapped findings.",
            "exploit_scenario": None,
            "affected_files": [case.get("filename", "input")],
            "checks_performed": checks,
            "findings": [],
        }
    v = Verdict.model_validate(raw)
    res = enforce(v)
    return res.verdict, True


def main() -> int:
    ap = argparse.ArgumentParser(description="Semgrep baseline for Nullsec-S1 benchmark")
    ap.add_argument("--dataset", default="detection.json")
    ap.add_argument("--config", default="benchmarks/baselines/semgrep_rules.yml")
    args = ap.parse_args()

    if shutil.which("semgrep") is None:
        print("Semgrep is not installed. Install with: python -m pip install semgrep", file=sys.stderr)
        return 2

    ds = load_dataset(args.dataset)
    config = Path(args.config)
    verdicts = {}
    for case in ds["cases"]:
        hits = _semgrep(case, config)
        verdicts[case["id"]] = _verdict_from_hits(case, hits)

    out = write_baseline_report(
        system_id="semgrep",
        system_name="Semgrep (local rules baseline)",
        dataset=args.dataset,
        cases=ds["cases"],
        verdicts=verdicts,
        provenance={"semgrep_config": str(config)},
        include_patch_metrics=False,
        coverage_limits={
            "supported_categories": SUPPORTED_CATEGORIES,
            "partial_or_unsupported_categories": PARTIAL_OR_UNSUPPORTED_CATEGORIES,
            "note": "Semgrep is a static rule engine; unsupported categories are not forced into coverage.",
        },
    )
    print(f"Semgrep baseline report -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
