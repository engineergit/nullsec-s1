"""Shared baseline evaluation helpers.

Baselines emit the same `verdicts` shape consumed by `benchmarks.metrics`:

    dict[case_id] = (Verdict | None, aligned_bool)

This lets base-model and tool baselines use the same scoring functions as
Nullsec-S1 without changing labels or metric semantics.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.metrics import (
    debug_report,
    detection_over,
    failed_case_ids,
    false_safe_rate,
    hallucination_rate,
    owasp_coverage,
    patch_correctness,
    per_category_recall,
    secure_generation_score,
)

ROOT = Path(__file__).resolve().parents[2]
REPORT_ROOT = ROOT / "benchmarks" / "reports" / "baselines"

FAMILIES = {
    "detection_accuracy": detection_over,
    "false_safe_rate": false_safe_rate,
    "hallucination_rate": hallucination_rate,
    "owasp_coverage": owasp_coverage,
    "patch_correctness": patch_correctness,
    "secure_generation": secure_generation_score,
    "per_category_recall": per_category_recall,
    "failed_cases": failed_case_ids,
}


def build_suite(cases: list[dict], verdicts: dict, *, include_patch_metrics: bool = True) -> dict:
    suite = {}
    for name, fn in FAMILIES.items():
        if not include_patch_metrics and name in {"patch_correctness", "secure_generation"}:
            suite[name] = {
                "not_applicable": True,
                "note": "baseline does not generate secure patches",
            }
            continue
        suite[name] = fn(cases, verdicts)

    dbg = debug_report(cases, verdicts, failed_only=True)
    suite["debug"] = dbg
    produced = sum(1 for c in cases if verdicts.get(c["id"], (None, False))[1])
    suite["summary"] = {
        "total_cases": len(cases),
        "total_outputs": produced,
        "detection_f1": suite["detection_accuracy"].get("detection_f1"),
        "detection_precision": suite["detection_accuracy"].get("detection_precision"),
        "detection_recall": suite["detection_accuracy"].get("detection_recall"),
        "false_safe_rate": suite["false_safe_rate"].get("false_safe_rate"),
        "hallucination_rate": suite["hallucination_rate"].get("hallucination_rate"),
        "patch_correctness": suite["patch_correctness"].get("patch_correctness"),
        "secure_generation_score": suite["secure_generation"].get("secure_generation_score"),
        "owasp_coverage": suite["owasp_coverage"].get("coverage"),
        "categories_below_full_recall": suite["per_category_recall"].get("categories_below_full_recall"),
        "failed_case_ids": [f["id"] for f in suite["failed_cases"].get("failed", [])],
    }
    return suite


def write_baseline_report(
    *,
    system_id: str,
    system_name: str,
    dataset: str,
    cases: list[dict],
    verdicts: dict,
    provenance: dict,
    include_patch_metrics: bool = True,
    coverage_limits: dict | None = None,
) -> Path:
    suite = build_suite(cases, verdicts, include_patch_metrics=include_patch_metrics)
    if coverage_limits:
        suite["coverage_limits"] = coverage_limits
    report = {
        "benchmark": "SUITE",
        "system": system_name,
        "provenance": {
            "system_id": system_id,
            "system_name": system_name,
            "dataset": dataset,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **provenance,
        },
        "results": suite,
    }
    out_dir = REPORT_ROOT / system_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "SUITE.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return out
