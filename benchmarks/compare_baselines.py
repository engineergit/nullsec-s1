#!/usr/bin/env python3
"""Generate a Markdown comparison table from benchmark reports.

This script reads reports produced by benchmark runners. It never invents or
hand-enters metrics.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_report(path: str | None, label: str) -> dict | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{label} report not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    return {"path": str(p), "data": data}


def row(label: str, report: dict | None, notes: str) -> list[str]:
    if report is None:
        return [label, "-", "-", "-", "-", "-", "-", "-", notes]
    data = report["data"]
    res = data.get("results", {})
    det = res.get("detection_accuracy", {})
    fsr = res.get("false_safe_rate", {})
    hall = res.get("hallucination_rate", {})
    summary = res.get("summary", {})
    system = data.get("system") or data.get("provenance", {}).get("model_name") or label
    cases = str(summary.get("total_cases") or det.get("cases") or "-")
    outputs = str(summary.get("total_outputs") or det.get("json_validity") or "-")
    return [
        system,
        cases,
        outputs,
        str(det.get("detection_precision", "-")),
        str(det.get("detection_recall", "-")),
        str(det.get("detection_f1", "-")),
        str(fsr.get("false_safe_rate", "-")),
        str(hall.get("hallucination_rate", "-")),
        notes,
    ]


def render(rows: list[list[str]]) -> str:
    headers = [
        "System / tool",
        "Total cases",
        "Outputs / analyzable",
        "Precision",
        "Recall",
        "F1",
        "false_safe_rate",
        "hallucination_rate",
        "Notes / coverage limits",
    ]
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for r in rows:
        out.append("| " + " | ".join(r) + " |")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare Nullsec-S1 and baseline benchmark reports")
    ap.add_argument("--nullsec", help="Nullsec-S1 SUITE.json")
    ap.add_argument("--base", help="base Qwen SUITE.json")
    ap.add_argument("--semgrep", help="Semgrep SUITE.json")
    ap.add_argument("--out", default=None, help="optional Markdown output path")
    args = ap.parse_args()

    reports = [
        row("Nullsec-S1", load_report(args.nullsec, "Nullsec"), "RC2/v1.1 release or local run"),
        row("Base Qwen", load_report(args.base, "base Qwen"), "base model, no Nullsec adapter"),
        row("Semgrep", load_report(args.semgrep, "Semgrep"), "static rules; partial category coverage"),
    ]
    md = render(reports)
    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(md, encoding="utf-8")
        print(f"comparison table -> {p}")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
