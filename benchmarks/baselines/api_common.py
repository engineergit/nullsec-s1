"""Shared helpers for hosted API model baselines.

API baselines are comparison-only. They use the same prompt and scoring pipeline
as Nullsec-S1, write raw responses incrementally for resumability, and never
invent metrics.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from benchmarks.baselines.common import write_baseline_report
from benchmarks.harness import finalize_raw, load_dataset
from nullsec.core.prompts import ANALYZE_TEMPLATE, SYSTEM_PROMPT

REPORT_ROOT = Path(__file__).resolve().parents[2] / "benchmarks" / "reports" / "baselines"


def user_prompt(case: dict) -> str:
    return ANALYZE_TEMPLATE.format(
        filename=case.get("filename", "input"),
        lang=case.get("lang", ""),
        code=case["code"],
    )


def load_raw_cache(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    out: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        out[obj["id"]] = obj
    return out


def append_raw(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj) + "\n")


def run_api_baseline(
    *,
    provider_id: str,
    system_name: str,
    dataset_name: str,
    model: str,
    limit: int | None,
    resume: bool,
    sleep_s: float,
    call_model,
    provenance: dict,
) -> Path:
    ds = load_dataset(dataset_name)
    cases = ds["cases"][:limit] if limit else ds["cases"]
    out_dir = REPORT_ROOT / provider_id
    raw_path = out_dir / "raw_outputs.jsonl"
    cached = load_raw_cache(raw_path) if resume else {}
    verdicts: dict = {}

    print(f"{provider_id}: {len(cases)} case(s), model={model}, resume={resume}")
    for i, case in enumerate(cases, start=1):
        cid = case["id"]
        if cid in cached:
            raw = cached[cid]["raw"]
            print(f"[{i}/{len(cases)}] {cid}: cached")
        else:
            print(f"[{i}/{len(cases)}] {cid}: requesting")
            raw = call_model(SYSTEM_PROMPT, user_prompt(case))
            append_raw(raw_path, {"id": cid, "raw": raw, "provider": provider_id, "model": model})
            if sleep_s:
                time.sleep(sleep_s)
        verdicts[cid] = finalize_raw(raw)

    report = write_baseline_report(
        system_id=provider_id,
        system_name=system_name,
        dataset=dataset_name,
        cases=cases,
        verdicts=verdicts,
        provenance={
            "provider": provider_id,
            "model": model,
            "limit": limit,
            "raw_outputs": str(raw_path),
            **provenance,
        },
    )
    print(f"{provider_id} baseline report -> {report}")
    print("Generated report/cache are under benchmarks/reports/ and should not be committed unless explicitly approved.")
    return report
