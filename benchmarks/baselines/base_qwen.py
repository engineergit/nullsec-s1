#!/usr/bin/env python3
"""Run the 111-case security benchmark against the base Qwen model.

This baseline uses the same prompt, raw-output finalization, and metrics as
Nullsec-S1, but loads Qwen/Qwen2.5-Coder-7B-Instruct without the Nullsec adapter.
Malformed/non-JSON output is counted honestly as a miss.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.baselines.common import write_baseline_report
from benchmarks.harness import OutputProvider, load_dataset
from benchmarks.runners._common import collect_verdicts
from nullsec.core.version import TRAINING_BASE


def main() -> int:
    ap = argparse.ArgumentParser(description="Base Qwen2.5-Coder benchmark baseline")
    ap.add_argument("--mode", choices=["model", "replay"], default="model")
    ap.add_argument("--dataset", default="detection.json")
    ap.add_argument("--replay", default=None, help="captured raw outputs JSONL for replay mode")
    args = ap.parse_args()

    ds = load_dataset(args.dataset)
    provider = OutputProvider(mode=args.mode, adapter=None, replay_path=Path(args.replay) if args.replay else None)
    verdicts = collect_verdicts(ds, provider)
    out = write_baseline_report(
        system_id="qwen2_5_coder_7b",
        system_name="Qwen2.5-Coder-7B-Instruct (base, no Nullsec adapter)",
        dataset=args.dataset,
        cases=ds["cases"],
        verdicts=verdicts,
        provenance={"run_mode": args.mode, "base_model": TRAINING_BASE, "adapter": None},
    )
    print(f"base Qwen baseline report -> {out}")
    print("Generated report is under benchmarks/reports/ and should not be committed unless explicitly approved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
