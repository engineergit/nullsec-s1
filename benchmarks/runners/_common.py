"""Shared logic for Nullsec-1 benchmark runners.

`collect_verdicts` obtains REAL Nullsec-1 output for every case in a dataset
(live model or captured replay) and aligns+enforces each through the Security
Alignment and Safety Layers. The returned map feeds every metric family. Cases
with no available output are recorded as misses, never fabricated.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from benchmarks.harness import OutputProvider, finalize_raw, load_dataset


def collect_verdicts(dataset: dict, provider: OutputProvider) -> dict:
    verdicts: dict = {}
    for case in dataset["cases"]:
        raw = provider.raw_for(case)
        verdicts[case["id"]] = finalize_raw(raw)
    return verdicts


def common_args(description: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--mode", choices=["model", "replay"], default="replay")
    ap.add_argument("--dataset", default="detection.json")
    ap.add_argument("--replay", default=None, help="captured raw outputs (JSONL) for replay mode")
    ap.add_argument("--adapter", default=None, help="LoRA adapter path for model mode")
    return ap


def build_provider(args) -> OutputProvider:
    replay = Path(args.replay) if args.replay else None
    return OutputProvider(mode=args.mode, adapter=args.adapter, replay_path=replay)


def load(args) -> dict:
    return load_dataset(args.dataset)
