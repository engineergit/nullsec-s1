#!/usr/bin/env python3
"""Build the training corpus from the single source of truth: corpus/.

Reads only the curated corpus via `corpus.load_corpus()`. Synthetic and ingested
examples are included only when `--include-synthetic` / `--include-ingested` are
passed — exactly mirroring `dataset_stats.py` and `release_threshold.py`, so the
number of training records always matches the number stats reports for the same
flags.

Each example is validated through the SAME parser + Safety Layer the server uses,
so no malformed or gate-inconsistent verdict ever enters training. Output is
chat-formatted JSONL ready for TRL's SFTTrainer. The train/eval split uses the
shared deterministic `corpus.split`, so the reported split matches what is written.

Usage:
  python training/prepare_dataset.py --out data/processed --eval-split 0.2
  python training/prepare_dataset.py --include-synthetic
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from corpus import load_corpus, split  # noqa: E402
from nullsec.core.prompts import build_analyze_messages  # noqa: E402
from nullsec.safety import (  # noqa: E402
    VerdictParseError,
    enforce,
    normalize_finding_severities,
    parse_verdict,
)


def _record(filename: str, code: str, lang: str, verdict_obj: dict) -> dict | None:
    """Validate a verdict and emit a chat-formatted training record, or None."""
    raw = json.dumps(verdict_obj)
    try:
        verdict = parse_verdict(raw)
    except VerdictParseError as e:
        print(f"  SKIP {filename}: {e}", file=sys.stderr)
        return None
    normalize_finding_severities(verdict)
    enforce(verdict)  # Safety Layer enforces the verdict in place
    target = verdict.model_dump_json()

    messages = build_analyze_messages(filename, code, lang)
    messages.append({"role": "assistant", "content": target})
    return {"messages": messages}


def _records_from_examples(examples: list[dict]) -> list[dict]:
    out = []
    for ex in examples:
        v = ex["verdict"]
        filename = (v.get("affected_files") or ["input"])[0]
        rec = _record(filename, ex["code"], ex.get("lang", ""), v)
        if rec:
            out.append(rec)
    return out


def build_records(include_synthetic: bool = False, include_ingested: bool = False) -> list[dict]:
    """All training records from the single corpus source (for the given flags)."""
    examples = load_corpus(include_synthetic=include_synthetic, include_ingested=include_ingested)
    return _records_from_examples(examples)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/processed")
    ap.add_argument("--eval-split", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--include-synthetic", action="store_true")
    ap.add_argument("--include-ingested", action="store_true")
    args = ap.parse_args()

    examples = load_corpus(include_synthetic=args.include_synthetic, include_ingested=args.include_ingested)
    if not examples:
        raise SystemExit("no examples in corpus")

    # Same deterministic split stats reports, applied at the example level.
    train_ex, eval_ex = split(examples, args.eval_split, args.seed)
    train_recs = _records_from_examples(train_ex)
    eval_recs = _records_from_examples(eval_ex)

    dropped = len(examples) - (len(train_recs) + len(eval_recs))
    if dropped:
        print(f"WARNING: {dropped} example(s) failed validation and were dropped", file=sys.stderr)

    out_dir = ROOT / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, recs in (("train.jsonl", train_recs), ("eval.jsonl", eval_recs)):
        path = out_dir / name
        with path.open("w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r) + "\n")
        print(f"wrote {len(recs):4d} -> {path}")
    print(f"total records: {len(train_recs) + len(eval_recs)} (corpus examples: {len(examples)})")


if __name__ == "__main__":
    main()
