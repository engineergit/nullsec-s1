#!/usr/bin/env python3
"""Claude API baseline for the Nullsec-S1 benchmark.

Requires ANTHROPIC_API_KEY and ANTHROPIC_MODEL (or --model). Generated reports
and raw outputs are written under benchmarks/reports/baselines/claude/ and are
not committed by default.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.baselines.api_common import run_api_baseline


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is required. Export {name}=... before running this baseline.")
    return value


def main() -> int:
    ap = argparse.ArgumentParser(description="Claude API baseline for the Nullsec-S1 benchmark")
    ap.add_argument("--dataset", default="detection.json")
    ap.add_argument("--limit", type=int, default=None, help="run only the first N cases (smoke test)")
    ap.add_argument("--model", default=os.environ.get("ANTHROPIC_MODEL"))
    ap.add_argument("--resume", action="store_true", help="reuse cached raw_outputs.jsonl entries")
    ap.add_argument("--sleep", type=float, default=0.0, help="seconds to sleep between requests")
    ap.add_argument("--max-tokens", type=int, default=1536)
    args = ap.parse_args()

    api_key = require_env("ANTHROPIC_API_KEY")
    if not args.model:
        raise SystemExit("ANTHROPIC_MODEL is required (or pass --model).")

    try:
        import anthropic
    except ImportError as e:
        raise SystemExit("anthropic package is required. Install with: python -m pip install anthropic") from e

    client = anthropic.Anthropic(api_key=api_key)

    def call(system_prompt: str, prompt: str) -> str:
        msg = client.messages.create(
            model=args.model,
            max_tokens=args.max_tokens,
            temperature=0,
            system=system_prompt,
            messages=[{"role": "user", "content": prompt}],
        )
        parts = []
        for block in msg.content:
            if getattr(block, "type", None) == "text":
                parts.append(block.text)
        return "\n".join(parts).strip()

    run_api_baseline(
        provider_id="claude",
        system_name=f"Claude API baseline ({args.model})",
        dataset_name=args.dataset,
        model=args.model,
        limit=args.limit,
        resume=args.resume,
        sleep_s=args.sleep,
        call_model=call,
        provenance={"api": "anthropic_messages", "max_tokens": args.max_tokens},
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
