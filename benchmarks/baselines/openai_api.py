#!/usr/bin/env python3
"""OpenAI/Codex API baseline for the Nullsec-S1 benchmark.

Requires OPENAI_API_KEY and OPENAI_MODEL (or --model). Generated reports and raw
outputs are written under benchmarks/reports/baselines/openai/ and are not
committed by default.
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


def _extract_response_text(resp) -> str:
    text = getattr(resp, "output_text", None)
    if text:
        return text.strip()
    chunks = []
    for item in getattr(resp, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            if getattr(content, "type", None) in {"output_text", "text"}:
                chunks.append(getattr(content, "text", ""))
    return "\n".join(chunks).strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="OpenAI/Codex API baseline for the Nullsec-S1 benchmark")
    ap.add_argument("--dataset", default="detection.json")
    ap.add_argument("--limit", type=int, default=None, help="run only the first N cases (smoke test)")
    ap.add_argument("--model", default=os.environ.get("OPENAI_MODEL"))
    ap.add_argument("--resume", action="store_true", help="reuse cached raw_outputs.jsonl entries")
    ap.add_argument("--sleep", type=float, default=0.0, help="seconds to sleep between requests")
    ap.add_argument("--max-tokens", type=int, default=1536)
    ap.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="sampling temperature; retried without temperature if the provider/model rejects it",
    )
    args = ap.parse_args()

    api_key = require_env("OPENAI_API_KEY")
    if not args.model:
        raise SystemExit("OPENAI_MODEL is required (or pass --model).")

    try:
        from openai import OpenAI
    except ImportError as e:
        raise SystemExit("openai package is required. Install with: python -m pip install openai") from e

    client = OpenAI(api_key=api_key)
    temperature_state = {
        "requested": args.temperature,
        "used": args.temperature is not None,
        "note": "temperature=0 used where supported",
    }

    def call(system_prompt: str, prompt: str) -> str:
        try:
            kwargs = dict(
                model=args.model,
                max_output_tokens=args.max_tokens,
                input=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
            )
            if args.temperature is not None:
                kwargs["temperature"] = args.temperature
            try:
                resp = client.responses.create(**kwargs)
            except Exception as e:
                if "temperature" in kwargs and "temperature" in str(e).lower() and (
                    "unsupported" in str(e).lower()
                    or "not support" in str(e).lower()
                    or "not compatible" in str(e).lower()
                    or "deprecated" in str(e).lower()
                ):
                    kwargs.pop("temperature", None)
                    temperature_state["used"] = False
                    temperature_state["note"] = "temperature omitted after provider rejected/deprecated it"
                    resp = client.responses.create(**kwargs)
                else:
                    raise
            return _extract_response_text(resp)
        except AttributeError:
            # Compatibility with older SDKs that only expose chat.completions.
            kwargs = dict(
                model=args.model,
                max_tokens=args.max_tokens,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
            )
            if args.temperature is not None:
                kwargs["temperature"] = args.temperature
            try:
                resp = client.chat.completions.create(**kwargs)
            except Exception as e:
                if "temperature" in kwargs and "temperature" in str(e).lower() and (
                    "unsupported" in str(e).lower()
                    or "not support" in str(e).lower()
                    or "not compatible" in str(e).lower()
                    or "deprecated" in str(e).lower()
                ):
                    kwargs.pop("temperature", None)
                    temperature_state["used"] = False
                    temperature_state["note"] = "temperature omitted after provider rejected/deprecated it"
                    resp = client.chat.completions.create(**kwargs)
                else:
                    raise
            return resp.choices[0].message.content.strip()

    run_api_baseline(
        provider_id="openai",
        system_name=f"OpenAI/Codex API baseline ({args.model})",
        dataset_name=args.dataset,
        model=args.model,
        limit=args.limit,
        resume=args.resume,
        sleep_s=args.sleep,
        call_model=call,
        provenance={
            "api": "openai_responses_or_chat",
            "max_tokens": args.max_tokens,
            "temperature": temperature_state,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
