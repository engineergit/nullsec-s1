#!/usr/bin/env python3
"""Merge a trained LoRA adapter into the base model for standalone deployment.

Produces full (de-quantized, fp16/bf16) weights you can serve without PEFT.
Note: merging requires loading the base in full precision, so run this on a box
with enough RAM/VRAM for the dense model (more than 24GB for 14B).

Usage:
  python training/merge_adapter.py \
      --base Qwen/Qwen2.5-Coder-7B-Instruct \
      --adapter outputs/nullsec-s1-qlora \
      --out outputs/nullsec-s1-merged
"""
from __future__ import annotations

import argparse


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dtype", default="bfloat16", choices=["bfloat16", "float16"])
    args = ap.parse_args()

    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    dtype = getattr(torch, args.dtype)
    base = AutoModelForCausalLM.from_pretrained(
        args.base, torch_dtype=dtype, device_map="cpu", trust_remote_code=True
    )
    merged = PeftModel.from_pretrained(base, args.adapter).merge_and_unload()
    merged.save_pretrained(args.out, safe_serialization=True)
    AutoTokenizer.from_pretrained(args.base, trust_remote_code=True).save_pretrained(
        args.out
    )
    print(f"merged model saved to {args.out}")


if __name__ == "__main__":
    main()
