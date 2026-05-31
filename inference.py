#!/usr/bin/env python3
"""Nullsec-S1 Transformers + PEFT inference quickstart.

Loads the base model from training/config.yaml and a QLoRA adapter from
--adapter, NULLSEC_ADAPTER_PATH, or outputs/nullsec-s1-qlora. Prints the
Safety-Layer-enforced JSON verdict. Source code is never echoed unless
--show-raw is explicitly requested.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from nullsec.core.prompts import build_analyze_messages  # noqa: E402
from nullsec.safety import VerdictParseError, align_and_enforce  # noqa: E402


DEFAULT_ADAPTER = "outputs/nullsec-s1-qlora"


def load_training_config(path: str = "training/config.yaml") -> dict:
    with (ROOT / path).open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def detect_lang(path: str | None) -> str:
    if not path:
        return ""
    suffix = Path(path).suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".sol": "solidity",
        ".go": "go",
        ".java": "java",
        ".php": "php",
        ".rb": "ruby",
        ".sh": "bash",
        ".json": "json",
        ".yaml": "yaml",
        ".yml": "yaml",
    }.get(suffix, suffix.lstrip("."))


def load_model(base_model: str, adapter_path: str, load_in_4bit: bool, dtype_name: str):
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    quant = None
    dtype = getattr(torch, dtype_name)
    if load_in_4bit:
        from transformers import BitsAndBytesConfig

        quant = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=dtype,
            bnb_4bit_use_double_quant=True,
        )

    # Prefer tokenizer/chat template from the adapter directory when present;
    # otherwise fall back to the base tokenizer.
    tok_src = adapter_path if (Path(adapter_path) / "tokenizer.json").exists() else base_model
    tokenizer = AutoTokenizer.from_pretrained(tok_src, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    try:
        model = AutoModelForCausalLM.from_pretrained(
            base_model,
            quantization_config=quant,
            device_map="auto",
            dtype=dtype,
            trust_remote_code=True,
        )
    except TypeError:
        # Older transformers use torch_dtype instead of dtype.
        model = AutoModelForCausalLM.from_pretrained(
            base_model,
            quantization_config=quant,
            device_map="auto",
            torch_dtype=dtype,
            trust_remote_code=True,
        )
    model = PeftModel.from_pretrained(model, adapter_path)
    model.eval()
    return tokenizer, model


def generate_raw(tokenizer, model, filename: str, code: str, lang: str, max_new_tokens: int) -> str:
    import torch

    messages = build_analyze_messages(filename, code, lang)
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    gen = out[0][inputs["input_ids"].shape[1] :]
    return tokenizer.decode(gen, skip_special_tokens=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run Nullsec-S1 inference over one file or code snippet.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="file to audit")
    src.add_argument("--code", help="inline code to audit")
    ap.add_argument("--adapter", default=os.environ.get("NULLSEC_ADAPTER_PATH", DEFAULT_ADAPTER))
    ap.add_argument("--config", default="training/config.yaml")
    ap.add_argument("--lang", default=None, help="language hint; defaults from --file extension")
    ap.add_argument("--max-new-tokens", type=int, default=int(os.environ.get("NULLSEC_MAX_NEW_TOKENS", "1536")))
    ap.add_argument("--show-raw", action="store_true", help="include raw model text on malformed output")
    args = ap.parse_args()

    cfg = load_training_config(args.config)
    base_model = cfg["model"]["base_model"]
    q = cfg.get("quantization", {})
    adapter_path = args.adapter

    if args.file:
        path = Path(args.file)
        code = path.read_text(encoding="utf-8", errors="replace")
        filename = str(path)
        lang = args.lang or detect_lang(str(path))
    else:
        code = args.code
        filename = "inline"
        lang = args.lang or ""

    try:
        tokenizer, model = load_model(
            base_model=base_model,
            adapter_path=adapter_path,
            load_in_4bit=bool(q.get("load_in_4bit", True)),
            dtype_name=q.get("bnb_4bit_compute_dtype", "bfloat16"),
        )
        raw = generate_raw(tokenizer, model, filename, code, lang, args.max_new_tokens)
        result = align_and_enforce(raw)
        payload = json.loads(result.verdict.model_dump_json())
        payload["_safety_layer"] = {
            "production_ready": result.production_ready,
            "blocking_reasons": result.blocking_reasons,
            "adjustments": result.adjustments,
        }
        print(json.dumps(payload, indent=2))
        return 0
    except VerdictParseError as e:
        err = {"error": "malformed_model_output", "detail": str(e)}
        if args.show_raw:
            err["raw_model_output"] = raw if "raw" in locals() else None
        print(json.dumps(err, indent=2), file=sys.stderr)
        return 2
    except Exception as e:
        print(json.dumps({"error": "inference_failed", "detail": str(e)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
