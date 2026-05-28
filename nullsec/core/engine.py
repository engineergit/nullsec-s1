"""Nullsec-1 reasoning pipeline.

The reasoning pipeline is the full path Nullsec-1 takes from source code to a
trusted security verdict:

    code -> Nullsec-1 generation -> Security Alignment Layer -> Nullsec Safety Layer -> verdict

Heavy model dependencies (torch, transformers, peft) are imported lazily so the
Security Alignment Layer, Safety Layer, CLI help, and tests run without a GPU
stack installed.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Iterator, Optional

from nullsec.core.prompts import build_analyze_messages
from nullsec.safety import (
    SafetyResult,
    VerdictParseError,
    align_and_enforce,
)


@dataclass
class PipelineConfig:
    base_model: str = os.environ.get(
        "NULLSEC_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct"
    )
    adapter_path: Optional[str] = os.environ.get("NULLSEC_ADAPTER_PATH") or None
    load_in_4bit: bool = os.environ.get("NULLSEC_4BIT", "1") == "1"
    max_new_tokens: int = int(os.environ.get("NULLSEC_MAX_NEW_TOKENS", "1536"))
    temperature: float = float(os.environ.get("NULLSEC_TEMPERATURE", "0.0"))
    device_map: str = os.environ.get("NULLSEC_DEVICE_MAP", "auto")


# Backwards-compatible alias.
EngineConfig = PipelineConfig


class NullsecPipeline:
    """Loads Nullsec-1, generates, and runs the deterministic security stages so
    every caller receives an aligned, Safety-Layer-enforced verdict."""

    def __init__(self, config: PipelineConfig | None = None):
        self.config = config or PipelineConfig()
        self._model = None
        self._tokenizer = None

    # ---- lazy weight load ------------------------------------------------
    def load(self) -> "NullsecPipeline":
        if self._model is not None:
            return self
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        quant = None
        if self.config.load_in_4bit:
            from transformers import BitsAndBytesConfig

            quant = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.bfloat16,
                bnb_4bit_use_double_quant=True,
            )

        self._tokenizer = AutoTokenizer.from_pretrained(
            self.config.base_model, trust_remote_code=True
        )
        model = AutoModelForCausalLM.from_pretrained(
            self.config.base_model,
            quantization_config=quant,
            device_map=self.config.device_map,
            torch_dtype=torch.bfloat16,
            trust_remote_code=True,
        )
        if self.config.adapter_path:
            from peft import PeftModel

            model = PeftModel.from_pretrained(model, self.config.adapter_path)
        model.eval()
        self._model = model
        return self

    # ---- generation ------------------------------------------------------
    def _render(self, filename: str, code: str, lang: str) -> str:
        messages = build_analyze_messages(filename, code, lang)
        return self._tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )

    def _generate(self, prompt: str) -> str:
        import torch

        inputs = self._tokenizer(prompt, return_tensors="pt").to(self._model.device)
        with torch.no_grad():
            out = self._model.generate(
                **inputs,
                max_new_tokens=self.config.max_new_tokens,
                do_sample=self.config.temperature > 0,
                temperature=max(self.config.temperature, 1e-5),
                pad_token_id=self._tokenizer.eos_token_id,
            )
        gen = out[0][inputs["input_ids"].shape[1] :]
        return self._tokenizer.decode(gen, skip_special_tokens=True)

    def generate_stream(self, filename: str, code: str, lang: str = "") -> Iterator[str]:
        """Yield tokens as Nullsec-1 produces them (serving layer uses this for SSE)."""
        from threading import Thread

        from transformers import TextIteratorStreamer

        self.load()
        prompt = self._render(filename, code, lang)
        inputs = self._tokenizer(prompt, return_tensors="pt").to(self._model.device)
        streamer = TextIteratorStreamer(
            self._tokenizer, skip_prompt=True, skip_special_tokens=True
        )
        kwargs = dict(
            **inputs,
            max_new_tokens=self.config.max_new_tokens,
            do_sample=self.config.temperature > 0,
            temperature=max(self.config.temperature, 1e-5),
            pad_token_id=self._tokenizer.eos_token_id,
            streamer=streamer,
        )
        Thread(target=self._model.generate, kwargs=kwargs).start()
        for token in streamer:
            yield token

    # ---- public API: always returns an enforced verdict ------------------
    def analyze(self, filename: str, code: str, lang: str = "") -> SafetyResult:
        self.load()
        raw = self._generate(self._render(filename, code, lang))
        return self.finalize(raw)

    @staticmethod
    def finalize(raw: str) -> SafetyResult:
        """Run the deterministic security stages over raw Nullsec-1 output.
        Raises VerdictParseError if the output cannot be aligned."""
        return align_and_enforce(raw)

    @staticmethod
    def to_json(result: SafetyResult) -> str:
        payload = json.loads(result.verdict.model_dump_json())
        payload["_safety_layer"] = {
            "production_ready": result.production_ready,
            "blocking_reasons": result.blocking_reasons,
            "adjustments": result.adjustments,
        }
        return json.dumps(payload, indent=2)


# Backwards-compatible alias for prior import paths.
NullsecEngine = NullsecPipeline
