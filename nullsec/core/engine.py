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
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from nullsec.core.prompts import build_analyze_messages
from nullsec.safety import (
    SafetyResult,
    VerdictParseError,
    align_and_enforce,
)

LOGGER = logging.getLogger("nullsec.s1")


def _env_bool(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: str) -> int:
    return int(os.environ.get(name, default))


def _env_float(name: str, default: str) -> float:
    return float(os.environ.get(name, default))


def detect_adapter_source(adapter_path: Optional[str]) -> str:
    if not adapter_path:
        return "none"
    expanded = Path(adapter_path).expanduser()
    if expanded.is_absolute() or adapter_path.startswith(("./", "../", "~")):
        return "local_path"
    if "/" in adapter_path and not adapter_path.startswith(("http://", "https://")):
        return "hf_repo"
    return "local_path"


class PipelineLoadError(RuntimeError):
    """Raised when model or adapter loading fails with deployment context."""


def _adapter_failure_hint(error: Exception, adapter_path: str) -> str:
    text = str(error).lower()
    source = detect_adapter_source(adapter_path)
    if "adapter_config.json" in text:
        return "Check that the adapter contains adapter_config.json and that NULLSEC_ADAPTER_PATH points to the adapter root."
    if "safetensors" in text or "adapter_model" in text:
        return "Check that adapter_model.safetensors is present and readable."
    if "401" in text or "403" in text or "private" in text or "gated" in text:
        return "Check Hugging Face access. If the repository is private, configure an HF token in the runtime environment."
    if "revision" in text or "not found" in text or "404" in text:
        if source == "hf_repo":
            return "Check the Hugging Face adapter repo id for typos."
        return "Check that the local adapter path exists on the server."
    if "peft" in text or "lora" in text:
        return "Check that the installed PEFT version is compatible with the adapter metadata."
    if "cuda" in text or "out of memory" in text or "mps" in text or "memory" in text:
        return "Check GPU availability, CUDA/bitsandbytes compatibility, and memory headroom."
    if "size mismatch" in text or "base model" in text:
        return "Check that NULLSEC_BASE_MODEL matches the adapter base model."
    return "Check the adapter path/repo id, PEFT installation, base model compatibility, and GPU memory."


@dataclass
class PipelineConfig:
    base_model: str = field(
        default_factory=lambda: os.environ.get(
            "NULLSEC_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct"
        )
    )
    adapter_path: Optional[str] = field(
        default_factory=lambda: os.environ.get("NULLSEC_ADAPTER_PATH") or None
    )
    load_in_4bit: bool = field(default_factory=lambda: _env_bool("NULLSEC_4BIT", "1"))
    max_new_tokens: int = field(default_factory=lambda: _env_int("NULLSEC_MAX_NEW_TOKENS", "1536"))
    temperature: float = field(default_factory=lambda: _env_float("NULLSEC_TEMPERATURE", "0.0"))
    device_map: str = field(default_factory=lambda: os.environ.get("NULLSEC_DEVICE_MAP", "auto"))

    @property
    def adapter_source(self) -> str:
        return detect_adapter_source(self.adapter_path)


# Backwards-compatible alias.
EngineConfig = PipelineConfig


class NullsecPipeline:
    """Loads Nullsec-1, generates, and runs the deterministic security stages so
    every caller receives an aligned, Safety-Layer-enforced verdict."""

    def __init__(self, config: PipelineConfig | None = None):
        self.config = config or PipelineConfig()
        self._model = None
        self._tokenizer = None
        self._device = None
        self._dtype = None
        self._adapter_loaded = False

    # ---- lazy weight load ------------------------------------------------
    def load(self) -> "NullsecPipeline":
        if self._model is not None:
            return self
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except Exception as e:
            raise PipelineLoadError(
                "Nullsec-S1 runtime dependency load failed. "
                f"base_model={self.config.base_model!r}; "
                f"adapter_path={self.config.adapter_path!r}; "
                f"failure={type(e).__name__}: {e}; "
                "likely_fix=Install the GPU inference stack, for example "
                "`python -m pip install -r requirements-train-cu121.txt`, and verify "
                "torch, transformers, PEFT, bitsandbytes, CUDA, and GPU memory."
            ) from e

        LOGGER.info("[Nullsec S1] Loading base model: %s", self.config.base_model)
        LOGGER.info(
            "[Nullsec S1] Eager loading enabled: %s",
            "yes" if _env_bool("NULLSEC_EAGER_LOAD", "0") else "no",
        )
        quant = None
        if self.config.load_in_4bit:
            try:
                from transformers import BitsAndBytesConfig
            except Exception as e:
                raise PipelineLoadError(
                    "Nullsec-S1 quantization dependency load failed. "
                    f"base_model={self.config.base_model!r}; "
                    f"adapter_path={self.config.adapter_path!r}; "
                    f"failure={type(e).__name__}: {e}; "
                    "likely_fix=Install a transformers version with BitsAndBytesConfig "
                    "and ensure bitsandbytes/CUDA are available, or set NULLSEC_4BIT=0 "
                    "on a runtime with enough memory."
                ) from e

            quant = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.bfloat16,
                bnb_4bit_use_double_quant=True,
            )

        try:
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
        except Exception as e:
            raise PipelineLoadError(
                "Nullsec-S1 base model load failed. "
                f"base_model={self.config.base_model!r}; "
                f"adapter_path={self.config.adapter_path!r}; "
                f"failure={type(e).__name__}: {e}; "
                "likely_fix=Check the base model id/path, network/Hugging Face access, "
                "transformers version, CUDA/bitsandbytes compatibility, and available memory."
            ) from e

        if self.config.adapter_path:
            LOGGER.info("[Nullsec S1] Loading PEFT adapter: %s", self.config.adapter_path)
            LOGGER.info(
                "[Nullsec S1] Adapter source detected: %s",
                "Hugging Face repo" if self.config.adapter_source == "hf_repo" else "local path",
            )
            try:
                from peft import PeftModel

                model = PeftModel.from_pretrained(model, self.config.adapter_path)
                self._adapter_loaded = True
                LOGGER.info("[Nullsec S1] Adapter loaded successfully")
            except Exception as e:
                raise PipelineLoadError(
                    "Nullsec-S1 PEFT adapter load failed. "
                    f"base_model={self.config.base_model!r}; "
                    f"adapter_path={self.config.adapter_path!r}; "
                    f"adapter_source={self.config.adapter_source!r}; "
                    f"failure={type(e).__name__}: {e}; "
                    f"likely_fix={_adapter_failure_hint(e, self.config.adapter_path)}"
                ) from e
        model.eval()
        self._model = model
        self._device = str(getattr(model, "device", "unknown"))
        self._dtype = str(getattr(model, "dtype", "unknown"))
        LOGGER.info("[Nullsec S1] Final device/dtype: %s / %s", self._device, self._dtype)
        LOGGER.info("[Nullsec S1] Pipeline ready")
        return self

    def info(self) -> dict:
        return {
            "base_model": self.config.base_model,
            "adapter_path": self.config.adapter_path,
            "adapter_loaded": self._adapter_loaded,
            "adapter_source": self.config.adapter_source,
            "device": self._device,
            "dtype": self._dtype,
            "eager_loaded": _env_bool("NULLSEC_EAGER_LOAD", "0"),
        }

    # ---- generation ------------------------------------------------------
    def _render(self, filename: str, code: str, lang: str) -> str:
        messages = build_analyze_messages(filename, code, lang)
        return self._tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )

    def _gen_kwargs(self, **extra) -> dict:
        """Generation kwargs. For deterministic (greedy) decoding we do NOT pass
        sampling-only flags like temperature/top_p — passing them while
        do_sample=False is invalid and emits warnings."""
        kw = dict(
            max_new_tokens=self.config.max_new_tokens,
            pad_token_id=self._tokenizer.eos_token_id,
        )
        if self.config.temperature and self.config.temperature > 0:
            kw["do_sample"] = True
            kw["temperature"] = self.config.temperature
        else:
            kw["do_sample"] = False  # greedy; no temperature/top_p
        kw.update(extra)
        return kw

    def _generate(self, prompt: str) -> str:
        import torch

        inputs = self._tokenizer(prompt, return_tensors="pt").to(self._model.device)
        with torch.no_grad():
            out = self._model.generate(**inputs, **self._gen_kwargs())
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
        kwargs = dict(**inputs, **self._gen_kwargs(streamer=streamer))
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
