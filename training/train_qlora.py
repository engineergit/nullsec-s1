#!/usr/bin/env python3
"""QLoRA fine-tuning for Nullsec-1.

Single-GPU defaults via training/config.yaml. Trains a LoRA adapter on top of a
4-bit quantized base model.

Stack compatibility (hardened after the RC1 RunPod A100 run):
  - Uses SFTConfig(max_length=...) — the modern TRL field. Older TRL used
    `max_seq_length`, which the pinned build (see requirements-train-cu121.txt)
    no longer accepts.
  - Does NOT import trl.DataCollatorForCompletionOnlyLM. That helper was removed
    from recent TRL releases and broke the RC1 run. Modern TRL expresses
    "train only on the assistant turn" via SFTConfig(assistant_only_loss=True),
    which requires the tokenizer chat template to mark the assistant span with
    {% generation %} ... {% endgeneration %}. Qwen2.5-Coder's stock template does
    not include those markers, so RC1 trained with standard full-sequence SFT and
    still reached detection F1 0.9091. We enable assistant-only loss only when it
    is genuinely supported, and otherwise fall back to full-sequence SFT with a
    clear warning (never a silent break). See docs/training_guide.md.
  - Prefers the new `dtype=` kwarg over the deprecated `torch_dtype=` when the
    installed transformers supports it.
  - Uses explicit `warmup_steps` rather than `warmup_ratio`.

Usage:
  python training/train_qlora.py --config training/config.yaml
  python training/train_qlora.py --config training/config.yaml --resume auto
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _transformers_supports_dtype() -> bool:
    """`dtype=` replaced the deprecated `torch_dtype=` in transformers 4.56."""
    try:
        import transformers

        parts = transformers.__version__.split(".")
        major, minor = int(parts[0]), int(parts[1])
        return (major, minor) >= (4, 56)
    except Exception:
        return False


def _template_supports_assistant_only_loss(tokenizer) -> bool:
    """assistant_only_loss needs a chat template with {% generation %} markers."""
    tpl = getattr(tokenizer, "chat_template", None) or ""
    return "generation" in tpl and "endgeneration" in tpl


def _build_sft_config(SFTConfig, tr: dict, max_length: int, want_assistant_only: bool):
    """Construct SFTConfig, tolerating TRL versions that lack newer kwargs."""
    kwargs = dict(
        output_dir=tr["output_dir"],
        num_train_epochs=tr["num_train_epochs"],
        per_device_train_batch_size=tr["per_device_train_batch_size"],
        gradient_accumulation_steps=tr["gradient_accumulation_steps"],
        learning_rate=tr["learning_rate"],
        lr_scheduler_type=tr["lr_scheduler_type"],
        warmup_steps=tr.get("warmup_steps", 10),
        weight_decay=tr["weight_decay"],
        logging_steps=tr["logging_steps"],
        save_steps=tr["save_steps"],
        save_total_limit=tr["save_total_limit"],
        gradient_checkpointing=tr["gradient_checkpointing"],
        optim=tr["optim"],
        bf16=tr["bf16"],
        fp16=tr["fp16"],
        max_grad_norm=tr["max_grad_norm"],
        seed=tr["seed"],
        max_length=max_length,
        packing=False,
        dataset_text_field="text",
        report_to="none",
    )
    if want_assistant_only:
        kwargs["assistant_only_loss"] = True
    try:
        return SFTConfig(**kwargs)
    except TypeError as e:
        # An older/newer TRL rejected a kwarg (commonly assistant_only_loss).
        # Drop it and retry so the run proceeds with full-sequence SFT.
        if "assistant_only_loss" in kwargs:
            kwargs.pop("assistant_only_loss")
            print(f"WARNING: SFTConfig rejected assistant_only_loss ({e}); "
                  "falling back to full-sequence SFT.")
            return SFTConfig(**kwargs)
        raise


def _build_trainer(SFTTrainer, model, sft_config, train_ds, eval_ds, peft_config, tokenizer):
    """Construct SFTTrainer across TRL versions (processing_class vs tokenizer)."""
    base = dict(model=model, args=sft_config, train_dataset=train_ds,
                eval_dataset=eval_ds, peft_config=peft_config)
    for tok_kw in ("processing_class", "tokenizer"):
        try:
            return SFTTrainer(**base, **{tok_kw: tokenizer})
        except TypeError:
            continue
    # Last resort: let SFTTrainer load the tokenizer from the model (RC1 path).
    return SFTTrainer(**base)


def _adapter_artifacts_present(out_dir: Path) -> bool:
    has_config = (out_dir / "adapter_config.json").exists()
    has_weights = (out_dir / "adapter_model.safetensors").exists() or (
        out_dir / "adapter_model.bin"
    ).exists()
    return has_config and has_weights


def main() -> int:
    ap = argparse.ArgumentParser(description="QLoRA fine-tuning for Nullsec-1")
    ap.add_argument("--config", default="training/config.yaml")
    ap.add_argument(
        "--resume",
        default=None,
        help="resume training: 'auto' to continue from the latest checkpoint in "
        "output_dir, or an explicit checkpoint path",
    )
    args = ap.parse_args()
    cfg = load_config(args.config)

    import torch
    from datasets import load_dataset
    from peft import LoraConfig, prepare_model_for_kbit_training
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from transformers.trainer_utils import get_last_checkpoint
    from trl import SFTConfig, SFTTrainer

    m, q, lo, tr, da = (
        cfg["model"], cfg["quantization"], cfg["lora"], cfg["training"], cfg["data"],
    )

    dtype = getattr(torch, q["bnb_4bit_compute_dtype"])
    bnb = BitsAndBytesConfig(
        load_in_4bit=q["load_in_4bit"],
        bnb_4bit_quant_type=q["bnb_4bit_quant_type"],
        bnb_4bit_use_double_quant=q["bnb_4bit_use_double_quant"],
        bnb_4bit_compute_dtype=dtype,
    )

    tokenizer = AutoTokenizer.from_pretrained(
        m["base_model"], trust_remote_code=m.get("trust_remote_code", True)
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Prefer `dtype=` (transformers >= 4.56); fall back to `torch_dtype=`.
    dtype_kw = "dtype" if _transformers_supports_dtype() else "torch_dtype"
    model = AutoModelForCausalLM.from_pretrained(
        m["base_model"],
        quantization_config=bnb,
        device_map="auto",
        trust_remote_code=m.get("trust_remote_code", True),
        **{dtype_kw: dtype},
    )
    model = prepare_model_for_kbit_training(
        model, use_gradient_checkpointing=tr.get("gradient_checkpointing", True)
    )
    model.config.use_cache = False

    peft_config = LoraConfig(
        r=lo["r"],
        lora_alpha=lo["alpha"],
        lora_dropout=lo["dropout"],
        bias=lo["bias"],
        task_type=lo["task_type"],
        target_modules=lo["target_modules"],
    )

    ds = load_dataset(
        "json", data_files={"train": da["dataset_path"], "eval": da["eval_path"]}
    )

    def to_text(batch):
        return {
            "text": [
                tokenizer.apply_chat_template(msgs, tokenize=False)
                for msgs in batch["messages"]
            ]
        }

    ds = ds.map(to_text, batched=True, remove_columns=ds["train"].column_names)

    # Completion-only (assistant-only) loss: enabled only when the config asks for
    # it AND the chat template actually supports it; otherwise full-sequence SFT.
    want_completions_only = bool(tr.get("train_on_completions_only", False))
    can_assistant_only = want_completions_only and _template_supports_assistant_only_loss(tokenizer)
    if want_completions_only and not can_assistant_only:
        print(
            "NOTE: train_on_completions_only requested, but the tokenizer chat "
            "template has no {% generation %} markers, so assistant-only loss is "
            "not available on this stack. Training with full-sequence SFT "
            "(this is the RC1 known-good behavior)."
        )

    sft_config = _build_sft_config(SFTConfig, tr, m["max_seq_length"], can_assistant_only)
    trainer = _build_trainer(
        SFTTrainer, model, sft_config, ds["train"], ds["eval"], peft_config, tokenizer
    )

    out_dir = Path(tr["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)

    # Resume support.
    resume_arg = None
    if args.resume == "auto":
        last = get_last_checkpoint(str(out_dir)) if out_dir.exists() else None
        if last:
            print(f"resuming from latest checkpoint: {last}")
            resume_arg = last
        else:
            print("no checkpoint found in output_dir; starting fresh")
    elif args.resume:
        resume_arg = args.resume
        print(f"resuming from checkpoint: {resume_arg}")

    train_result = trainer.train(resume_from_checkpoint=resume_arg)

    # Persist everything: adapter config+weights, tokenizer, args, logs, checkpoint.
    trainer.save_model(str(out_dir))           # adapter_config.json + weights + training_args.bin
    trainer.save_state()                        # trainer_state.json (final checkpoint state)
    tokenizer.save_pretrained(str(out_dir))     # tokenizer files

    # Write a compact training log/summary for provenance.
    try:
        metrics = dict(train_result.metrics)
    except Exception:
        metrics = {}
    (out_dir / "training_summary.json").write_text(
        json.dumps(
            {
                "base_model": m["base_model"],
                "epochs": tr["num_train_epochs"],
                "lora_r": lo["r"],
                "assistant_only_loss": bool(can_assistant_only),
                "metrics": metrics,
                "log_history": getattr(trainer.state, "log_history", []),
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    if not _adapter_artifacts_present(out_dir):
        print(
            f"ERROR: training finished but adapter artifacts are missing in {out_dir} "
            "(expected adapter_config.json + adapter_model.safetensors/.bin).",
            file=sys.stderr,
        )
        return 1

    print(f"adapter saved to {out_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
