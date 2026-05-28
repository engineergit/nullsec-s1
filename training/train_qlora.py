#!/usr/bin/env python3
"""QLoRA fine-tuning for Nullsec-1.

Single-24GB-GPU defaults via training/config.yaml. Trains a LoRA adapter on top
of a 4-bit quantized base, with completion-only loss so gradient flows only
through the verdict JSON, not the prompt.

Usage:
  python training/train_qlora.py --config training/config.yaml
"""
from __future__ import annotations

import argparse
from pathlib import Path

import yaml


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="training/config.yaml")
    args = ap.parse_args()
    cfg = load_config(args.config)

    import torch
    from datasets import load_dataset
    from peft import LoraConfig, prepare_model_for_kbit_training
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
    )
    from trl import SFTConfig, SFTTrainer

    m, q, lo, tr, da = (
        cfg["model"],
        cfg["quantization"],
        cfg["lora"],
        cfg["training"],
        cfg["data"],
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

    model = AutoModelForCausalLM.from_pretrained(
        m["base_model"],
        quantization_config=bnb,
        device_map="auto",
        torch_dtype=dtype,
        trust_remote_code=m.get("trust_remote_code", True),
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
        "json",
        data_files={"train": da["dataset_path"], "eval": da["eval_path"]},
    )

    def to_text(batch):
        return {
            "text": [
                tokenizer.apply_chat_template(msgs, tokenize=False)
                for msgs in batch["messages"]
            ]
        }

    ds = ds.map(to_text, batched=True, remove_columns=ds["train"].column_names)

    sft_config = SFTConfig(
        output_dir=tr["output_dir"],
        num_train_epochs=tr["num_train_epochs"],
        per_device_train_batch_size=tr["per_device_train_batch_size"],
        gradient_accumulation_steps=tr["gradient_accumulation_steps"],
        learning_rate=tr["learning_rate"],
        lr_scheduler_type=tr["lr_scheduler_type"],
        warmup_ratio=tr["warmup_ratio"],
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
        max_seq_length=m["max_seq_length"],
        packing=False,
        dataset_text_field="text",
    )

    # Completion-only loss: mask everything up to the assistant turn.
    collator = None
    if tr.get("train_on_completions_only", True):
        from trl import DataCollatorForCompletionOnlyLM

        # Qwen2.5 chat template assistant marker.
        response_template = "<|im_start|>assistant\n"
        collator = DataCollatorForCompletionOnlyLM(
            response_template, tokenizer=tokenizer
        )

    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=ds["train"],
        eval_dataset=ds["eval"],
        peft_config=peft_config,
        data_collator=collator,
    )
    trainer.train()
    trainer.save_model(tr["output_dir"])
    tokenizer.save_pretrained(tr["output_dir"])
    print(f"adapter saved to {Path(tr['output_dir']).resolve()}")


if __name__ == "__main__":
    main()
