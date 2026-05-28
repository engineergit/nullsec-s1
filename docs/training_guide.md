# Training Guide — Nullsec-1

This walks through training the LoRA adapter from a clean checkout on a single 24GB GPU.

## 1. Environment

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[train]"        # torch, transformers, peft, trl, bitsandbytes, datasets, accelerate
```

Verify CUDA sees the GPU:
```bash
python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_device_name(0))"
```

You also need access to the base model on Hugging Face (Qwen2.5-Coder is open, Apache 2.0). Log in if you hit rate limits: `huggingface-cli login`.

## 2. Build the dataset

```bash
python training/prepare_dataset.py --out data/processed --eval-split 0.1
```

This reads the curated corpus (`corpus/`, the single source of truth), validates every verdict through the Security Alignment Layer and Nullsec Safety Layer, and writes `data/processed/train.jsonl` and `eval.jsonl`. The number of records matches `dataset_stats.py` for the same flags. Synthetic/ingested examples are included only with `--include-synthetic` / `--include-ingested`.

To scale before training, ingest real data first (see `docs/dataset_card.md`):
```bash
# 1) ingest to a staging area (raw, uncurated)
python -m nullsec.ingest.import_cve --feed nvdcve-2.0.json --out data/raw/cve.jsonl
python -m nullsec.ingest.import_scanners --semgrep semgrep.json --out data/raw/semgrep.jsonl
# 2) validate + human-curate, then land records in corpus/ingested/ (provenance curated_ingested)
#    only curated data in corpus/ingested/ is training-eligible via --include-ingested
# curate the NEEDS_CURATION patch fields, then re-run prepare_dataset.py
```

## 3. Train

```bash
python training/train_qlora.py --config training/config.yaml
```

What the config does on 24GB:
- 4-bit NF4 quantization of the base, LoRA rank 16 on all attention + MLP projections.
- `per_device_train_batch_size: 1` × `gradient_accumulation_steps: 16` → effective batch 16.
- `max_seq_length: 2048`, gradient checkpointing on, `paged_adamw_8bit`, bf16.
- **Completion-only loss:** `DataCollatorForCompletionOnlyLM` masks everything up to the Qwen assistant marker (`<|im_start|>assistant\n`), so the model learns to produce the verdict, not to echo the prompt.

The adapter is saved to `outputs/nullsec-s1-qlora/`.

## 4. Hyperparameters worth tuning
| Knob | Default | When to change |
|------|---------|----------------|
| `num_train_epochs` | 3 | Raise for a small corpus, lower if you scale to tens of thousands of examples. |
| `learning_rate` | 2e-4 | Lower (1e-4) if loss is unstable. |
| `lora.r` / `lora.alpha` | 16 / 32 | Raise to 32/64 for more capacity on a larger corpus (needs more VRAM). |
| `max_seq_length` | 2048 | Raise to fit multi-file context on bigger cards. |

## 5. Swapping to 14B (A100/40GB+)
Edit `training/config.yaml`, uncomment the override block at the bottom and merge into the keys above: set `base_model` to `Qwen/Qwen2.5-Coder-14B-Instruct`, `max_seq_length: 4096`, batch 2 × grad-accum 8, LoRA 32/64. Everything else is identical.

## 6. Common OOM fixes on 24GB
- Keep `per_device_train_batch_size: 1`; increase `gradient_accumulation_steps` instead.
- Ensure `gradient_checkpointing: true`.
- Lower `max_seq_length` (e.g. 1536) if your examples are short.
- Close other GPU processes; QLoRA 7B should sit around 14–18GB.
- If `bitsandbytes` errors on load, confirm the CUDA toolkit matches your torch build.

## 7. Evaluate the result
```bash
python training/evaluate.py --mode model --adapter outputs/nullsec-s1-qlora
```
Compare detection F1, severity accuracy, and verdict accuracy against the baseline in the report. Track these across runs as you scale the dataset.
