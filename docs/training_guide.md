# Training Guide — Nullsec-1

This walks through training the LoRA adapter from a clean checkout on a single 24GB GPU.

## 1. Environment

Use the known-good CUDA 12.1 stack that completed RC1 (RunPod A100 80GB). Install
the pinned torch build first so nothing replaces it:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pip install torch==2.5.1+cu121 --index-url https://download.pytorch.org/whl/cu121
pip install -r requirements-train-cu121.txt
```

Verify CUDA sees the GPU (and torch can actually use it):
```bash
python -c "import torch; print(torch.__version__, torch.version.cuda, torch.cuda.is_available())"
# expect e.g.  2.5.1+cu121 12.1 True
```

> A CUDA 13 / Torch 2.12 wheel failed on the RunPod driver during RC1. If
> `torch.cuda.is_available()` is `False` while `nvidia-smi` shows a GPU, reinstall
> the cu121 line above. If `datasets` errors on fsspec, `pip install "fsspec==2024.6.1"`.
> `python training/preflight_train.py` detects both before you spend GPU time.

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
- 2048-token context (`max_seq_length` in config → `SFTConfig(max_length=...)`), gradient checkpointing on, `paged_adamw_8bit`, bf16, explicit `warmup_steps`.

**Loss / completion-only (RC1 stack note).** The legacy
`trl.DataCollatorForCompletionOnlyLM` was **removed** — recent TRL no longer
exports it, which broke the RC1 run. `train_qlora.py` now uses full-sequence SFT
by default. Modern TRL expresses assistant-only loss via
`SFTConfig(assistant_only_loss=True)`, which needs a chat template with
`{% generation %}` markers; Qwen2.5-Coder's stock template lacks them, so RC1
trained with full-sequence SFT (and still reached its reported detection F1). The
script enables assistant-only loss only when `train_on_completions_only: true`
**and** the template supports it, and otherwise falls back with a clear warning —
never a silent break.

**Resume.** `python training/train_qlora.py --config training/config.yaml --resume auto`
continues from the latest checkpoint in `output_dir`. The script saves the adapter
config + weights, tokenizer, training args, a `training_summary.json` log, and the
final checkpoint, and **exits non-zero** if adapter artifacts are missing after
training.

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
python benchmarks/run_all.py --mode model --adapter outputs/nullsec-s1-qlora
```
This runs the real model over the 111-case benchmark (`benchmarks/datasets/detection.json`)
and writes `benchmarks/reports/SUITE.json` with detection precision/recall/F1,
false-safe rate, hallucination rate, patch correctness, secure-generation score,
OWASP coverage, **per-category recall**, and the **failed case IDs** for triage.
Numbers come only from real runs; a case with no output is a real miss. Track these
across runs as you scale the dataset.

## 8. Cut a release candidate
```bash
python scripts/release_candidate.py --adapter outputs/nullsec-s1-qlora --dataset detection.json
python scripts/validate_claims.py --adapter outputs/nullsec-s1-qlora \
    --report releases/nullsec-1.0/benchmark/SUITE.json --check
```
The release pipeline aborts unless the adapter, real-model benchmark, and safety
probes are all real. The RC2 production-ready gate additionally requires ≥ 100
benchmark cases, zero false-safe rate, and detection F1 ≥ 0.90.
