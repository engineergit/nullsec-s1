# Training Nullsec S1 on RunPod

A step-by-step, copy-paste guide to running a **real** Nullsec S1 (`Nullsec-1.0`)
QLoRA training run on [RunPod](https://www.runpod.io/). If you have never rented
a GPU before, follow this top to bottom.

For the provider-agnostic version (Lambda, Vast, your own box) see
[`GPU_QUICKSTART.md`](GPU_QUICKSTART.md). This file is the RunPod-specific path.

> Nothing here fakes a model. You are running the real pipeline; it produces real
> artifacts and refuses to produce a release bundle unless they are real.

---

## 1. Pick a GPU

The 7B default fits on a single 24 GB card.

| Tier | GPU | Notes |
|------|-----|-------|
| **Minimum** | **RTX 4090 (24 GB)** | Runs the 7B QLoRA default comfortably. |
| Better | **A40 / A6000 (48 GB)** | More VRAM headroom, longer context. |
| Best | **A100 (40/80 GB)** | Fastest; required for the 14B config swap. |

A single GPU is enough — you do **not** need a multi-GPU pod.

## 2. Pick storage

QLoRA writes a small adapter, but the base model download and caches are large.

- **Minimum: 100 GB** container/volume disk.
- **Safer: 150 GB** (especially if you also merge to dense weights with `MERGE=1`).

Set this as the **Volume Disk** (and/or Container Disk) size when you configure
the pod.

## 3. Create the pod with a PyTorch/CUDA template

1. In the RunPod console, go to **Pods → Deploy**.
2. Choose a GPU from the table above (e.g. **RTX 4090**).
3. Select an official **PyTorch** template (e.g. *"RunPod PyTorch 2.x"*) — it ships
   CUDA drivers and PyTorch preinstalled, which is what the train stack needs.
4. Set **Volume Disk** to 100–150 GB.
5. Deploy the pod and wait until its status is **Running**.

## 4. Open the web terminal

1. Click your running pod → **Connect**.
2. Choose **Start Web Terminal** → **Connect to Web Terminal** (or use SSH if you
   prefer). You now have a shell on the GPU box.

## 5. Confirm the GPU is visible

```bash
nvidia-smi
```

You should see your GPU (e.g. `NVIDIA GeForce RTX 4090`) and its memory. If this
errors, the pod has no GPU attached — redeploy with a GPU template before going
further.

## 6. Clone the repo

```bash
git clone https://github.com/trynullsec/nullsec-s1.git
cd nullsec-s1
```

## 7. Create a virtualenv

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
```

## 8. Install dev dependencies (CPU/runtime)

```bash
python -m pip install -e ".[dev]"
```

## 9. Install train dependencies (GPU stack)

```bash
python -m pip install -r requirements-train.txt
```

This pulls torch, transformers, peft, trl, bitsandbytes, datasets, accelerate,
and sentencepiece.

## 10. Prepare the dataset

```bash
python training/prepare_dataset.py --include-ingested --out data/processed
```

Expected: `400 -> train.jsonl`, `100 -> eval.jsonl` (500 total).

## 11. Run preflight

```bash
python training/preflight_train.py
```

On a correctly configured GPU pod every row should read `OK` and it prints
`RESULT: READY` (exit `0`). If it prints `NO GPU` / exits `2`, your pod is not
GPU-backed — fix that first (step 5).

## 12. Run the training pipeline

```bash
bash scripts/run_training_pipeline.sh
```

This runs, in order: prepare → validate corpus → release threshold → preflight →
train QLoRA → (optional merge) → benchmark against the real model → build the
release candidate → validate public claims.

Optional: also produce merged dense weights for high-throughput serving:

```bash
MERGE=1 bash scripts/run_training_pipeline.sh
```

The adapter is written to **`outputs/nullsec-s1-qlora/`** (set in
`training/config.yaml`).

## 13. Expected output artifacts

After a successful run, confirm these exist:

```bash
ls -la outputs/nullsec-s1-qlora/adapter_config.json
ls -la outputs/nullsec-s1-qlora/adapter_model.safetensors
ls -la benchmarks/reports/SUITE.json
ls -la releases/nullsec-1.0/RELEASE_SUMMARY.md
ls -la releases/nullsec-1.0/fingerprint.txt
ls -la releases/nullsec-1.0/safety_probes.json
```

- `outputs/nullsec-s1-qlora/adapter_config.json` — adapter config
- `outputs/nullsec-s1-qlora/adapter_model.safetensors` — adapter weights
- `benchmarks/reports/SUITE.json` — real-model benchmark report (`run_mode: "model"`)
- `releases/nullsec-1.0/RELEASE_SUMMARY.md` — generated release summary
- `releases/nullsec-1.0/fingerprint.txt` — model fingerprint
- `releases/nullsec-1.0/safety_probes.json` — adversarial probe result (`passed: true`)

Then re-check which public claims the artifacts now support:

```bash
python scripts/validate_claims.py --adapter outputs/nullsec-s1-qlora \
    --report releases/nullsec-1.0/benchmark/SUITE.json --check
```

`trained model` and `benchmarked` unlock once the adapter and a real-model report
exist; `release candidate` unlocks only with the full bundle + passing probes;
`production-ready` only if the strict quality gate passes (zero false-safe rate and
adequate detection F1). If quality is weak, report the numbers honestly and retrain
— do **not** assert production-ready (see [`docs/NON_CLAIMS.md`](docs/NON_CLAIMS.md)).

## 14. Package the artifacts

Bundle everything you want to download into one tarball:

```bash
tar -czf nullsec-s1-trained-artifacts.tar.gz outputs benchmarks/reports releases reports
```

Download it from the RunPod console (file browser) or via SSH/`scp`/`runpodctl`,
then verify locally.

## 15. Stop / terminate the pod

**Do this as soon as your tarball is downloaded — RunPod bills while the pod runs.**

1. RunPod console → your pod → **Stop** (keeps the volume, stops GPU billing) or
   **Terminate** (deletes the pod and its disk).
2. Confirm the pod is no longer in **Running** state. A stopped pod may still incur
   storage cost; **Terminate** to stop all charges once you have your artifacts.

Your trained adapter lives in the downloaded tarball — you do not need the pod
anymore.
