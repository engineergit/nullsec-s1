#!/usr/bin/env bash
#
# Nullsec S1 — end-to-end training pipeline.
#
# Runs the full path from the curated corpus to a validated release bundle:
#
#   prepare -> validate corpus -> release threshold -> preflight ->
#   train QLoRA -> (optional) merge -> benchmark -> release candidate ->
#   validate public claims
#
# Run this on a CUDA-capable NVIDIA GPU box, inside the project virtualenv
# (see GPU_QUICKSTART.md). Every step is real and refuses to proceed on bad
# input; nothing here fabricates a model, a benchmark, or a claim.
#
# Environment overrides:
#   CONFIG       training config            (default: training/config.yaml)
#   ADAPTER_OUT  adapter output directory   (default: outputs/nullsec1-7b-qlora)
#   DATASET      benchmark dataset filename (default: detection.json)
#   MERGE        set to 1 to also merge the adapter into dense weights
#   BASE_MODEL   base model for the merge step (default: Qwen/Qwen2.5-Coder-7B-Instruct)
#
# Usage:
#   bash scripts/run_training_pipeline.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONFIG="${CONFIG:-training/config.yaml}"
ADAPTER_OUT="${ADAPTER_OUT:-outputs/nullsec1-7b-qlora}"
DATASET="${DATASET:-detection.json}"
BASE_MODEL="${BASE_MODEL:-Qwen/Qwen2.5-Coder-7B-Instruct}"
PY="${PYTHON:-python}"

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

step "1/8  Prepare dataset (curated + ingested)"
"$PY" training/prepare_dataset.py --include-ingested --out data/processed

step "2/8  Validate corpus quality"
"$PY" training/validate_corpus.py --include-ingested

step "3/8  Release-readiness threshold"
"$PY" training/release_threshold.py --include-ingested

step "4/8  Preflight (GPU, deps, dataset, corpus, safety probes)"
set +e
"$PY" training/preflight_train.py --config "$CONFIG"
PF=$?
set -e
if [ "$PF" -eq 2 ]; then
    echo "ABORT: no CUDA GPU detected. QLoRA training requires an NVIDIA GPU."
    echo "       See GPU_QUICKSTART.md to provision one, then re-run this script."
    exit 2
elif [ "$PF" -ne 0 ]; then
    echo "ABORT: preflight reported a blocking problem (exit $PF). Fix the FAIL rows above."
    exit "$PF"
fi

step "5/8  Train QLoRA adapter -> ${ADAPTER_OUT}"
"$PY" training/train_qlora.py --config "$CONFIG"

if [ "${MERGE:-0}" = "1" ]; then
    step "6/8  Merge adapter into dense weights"
    "$PY" training/merge_adapter.py --base "$BASE_MODEL" --adapter "$ADAPTER_OUT" --out "${ADAPTER_OUT}-merged"
else
    step "6/8  Merge adapter  (skipped; set MERGE=1 to enable)"
fi

step "7/8  Benchmark against the real model"
"$PY" benchmarks/run_all.py --mode model --adapter "$ADAPTER_OUT"

step "8/8  Build release candidate + validate public claims"
"$PY" scripts/release_candidate.py --adapter "$ADAPTER_OUT" --dataset "$DATASET"
"$PY" scripts/validate_claims.py --adapter "$ADAPTER_OUT" \
    --report releases/nullsec-1.0/benchmark/SUITE.json --check

echo
echo "Pipeline complete. Release bundle (if all gates passed): releases/nullsec-1.0/"
echo "Public claims now reflect exactly what the produced artifacts support."
