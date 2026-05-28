# Deployment Guide — Nullsec-1

How to serve Nullsec-1 in production, as an adapter or a merged model, locally or in Docker.

## Serving modes

### A. Base + adapter (recommended for iteration)
Keep the LoRA adapter separate and load it on top of the quantized base at runtime. Smallest footprint, easy to swap adapter versions.

```bash
export NULLSEC_BASE_MODEL=Qwen/Qwen2.5-Coder-7B-Instruct
export NULLSEC_ADAPTER_PATH=outputs/nullsec1-7b-qlora
export NULLSEC_4BIT=1
nullsec1 serve --host 0.0.0.0 --port 8000
# or: uvicorn serving.server:app --host 0.0.0.0 --port 8000
```

### B. Merged model (simplest runtime)
Merge once (`training/merge_adapter.py`), then serve the dense weights with no PEFT dependency. Best when the adapter is stable.

```bash
export NULLSEC_BASE_MODEL=outputs/nullsec1-7b-merged
unset NULLSEC_ADAPTER_PATH
nullsec1 serve --port 8000
```

## Environment variables
| Var | Default | Meaning |
|-----|---------|---------|
| `NULLSEC_BASE_MODEL` | `Qwen/Qwen2.5-Coder-7B-Instruct` | Base model id or local path. |
| `NULLSEC_ADAPTER_PATH` | (unset) | LoRA adapter dir; omit when serving a merged model. |
| `NULLSEC_4BIT` | `1` | Load base in 4-bit NF4. Set `0` for fp16/bf16 on big cards. |
| `NULLSEC_MAX_NEW_TOKENS` | `1536` | Generation budget for a verdict. |
| `NULLSEC_TEMPERATURE` | `0.0` | Greedy by default for deterministic verdicts. |
| `NULLSEC_DEVICE_MAP` | `auto` | Passed to `from_pretrained`. |
| `NULLSEC_EAGER_LOAD` | `0` | `1` loads the model at startup instead of first request. |

## Docker

```bash
docker build -t nullsec1:latest .
docker run --gpus all -p 8000:8000 \
  -e NULLSEC_ADAPTER_PATH=/adapter \
  -v $(pwd)/outputs/nullsec1-7b-qlora:/adapter:ro \
  nullsec1:latest
```

The image is CUDA 12.1 runtime + cuDNN8, installs `requirements-train.txt`, and has a `/health` healthcheck (120s start period to allow model load). Mount the adapter read-only and point `NULLSEC_ADAPTER_PATH` at the mount.

For a CPU-only image (no model weights — useful for running the deterministic Security Alignment and Safety Layers over captured outputs), swap the base image for `python:3.11-slim` and install `requirements.txt`.

## Scaling & operations
- **Warm start:** set `NULLSEC_EAGER_LOAD=1` so the first request doesn't pay the load cost; pair with the healthcheck start period.
- **Concurrency:** generation is GPU-bound; run one worker per GPU and put a queue/load balancer in front rather than many uvicorn workers sharing a card.
- **Throughput:** for high volume, serve merged Nullsec-1 weights via a dedicated inference engine (vLLM/TGI) using the same system instruction from `nullsec/core/prompts.py`, and keep the Nullsec Safety Layer (`nullsec/safety/`) as a thin post-processing service in front of it — it is pure Python and CPU-cheap.
- **The Safety Layer is independent of serving.** However you generate, always pipe raw output through `NullsecPipeline.finalize()` (Security Alignment Layer → Nullsec Safety Layer) before trusting `production_ready`.

## CI integration
Use the CLI as a gate in a pipeline:
```bash
nullsec1 analyze ./src --json-out nullsec-report.json
# exit code 1 if any file is not production-ready -> fails the build
```
