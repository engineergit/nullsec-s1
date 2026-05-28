# Nullsec-1

**Nullsec-1 is a real training, serving, and safety framework for a specialized security LLM purpose-built for securing AI-generated applications.**

It defines a security-native model that reviews code — AI-generated apps, agents, MCP tools, smart contracts, and vibecoded software — to detect vulnerabilities, classify severity, reason about exploit scenarios, generate secure patches, and emit a single structured security verdict. Every verdict passes through a deterministic **Security Alignment Layer** and **Nullsec Safety Layer** before it is trusted.

> Nullsec-1 proposes. The Nullsec Safety Layer enforces.

### What is real right now

The training pipeline, dataset schema and ingestion, the Security Alignment + Safety Layers, the serving layer, the CLI, the CI gate, the benchmark suite, and the adversarial safety probes are all real and runnable today. The deterministic safety layer is enforceable independent of any model.

The **trained adapter** is produced by you, by running the release pipeline (`RELEASE_TRAINING.md`). Until then this repo is *training-ready*, not a *trained model*. The repo enforces that distinction automatically:

```bash
python scripts/validate_claims.py        # which public claims the artifacts currently support
```

- **Before adapter training:** "Nullsec-1 is a real training, serving, and safety framework for a specialized security LLM."
- **After a validated release run** (trained adapter + real-model benchmarks + passing safety probes): the generated `RELEASE_SUMMARY.md` states the trained-model claim, and `validate_claims.py` permits it. Until that run exists, the repo will not assert it.

### Technical honesty

Nullsec-1 is **not trained from scratch**. It is fine-tuned from an open code model (Qwen2.5-Coder, Apache 2.0) on code-security datasets and aligned through deterministic security enforcement. The model proposes verdicts; the deterministic Security Alignment Layer and Safety Layer enforce them. That combination — a security-tuned model plus a non-bypassable safety layer — is what makes Nullsec-1 a security-native system rather than a code model that emits opinions. Benchmark numbers exist only after a real evaluation run; this repo ships none.

---

## Why Nullsec-1

- **Security-native LLM.** Trained and aligned for one job: finding and fixing security risk in code.
- **Purpose-built for AI-generated applications.** Oriented toward the failure modes of LLM-written apps, autonomous agents, and MCP tooling.
- **Trained for vibecoded software.** The taxonomy and datasets target the exact classes of bug that ship when software is generated fast: exposed secrets, missing auth, unbounded wallet transactions, prompt injection, over-scoped tools.
- **Built for secure autonomous software creation.** A non-bypassable safety layer means an agent cannot talk Nullsec-1 into declaring unsafe code shippable.

## Architecture

```
   source code
        │
        ▼
┌──────────────────────┐
│  Nullsec-1            │  security-tuned model: detect · classify · explain · patch
│  (reasoning pipeline) │
└──────────┬───────────┘
           │ raw verdict
           ▼
┌──────────────────────┐
│ Security Alignment    │  parse · schema-validate · normalize severities
│ Layer                 │
└──────────┬───────────┘
           │ structurally-valid verdict
           ▼
┌──────────────────────┐
│ Nullsec Safety Layer  │  deterministic enforcement of production-readiness
└──────────┬───────────┘
           │
           ▼
   enforced security verdict   (production_ready computed, never trusted from the model)
```

The model's own `production_ready` claim is **advisory only**. The Safety Layer recomputes it and allows `true` only when all eight check dimensions pass with no HIGH/CRITICAL finding:

`auth · secrets · input_validation · rate_limits · permissions · dangerous_exec · dependency_risk · environment_exposure`

A verdict is blocked if any dimension is `not_checked` or `fail`, any finding is HIGH/CRITICAL, risk exceeds threshold, or a finding contradicts a dimension marked `pass`. The Safety Layer also raises (never lowers) severity and risk to match findings, so the model cannot under-report.

Full design: [`docs/architecture/nullsec1_architecture.md`](docs/architecture/nullsec1_architecture.md). Methodology and limitations: [`docs/research/NULLSEC1_TECHNICAL_REPORT.md`](docs/research/NULLSEC1_TECHNICAL_REPORT.md). Identity and intended use: [`model_card/NULLSEC1.md`](model_card/NULLSEC1.md).

## Repo layout

```
model_card/        Nullsec-1 model card (identity, intended use, limitations)
taxonomy/          canonical security taxonomy — single source of truth
corpus/            curated training corpus (single source of truth) + authored/ + synthetic/ + ingested/
data/              verdict schema (data/schemas)
training/          QLoRA fine-tuning: prepare_dataset · train_qlora · merge_adapter · config.yaml
nullsec/
  core/            reasoning pipeline (engine), models, prompts, version/identity
  safety/          Security Alignment Layer (alignment) + Nullsec Safety Layer (enforcement)
  ingest/          CVE/NVD, Semgrep, SARIF/CodeQL ingestion
serving/           FastAPI serving layer (/v1/model, /v1/analyze, /v1/patch, streaming)
benchmarks/        benchmark suite + adversarial Safety Layer probes
scripts/           release_candidate.py (build a release) + validate_claims.py (enforce honesty)
releases/          generated release bundles (real artifacts only; ships empty)
cli/               nullsec1 command-line analyzer + CI gate
tests/             deterministic-layer test suite (no GPU)
docs/              architecture · technical report · dataset card · guides · API
.github/workflows/ CI security gate
```

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q                                  # deterministic security layers, no GPU
python -m nullsec.core.version             # model identity + fingerprint
```

Train (single 24GB GPU):
```bash
pip install -e ".[train]"
python training/prepare_dataset.py --out data/processed
python training/train_qlora.py --config training/config.yaml
```

Serve and analyze:
```bash
export NULLSEC_ADAPTER_PATH=outputs/nullsec1-7b-qlora
nullsec1 serve --port 8000                 # GET /v1/model, POST /v1/analyze, ...
nullsec1 analyze ./my-app                  # CI gate: exits non-zero if not production-ready
```

Benchmark (produces reports only from real runs):
```bash
python benchmarks/run_all.py --mode model --adapter outputs/nullsec1-7b-qlora
```

Cut a release candidate (full path in `RELEASE_TRAINING.md`):
```bash
python scripts/release_candidate.py --adapter outputs/nullsec1-7b-qlora
python scripts/validate_claims.py --adapter outputs/nullsec1-7b-qlora --check
```

## Hardware

| Setup | Model | Configuration |
|-------|-------|---------------|
| Single 24GB (3090/4090) | Qwen2.5-Coder-7B-Instruct (default) | 4-bit QLoRA, batch 1 × grad-accum 16, configurable context (2048 default) |
| A100 / 40GB+ | Qwen2.5-Coder-14B-Instruct | uncomment the override block in `training/config.yaml` — config-only swap |

## Project status

Nullsec-1 is an early but real security LLM project, and the repo enforces honesty about its own state. The components here are real and executable: the QLoRA training pipeline, dataset schema and ingestion, the Security Alignment + Safety Layers, the serving layer, the CLI, the CI gate, the tests, the benchmark suite, the adversarial safety probes, and the release pipeline. The **curated corpus** in `corpus/` is the single source of truth for training data; production-grade detection requires scaling it with CVEs, scanner outputs, and real AI-generated application failures (see [`docs/dataset_card.md`](docs/dataset_card.md)). Benchmarks report numbers only after running against real datasets — this repo ships no precomputed results — and `scripts/validate_claims.py` gates which public claims the current artifacts support. Deeper patch verification (compile/run/test) is tracked as future work in the technical report.

## License
Apache 2.0 (matches the Qwen2.5-Coder base).
