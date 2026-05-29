#!/usr/bin/env python3
"""Preflight checks before a Nullsec-1 GPU training run.

Run this on the GPU box before `train_qlora.py` so a doomed run fails fast and
cheaply instead of failing after the base model has downloaded. It verifies, in
order:

  1. Python version is recent enough.
  2. The GPU training dependencies import (torch, transformers, peft, trl,
     bitsandbytes, datasets, accelerate).
  3. A CUDA-capable NVIDIA GPU is visible to torch.
  4. The processed dataset exists (train.jsonl + eval.jsonl from prepare_dataset).
  5. The curated corpus meets the v1.0 training threshold.
  6. The adversarial Safety Layer probes all pass.

Exit codes:
  0  ready to train on this machine
  2  no CUDA GPU available — you cannot train here; use a GPU box (see GPU_QUICKSTART.md)
  1  another blocking problem (missing deps, missing dataset, or corpus not ready)

Usage:
  python training/preflight_train.py
  python training/preflight_train.py --config training/config.yaml
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

GPU_DEPS = ("torch", "transformers", "peft", "trl", "bitsandbytes", "datasets", "accelerate")
MIN_PYTHON = (3, 10)

# Known-good build from RC1; a CUDA 13 / Torch 2.12 wheel failed on the RunPod driver.
CU121_TORCH_HINT = (
    "Likely a Torch/CUDA build mismatch (e.g. a CUDA 13 / Torch 2.12 wheel on a "
    "CUDA 12.x driver). Reinstall the known-good build:\n"
    "    pip install torch==2.5.1+cu121 --index-url https://download.pytorch.org/whl/cu121\n"
    "Then re-run preflight. See RUNPOD.md / GPU_QUICKSTART.md."
)


def _nvidia_smi_gpu_name() -> str | None:
    """Return the first GPU name reported by nvidia-smi, or None if unavailable."""
    import shutil
    import subprocess

    if not shutil.which("nvidia-smi"):
        return None
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        lines = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
        return lines[0] if lines else None
    except Exception:
        return None


class Check:
    """A single preflight result."""

    def __init__(self, name: str, ok: bool, detail: str, *, gpu: bool = False, mismatch: bool = False):
        self.name = name
        self.ok = ok
        self.detail = detail
        self.gpu = gpu  # True if this check specifically establishes GPU availability
        self.mismatch = mismatch  # True if a GPU is present but torch.cuda can't see it


def check_python() -> Check:
    v = sys.version_info
    ok = (v.major, v.minor) >= MIN_PYTHON
    return Check("python version", ok, f"{v.major}.{v.minor}.{v.micro} (need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})")


def check_gpu_deps() -> tuple[list[Check], bool]:
    checks, all_ok = [], True
    import importlib.util

    for dep in GPU_DEPS:
        present = importlib.util.find_spec(dep) is not None
        checks.append(Check(f"dependency: {dep}", present, "installed" if present else "missing (pip install -e \".[train]\")"))
        all_ok = all_ok and present
    return checks, all_ok


def check_cuda() -> Check:
    """Establish whether a CUDA GPU is visible. This is the GPU gate (exit 2).

    Distinguishes two failure modes:
      - genuinely no GPU (laptop / CPU box), and
      - a GPU is present (nvidia-smi sees it) but torch.cuda cannot use it, which
        is almost always a Torch/CUDA build mismatch.
    """
    try:
        import torch
    except Exception as e:  # torch not installed -> cannot train here
        gpu_name = _nvidia_smi_gpu_name()
        if gpu_name:
            return Check(
                "CUDA GPU", False,
                f"GPU '{gpu_name}' present but torch is not importable ({type(e).__name__})",
                gpu=True, mismatch=True,
            )
        return Check("CUDA GPU", False, f"torch not importable ({type(e).__name__}); install the train stack on a GPU box", gpu=True)
    try:
        available = bool(torch.cuda.is_available())
    except Exception as e:
        return Check("CUDA GPU", False, f"torch.cuda check raised {type(e).__name__}", gpu=True, mismatch=True)
    if not available:
        gpu_name = _nvidia_smi_gpu_name()
        if gpu_name:
            return Check(
                "CUDA GPU", False,
                f"MISMATCH: nvidia-smi sees '{gpu_name}' but torch.cuda.is_available() is False",
                gpu=True, mismatch=True,
            )
        return Check("CUDA GPU", False, "no CUDA device visible to torch (and nvidia-smi reports no GPU)", gpu=True)
    count = torch.cuda.device_count()
    names = ", ".join(torch.cuda.get_device_name(i) for i in range(count))
    built = getattr(torch.version, "cuda", "?")
    return Check("CUDA GPU", True, f"{count} device(s): {names} (torch CUDA {built})", gpu=True)


def check_dataset(config_path: Path) -> Check:
    train_path = ROOT / "data" / "processed" / "train.jsonl"
    eval_path = ROOT / "data" / "processed" / "eval.jsonl"
    # Honor explicit paths from the config when present.
    try:
        import yaml

        if config_path.exists():
            cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            data = cfg.get("data", {})
            train_path = ROOT / data.get("dataset_path", "data/processed/train.jsonl")
            eval_path = ROOT / data.get("eval_path", "data/processed/eval.jsonl")
    except Exception:
        pass
    have_train = train_path.exists() and train_path.stat().st_size > 0
    have_eval = eval_path.exists() and eval_path.stat().st_size > 0
    if have_train and have_eval:
        n = sum(1 for _ in train_path.open()) + sum(1 for _ in eval_path.open())
        return Check("processed dataset", True, f"{n} records ({train_path.name} + {eval_path.name})")
    return Check("processed dataset", False, "run: python training/prepare_dataset.py --include-ingested --out data/processed")


def check_corpus_threshold() -> Check:
    try:
        from corpus import load_corpus
        from training.release_threshold import (
            MIN_CURATED,
            MIN_EVAL,
            MIN_PER_CATEGORY,
            evaluate,
        )

        examples = load_corpus(include_ingested=True)
        r = evaluate(examples, 0.2, 42, MIN_CURATED, MIN_PER_CATEGORY, MIN_EVAL)
        if r["passed"]:
            return Check("corpus threshold", True, f"PASS ({r['stats_summary']['curated_total']} curated)")
        return Check("corpus threshold", False, "BLOCKED — see python training/release_threshold.py --include-ingested")
    except Exception as e:
        return Check("corpus threshold", False, f"could not evaluate ({type(e).__name__}: {e})")


def check_safety_probes() -> Check:
    try:
        from benchmarks.safety_probes import run_safety_probes

        out = run_safety_probes()
        if out["passed"]:
            return Check("safety probes", True, f"{out['total_probes']}/{out['total_probes']} blocked")
        return Check("safety probes", False, f"bypassed: {out['bypassed']}")
    except Exception as e:
        return Check("safety probes", False, f"could not run ({type(e).__name__}: {e})")


def main() -> int:
    ap = argparse.ArgumentParser(description="Preflight checks before GPU training")
    ap.add_argument("--config", default="training/config.yaml")
    args = ap.parse_args()
    config_path = ROOT / args.config

    checks: list[Check] = [check_python()]
    dep_checks, _ = check_gpu_deps()
    checks += dep_checks
    checks.append(check_cuda())
    checks.append(check_dataset(config_path))
    checks.append(check_corpus_threshold())
    checks.append(check_safety_probes())

    width = max(len(c.name) for c in checks)
    print("Nullsec-1 training preflight")
    print("=" * 64)
    for c in checks:
        print(f"[{'OK  ' if c.ok else 'FAIL'}] {c.name.ljust(width)}  {c.detail}")
    print("=" * 64)

    gpu_ok = all(c.ok for c in checks if c.gpu)
    other_ok = all(c.ok for c in checks if not c.gpu)
    mismatch = any(c.mismatch for c in checks if c.gpu)

    if not gpu_ok:
        if mismatch:
            print("RESULT: GPU PRESENT BUT UNUSABLE — Torch/CUDA mismatch.")
            print("        " + CU121_TORCH_HINT.replace("\n", "\n        "))
        else:
            print("RESULT: NO GPU — this machine cannot run QLoRA training.")
            print("        Provision a CUDA-capable NVIDIA GPU box and see GPU_QUICKSTART.md.")
        return 2
    if not other_ok:
        print("RESULT: BLOCKED — a non-GPU prerequisite is not satisfied (see FAIL rows above).")
        return 1
    print("RESULT: READY — preflight passed. You can run training/train_qlora.py.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
