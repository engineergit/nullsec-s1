"""Nullsec-1 training corpus loader.

`load_corpus()` returns the curated, hand-authored examples by default. Synthetic
(augmented) and ingested examples are included only when explicitly requested, so
"curated" never silently includes generated data.

  load_corpus()                      -> hand-authored only (curated)
  load_corpus(include_synthetic=True)-> curated + synthetic/*.jsonl
  load_corpus(include_ingested=True) -> curated + ingested/*.jsonl
"""
from __future__ import annotations

import importlib
import json
import pkgutil
from pathlib import Path

_HERE = Path(__file__).resolve().parent
SYNTHETIC_DIR = _HERE / "synthetic"
INGESTED_DIR = _HERE / "ingested"

CURATED_PROVENANCE = {"hand_authored", "curated_ingested"}


def _load_authored() -> list[dict]:
    import corpus.authored as authored_pkg

    examples: list[dict] = []
    for mod in pkgutil.iter_modules(authored_pkg.__path__):
        if mod.name.startswith("_"):
            continue
        m = importlib.import_module(f"corpus.authored.{mod.name}")
        examples.extend(getattr(m, "EXAMPLES", []))
    return examples


def _load_jsonl_dir(d: Path) -> list[dict]:
    out: list[dict] = []
    if not d.exists():
        return out
    for fp in sorted(d.glob("*.jsonl")):
        for line in fp.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def load_corpus(include_synthetic: bool = False, include_ingested: bool = False) -> list[dict]:
    examples = _load_authored()
    if include_ingested:
        examples += _load_jsonl_dir(INGESTED_DIR)
    if include_synthetic:
        examples += _load_jsonl_dir(SYNTHETIC_DIR)
    return examples


def is_curated(example: dict) -> bool:
    return example.get("provenance") in CURATED_PROVENANCE


def split(examples: list[dict], eval_frac: float = 0.2, seed: int = 42):
    """Deterministic train/eval split, returned as (train, eval). Shared by
    prepare_dataset and dataset_stats so the reported split matches what is
    actually written."""
    import random

    items = list(examples)
    random.Random(seed).shuffle(items)
    n_eval = max(1, int(len(items) * eval_frac)) if items else 0
    return items[n_eval:], items[:n_eval]
