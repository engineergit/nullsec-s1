#!/usr/bin/env python3
"""Augment the corpus with LABELED synthetic variants of curated examples.

This is optional bootstrap augmentation, not curation. Every variant is tagged
`provenance: "synthetic_variant"` with a `source` pointing at the curated example
it derives from, and is written to corpus/synthetic/. Synthetic variants never
count toward the curated thresholds in release_threshold.py — they exist to add
surface-form robustness during early training, and should be replaced by real
ingested/curated data before a production release.

Transformations are conservative and structure-preserving (identifier renames,
literal-value swaps, file renames), so the embedded verdict stays valid and
Safety-Layer-consistent. The vulnerability class, severity, and checks are never
altered.

  python training/synthesize_corpus.py --per-source 3
  python training/synthesize_corpus.py --target 500   # generate up to a total count
"""
from __future__ import annotations

import argparse
import copy
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from corpus import is_curated, load_corpus
from nullsec.safety import VerdictParseError, align_and_enforce

OUT = ROOT / "corpus" / "synthetic"

_VAR_RENAMES = [("uid", "userId"), ("host", "target"), ("url", "endpoint"),
                ("file", "filename"), ("cmd", "command"), ("amt", "amount"),
                ("data", "payload"), ("name", "ident")]
_FILE_PREFIX = ["svc", "handler", "mod", "api", "core", "app"]


def _variant(ex: dict, rng: random.Random, n: int) -> dict | None:
    v = copy.deepcopy(ex)
    v["id"] = f"{ex['id']}-syn{n}"
    v["provenance"] = "synthetic_variant"
    v["source"] = ex["id"]

    # rename a couple of identifiers consistently across code + patch
    renames = rng.sample(_VAR_RENAMES, k=min(2, len(_VAR_RENAMES)))
    code = ex["code"]
    for a, b in renames:
        code = code.replace(a, b)
    v["code"] = code
    for f in v["verdict"].get("findings", []):
        if f.get("secure_patch"):
            for a, b in renames:
                f["secure_patch"] = f["secure_patch"].replace(a, b)

    # rename the file consistently in the verdict
    old_files = v["verdict"].get("affected_files") or []
    if old_files:
        old = old_files[0]
        new = f"{rng.choice(_FILE_PREFIX)}_{old}"
        v["verdict"]["affected_files"] = [new] + old_files[1:]
        for f in v["verdict"].get("findings", []):
            if f.get("file") == old:
                f["file"] = new

    # validity gate: a variant that does not validate or flips the Safety Layer
    # decision is discarded, never shipped.
    try:
        res = align_and_enforce(json.dumps(v["verdict"]))
    except VerdictParseError:
        return None
    if res.production_ready != v.get("expected_production_ready"):
        return None
    return v


def main():
    ap = argparse.ArgumentParser(description="Generate labeled synthetic corpus variants")
    ap.add_argument("--per-source", type=int, default=2)
    ap.add_argument("--target", type=int, default=None, help="generate until total corpus reaches this size")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    curated = [e for e in load_corpus() if is_curated(e)]
    rng = random.Random(args.seed)

    if args.target:
        existing = len(load_corpus(include_synthetic=True))
        need = max(0, args.target - existing)
        per = (need // max(1, len(curated))) + 1
    else:
        per = args.per_source

    variants: list[dict] = []
    for ex in curated:
        for i in range(per):
            var = _variant(ex, rng, i)
            if var:
                variants.append(var)
    if args.target:
        existing = len(load_corpus(include_synthetic=True))
        variants = variants[: max(0, args.target - existing)]

    OUT.mkdir(parents=True, exist_ok=True)
    out_file = OUT / "variants.jsonl"
    with out_file.open("w", encoding="utf-8") as fh:
        for v in variants:
            fh.write(json.dumps(v) + "\n")
    print(f"wrote {len(variants)} synthetic variants -> {out_file}")
    print("NOTE: synthetic variants are labeled and do NOT count as curated. "
          "Run training/release_threshold.py to see the honest curated count.")


if __name__ == "__main__":
    main()
