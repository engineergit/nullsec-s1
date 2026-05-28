#!/usr/bin/env python3
"""Nullsec-1 release-candidate pipeline.

Turns a trained adapter into a real release bundle — and refuses to produce one
unless the model, its outputs, and the Safety Layer are all real.

    python scripts/release_candidate.py \
        --adapter outputs/nullsec-s1-qlora \
        --dataset benchmarks/datasets/detection.json

Hard gates (each aborts the release):
  1. adapter directory missing, or no adapter_config.json + weights
  2. model fails to load
  3. zero usable model outputs over the dataset
  4. any benchmark report section is empty
  5. any adversarial Safety Layer probe is bypassed

On success it writes releases/nullsec-1.0/ containing only real artifacts and a
RELEASE_SUMMARY.md generated from the measured numbers.

By default it runs in real-model mode. `--mode replay --replay <file>` scores
captured real outputs instead; the resulting bundle and summary are clearly
marked replay-only, and validate_claims will not grant 'evaluated with real
model outputs' to a replay bundle.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks.harness import OutputProvider, finalize_raw, load_dataset, provenance
from benchmarks.metrics import (
    detection_over,
    false_safe_rate,
    hallucination_rate,
    owasp_coverage,
    patch_correctness,
    secure_generation_score,
)
from benchmarks.safety_probes import run_safety_probes
from scripts._artifacts import find_adapter

RELEASE_DIR = ROOT / "releases" / "nullsec-1.0"
_TOKENIZER_FILES = ("tokenizer.json", "tokenizer_config.json", "tokenizer.model",
                    "vocab.json", "merges.txt", "special_tokens_map.json")


def abort(msg: str) -> "None":
    print(f"\nRELEASE ABORTED: {msg}", file=sys.stderr)
    sys.exit(1)


def run_benchmarks(dataset: dict, provider: OutputProvider):
    """Return (verdicts, raw_capture). raw_capture is the real model output per
    case — saved into the bundle for provenance. No fabrication: a case with no
    output is recorded as None and scored as a miss."""
    verdicts, raw_capture, produced = {}, [], 0
    for case in dataset["cases"]:
        raw = provider.raw_for(case)
        if raw:
            produced += 1
            raw_capture.append({"id": case["id"], "raw": raw})
        verdicts[case["id"]] = finalize_raw(raw)
    return verdicts, raw_capture, produced


def build_suite(cases, verdicts) -> dict:
    return {
        "detection_accuracy": detection_over(cases, verdicts),
        "false_safe_rate": false_safe_rate(cases, verdicts),
        "hallucination_rate": hallucination_rate(cases, verdicts),
        "owasp_coverage": owasp_coverage(cases, verdicts),
        "patch_correctness": patch_correctness(cases, verdicts),
        "secure_generation": secure_generation_score(cases, verdicts),
    }


def write_summary_md(path: Path, summary: dict) -> None:
    s = summary
    res = s["benchmark_results"]
    det = res["detection_accuracy"]
    fsr = res["false_safe_rate"]
    real_model = s["run_mode"] == "model"
    headline = (
        "Nullsec-1.0 is a trained specialized security LLM purpose-built for securing AI-generated applications."
        if real_model else
        "Nullsec-1.0 was evaluated in REPLAY mode over captured outputs (not a live-model evaluation)."
    )
    lines = [
        "# Nullsec-1.0 — Release Summary",
        "",
        f"> {headline}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Model name | {s['model_name']} |",
        f"| Version | {s['version']} |",
        f"| Base model | {s['base_model']} |",
        f"| Training method | {s['training_method']} |",
        f"| Dataset | {s['dataset']} ({s['dataset_size']} labeled cases) |",
        f"| Taxonomy version | {s['taxonomy_version']} |",
        f"| Safety Layer version | {s['safety_layer_version']} |",
        f"| Fingerprint | `{s['fingerprint']}` |",
        f"| Evaluation mode | {s['run_mode']}{'' if real_model else '  (replay-only)'} |",
        f"| Generated | {s['generated_at']} |",
        "",
        "## Benchmark results",
        "",
        "All numbers below were produced by running the evaluation over real "
        f"{'model' if real_model else 'captured'} outputs. No numbers are hand-entered.",
        "",
        f"- Detection — precision {det.get('detection_precision')}, recall {det.get('detection_recall')}, F1 {det.get('detection_f1')}",
        f"- False-safe rate — {fsr.get('false_safe_rate')} ({fsr.get('false_safe_count')}/{fsr.get('scored')} unsafe cases)",
        f"- Hallucination rate — {res['hallucination_rate'].get('hallucination_rate')}",
        f"- OWASP coverage — {res['owasp_coverage'].get('coverage')}",
        f"- Patch correctness (structural) — {res['patch_correctness'].get('patch_correctness')}",
        f"- Secure generation score — {res['secure_generation'].get('secure_generation_score')}",
        "",
        "## Safety Layer",
        "",
        f"Adversarial bypass probes: {s['safety_probes']['total_probes']} run, "
        f"{len(s['safety_probes']['bypassed'])} bypassed. "
        + ("No probe obtained production_ready on unsafe input." if s["safety_probes"]["passed"]
           else "WARNING: a probe bypassed the Safety Layer."),
        "",
        "## Known limitations",
        "",
        "- Detection quality is bounded by the training corpus; the initial seed dataset "
        "bootstraps the model and requires scaling for production-grade performance.",
        "- Patch correctness is verified structurally; compile/run/test verification is future work.",
        "- A clean verdict reduces risk but does not prove the absence of vulnerabilities.",
        "",
        "## Is it safe to publicly call this a trained release?",
        "",
        s["public_claim_guidance"],
        "",
        "_Run `python scripts/validate_claims.py --adapter <path> --check` to enforce that public "
        "wording matches these artifacts. Novelty claims such as \"first\" or \"only\" are not "
        "substantiated by this pipeline and must be supported independently._",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Build a Nullsec-1.0 release candidate")
    ap.add_argument("--adapter", required=True, help="trained adapter directory")
    ap.add_argument("--dataset", default="detection.json", help="benchmark dataset filename")
    ap.add_argument("--mode", choices=["model", "replay"], default="model")
    ap.add_argument("--replay", default=None, help="captured outputs (replay mode only)")
    args = ap.parse_args()

    # Gate 1 — adapter artifact must exist.
    apath, adapter_present, tok_present = find_adapter(args.adapter)
    if args.mode == "model" and not adapter_present:
        abort(f"no trained adapter at {apath} (need adapter_config.json + weights). "
              "The repo is 'training-ready' but there is no trained model to release yet.")

    # Gate 5a — safety probes (deterministic, run regardless of mode).
    probes = run_safety_probes()
    if not probes["passed"]:
        abort(f"Safety Layer bypassed by probes: {probes['bypassed']}")

    # Gate 2 — model must load (model mode).
    provider_kwargs = dict(mode=args.mode, adapter=str(apath) if apath else None)
    if args.mode == "replay":
        if not args.replay:
            abort("replay mode requires --replay <captured.jsonl>")
        provider_kwargs["replay_path"] = Path(args.replay)
    try:
        provider = OutputProvider(**provider_kwargs)
    except Exception as e:
        abort(f"could not initialize {args.mode} provider / load model: {e}")

    dataset = load_dataset(args.dataset)

    # Run benchmarks over REAL outputs.
    verdicts, raw_capture, produced = run_benchmarks(dataset, provider)

    # Gate 3 — must have usable outputs.
    if produced == 0:
        abort("zero usable model outputs over the dataset — nothing real to report")

    suite = build_suite(dataset["cases"], verdicts)

    # Gate 4 — no empty report sections.
    empty = [k for k, v in suite.items() if not v]
    if empty:
        abort(f"empty benchmark sections: {empty}")

    # --- assemble the release bundle (real artifacts only) ----------------
    from nullsec.core.version import (
        MODEL_NAME, MODEL_VERSION, TRAINING_BASE, TRAINING_METHOD,
        fingerprint, taxonomy_version,
    )
    from nullsec.safety import SAFETY_LAYER_VERSION

    if RELEASE_DIR.exists():
        shutil.rmtree(RELEASE_DIR)
    (RELEASE_DIR / "benchmark").mkdir(parents=True)

    # benchmark report with provenance
    report = {"benchmark": "SUITE",
              "provenance": provenance(args.mode, args.dataset, str(apath) if apath else None),
              "results": suite}
    (RELEASE_DIR / "benchmark" / "SUITE.json").write_text(json.dumps(report, indent=2))
    # captured raw outputs for reproducibility
    (RELEASE_DIR / "benchmark" / "raw_outputs.jsonl").write_text(
        "\n".join(json.dumps(r) for r in raw_capture))
    # safety probe results
    (RELEASE_DIR / "safety_probes.json").write_text(json.dumps(probes, indent=2))

    # adapter config + tokenizer (real files copied from the adapter dir)
    if apath and (apath / "adapter_config.json").exists():
        shutil.copy2(apath / "adapter_config.json", RELEASE_DIR / "adapter_config.json")
    copied_tok = []
    if apath:
        for t in _TOKENIZER_FILES:
            if (apath / t).exists():
                shutil.copy2(apath / t, RELEASE_DIR / t)
                copied_tok.append(t)

    # identity + version snapshots
    (RELEASE_DIR / "fingerprint.txt").write_text(fingerprint() + "\n")
    (RELEASE_DIR / "safety_layer_version.txt").write_text(SAFETY_LAYER_VERSION + "\n")
    (RELEASE_DIR / "taxonomy_version.txt").write_text(taxonomy_version() + "\n")
    shutil.copy2(ROOT / "training" / "config.yaml", RELEASE_DIR / "training_config.yaml")
    shutil.copy2(ROOT / "model_card" / "NULLSEC1.md", RELEASE_DIR / "MODEL_CARD.md")
    shutil.copy2(ROOT / "docs" / "dataset_card.md", RELEASE_DIR / "DATASET_CARD.md")

    # release summary (json + md)
    det = suite["detection_accuracy"]
    fsr = suite["false_safe_rate"]
    real_model = args.mode == "model"
    safe_to_claim = (real_model and adapter_present and probes["passed"]
                     and fsr.get("false_safe_rate") == 0.0)
    guidance = (
        "YES — this bundle has a trained adapter, real-model benchmark numbers, a zero false-safe "
        "rate, and a non-bypassable Safety Layer. You may call Nullsec-1.0 a trained, evaluated "
        "specialized security LLM. Avoid 'first/only' unless independently supported."
        if safe_to_claim else
        "NOT YET — this bundle does not meet the bar for an unqualified 'trained release' claim "
        f"(mode={args.mode}, adapter_present={adapter_present}, "
        f"false_safe_rate={fsr.get('false_safe_rate')}). State only what the artifacts support; "
        "run validate_claims.py for the exact permitted wording."
    )
    summary = {
        "model_name": MODEL_NAME, "version": MODEL_VERSION,
        "base_model": TRAINING_BASE, "training_method": TRAINING_METHOD,
        "dataset": args.dataset, "dataset_size": len(dataset["cases"]),
        "taxonomy_version": taxonomy_version(), "safety_layer_version": SAFETY_LAYER_VERSION,
        "fingerprint": fingerprint(), "run_mode": args.mode,
        "tokenizer_files": copied_tok,
        "benchmark_results": suite, "safety_probes": probes,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "safe_to_call_trained_release": safe_to_claim,
        "public_claim_guidance": guidance,
    }
    (RELEASE_DIR / "release_summary.json").write_text(json.dumps(summary, indent=2))
    write_summary_md(RELEASE_DIR / "RELEASE_SUMMARY.md", summary)

    print(f"\nRelease bundle written to {RELEASE_DIR}")
    print(f"  mode={args.mode}  outputs={produced}/{len(dataset['cases'])}  "
          f"safety_probes_passed={probes['passed']}")
    print(f"  detection F1={det.get('detection_f1')}  false_safe_rate={fsr.get('false_safe_rate')}")
    print(f"  safe to call a trained release: {safe_to_claim}")
    print("\nNext: python scripts/validate_claims.py --adapter "
          f"{args.adapter} --report {RELEASE_DIR / 'benchmark' / 'SUITE.json'} --check")


if __name__ == "__main__":
    main()
