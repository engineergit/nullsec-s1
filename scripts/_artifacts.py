"""Artifact discovery and claim evaluation — the honesty core.

Pure filesystem inspection (no torch), used by both scripts/validate_claims.py
and scripts/release_candidate.py so there is exactly one definition of "what is
actually true about this repo right now."

A claim is permitted only when the artifacts that would make it true exist on
disk. Novelty/superiority claims ("first", "only") are never auto-permitted —
no local artifact can substantiate a statement about the rest of the world.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RELEASE = ROOT / "releases" / "nullsec-1.0"

# Detection F1 below which we will not call the model meaningfully "evaluated well".
MIN_USEFUL_F1 = 0.50

_TOKENIZER_HINTS = ("tokenizer.json", "tokenizer_config.json", "tokenizer.model", "vocab.json")


@dataclass
class RepoState:
    adapter_path: Path | None = None
    adapter_present: bool = False
    tokenizer_present: bool = False
    benchmark_report: dict | None = None
    report_path: Path | None = None
    safety_probes_passed: bool | None = None
    release_bundle: Path | None = None
    notes: list[str] = field(default_factory=list)

    # ---- derived from the benchmark report -------------------------------
    @property
    def run_mode(self) -> str | None:
        if not self.benchmark_report:
            return None
        return self.benchmark_report.get("provenance", {}).get("run_mode")

    @property
    def report_nonempty(self) -> bool:
        return bool(self.benchmark_report and self.benchmark_report.get("results"))

    @property
    def detection_f1(self) -> float | None:
        if not self.benchmark_report:
            return None
        det = self.benchmark_report.get("results", {}).get("detection_accuracy", {})
        return det.get("detection_f1")

    @property
    def false_safe_rate(self):
        if not self.benchmark_report:
            return None
        return self.benchmark_report.get("results", {}).get("false_safe_rate", {}).get("false_safe_rate")


def find_adapter(path: str | Path | None) -> tuple[Path | None, bool, bool]:
    """Return (path, adapter_present, tokenizer_present)."""
    if not path:
        return None, False, False
    p = Path(path)
    if not p.exists():
        return p, False, False
    adapter_present = (p / "adapter_config.json").exists() and any(
        (p / w).exists() for w in ("adapter_model.safetensors", "adapter_model.bin")
    )
    tokenizer_present = any((p / t).exists() for t in _TOKENIZER_HINTS)
    return p, adapter_present, tokenizer_present


def load_benchmark_report(report_path: str | Path | None) -> tuple[dict | None, Path | None]:
    candidates = []
    if report_path:
        candidates.append(Path(report_path))
    candidates.append(DEFAULT_RELEASE / "benchmark" / "SUITE.json")
    candidates.append(ROOT / "benchmarks" / "reports" / "SUITE.json")
    for c in candidates:
        if c and c.exists():
            try:
                data = json.loads(c.read_text(encoding="utf-8"))
                return data, c
            except json.JSONDecodeError:
                continue
    return None, None


def gather_state(adapter: str | None = None, report: str | None = None) -> RepoState:
    p, adapter_present, tok_present = find_adapter(adapter)
    rpt, rpath = load_benchmark_report(report)
    st = RepoState(
        adapter_path=p,
        adapter_present=adapter_present,
        tokenizer_present=tok_present,
        benchmark_report=rpt,
        report_path=rpath,
        release_bundle=DEFAULT_RELEASE if DEFAULT_RELEASE.exists() else None,
    )
    # Safety probes are deterministic; we can run them right here.
    try:
        from benchmarks.safety_probes import run_safety_probes

        st.safety_probes_passed = run_safety_probes()["passed"]
    except Exception as e:  # pragma: no cover
        st.safety_probes_passed = None
        st.notes.append(f"could not run safety probes: {e}")
    return st


@dataclass
class Claim:
    name: str
    allowed: bool
    reason: str


def evaluate_claims(st: RepoState) -> list[Claim]:
    claims: list[Claim] = []

    # training-ready — the framework is real and runnable AND the corpus is non-empty.
    def _corpus_nonempty() -> bool:
        try:
            import sys
            if str(ROOT) not in sys.path:
                sys.path.insert(0, str(ROOT))
            from corpus import load_corpus
            return len(load_corpus()) > 0
        except Exception:
            return False

    framework_ok = (
        (ROOT / "training" / "config.yaml").exists()
        and (ROOT / "data" / "schemas" / "verdict.schema.json").exists()
        and _corpus_nonempty()
    )
    claims.append(
        Claim("training-ready", framework_ok,
              "training pipeline, dataset schema, and a non-empty curated corpus are present"
              if framework_ok else "training framework files or curated corpus missing")
    )

    # trained model — requires a real adapter artifact.
    claims.append(
        Claim("trained model", st.adapter_present,
              f"adapter + weights found at {st.adapter_path}"
              if st.adapter_present else
              "no adapter_config.json + weights found; only 'training-ready' applies")
    )

    # benchmarked — requires a non-empty report from a real run.
    benched = st.report_nonempty
    claims.append(
        Claim("benchmarked", benched,
              f"benchmark report present ({st.report_path})"
              if benched else "no non-empty benchmark report found")
    )

    # real-model evaluation vs replay.
    if benched and st.run_mode == "model":
        claims.append(Claim("evaluated with real model outputs", True,
                            "benchmark report run_mode == 'model'"))
    elif benched and st.run_mode == "replay":
        claims.append(Claim("evaluated with real model outputs", False,
                            "benchmark report is REPLAY-ONLY; must say 'evaluated in replay mode'"))
    else:
        claims.append(Claim("evaluated with real model outputs", False,
                            "no benchmark report"))

    # safety-layer-enforced — deterministic probes must pass.
    claims.append(
        Claim("safety-layer-enforced", st.safety_probes_passed is True,
              "all adversarial Safety Layer probes blocked"
              if st.safety_probes_passed else "safety probes did not pass / not run")
    )

    # release candidate — trained + real-model benchmarked + bundle + probes.
    rc = (st.adapter_present and benched and st.run_mode == "model"
          and st.safety_probes_passed is True and st.release_bundle is not None)
    claims.append(
        Claim("release candidate", rc,
              "trained adapter, real-model benchmark, safety probes, and release bundle all present"
              if rc else "missing one of: trained adapter, real-model benchmark, safety probes, release bundle")
    )

    # production-ready (the MODEL) — deliberately the highest bar, and still cautious.
    f1 = st.detection_f1 or 0.0
    fsr = st.false_safe_rate
    prod = (rc and fsr == 0.0 and f1 >= MIN_USEFUL_F1)
    claims.append(
        Claim("production-ready", prod,
              f"release candidate + false_safe_rate==0 + detection F1 {f1:.2f} >= {MIN_USEFUL_F1} "
              "(still recommend independent review before this claim)"
              if prod else
              "not substantiated: requires release-candidate status, zero false-safe rate, "
              "and adequate detection F1 from a real-model run")
    )

    # novelty / superiority — never auto-permitted.
    claims.append(
        Claim("first / only / best ('first LLM purpose-built for ...')", False,
              "UNVERIFIABLE from local artifacts: no file can substantiate a claim about "
              "the rest of the world. State it only if you can independently support it.")
    )
    return claims
