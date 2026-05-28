"""Nullsec-1 benchmark harness.

Provides the shared machinery every benchmark runner uses:

  - OutputProvider: yields raw Nullsec-1 output for a case, either by running the
    reasoning pipeline live (`model` mode, needs GPU) or by reading previously
    captured real outputs (`replay` mode).
  - dataset loading from benchmarks/datasets/.
  - a report writer that stamps every report with provenance: the Nullsec-1
    fingerprint, version, run mode, dataset, and UTC timestamp.

Design rule: benchmarks NEVER emit invented numbers. A runner produces a report
only after obtaining real Nullsec-1 outputs for the dataset. In replay mode, if a
case has no captured output the runner records it as a real miss (it is one),
never as a synthetic pass. There are no pre-baked result files in this repo.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DATASETS = ROOT / "benchmarks" / "datasets"
REPORTS = ROOT / "benchmarks" / "reports"


def load_dataset(name: str) -> dict:
    path = DATASETS / name
    if not path.exists():
        raise FileNotFoundError(f"benchmark dataset not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_replay(path: Path) -> dict[str, str]:
    """Read captured raw Nullsec-1 outputs: JSONL of {"id": ..., "raw": ...}."""
    if not path.exists():
        raise FileNotFoundError(
            f"replay file not found: {path}\n"
            "Provide real captured Nullsec-1 outputs, or run with --mode model."
        )
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            obj = json.loads(line)
            out[obj["id"]] = obj["raw"]
    return out


@dataclass
class OutputProvider:
    """Yields raw Nullsec-1 output per case id. No fabrication: a missing replay
    entry yields None, which runners must score as a real failure."""

    mode: str  # "model" | "replay"
    adapter: Optional[str] = None
    replay_path: Optional[Path] = None
    _replay: Optional[dict[str, str]] = None
    _pipeline: object = None

    def __post_init__(self):
        if self.mode == "replay":
            self._replay = load_replay(Path(self.replay_path))
        elif self.mode == "model":
            from nullsec.core.engine import NullsecPipeline, PipelineConfig

            self._pipeline = NullsecPipeline(PipelineConfig(adapter_path=self.adapter)).load()
        else:
            raise ValueError(f"unknown mode: {self.mode}")

    def raw_for(self, case: dict) -> Optional[str]:
        if self.mode == "replay":
            return self._replay.get(case["id"])
        # model mode: generate live
        prompt = self._pipeline._render(  # noqa: SLF001 (intended internal use)
            case.get("filename", "input"), case["code"], case.get("lang", "")
        )
        return self._pipeline._generate(prompt)  # noqa: SLF001


def provenance(mode: str, dataset: str, adapter: Optional[str]) -> dict:
    from nullsec.core.version import (
        MODEL_NAME,
        MODEL_VERSION,
        RELEASE_TAG,
        fingerprint,
        taxonomy_version,
    )

    return {
        "model_name": MODEL_NAME,
        "version": MODEL_VERSION,
        "release_tag": RELEASE_TAG,
        "fingerprint": fingerprint(),
        "taxonomy_version": taxonomy_version(),
        "run_mode": mode,
        "adapter": adapter or "(base, no adapter)",
        "dataset": dataset,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def write_report(name: str, mode: str, dataset: str, adapter: Optional[str], results: dict) -> Path:
    REPORTS.mkdir(parents=True, exist_ok=True)
    report = {"benchmark": name, "provenance": provenance(mode, dataset, adapter), "results": results}
    out = REPORTS / f"{name}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return out


def finalize_raw(raw: Optional[str]):
    """Align + enforce a raw output. Returns (verdict_or_None, aligned_bool)."""
    from nullsec.safety import VerdictParseError, align_and_enforce

    if not raw:
        return None, False
    try:
        res = align_and_enforce(raw)
        return res.verdict, True
    except VerdictParseError:
        return None, False


def iter_cases(dataset: dict) -> Iterator[dict]:
    yield from dataset["cases"]
