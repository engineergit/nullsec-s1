"""Nullsec-1 deterministic security components.

Two deterministic stages sit between Nullsec-1's raw output and any trusted
decision:

  1. Security Alignment Layer (alignment.py) — parse, schema-validate, and
     normalize raw output into the verdict contract.
  2. Nullsec Safety Layer (enforcement.py) — enforce production-readiness;
     Nullsec-1's own claim is advisory and is replaced by the computed value.

`align_and_enforce` runs both stages and is the single entry point used by the
reasoning pipeline, the serving layer, the CLI, and the benchmark runner.
"""
from __future__ import annotations

from nullsec.core.models import Verdict
from nullsec.safety.alignment import (
    VerdictParseError,
    is_valid_verdict,
    normalize_finding_severities,
    parse_verdict,
)
from nullsec.safety.enforcement import (
    PRODUCTION_RISK_THRESHOLD,
    SAFETY_LAYER_VERSION,
    SafetyResult,
    enforce,
)

__all__ = [
    "VerdictParseError",
    "is_valid_verdict",
    "normalize_finding_severities",
    "parse_verdict",
    "PRODUCTION_RISK_THRESHOLD",
    "SAFETY_LAYER_VERSION",
    "SafetyResult",
    "enforce",
    "align_and_enforce",
]


def align_and_enforce(raw: str, risk_threshold: int = PRODUCTION_RISK_THRESHOLD) -> SafetyResult:
    """Full deterministic pipeline: align raw Nullsec-1 output to the verdict
    contract, normalize, then enforce the Safety Layer. Raises VerdictParseError
    if the output cannot be aligned."""
    verdict: Verdict = parse_verdict(raw)
    normalize_finding_severities(verdict)
    return enforce(verdict, risk_threshold=risk_threshold)
