"""Nullsec Safety Layer — deterministic security enforcement.

This is the core of Nullsec-1's architecture and the reason it is a
security-native model rather than a code model that emits opinions.

Nullsec-1 proposes a security verdict. The Nullsec Safety Layer enforces it. A
verdict may NOT assert `production_ready: true` unless it survives every rule
below. Nullsec-1's own production-readiness claim is treated as advisory and is
always replaced by the Safety Layer's computed value.

Enforcement rules (production_ready is denied if ANY hold):
  R1  Any required check dimension has status `not_checked`.
  R2  Any required check dimension has status `fail`.
  R3  Any finding has severity HIGH or CRITICAL.
  R4  risk_score exceeds the production threshold (default 20).
  R5  A finding's category maps to a dimension reported as `pass`
      (contradiction: a SQL_INJECTION finding while input_validation = pass).
  R6  Overall severity is HIGH or CRITICAL.

The Safety Layer also raises (never lowers) `severity` and `risk_score` to match
the worst finding, so Nullsec-1 cannot under-report.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from nullsec.core.models import REQUIRED_DIMENSIONS, Verdict
from taxonomy import check_dimension_for, max_severity, severity_rank

SAFETY_LAYER_VERSION = "1.0.0"
PRODUCTION_RISK_THRESHOLD = 20
_SEVERITY_RISK_FLOOR = {
    "INFO": 0,
    "LOW": 10,
    "MEDIUM": 35,
    "HIGH": 70,
    "CRITICAL": 90,
}


@dataclass
class SafetyResult:
    """Outcome of running a verdict through the Nullsec Safety Layer."""

    verdict: Verdict
    production_ready: bool
    blocking_reasons: list[str] = field(default_factory=list)
    adjustments: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.production_ready


def enforce(
    verdict: Verdict,
    risk_threshold: int = PRODUCTION_RISK_THRESHOLD,
) -> SafetyResult:
    """Run the Nullsec Safety Layer over a structurally-valid verdict.

    Mutates the verdict so `production_ready`, `severity`, and `risk_score`
    reflect deterministic enforcement rather than Nullsec-1's raw claims, and
    returns a SafetyResult recording what was blocked and adjusted.
    """
    blocking: list[str] = []
    adjustments: list[str] = []

    checks = verdict.checks_performed.as_dict()

    # R1 / R2 — every dimension must be explicitly resolved and not failing.
    for dim in REQUIRED_DIMENSIONS:
        status = checks[dim].status
        if status == "not_checked":
            blocking.append(f"R1: dimension '{dim}' was not checked")
        elif status == "fail":
            blocking.append(f"R2: dimension '{dim}' failed its check")

    # R3 — any serious finding blocks.
    finding_sevs = [f.severity for f in verdict.findings]
    if any(severity_rank(s) >= severity_rank("HIGH") for s in finding_sevs):
        blocking.append("R3: at least one HIGH/CRITICAL finding present")

    # R5 — contradiction between findings and 'pass' dimensions.
    for f in verdict.findings:
        dim = check_dimension_for(f.category)
        if dim and dim in checks and checks[dim].status == "pass":
            blocking.append(
                f"R5: finding '{f.category}' contradicts '{dim}' reported as pass"
            )

    # Raise severity floor from findings (Nullsec-1 cannot under-report).
    computed_sev = max_severity(finding_sevs) if finding_sevs else "INFO"
    if severity_rank(computed_sev) > severity_rank(verdict.severity):
        adjustments.append(
            f"severity raised {verdict.severity} -> {computed_sev} from findings"
        )
        verdict.severity = computed_sev  # type: ignore[assignment]

    # Raise risk_score floor (never lower Nullsec-1's number).
    floor = _SEVERITY_RISK_FLOOR.get(verdict.severity, 0)
    if verdict.risk_score < floor:
        adjustments.append(f"risk_score raised {verdict.risk_score} -> {floor}")
        verdict.risk_score = floor

    # R4 / R6 — threshold and overall severity.
    if verdict.risk_score > risk_threshold:
        blocking.append(
            f"R4: risk_score {verdict.risk_score} exceeds threshold {risk_threshold}"
        )
    if severity_rank(verdict.severity) >= severity_rank("HIGH"):
        blocking.append(f"R6: overall severity {verdict.severity} is HIGH/CRITICAL")

    production_ready = len(blocking) == 0

    if verdict.production_ready and not production_ready:
        adjustments.append("production_ready overridden true -> false by Safety Layer")
    verdict.production_ready = production_ready

    return SafetyResult(
        verdict=verdict,
        production_ready=production_ready,
        blocking_reasons=blocking,
        adjustments=adjustments,
    )
