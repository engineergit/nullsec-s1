"""Typed verdict models. Mirrors data/schemas/verdict.schema.json.

These models do structural validation. The *semantic* gate (can this verdict
legitimately claim production_ready?) lives in the Nullsec Safety Layer
(nullsec.safety.enforcement) and is applied on top of a structurally-valid verdict.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Confidence = Literal["LOW", "MEDIUM", "HIGH"]
CheckState = Literal["pass", "fail", "not_applicable", "not_checked"]

REQUIRED_DIMENSIONS = (
    "auth",
    "secrets",
    "input_validation",
    "rate_limits",
    "permissions",
    "dangerous_exec",
    "dependency_risk",
    "environment_exposure",
)


class CheckStatus(BaseModel):
    status: CheckState
    note: str = ""


class ChecksPerformed(BaseModel):
    auth: CheckStatus
    secrets: CheckStatus
    input_validation: CheckStatus
    rate_limits: CheckStatus
    permissions: CheckStatus
    dangerous_exec: CheckStatus
    dependency_risk: CheckStatus
    environment_exposure: CheckStatus

    def as_dict(self) -> dict[str, CheckStatus]:
        return {d: getattr(self, d) for d in REQUIRED_DIMENSIONS}


class Finding(BaseModel):
    category: str
    severity: Severity
    confidence: Confidence
    file: str
    line: Optional[int] = None
    description: str
    exploit_scenario: str = ""
    recommended_fix: str = ""
    secure_patch: str = ""

    @field_validator("category")
    @classmethod
    def _known_category(cls, v: str) -> str:
        # Lazy import to avoid a hard cycle at module import time.
        from taxonomy import category_ids

        if v not in category_ids():
            raise ValueError(f"unknown taxonomy category: {v}")
        return v


class Verdict(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    production_ready: bool
    severity: Severity
    confidence: Confidence
    reasoning_summary: str
    exploit_scenario: Optional[str] = None
    affected_files: list[str] = Field(default_factory=list)
    checks_performed: ChecksPerformed
    findings: list[Finding] = Field(default_factory=list)
