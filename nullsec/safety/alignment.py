"""Security Alignment Layer — alignment stage.

Nullsec-1 emits a structured security verdict. The Security Alignment Layer is
the deterministic component that aligns Nullsec-1's raw output to the verdict
contract before any decision is trusted. This module performs the first stage:

    raw output -> extract JSON -> schema-validate -> type-check -> normalize

It handles the real-world shapes a language model produces (code fences,
preamble, trailing prose) deterministically rather than assuming clean output,
and it normalizes finding severities up to the taxonomy floor so Nullsec-1
cannot under-report a known category.

The second stage — enforcement of production-readiness — lives in
nullsec.safety.enforcement (the Nullsec Safety Layer).
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

import jsonschema

from nullsec.core.models import Verdict
from taxonomy import default_severity, severity_rank

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "schemas" / "verdict.schema.json"
)

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


class VerdictParseError(ValueError):
    """Raised when Nullsec-1 output cannot be aligned to a valid verdict."""


@lru_cache(maxsize=1)
def _schema() -> dict:
    with _SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _extract_json_object(raw: str) -> str:
    raw = raw.strip()
    m = _FENCE_RE.search(raw)
    if m:
        raw = m.group(1).strip()
    start = raw.find("{")
    if start == -1:
        raise VerdictParseError("no JSON object found in Nullsec-1 output")
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(raw)):
        ch = raw[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return raw[start : i + 1]
    raise VerdictParseError("unbalanced JSON object in Nullsec-1 output")


def parse_verdict(raw: str) -> Verdict:
    """Align raw Nullsec-1 text to a typed, schema-valid Verdict.

    Raises VerdictParseError on any failure to align.
    """
    snippet = _extract_json_object(raw)
    try:
        data = json.loads(snippet)
    except json.JSONDecodeError as e:
        raise VerdictParseError(f"invalid JSON: {e}") from e

    try:
        jsonschema.validate(data, _schema())
    except jsonschema.ValidationError as e:
        raise VerdictParseError(f"schema violation: {e.message}") from e

    # Normalize equivalent/synonym finding-category labels to canonical taxonomy
    # ids before type validation. This recovers a correct finding when the model
    # emits a known synonym (e.g. "IDOR" -> BROKEN_AUTH, "RCE" -> COMMAND_INJECTION);
    # genuinely unknown categories are left unchanged and still rejected below.
    from taxonomy import normalize_category

    for f in data.get("findings", []) or []:
        if isinstance(f, dict) and "category" in f:
            f["category"] = normalize_category(f["category"])

    try:
        return Verdict.model_validate(data)
    except Exception as e:  # pydantic ValidationError
        raise VerdictParseError(f"type validation failed: {e}") from e


def normalize_finding_severities(verdict: Verdict) -> None:
    """Clamp finding severities up to the taxonomy default when Nullsec-1 reports
    a category below its category floor (e.g. labeling SQL_INJECTION as LOW).
    Never lowers a severity."""
    for f in verdict.findings:
        floor = default_severity(f.category)
        if severity_rank(f.severity) < severity_rank(floor):
            f.severity = floor  # type: ignore[assignment]


def is_valid_verdict(raw: str) -> bool:
    try:
        parse_verdict(raw)
        return True
    except VerdictParseError:
        return False
