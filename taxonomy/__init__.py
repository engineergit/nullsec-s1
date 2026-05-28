"""Canonical taxonomy loader. Single source of truth for categories and check dimensions.

Everything else in Nullsec-1 (schema validation, the deterministic validator,
the eval harness, the CLI) imports from here so the taxonomy is never duplicated.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_TAXONOMY_PATH = Path(__file__).with_name("taxonomy.json")

# The eight dimensions a verdict MUST address before it may claim production_ready.
# This list is enforced deterministically by the Nullsec Safety Layer
# (nullsec.safety.enforcement).
REQUIRED_CHECK_DIMENSIONS: tuple[str, ...] = (
    "auth",
    "secrets",
    "input_validation",
    "rate_limits",
    "permissions",
    "dangerous_exec",
    "dependency_risk",
    "environment_exposure",
)

SEVERITY_ORDER: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

CONFIDENCE_LEVELS: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH")


@lru_cache(maxsize=1)
def load_taxonomy() -> dict:
    with _TAXONOMY_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def category_ids() -> frozenset[str]:
    return frozenset(c["id"] for c in load_taxonomy()["categories"])


@lru_cache(maxsize=1)
def category_index() -> dict[str, dict]:
    return {c["id"]: c for c in load_taxonomy()["categories"]}


def default_severity(category_id: str) -> str:
    return category_index().get(category_id, {}).get("default_severity", "MEDIUM")


def check_dimension_for(category_id: str) -> str | None:
    return category_index().get(category_id, {}).get("check_dimension")


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.upper(), -1)


def max_severity(severities: list[str]) -> str:
    if not severities:
        return "INFO"
    return max(severities, key=severity_rank)
