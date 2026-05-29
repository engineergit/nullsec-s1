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


# Conservative equivalent-label aliases. These map ONLY well-known synonyms a
# model might emit to their canonical taxonomy id. Anything not a canonical id or
# an explicit alias here is left unchanged (and therefore rejected downstream as
# an unknown category — we never silently invent a category to make a verdict
# pass). This recovers correct findings when the model uses a common synonym, and
# does not change any benchmark label.
CATEGORY_ALIASES: dict[str, str] = {
    # BROKEN_AUTH
    "IDOR": "BROKEN_AUTH",
    "BROKEN_ACCESS_CONTROL": "BROKEN_AUTH",
    "MISSING_AUTH": "BROKEN_AUTH",
    "MISSING_AUTHENTICATION": "BROKEN_AUTH",
    "MISSING_AUTHORIZATION": "BROKEN_AUTH",
    "BROKEN_AUTHENTICATION": "BROKEN_AUTH",
    "AUTH_BYPASS": "BROKEN_AUTH",
    "AUTHENTICATION_BYPASS": "BROKEN_AUTH",
    "INSECURE_SESSION": "BROKEN_AUTH",
    # COMMAND_INJECTION (incl. code-exec / deserialization sinks)
    "RCE": "COMMAND_INJECTION",
    "REMOTE_CODE_EXECUTION": "COMMAND_INJECTION",
    "OS_COMMAND_INJECTION": "COMMAND_INJECTION",
    "CODE_INJECTION": "COMMAND_INJECTION",
    "INSECURE_DESERIALIZATION": "COMMAND_INJECTION",
    "DESERIALIZATION": "COMMAND_INJECTION",
    # EXPOSED_SECRET
    "HARDCODED_SECRET": "EXPOSED_SECRET",
    "HARDCODED_CREDENTIAL": "EXPOSED_SECRET",
    "HARDCODED_CREDENTIALS": "EXPOSED_SECRET",
    "SECRET_EXPOSURE": "EXPOSED_SECRET",
    "EXPOSED_CREDENTIALS": "EXPOSED_SECRET",
    "EXPOSED_CREDENTIAL": "EXPOSED_SECRET",
    "API_KEY_LEAK": "EXPOSED_SECRET",
    "CREDENTIAL_LEAK": "EXPOSED_SECRET",
    # UNSAFE_FILE_UPLOAD
    "PATH_TRAVERSAL": "UNSAFE_FILE_UPLOAD",
    "DIRECTORY_TRAVERSAL": "UNSAFE_FILE_UPLOAD",
    "ARBITRARY_FILE_UPLOAD": "UNSAFE_FILE_UPLOAD",
    "FILE_UPLOAD": "UNSAFE_FILE_UPLOAD",
    "UNRESTRICTED_FILE_UPLOAD": "UNSAFE_FILE_UPLOAD",
    # XSS
    "CROSS_SITE_SCRIPTING": "XSS",
    "STORED_XSS": "XSS",
    "REFLECTED_XSS": "XSS",
    "DOM_XSS": "XSS",
    # SSRF
    "SERVER_SIDE_REQUEST_FORGERY": "SSRF",
    # DANGEROUS_SHELL_COMMAND
    "DANGEROUS_SHELL": "DANGEROUS_SHELL_COMMAND",
    "UNSAFE_SHELL_COMMAND": "DANGEROUS_SHELL_COMMAND",
    "DESTRUCTIVE_COMMAND": "DANGEROUS_SHELL_COMMAND",
    # MISSING_RATE_LIMIT
    "NO_RATE_LIMIT": "MISSING_RATE_LIMIT",
    "RATE_LIMIT_MISSING": "MISSING_RATE_LIMIT",
    "MISSING_RATE_LIMITING": "MISSING_RATE_LIMIT",
    # UNSAFE_ADMIN_ROUTE
    "UNSAFE_ADMIN": "UNSAFE_ADMIN_ROUTE",
    "EXPOSED_ADMIN_ROUTE": "UNSAFE_ADMIN_ROUTE",
    "DEBUG_ROUTE": "UNSAFE_ADMIN_ROUTE",
    "EXPOSED_DEBUG_ROUTE": "UNSAFE_ADMIN_ROUTE",
    "EXPOSED_DEBUG_ENDPOINT": "UNSAFE_ADMIN_ROUTE",
    # SQL_INJECTION
    "SQLI": "SQL_INJECTION",
    # PROMPT_INJECTION
    "LLM_PROMPT_INJECTION": "PROMPT_INJECTION",
    "INDIRECT_PROMPT_INJECTION": "PROMPT_INJECTION",
    # MCP_TOOL_ABUSE
    "MCP_TOOL": "MCP_TOOL_ABUSE",
    "TOOL_ABUSE": "MCP_TOOL_ABUSE",
    "EXCESSIVE_AGENCY": "MCP_TOOL_ABUSE",
    "OVERPRIVILEGED_TOOL": "MCP_TOOL_ABUSE",
    # WALLET_TRANSACTION_RISK
    "WALLET_RISK": "WALLET_TRANSACTION_RISK",
    "TRANSACTION_RISK": "WALLET_TRANSACTION_RISK",
    "UNBOUNDED_APPROVAL": "WALLET_TRANSACTION_RISK",
    "UNSAFE_APPROVAL": "WALLET_TRANSACTION_RISK",
    "UNSAFE_WEB3_SIGNING": "WALLET_TRANSACTION_RISK",
    # SMART_CONTRACT_RISK
    "SMART_CONTRACT": "SMART_CONTRACT_RISK",
    "REENTRANCY": "SMART_CONTRACT_RISK",
    # DEPENDENCY_RISK
    "DEPENDENCY": "DEPENDENCY_RISK",
    "SUPPLY_CHAIN": "DEPENDENCY_RISK",
    "SUPPLY_CHAIN_RISK": "DEPENDENCY_RISK",
    "VULNERABLE_DEPENDENCY": "DEPENDENCY_RISK",
    "DEPENDENCY_CONFUSION": "DEPENDENCY_RISK",
    # ENVIRONMENT_EXPOSURE
    "ENV_EXPOSURE": "ENVIRONMENT_EXPOSURE",
    "CONFIG_EXPOSURE": "ENVIRONMENT_EXPOSURE",
    "CONFIGURATION_EXPOSURE": "ENVIRONMENT_EXPOSURE",
    "PUBLIC_BUCKET": "ENVIRONMENT_EXPOSURE",
}


def normalize_category(raw: str) -> str:
    """Map an equivalent/synonym category label to its canonical taxonomy id.

    Case- and separator-insensitive. Returns the canonical id when the input is a
    known category or a known alias; otherwise returns the input unchanged (so a
    genuinely unknown category is still rejected by validation — we never invent a
    category to force a pass)."""
    if not isinstance(raw, str):
        return raw
    key = raw.strip().upper().replace(" ", "_").replace("-", "_")
    if key in category_ids():
        return key
    return CATEGORY_ALIASES.get(key, raw)


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
