"""Semgrep rule-id to Nullsec category mapping for baseline evaluation.

The mapping is intentionally conservative. Unsupported categories remain
unsupported rather than being forced into misleading coverage.
"""
from __future__ import annotations

RULE_TO_CATEGORY = {
    "nullsec.exposed-secret": "EXPOSED_SECRET",
    "nullsec.sql-injection": "SQL_INJECTION",
    "nullsec.xss-dangerously-set-html": "XSS",
    "nullsec.ssrf-user-controlled-fetch": "SSRF",
    "nullsec.command-injection-shell": "COMMAND_INJECTION",
    "nullsec.dangerous-shell-curl-pipe": "DANGEROUS_SHELL_COMMAND",
    "nullsec.dangerous-shell-chmod-777": "DANGEROUS_SHELL_COMMAND",
    "nullsec.unsafe-admin-route": "UNSAFE_ADMIN_ROUTE",
    "nullsec.missing-rate-limit": "MISSING_RATE_LIMIT",
    "nullsec.unsafe-file-upload": "UNSAFE_FILE_UPLOAD",
    "nullsec.dependency-risk-postinstall": "DEPENDENCY_RISK",
    "nullsec.env-exposure": "ENVIRONMENT_EXPOSURE",
}

SUPPORTED_CATEGORIES = sorted(set(RULE_TO_CATEGORY.values()))
PARTIAL_OR_UNSUPPORTED_CATEGORIES = [
    "BROKEN_AUTH",
    "MCP_TOOL_ABUSE",
    "PROMPT_INJECTION",
    "SMART_CONTRACT_RISK",
    "WALLET_TRANSACTION_RISK",
]


def category_for_rule(rule_id: str) -> str | None:
    return RULE_TO_CATEGORY.get(rule_id)
