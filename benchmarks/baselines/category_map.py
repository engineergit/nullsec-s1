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
    """Return the Nullsec category for a Semgrep rule id.

    Semgrep prefixes local rule ids with the config path (for example
    `benchmarks.baselines.nullsec.sql-injection`). The rules file itself uses
    `nullsec.sql-injection`. Normalize both shapes so findings are not lost
    before scoring.
    """
    if rule_id in RULE_TO_CATEGORY:
        return RULE_TO_CATEGORY[rule_id]
    marker = "nullsec."
    if marker in rule_id:
        normalized = rule_id[rule_id.index(marker) :]
        return RULE_TO_CATEGORY.get(normalized)
    return None
