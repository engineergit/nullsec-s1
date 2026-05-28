# Nullsec-1 Security Taxonomy (v1.1.0)

The canonical taxonomy is `taxonomy/taxonomy.json`. This document explains its two
distinct concepts, which must never be conflated.

## Check dimensions (8) — axes, not categories

Every Nullsec-1 verdict must report a status for all eight **check dimensions**.
They are the axes of review, not vulnerability classes:

`auth`, `secrets`, `input_validation`, `rate_limits`, `permissions`,
`dangerous_exec`, `dependency_risk`, `environment_exposure`.

**`INPUT_VALIDATION` is a dimension, not a category.** There is no
`INPUT_VALIDATION` category and there should not be one. Multiple categories
exercise the `input_validation` dimension — `SQL_INJECTION`, `XSS`, `SSRF`,
`UNSAFE_FILE_UPLOAD`, `PROMPT_INJECTION`, and `SMART_CONTRACT_RISK`. Likewise
`environment_exposure` is a dimension that, as of v1.1.0, is also the primary
dimension of the `ENVIRONMENT_EXPOSURE` category (below).

## Categories (16) — specific vulnerability classes

Each category is a concrete vulnerability class and maps to exactly one primary
`check_dimension`.

| Category | Primary dimension | Default severity | Nullsec-native |
|---|---|---|---|
| EXPOSED_SECRET | secrets | CRITICAL | |
| BROKEN_AUTH | auth | CRITICAL | |
| MISSING_RATE_LIMIT | rate_limits | MEDIUM | |
| UNSAFE_ADMIN_ROUTE | permissions | HIGH | |
| SQL_INJECTION | input_validation | CRITICAL | |
| XSS | input_validation | HIGH | |
| SSRF | input_validation | HIGH | |
| COMMAND_INJECTION | dangerous_exec | CRITICAL | |
| UNSAFE_FILE_UPLOAD | input_validation | HIGH | |
| PROMPT_INJECTION | input_validation | HIGH | yes |
| MCP_TOOL_ABUSE | permissions | HIGH | yes |
| DANGEROUS_SHELL_COMMAND | dangerous_exec | HIGH | |
| WALLET_TRANSACTION_RISK | secrets | CRITICAL | yes |
| SMART_CONTRACT_RISK | input_validation | HIGH | yes |
| DEPENDENCY_RISK | dependency_risk | MEDIUM | |
| ENVIRONMENT_EXPOSURE | environment_exposure | HIGH | |

### ENVIRONMENT_EXPOSURE (added in v1.1.0)
Environment files, server configuration, debug settings, source maps, or cloud
metadata exposed to untrusted parties. Representative cases: a `.env` served from
a public directory; server secrets compiled into a frontend bundle; debug config
enabled in production; source maps leaking internal env names; cloud
instance-metadata leakage. This is distinct from `EXPOSED_SECRET` (a hardcoded
credential in source) — it covers configuration/environment surface exposed
through deployment and build mistakes.

### Nullsec-native categories
`PROMPT_INJECTION`, `MCP_TOOL_ABUSE`, `WALLET_TRANSACTION_RISK`, and
`SMART_CONTRACT_RISK` are marked `nullsec_native` in the taxonomy. They extend
beyond classic web-app taxonomies to cover AI-agent and Web3 surfaces.
`SMART_CONTRACT_RISK` is retained as an additional native category, not a
replacement for `ENVIRONMENT_EXPOSURE`.

## Versioning
Adding or removing a category or dimension is a taxonomy change and bumps
`version` in `taxonomy.json` (now `1.1.0`). The model fingerprint folds in the
taxonomy file, so any taxonomy change changes the fingerprint.
