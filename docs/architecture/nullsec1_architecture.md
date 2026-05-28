# Nullsec-1 Architecture

Nullsec-1 is a security-native LLM system. It is not a single model call — it is a pipeline in which a security-tuned model proposes a verdict and two deterministic layers align and enforce it before anything is trusted. This document describes that system.

## 1. Design principle

A model's confidence is not a security guarantee. Language models drift, can be prompt-injected, and will occasionally declare unsafe code safe. Nullsec-1 therefore separates two responsibilities:

- **Proposal (learned).** Nullsec-1, fine-tuned for security review, reads code and proposes a structured verdict: findings, severities, exploit scenarios, patches, and a self-assessed production-readiness.
- **Enforcement (deterministic).** The Security Alignment Layer and Nullsec Safety Layer take that proposal and decide, by fixed rules, whether it is well-formed and whether the code may be called production-ready.

> Nullsec-1 proposes. The Nullsec Safety Layer enforces. The model never has the final word on safety.

## 2. The reasoning pipeline

```
source code
   │
   ▼  build_analyze_messages()  — system instruction (strict reviewer) + code
Nullsec-1 generation  (nullsec/core/engine.py :: NullsecPipeline)
   │  raw text (expected: a JSON verdict)
   ▼
Security Alignment Layer  (nullsec/safety/alignment.py)
   │  • extract the JSON object (tolerant of fences / preamble / trailing prose)
   │  • validate against data/schemas/verdict.schema.json
   │  • type-check into the Verdict model
   │  • normalize finding severities up to the taxonomy floor
   ▼  structurally-valid, normalized Verdict
Nullsec Safety Layer  (nullsec/safety/enforcement.py)
   │  • apply enforcement rules R1–R6
   │  • raise severity and risk_score to match findings
   │  • compute production_ready (replacing the model's claim)
   ▼
enforced verdict  (+ _safety_layer: blocking_reasons, adjustments)
```

The two deterministic layers run identically whether Nullsec-1 is invoked through the serving layer, the CLI, the benchmark suite, or the training data builder. There is exactly one enforcement path.

## 3. The verdict contract

Nullsec-1's output is a single JSON object defined by `data/schemas/verdict.schema.json`:

- `risk_score` (0–100), `production_ready` (bool, advisory), `severity`, `confidence`
- `reasoning_summary`, optional `exploit_scenario`, `affected_files`
- `checks_performed` — an explicit status (`pass | fail | not_applicable | not_checked`) for each of the eight required dimensions
- `findings[]` — each with category (taxonomy), severity, confidence, file, line, description, exploit scenario, recommended fix, and a secure patch

The schema is the contract between the learned and deterministic halves of the system.

## 4. Security taxonomy

`taxonomy/taxonomy.json` is the single source of truth: 16 vulnerability categories, each mapped to one of 8 check dimensions, with default severity, CWE references, and detection signals. The categories target the failure modes of AI-generated software — exposed secrets, broken/missing auth, missing rate limits, unsafe admin routes, SQL injection, XSS, SSRF, command injection, unsafe file upload, prompt injection, MCP tool abuse, dangerous shell commands, wallet/transaction risk, smart-contract risk, dependency/supply-chain risk, and environment/configuration exposure. Every other component imports the taxonomy rather than redefining categories.

## 5. The Security Alignment Layer

Aligns raw model output to the verdict contract. It is deliberately tolerant of the shapes a language model produces (code fences, preamble, trailing commentary) and deterministic about the result: anything that cannot be extracted, schema-validated, and type-checked raises `VerdictParseError` rather than being guessed at. It then normalizes finding severities up to each category's taxonomy floor, so a finding can never be recorded below its category's minimum severity.

## 6. The Nullsec Safety Layer

The core of the system. Given a structurally-valid verdict it enforces:

| Rule | Blocks production_ready when… |
|------|-------------------------------|
| R1 | any required dimension is `not_checked` |
| R2 | any required dimension is `fail` |
| R3 | any finding is HIGH or CRITICAL |
| R4 | `risk_score` exceeds the production threshold |
| R5 | a finding contradicts a dimension reported as `pass` |
| R6 | overall severity is HIGH or CRITICAL |

It also raises severity to the maximum finding severity and floors `risk_score` to a per-severity minimum — always upward, never down. Finally it sets `production_ready` to the computed value and records every blocking reason and adjustment under `_safety_layer`. Because enforcement is deterministic and independent of the model, an attacker who manipulates the model (e.g. via prompt injection in the code under review) still cannot obtain a false `production_ready: true` for code with detected issues.

## 7. Serving

`serving/server.py` exposes the pipeline over HTTP. `GET /v1/model` and `GET /v1/capabilities` describe the release (version, fingerprint, taxonomy version, Safety Layer version, supported languages/frameworks, capabilities). `POST /v1/analyze`, `/v1/patch`, and `/v1/analyze/stream` run the full pipeline; the returned `production_ready` is always the Safety Layer's enforced value.

## 8. Versioning and fingerprint

`nullsec/core/version.py` centralizes release identity and computes a SHA-256 fingerprint over the taxonomy, verdict schema, system instruction, Safety Layer version, and (when mounted) the trained adapter config. Two deployments with the same fingerprint enforce the same security contract — a reproducible identity for audit and rollback.
