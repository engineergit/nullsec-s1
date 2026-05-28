# API Reference — Nullsec-1

Base URL: `http://localhost:8000` (see deployment guide for hosting).

All analysis endpoints run Nullsec-1's raw output through the deterministic pipeline (Security Alignment Layer → Nullsec Safety Layer) before responding. The `production_ready` field in every response is the **Safety Layer's** computed value, not Nullsec-1's raw claim. Safety Layer metadata is attached under `_safety_layer`.

---

## GET /health
Liveness + which base model is configured.

```bash
curl -s localhost:8000/health
```
```json
{ "status": "ok", "model": "Qwen/Qwen2.5-Coder-7B-Instruct" }
```

---

## GET /v1/model

Nullsec-1 release identity. No model load required.

```bash
curl -s localhost:8000/v1/model
```

```json
{
  "model_name": "Nullsec-1",
  "version": "1.0.0",
  "release_tag": "Nullsec-1.0",
  "taxonomy_version": "1.0.0",
  "safety_layer_version": "1.0.0",
  "fingerprint": "sha256:...",
  "training_base": "Qwen/Qwen2.5-Coder-7B-Instruct",
  "training_method": "QLoRA (4-bit NF4) supervised fine-tuning + deterministic security alignment",
  "max_context": 32768,
  "supported_languages": ["python", "javascript", "typescript", "solidity", "..."],
  "supported_frameworks": ["fastapi", "express", "mcp", "anchor", "..."],
  "category_count": 15
}
```

The `fingerprint` is a SHA-256 over the artifacts that define Nullsec-1's security behavior (taxonomy, verdict schema, system instruction, Safety Layer version, and adapter config when mounted). Two deployments with the same fingerprint enforce the same security contract.

## GET /v1/capabilities

What this Nullsec-1 release can do: the detectable taxonomy categories, the eight check dimensions, the action set (detection, severity classification, exploit-scenario reasoning, secure-patch generation, production-readiness enforcement), output types, and streaming/enforcement flags.

```bash
curl -s localhost:8000/v1/capabilities
```

## POST /v1/analyze
Audit a single file/snippet and return a gated verdict.

**Request**
```json
{
  "filename": "users.py",
  "lang": "python",
  "code": "def get(c,u):\n  c.execute(f\"SELECT * FROM users WHERE n='{u}'\")"
}
```
`lang` is optional (used only to tag the code fence).

**Response (abridged)**
```json
{
  "risk_score": 92,
  "production_ready": false,
  "severity": "CRITICAL",
  "confidence": "HIGH",
  "reasoning_summary": "...",
  "affected_files": ["users.py"],
  "checks_performed": {
    "auth": {"status": "not_checked", "note": "..."},
    "secrets": {"status": "pass", "note": "..."},
    "input_validation": {"status": "fail", "note": "f-string SQL"},
    "rate_limits": {"status": "not_applicable", "note": "..."},
    "permissions": {"status": "not_checked", "note": "..."},
    "dangerous_exec": {"status": "pass", "note": "..."},
    "dependency_risk": {"status": "pass", "note": "..."},
    "environment_exposure": {"status": "pass", "note": "..."}
  },
  "findings": [
    {
      "category": "SQL_INJECTION",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "file": "users.py",
      "line": 2,
      "description": "...",
      "exploit_scenario": "...",
      "recommended_fix": "Use a parameterized query.",
      "secure_patch": "-  c.execute(f\"...{u}...\")\n+  c.execute(\"... %s\", (u,))"
    }
  ],
  "_safety_layer": {
    "production_ready": false,
    "blocking_reasons": ["R2: dimension 'input_validation' failed its check", "R3: at least one HIGH/CRITICAL finding present"],
    "adjustments": ["production_ready overridden true -> false by Safety Layer"]
  }
}
```

**Status codes**
- `200` — verdict returned.
- `502` — the model produced output that could not be parsed into a valid verdict (`detail` explains why).

---

## POST /v1/patch
Same input and pipeline as `/v1/analyze`, but the response additionally surfaces a top-level `patches` array for convenience:

```json
{
  "...": "all analyze fields ...",
  "patches": [
    {
      "file": "users.py",
      "category": "SQL_INJECTION",
      "secure_patch": "-  ...\n+  ...",
      "recommended_fix": "Use a parameterized query."
    }
  ]
}
```

---

## POST /v1/analyze/stream
Server-Sent Events. Streams generation tokens as they are produced, then a final gated verdict.

**Events**
- `event: token` — `{"t": "<chunk>"}` incremental model text.
- `event: verdict` — the full enforced JSON (same shape as `/v1/analyze`).
- `event: error` — `{"error": "..."}` if the completed output failed to parse.
- `event: done` — `{}` terminator.

```bash
curl -N localhost:8000/v1/analyze/stream -H 'content-type: application/json' \
  -d '{"filename":"a.js","lang":"javascript","code":"exec(req.query.cmd)"}'
```

```
event: token
data: {"t": "{\"risk_score\""}

event: token
data: {"t": ": 90, ..."}

event: verdict
data: {"risk_score": 90, "production_ready": false, ... "_safety_layer": {...}}

event: done
data: {}
```

Consume the `verdict` event for the authoritative result; the `token` stream is for UX only.

---

## The verdict contract
The full JSON Schema is at `data/schemas/verdict.schema.json`. Key invariants the Nullsec Safety Layer enforces regardless of Nullsec-1 output:
- `production_ready: true` requires all 8 `checks_performed` dimensions to be `pass` or `not_applicable` (never `not_checked`/`fail`), no HIGH/CRITICAL finding, `risk_score` under threshold (default 20), and no finding that contradicts a `pass` dimension.
- `severity` and `risk_score` are floored upward to match the worst finding — the model cannot under-report.
