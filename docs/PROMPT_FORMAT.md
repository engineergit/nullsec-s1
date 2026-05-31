# Nullsec-S1 Prompt and Output Format

Nullsec-S1 ("Security-1") returns final structured JSON security audits. It does
not use a hidden reasoning-token loop, `<thought>` format, or chain-of-thought
parser.

The canonical prompt is defined in [`nullsec/core/prompts.py`](../nullsec/core/prompts.py).
Training data generation, inference, CLI, and serving should use the same
message structure.

## System Prompt

Use the canonical `SYSTEM_PROMPT`. It instructs the model to:

- audit code only;
- inspect all eight check dimensions;
- emit one JSON object;
- return an empty `findings` array for genuinely safe code;
- emit one finding per independent vulnerability in mixed cases.

Do not ask the model for hidden reasoning traces. Ask for the final JSON verdict.

## User Prompt

Recommended user message:

````text
Audit the following code for security vulnerabilities. Emit only the JSON verdict.

FILE: path/to/file.ts
```typescript
<code here>
```
````

`inference.py` builds this format automatically from `--file` or `--code`.

## Expected JSON Schema

The output contract is [`data/schemas/verdict.schema.json`](../data/schemas/verdict.schema.json).
Top-level keys:

- `risk_score` (`0..100`)
- `production_ready` (`bool`; advisory until recomputed by the Safety Layer)
- `severity` (`INFO | LOW | MEDIUM | HIGH | CRITICAL`)
- `confidence` (`LOW | MEDIUM | HIGH`)
- `reasoning_summary`
- `exploit_scenario`
- `affected_files`
- `checks_performed`
- `findings`

`checks_performed` must include all eight dimensions:

`auth · secrets · input_validation · rate_limits · permissions · dangerous_exec · dependency_risk · environment_exposure`

## Safe-Code Response

For genuinely safe code:

```json
{
  "risk_score": 0,
  "production_ready": true,
  "severity": "INFO",
  "confidence": "HIGH",
  "reasoning_summary": "Reviewed all required security dimensions; no vulnerability found.",
  "exploit_scenario": null,
  "affected_files": ["example.ts"],
  "checks_performed": {
    "auth": { "status": "pass", "note": "reviewed" },
    "secrets": { "status": "pass", "note": "reviewed" },
    "input_validation": { "status": "pass", "note": "reviewed" },
    "rate_limits": { "status": "pass", "note": "reviewed" },
    "permissions": { "status": "pass", "note": "reviewed" },
    "dangerous_exec": { "status": "pass", "note": "reviewed" },
    "dependency_risk": { "status": "pass", "note": "reviewed" },
    "environment_exposure": { "status": "pass", "note": "reviewed" }
  },
  "findings": []
}
```

Security-sensitive code is not automatically vulnerable. For example:

- server-only secrets loaded from env/secret managers are safe;
- parameterized SQL is safe;
- validated uploads with server-generated names are safe;
- MCP tools with fixed allowlists and no shell are safe;
- exact token approvals to known spenders are safe;
- verified webhooks are safe.

## Unsafe-Code Response

For unsafe code, include one finding per independent issue:

```json
{
  "risk_score": 90,
  "production_ready": false,
  "severity": "CRITICAL",
  "confidence": "HIGH",
  "reasoning_summary": "The route exposes a privileged action without authentication.",
  "exploit_scenario": "An unauthenticated caller can invoke the route and perform the privileged action.",
  "affected_files": ["route.ts"],
  "checks_performed": {
    "auth": { "status": "fail", "note": "privileged action lacks authentication" },
    "secrets": { "status": "pass", "note": "reviewed" },
    "input_validation": { "status": "pass", "note": "reviewed" },
    "rate_limits": { "status": "pass", "note": "reviewed" },
    "permissions": { "status": "fail", "note": "no role/ownership check" },
    "dangerous_exec": { "status": "pass", "note": "reviewed" },
    "dependency_risk": { "status": "pass", "note": "reviewed" },
    "environment_exposure": { "status": "pass", "note": "reviewed" }
  },
  "findings": [
    {
      "category": "BROKEN_AUTH",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "file": "route.ts",
      "line": 1,
      "description": "Privileged route has no authentication.",
      "exploit_scenario": "Anyone can call it.",
      "recommended_fix": "Require an authenticated admin session.",
      "secure_patch": "+ const session = await auth();"
    }
  ]
}
```

Mixed cases must include multiple findings. Do not stop after the first issue.

## Category Boundaries

- Concrete API keys, tokens, passwords, private keys, and service_role values:
  `EXPOSED_SECRET`.
- Wallet seed phrases, wallet private keys, signing, approvals, and transaction
  authority: `WALLET_TRANSACTION_RISK`.
- Unsanitized HTML/DOM rendering: `XSS`.
- Untrusted content influencing LLM instructions/tools: `PROMPT_INJECTION`.
- User-controlled URLs fetched server-side: `SSRF`.
- Shell/OS command execution from input: `COMMAND_INJECTION`.
- SQL query construction from input: `SQL_INJECTION`.
- Public/admin/debug routes without admin controls: `UNSAFE_ADMIN_ROUTE`.
- Missing brute-force/cost/abuse controls: `MISSING_RATE_LIMIT`.

## Reducing False Positives and False Negatives

- Always record all eight check dimensions.
- For safe code, explain why the relevant control is present and keep `findings`
  empty.
- For unsafe code, cite concrete evidence in `description` and
  `exploit_scenario`.
- For mixed code, emit all relevant categories, not just the most obvious one.
- Let the deterministic Safety Layer recompute `production_ready`; do not rely on
  the model's raw boolean.
