# Examples

Worked, real-world-shaped vulnerable cases that show what Nullsec S1 is built to
catch. Each folder contains a vulnerable code snippet, the **expected** taxonomy
category, the **expected** Safety Layer behavior, an exploit scenario, and a
secure patch direction.

> **These are source snippets for local testing and documentation.** They are not
> benchmark outputs. The "expected verdict" blocks in subdirectories describe what
> a correct verdict should look like under the
> [verdict schema](../data/schemas/verdict.schema.json) and the
> [Security Alignment Layer](../docs/SECURITY_ALIGNMENT_LAYER.md).
>
> **All secrets in these files are obviously-fake placeholders.** Never commit a
> real credential (see [`SECURITY.md`](../SECURITY.md)).

| Example | Category | Failing dimension |
|---------|----------|-------------------|
| [`vulnerable-nextjs-auth/`](vulnerable-nextjs-auth/) | `BROKEN_AUTH` | `auth` |
| [`exposed-supabase-key/`](exposed-supabase-key/) | `EXPOSED_SECRET` | `secrets` |
| [`mcp-tool-abuse/`](mcp-tool-abuse/) | `MCP_TOOL_ABUSE` | `permissions` |
| [`wallet-approval-risk/`](wallet-approval-risk/) | `WALLET_TRANSACTION_RISK` | `secrets` |
| [`unsafe-file-upload/`](unsafe-file-upload/) | `UNSAFE_FILE_UPLOAD` | `input_validation` |
| [`unsafe-next-admin-route.ts`](unsafe-next-admin-route.ts) | `UNSAFE_ADMIN_ROUTE` | `permissions` |
| [`unsafe-mcp-shell-tool.py`](unsafe-mcp-shell-tool.py) | `MCP_TOOL_ABUSE`, `COMMAND_INJECTION` | `permissions`, `dangerous_exec` |
| [`exposed-supabase-service-role.ts`](exposed-supabase-service-role.ts) | `EXPOSED_SECRET` | `secrets` |
| [`safe-scoped-mcp-tool.py`](safe-scoped-mcp-tool.py) | safe example | all dimensions pass |
| [`safe-server-supabase.ts`](safe-server-supabase.ts) | safe example | all dimensions pass |

In every case the deterministic Safety Layer recomputes `production_ready: false`
because a required check dimension is `fail` (R2) and/or a HIGH/CRITICAL finding
is present (R3) — the model's own opinion is never trusted for that decision.
