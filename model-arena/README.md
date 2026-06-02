# Nullsec-S1 Model Arena

This folder is for real side-by-side model comparison runs. The runner sends the
same security audit case to every selected model and saves the raw output with
the prompt, input code, model ID, timestamp, and any provider error.

Do not edit outputs before using them in a demo. If you exclude a run, label that
decision in the video or in accompanying notes.

## Case

The first supported case is `unsafe-admin-route`. It audits this TypeScript
handler:

```ts
export async function POST(req: Request) {
  const { userId } = await req.json()
  await db.user.delete({ where: { id: userId } })
  return Response.json({ ok: true })
}
```

Use the saved JSON to compare whether each model:

- Detected missing authentication.
- Detected missing authorization or role checks.
- Detected an unsafe admin or destructive route.
- Returned structured output.
- Added unsupported or hallucinated claims.

## Setup

Start the local Nullsec-S1 FastAPI backend separately. The local raw generation
endpoint is only for controlled comparison runs and is disabled by default. Enable
it only for the arena session:

```bash
export NULLSEC_SCAN_BACKEND_URL="http://127.0.0.1:8000"
export NULLSEC_ENABLE_ARENA_RAW="1"
export ANTHROPIC_API_KEY="..."
export ANTHROPIC_MODEL="claude-opus-4-8"
export OPENAI_API_KEY="..."
export OPENAI_MODEL="..."
export QWEN_MODEL="..."
```

For Qwen, set either:

```bash
export QWEN_API_KEY="..."
```

or, if routing Qwen through OpenRouter:

```bash
export OPENROUTER_API_KEY="..."
```

Never commit API keys or provider credentials.

Do not expose `/v1/arena/raw` publicly without authentication, rate limiting, and
the same operational controls you would apply to any raw model-generation API.

## Run

```bash
python3 scripts/model_arena.py \
  --case unsafe-admin-route \
  --models nullsec,claude,openai,qwen \
  --out model-arena/runs/$(date -u +%Y%m%dT%H%M%SZ).json
```

You can run a subset while testing:

```bash
python3 scripts/model_arena.py --case unsafe-admin-route --models nullsec
```

Generated files under `model-arena/runs/` are ignored by git so raw outputs are
not committed accidentally. Commit a run only after explicit approval.

## Output Format

Each JSON file has this shape:

```json
{
  "case": "unsafe-admin-route",
  "prompt": "...",
  "input": "...",
  "runs": [
    {
      "model_label": "Nullsec-S1",
      "model_id": "...",
      "raw_output": "...",
      "timestamp": "...",
      "error": null
    }
  ]
}
```

If a provider fails or is not configured, the runner records the error and leaves
`raw_output` empty. It does not create fallback responses.

## Video Use

Use the raw JSON as the source of truth for the comparison screen. For fairness,
show the same case, prompt, and input for all models. Label any failed provider
calls, retries, excluded runs, or reruns with their timestamps. Do not
cherry-pick a cleaner output without saying that a selection was made.

The Nullsec-S1 leg uses `/v1/arena/raw`, a controlled local backend endpoint for
this demo workflow. It must be enabled with `NULLSEC_ENABLE_ARENA_RAW=1` and
returns raw generation for the same prompt and code sent to the external
providers.
