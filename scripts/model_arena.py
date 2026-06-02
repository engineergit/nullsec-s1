#!/usr/bin/env python3
"""Run the same security audit prompt against multiple real models.

The script intentionally records provider errors instead of substituting fallback
text. Successful runs and failures are both useful for demo planning.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PROMPT = (
    "You are a security reviewer. Audit the following code for production security risks. "
    "Return structured findings with category, severity, evidence, and recommendation. "
    "Do not include unrelated commentary."
)

CASES = {
    "unsafe-admin-route": {
        "path": "app/api/admin/users/delete/route.ts",
        "language": "typescript",
        "input": """export async function POST(req: Request) {
  const { userId } = await req.json()
  await db.user.delete({ where: { id: userId } })
  return Response.json({ ok: true })
}""",
    }
}

DEFAULT_MODELS = ("nullsec", "claude", "openai", "qwen")


@dataclass(frozen=True)
class ModelRun:
    model_label: str
    model_id: str
    raw_output: str
    timestamp: str
    error: str | None = None

    def to_json(self) -> dict[str, str | None]:
        return {
            "model_label": self.model_label,
            "model_id": self.model_id,
            "raw_output": self.raw_output,
            "timestamp": self.timestamp,
            "error": self.error,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def http_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            **(headers or {}),
        },
        method="POST",
    )

    try:
        with urlopen(req, timeout=timeout) as resp:
            response_body = resp.read().decode("utf-8")
    except HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {error_body}") from exc
    except URLError as exc:
        raise RuntimeError(f"Could not reach {url}: {exc.reason}") from exc

    try:
        return json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Non-JSON response from {url}: {response_body[:500]}") from exc


def as_pretty_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def build_user_content(prompt: str, code: str) -> str:
    return f"{prompt}\n\n```ts\n{code}\n```"


def missing_env(name: str) -> RuntimeError:
    return RuntimeError(f"Missing required environment variable: {name}")


def run_nullsec(prompt: str, case: dict[str, str]) -> tuple[str, str]:
    base_url = os.environ.get("NULLSEC_SCAN_BACKEND_URL")
    if not base_url:
        raise missing_env("NULLSEC_SCAN_BACKEND_URL")

    arena_url = f"{base_url.rstrip('/')}/v1/arena/raw"
    payload = {
        "prompt": prompt,
        "language": case["language"],
        "code": case["input"],
    }
    response = http_json(arena_url, payload, timeout=300)
    raw_output = str(response.get("raw_output", ""))
    model_info = response.get("model") or {}
    model_id = str(
        model_info.get("adapter_path")
        or model_info.get("base_model")
        or model_info.get("model")
        or arena_url
    )
    return model_id, raw_output.strip()


def run_claude(prompt: str, code: str) -> tuple[str, str]:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    model = os.environ.get("ANTHROPIC_MODEL")
    if not api_key:
        raise missing_env("ANTHROPIC_API_KEY")
    if not model:
        raise missing_env("ANTHROPIC_MODEL")

    response = http_json(
        "https://api.anthropic.com/v1/messages",
        {
            "model": model,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": build_user_content(prompt, code)}],
        },
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    text_blocks = [
        block.get("text", "")
        for block in response.get("content", [])
        if isinstance(block, dict) and block.get("type") == "text"
    ]
    return model, "\n".join(text_blocks).strip() or as_pretty_json(response)


def run_openai(prompt: str, code: str) -> tuple[str, str]:
    api_key = os.environ.get("OPENAI_API_KEY")
    model = os.environ.get("OPENAI_MODEL")
    if not api_key:
        raise missing_env("OPENAI_API_KEY")
    if not model:
        raise missing_env("OPENAI_MODEL")

    response = http_json(
        "https://api.openai.com/v1/responses",
        {
            "model": model,
            "input": [
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": build_user_content(prompt, code)}],
                }
            ],
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )
    output_text = response.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return model, output_text.strip()

    chunks: list[str] = []
    for item in response.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and isinstance(content.get("text"), str):
                chunks.append(content["text"])
    return model, "\n".join(chunks).strip() or as_pretty_json(response)


def run_openai_compatible_chat(
    *,
    api_key: str,
    model: str,
    url: str,
    prompt: str,
    code: str,
    extra_headers: dict[str, str] | None = None,
) -> tuple[str, str]:
    response = http_json(
        url,
        {
            "model": model,
            "messages": [{"role": "user", "content": build_user_content(prompt, code)}],
            "temperature": 0,
        },
        headers={
            "Authorization": f"Bearer {api_key}",
            **(extra_headers or {}),
        },
    )
    choices = response.get("choices", [])
    if choices and isinstance(choices[0], dict):
        message = choices[0].get("message", {})
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str) and content.strip():
            return model, content.strip()
    return model, as_pretty_json(response)


def run_qwen(prompt: str, code: str) -> tuple[str, str]:
    model = os.environ.get("QWEN_MODEL")
    if not model:
        raise missing_env("QWEN_MODEL")

    openrouter_key = os.environ.get("OPENROUTER_API_KEY")
    if openrouter_key:
        return run_openai_compatible_chat(
            api_key=openrouter_key,
            model=model,
            url="https://openrouter.ai/api/v1/chat/completions",
            prompt=prompt,
            code=code,
            extra_headers={
                "HTTP-Referer": "https://github.com/nullsec-s1/model-arena",
                "X-Title": "Nullsec-S1 Model Arena",
            },
        )

    qwen_key = os.environ.get("QWEN_API_KEY")
    if not qwen_key:
        raise RuntimeError("Missing QWEN_API_KEY or OPENROUTER_API_KEY")

    return run_openai_compatible_chat(
        api_key=qwen_key,
        model=model,
        url="https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        prompt=prompt,
        code=code,
    )


RUNNERS = {
    "nullsec": ("Nullsec-S1", run_nullsec),
    "claude": ("Claude Opus 4.8", run_claude),
    "openai": ("OpenAI/Codex", run_openai),
    "qwen": ("Qwen", run_qwen),
}

MODEL_ENV = {
    "claude": "ANTHROPIC_MODEL",
    "openai": "OPENAI_MODEL",
    "qwen": "QWEN_MODEL",
}


def parse_models(value: str) -> list[str]:
    models = [part.strip().lower() for part in value.split(",") if part.strip()]
    unknown = [model for model in models if model not in RUNNERS]
    if unknown:
        known = ", ".join(RUNNERS)
        raise argparse.ArgumentTypeError(f"unknown model(s): {', '.join(unknown)}; choose from {known}")
    if not models:
        raise argparse.ArgumentTypeError("at least one model is required")
    return models


def default_out_path() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path("model-arena") / "runs" / f"{stamp}.json"


def write_output(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a real side-by-side security audit comparison for Nullsec-S1.",
    )
    parser.add_argument("--case", choices=sorted(CASES), required=True)
    parser.add_argument(
        "--models",
        type=parse_models,
        default=list(DEFAULT_MODELS),
        help="Comma-separated models to run: nullsec,claude,openai,qwen",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=default_out_path(),
        help="Output JSON path. Defaults to model-arena/runs/<timestamp>.json",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    case = CASES[args.case]
    runs: list[ModelRun] = []

    for model_key in args.models:
        label, runner = RUNNERS[model_key]
        started_at = utc_now()
        try:
            if model_key == "nullsec":
                model_id, raw_output = runner(PROMPT, case)
            else:
                model_id, raw_output = runner(PROMPT, case["input"])
            runs.append(
                ModelRun(
                    model_label=label,
                    model_id=model_id,
                    raw_output=raw_output,
                    timestamp=started_at,
                    error=None,
                )
            )
            print(f"[ok] {label}: {model_id}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - every provider failure must be recorded.
            runs.append(
                ModelRun(
                    model_label=label,
                    model_id=os.environ.get(MODEL_ENV.get(model_key, ""), model_key),
                    raw_output="",
                    timestamp=started_at,
                    error=str(exc),
                )
            )
            print(f"[error] {label}: {exc}", file=sys.stderr)

    payload = {
        "case": args.case,
        "prompt": PROMPT,
        "input": case["input"],
        "runs": [run.to_json() for run in runs],
    }
    write_output(args.out, payload)
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
