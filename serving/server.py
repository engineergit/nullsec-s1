#!/usr/bin/env python3
"""Nullsec-1 serving layer.

HTTP interface to the Nullsec-1 reasoning pipeline. Every analysis response runs
through the Security Alignment Layer and the Nullsec Safety Layer before it is
returned, so `production_ready` is always the Safety Layer's enforced value, not
Nullsec-1's unverified claim. Safety Layer metadata is attached under
`_safety_layer`.

Endpoints:
  GET  /health
  GET  /v1/model           model identity, version, fingerprint, support matrix
  GET  /v1/capabilities    detection + action capabilities
  POST /v1/analyze         enforced JSON verdict
  POST /v1/patch           verdict with secure patches surfaced
  POST /v1/analyze/stream  SSE stream of tokens, then the enforced verdict

Run:
  uvicorn serving.server:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from nullsec.core.engine import NullsecPipeline, PipelineConfig
from nullsec.core.version import (
    MODEL_NAME,
    MODEL_VERSION,
    capabilities,
    model_info,
)
from nullsec.safety import VerdictParseError

app = FastAPI(title=MODEL_NAME, version=MODEL_VERSION)
_pipeline: NullsecPipeline | None = None
MAX_CODE_CHARS = int(os.environ.get("NULLSEC_MAX_CODE_CHARS", "50000"))


def _cors_origins() -> list[str]:
    raw = os.environ.get(
        "NULLSEC_CORS_ORIGINS",
        "https://s1.trynullsec.com,http://localhost:3000,http://127.0.0.1:3000",
    )
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def _safe_validation_errors(exc: RequestValidationError) -> list[dict]:
    errors = []
    for error in exc.errors():
        safe = {
            key: value
            for key, value in error.items()
            if key not in {"input", "ctx", "url"}
        }
        errors.append(safe)
    return errors


def _assert_real_nullsec_config() -> None:
    config = PipelineConfig()
    allow_merged = os.environ.get("NULLSEC_ALLOW_MERGED_MODEL", "0") == "1"
    if config.adapter_path or allow_merged:
        return
    raise HTTPException(
        status_code=503,
        detail=(
            "Nullsec-S1 adapter is not configured. Set NULLSEC_ADAPTER_PATH to "
            "the Hugging Face adapter id or a local release artifact path."
        ),
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["content-type", "authorization"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "ok": False,
            "error": {
                "code": "invalid_request",
                "message": "Request body failed validation.",
                "details": _safe_validation_errors(exc),
            },
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
    code = "request_failed"
    if exc.status_code == 413:
        code = "input_too_large"
    elif exc.status_code == 502:
        code = "inference_alignment_failed"
    elif exc.status_code == 503:
        code = "backend_unavailable"
    return JSONResponse(
        status_code=exc.status_code,
        content={"ok": False, "error": {"code": code, "message": detail}},
    )


def get_pipeline() -> NullsecPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = NullsecPipeline(PipelineConfig())
        if os.environ.get("NULLSEC_EAGER_LOAD", "0") == "1":
            _pipeline.load()
    return _pipeline


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    filename: str = Field(..., min_length=1, max_length=512, examples=["app.py"])
    code: str = Field(..., min_length=1, max_length=MAX_CODE_CHARS)
    language: str = Field(default="", max_length=64)
    lang: str = Field(default="", max_length=64, exclude=True)

    @field_validator("filename", "language", "lang")
    @classmethod
    def strip_string(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def normalize_language(self) -> "AnalyzeRequest":
        if not self.language and self.lang:
            self.language = self.lang
        return self


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model": MODEL_NAME, "version": MODEL_VERSION}


@app.get("/v1/model")
def model() -> dict:
    return model_info()


@app.get("/v1/capabilities")
def caps() -> dict:
    return capabilities()


@app.post("/v1/analyze")
def analyze(req: AnalyzeRequest) -> dict:
    _assert_real_nullsec_config()
    pipeline = get_pipeline()
    try:
        result = pipeline.analyze(req.filename, req.code, req.language)
    except VerdictParseError as e:
        raise HTTPException(status_code=502, detail=f"Nullsec-1 output could not be aligned: {e}")
    return {"ok": True, "verdict": json.loads(pipeline.to_json(result))}


@app.post("/v1/patch")
def patch(req: AnalyzeRequest) -> dict:
    _assert_real_nullsec_config()
    pipeline = get_pipeline()
    try:
        result = pipeline.analyze(req.filename, req.code, req.language)
    except VerdictParseError as e:
        raise HTTPException(status_code=502, detail=f"Nullsec-1 output could not be aligned: {e}")
    payload = json.loads(pipeline.to_json(result))
    payload["patches"] = [
        {
            "file": f["file"],
            "category": f["category"],
            "secure_patch": f["secure_patch"],
            "recommended_fix": f["recommended_fix"],
        }
        for f in payload.get("findings", [])
    ]
    return payload


@app.post("/v1/analyze/stream")
def analyze_stream(req: AnalyzeRequest) -> StreamingResponse:
    _assert_real_nullsec_config()
    pipeline = get_pipeline()

    def event_gen():
        buffer = []
        for token in pipeline.generate_stream(req.filename, req.code, req.language):
            buffer.append(token)
            yield f"event: token\ndata: {json.dumps({'t': token})}\n\n"
        raw = "".join(buffer)
        try:
            result = pipeline.finalize(raw)
            final = json.loads(pipeline.to_json(result))
            yield f"event: verdict\ndata: {json.dumps(final)}\n\n"
        except VerdictParseError as e:
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream")
