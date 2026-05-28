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

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

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


def get_pipeline() -> NullsecPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = NullsecPipeline(PipelineConfig())
        if os.environ.get("NULLSEC_EAGER_LOAD", "0") == "1":
            _pipeline.load()
    return _pipeline


class AnalyzeRequest(BaseModel):
    filename: str = Field(..., examples=["app.py"])
    code: str
    lang: str = ""


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
    pipeline = get_pipeline()
    try:
        result = pipeline.analyze(req.filename, req.code, req.lang)
    except VerdictParseError as e:
        raise HTTPException(status_code=502, detail=f"Nullsec-1 output could not be aligned: {e}")
    return json.loads(pipeline.to_json(result))


@app.post("/v1/patch")
def patch(req: AnalyzeRequest) -> dict:
    pipeline = get_pipeline()
    try:
        result = pipeline.analyze(req.filename, req.code, req.lang)
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
    pipeline = get_pipeline()

    def event_gen():
        buffer = []
        for token in pipeline.generate_stream(req.filename, req.code, req.lang):
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
