import json
import os
import sys
import types

from fastapi.testclient import TestClient

from nullsec.core.engine import NullsecPipeline, PipelineConfig, detect_adapter_source
from nullsec.safety import VerdictParseError
from serving import server


REAL_PIPELINE_CONFIG = server.PipelineConfig
REAL_ENABLE_ARENA_RAW = os.environ.get("NULLSEC_ENABLE_ARENA_RAW")


def restore_arena_env():
    if REAL_ENABLE_ARENA_RAW is None:
        os.environ.pop("NULLSEC_ENABLE_ARENA_RAW", None)
    else:
        os.environ["NULLSEC_ENABLE_ARENA_RAW"] = REAL_ENABLE_ARENA_RAW


class FakePipeline:
    def analyze(self, filename: str, code: str, lang: str):
        self.last_request = {"filename": filename, "code": code, "lang": lang}
        return object()

    def generate_messages(self, messages: list[dict]) -> str:
        self.last_messages = messages
        return '{"findings":[{"category":"UNSAFE_ADMIN_ROUTE"}]}'

    def to_json(self, result) -> str:
        return json.dumps(
            {
                "risk_score": 87,
                "production_ready": False,
                "severity": "HIGH",
                "confidence": "HIGH",
                "reasoning_summary": "Unsafe admin route.",
                "exploit_scenario": "A caller can mutate user roles without authorization.",
                "affected_files": ["app/api/admin/route.ts"],
                "checks_performed": {
                    "auth": {"status": "fail", "note": "No session or role check."},
                    "secrets": {"status": "pass", "note": "No hardcoded secret observed."},
                    "input_validation": {"status": "not_checked", "note": "Not enough context."},
                    "rate_limits": {"status": "not_checked", "note": "Not enough context."},
                    "permissions": {"status": "fail", "note": "Admin mutation is not gated."},
                    "dangerous_exec": {"status": "pass", "note": "No shell execution observed."},
                    "dependency_risk": {"status": "not_applicable", "note": "No dependencies shown."},
                    "environment_exposure": {"status": "pass", "note": "No environment exposure observed."},
                },
                "findings": [
                    {
                        "category": "UNSAFE_ADMIN_ROUTE",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "file": "app/api/admin/route.ts",
                        "line": 1,
                        "description": "Admin-level mutation is exposed without authorization.",
                        "exploit_scenario": "Any caller can submit a user id and role.",
                        "recommended_fix": "Require authenticated admin role before mutation.",
                        "secure_patch": "+ requireAdmin()",
                    }
                ],
                "_safety_layer": {
                    "production_ready": False,
                    "blocking_reasons": ["R2: dimension 'auth' failed its check"],
                    "adjustments": [],
                },
            }
        )

    def info(self) -> dict:
        return {
            "base_model": "Qwen/Qwen2.5-Coder-7B-Instruct",
            "adapter_path": "Trynullsec/nullsec-s1",
            "adapter_loaded": True,
            "adapter_source": "hf_repo",
            "device": "cuda:0",
            "dtype": "torch.bfloat16",
            "eager_loaded": False,
        }


class FailingPipeline(FakePipeline):
    def analyze(self, filename: str, code: str, lang: str):
        self.last_request = {"filename": filename, "code": code, "lang": lang}
        raise VerdictParseError("test alignment failure")


def client_with_fake_pipeline():
    fake = FakePipeline()
    server._pipeline = fake
    server.PipelineConfig = lambda: type(  # noqa: E731
        "Config", (), {"adapter_path": "Trynullsec/nullsec-s1"}
    )()
    return TestClient(server.app), fake


def client_with_pipeline(fake):
    server._pipeline = fake
    server.PipelineConfig = lambda: type(  # noqa: E731
        "Config", (), {"adapter_path": "Trynullsec/nullsec-s1"}
    )()
    return TestClient(server.app), fake


def test_analyze_returns_wrapped_real_pipeline_verdict():
    try:
        client, fake = client_with_fake_pipeline()
        response = client.post(
            "/v1/analyze",
            json={
                "filename": "app/api/admin/route.ts",
                "language": "typescript",
                "code": "export async function POST(req: Request) { return Response.json({ ok: true }) }",
            },
        )
    finally:
        server.PipelineConfig = REAL_PIPELINE_CONFIG

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["verdict"]["severity"] == "HIGH"
    assert payload["verdict"]["findings"][0]["category"] == "UNSAFE_ADMIN_ROUTE"
    assert fake.last_request["lang"] == "typescript"


def test_analyze_accepts_legacy_lang_field():
    try:
        client, fake = client_with_fake_pipeline()
        response = client.post(
            "/v1/analyze",
            json={"filename": "route.ts", "lang": "typescript", "code": "export const ok = true"},
        )
    finally:
        server.PipelineConfig = REAL_PIPELINE_CONFIG

    assert response.status_code == 200
    assert fake.last_request["lang"] == "typescript"


def test_arena_raw_disabled_by_default():
    try:
        os.environ.pop("NULLSEC_ENABLE_ARENA_RAW", None)
        client, fake = client_with_fake_pipeline()
        response = client.post(
            "/v1/arena/raw",
            json={
                "prompt": "Audit exactly this snippet.",
                "language": "typescript",
                "code": "export async function POST() {}",
            },
        )
    finally:
        server.PipelineConfig = REAL_PIPELINE_CONFIG
        restore_arena_env()

    assert response.status_code == 403
    assert response.json() == {
        "ok": False,
        "error": {
            "code": "arena_disabled",
            "message": "Arena raw endpoint is disabled.",
        },
    }
    assert not hasattr(fake, "last_messages")


def test_arena_raw_uses_caller_supplied_prompt_when_enabled():
    try:
        os.environ["NULLSEC_ENABLE_ARENA_RAW"] = "1"
        client, fake = client_with_fake_pipeline()
        response = client.post(
            "/v1/arena/raw",
            json={
                "prompt": "Audit exactly this snippet.",
                "language": "typescript",
                "code": "export async function POST() {}",
            },
        )
    finally:
        server.PipelineConfig = REAL_PIPELINE_CONFIG
        restore_arena_env()

    assert response.status_code == 200
    payload = response.json()
    assert payload["raw_output"] == '{"findings":[{"category":"UNSAFE_ADMIN_ROUTE"}]}'
    assert fake.last_messages == [
        {
            "role": "user",
            "content": "Audit exactly this snippet.\n\n```typescript\nexport async function POST() {}\n```",
        }
    ]


def test_repo_scan_returns_cli_report_shape():
    try:
        client, fake = client_with_fake_pipeline()
        response = client.post(
            "/v1/scan",
            json={
                "project_name": "my-app",
                "scan_mode": "repo",
                "files": [
                    {
                        "path": "src/admin.ts",
                        "language": "typescript",
                        "content": "export async function POST() {}",
                    }
                ],
                "metadata": {
                    "cli_version": "0.1.0",
                    "total_files": 1,
                    "total_bytes": 31,
                    "timestamp": "2026-06-01T00:00:00.000Z",
                },
            },
        )
    finally:
        server.PipelineConfig = REAL_PIPELINE_CONFIG

    assert response.status_code == 200
    payload = response.json()
    assert payload["risk_score"] == 70
    assert payload["findings"][0]["severity"] == "high"
    assert payload["findings"][0]["title"] == "UNSAFE_ADMIN_ROUTE"
    assert payload["model"]["adapter_loaded"] is True
    assert fake.last_request["filename"] == "src/admin.ts"


def test_repo_scan_accepts_minimal_cli_payload():
    try:
        client, fake = client_with_fake_pipeline()
        response = client.post(
            "/v1/scan",
            json={
                "project_name": "my-app",
                "files": [
                    {
                        "path": "src/index.ts",
                        "content": "export const ok = true",
                    }
                ],
            },
        )
    finally:
        server.PipelineConfig = REAL_PIPELINE_CONFIG

    assert response.status_code == 200
    assert response.json()["risk_score"] == 70
    assert fake.last_request["lang"] == ""


def test_repo_scan_alignment_failure_returns_json_warning():
    try:
        client, fake = client_with_pipeline(FailingPipeline())
        response = client.post(
            "/v1/scan",
            json={
                "project_name": "my-app",
                "files": [
                    {
                        "path": "src/index.ts",
                        "language": "typescript",
                        "content": "export const ok = true",
                    }
                ],
            },
        )
    finally:
        server.PipelineConfig = REAL_PIPELINE_CONFIG

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert payload["risk_score"] == 20
    assert payload["findings"][0]["title"] == "MODEL_ALIGNMENT_WARNING"
    assert fake.last_request["filename"] == "src/index.ts"


def test_repo_scan_alignment_failure_uses_deterministic_fallback():
    try:
        client, _ = client_with_pipeline(FailingPipeline())
        response = client.post(
            "/v1/scan",
            json={
                "project_name": "my-app",
                "files": [
                    {
                        "path": "src/route.ts",
                        "language": "typescript",
                        "content": "eval(req.body.code)",
                    }
                ],
            },
        )
    finally:
        server.PipelineConfig = REAL_PIPELINE_CONFIG

    assert response.status_code == 200
    payload = response.json()
    assert payload["risk_score"] == 90
    assert payload["findings"][0]["title"] == "REMOTE_CODE_EXECUTION"
    assert payload["findings"][0]["severity"] == "critical"


def test_repo_scan_rejects_empty_file_content_with_details():
    try:
        client, _ = client_with_fake_pipeline()
        response = client.post(
            "/v1/scan",
            json={
                "project_name": "my-app",
                "files": [
                    {
                        "path": "src/index.ts",
                        "language": "typescript",
                        "content": "",
                    }
                ],
            },
        )
    finally:
        server.PipelineConfig = REAL_PIPELINE_CONFIG

    assert response.status_code == 422
    payload = response.json()
    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_request"
    assert payload["error"]["details"][0]["loc"] == ["files", 0, "content"]


def test_analyze_rejects_oversized_code_without_model_load():
    try:
        client, _ = client_with_fake_pipeline()
        response = client.post(
            "/v1/analyze",
            json={"filename": "large.ts", "language": "typescript", "code": "x" * (server.MAX_CODE_CHARS + 1)},
        )
    finally:
        server.PipelineConfig = REAL_PIPELINE_CONFIG

    assert response.status_code == 422
    assert response.json()["ok"] is False
    assert response.json()["error"]["code"] == "invalid_request"


def test_analyze_requires_adapter_configuration():
    server._pipeline = FakePipeline()
    server.PipelineConfig = lambda: type("Config", (), {"adapter_path": None})()  # noqa: E731
    try:
        client = TestClient(server.app)
        response = client.post(
            "/v1/analyze",
            json={"filename": "route.ts", "language": "typescript", "code": "export const ok = true"},
        )
    finally:
        server.PipelineConfig = REAL_PIPELINE_CONFIG

    assert response.status_code == 503
    assert response.json()["ok"] is False
    assert response.json()["error"]["code"] == "backend_unavailable"


def test_adapter_source_detection():
    assert detect_adapter_source("Trynullsec/nullsec-s1") == "hf_repo"
    assert detect_adapter_source("./local/path/to/adapter") == "local_path"
    assert detect_adapter_source("/absolute/path/to/adapter") == "local_path"
    assert detect_adapter_source(None) == "none"


def test_pipeline_config_reads_runtime_environment(monkeypatch):
    monkeypatch.setenv("NULLSEC_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
    monkeypatch.setenv("NULLSEC_ADAPTER_PATH", "Trynullsec/nullsec-s1")
    monkeypatch.setenv("NULLSEC_EAGER_LOAD", "1")
    server._pipeline = None

    try:
        config = PipelineConfig()

        assert config.base_model == "Qwen/Qwen2.5-Coder-7B-Instruct"
        assert config.adapter_path == "Trynullsec/nullsec-s1"
        assert config.adapter_source == "hf_repo"
        assert server._pipeline_info()["eager_loaded"] is True
    finally:
        server._pipeline = None


def test_model_info_endpoint_reads_server_config(monkeypatch):
    monkeypatch.setenv("NULLSEC_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
    monkeypatch.setenv("NULLSEC_ADAPTER_PATH", "Trynullsec/nullsec-s1")
    monkeypatch.setenv("NULLSEC_EAGER_LOAD", "1")
    server._pipeline = None

    try:
        response = TestClient(server.app).get("/model-info")
    finally:
        server._pipeline = None

    payload = response.json()
    assert payload["base_model"] == "Qwen/Qwen2.5-Coder-7B-Instruct"
    assert payload["adapter_path"] == "Trynullsec/nullsec-s1"
    assert payload["adapter_loaded"] is False
    assert payload["adapter_source"] == "hf_repo"
    assert payload["eager_loaded"] is True


def test_pipeline_load_passes_hf_adapter_id_to_peft(monkeypatch):
    calls = {}

    class FakeTensor:
        bfloat16 = "bfloat16"

        @staticmethod
        def no_grad():
            class Context:
                def __enter__(self):
                    return None

                def __exit__(self, *args):
                    return False

            return Context()

    class FakeBitsAndBytesConfig:
        def __init__(self, **kwargs):
            calls["quant"] = kwargs

    class FakeTokenizer:
        @classmethod
        def from_pretrained(cls, model_id, trust_remote_code):
            calls["tokenizer"] = (model_id, trust_remote_code)
            return cls()

    class FakeModel:
        device = "cuda:0"
        dtype = "torch.bfloat16"

        @classmethod
        def from_pretrained(cls, model_id, **kwargs):
            calls["base_model"] = (model_id, kwargs)
            return cls()

        def eval(self):
            calls["eval"] = True

    class FakePeftModel:
        @staticmethod
        def from_pretrained(model, adapter_path):
            calls["adapter"] = adapter_path
            return model

    monkeypatch.setitem(sys.modules, "torch", FakeTensor)
    monkeypatch.setitem(
        sys.modules,
        "transformers",
        types.SimpleNamespace(
            AutoModelForCausalLM=FakeModel,
            AutoTokenizer=FakeTokenizer,
            BitsAndBytesConfig=FakeBitsAndBytesConfig,
        ),
    )
    monkeypatch.setitem(sys.modules, "peft", types.SimpleNamespace(PeftModel=FakePeftModel))

    pipeline = NullsecPipeline(
        PipelineConfig(
            base_model="Qwen/Qwen2.5-Coder-7B-Instruct",
            adapter_path="Trynullsec/nullsec-s1",
        )
    )
    pipeline.load()

    assert calls["tokenizer"] == ("Qwen/Qwen2.5-Coder-7B-Instruct", True)
    assert calls["base_model"][0] == "Qwen/Qwen2.5-Coder-7B-Instruct"
    assert calls["adapter"] == "Trynullsec/nullsec-s1"
    assert pipeline.info()["adapter_loaded"] is True
    assert pipeline.info()["device"] == "cuda:0"


def test_analyze_returns_json_when_runtime_dependencies_missing(monkeypatch):
    monkeypatch.setenv("NULLSEC_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
    monkeypatch.setenv("NULLSEC_ADAPTER_PATH", "Trynullsec/nullsec-s1")
    server._pipeline = None
    monkeypatch.setitem(sys.modules, "torch", None)

    try:
        response = TestClient(server.app).post(
            "/v1/analyze",
            json={"filename": "route.ts", "language": "typescript", "code": "export const ok = true"},
        )
    finally:
        server._pipeline = None

    assert response.status_code == 503
    assert response.json()["ok"] is False
    assert response.json()["error"]["code"] == "backend_unavailable"
    assert "runtime dependency load failed" in response.json()["error"]["message"]
