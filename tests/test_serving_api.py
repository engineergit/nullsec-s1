import json

from fastapi.testclient import TestClient

from serving import server


REAL_PIPELINE_CONFIG = server.PipelineConfig


class FakePipeline:
    def analyze(self, filename: str, code: str, lang: str):
        self.last_request = {"filename": filename, "code": code, "lang": lang}
        return object()

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


def client_with_fake_pipeline():
    fake = FakePipeline()
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
