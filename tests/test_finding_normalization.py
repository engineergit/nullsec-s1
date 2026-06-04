from nullsec.safety.finding_normalization import normalize_verdict_payload


def base_payload():
    return {
        "risk_score": 0,
        "production_ready": True,
        "severity": "INFO",
        "confidence": "HIGH",
        "reasoning_summary": "No findings.",
        "exploit_scenario": None,
        "affected_files": [],
        "checks_performed": {
            "auth": {"status": "pass", "note": "not relevant"},
            "secrets": {"status": "pass", "note": "not relevant"},
            "input_validation": {"status": "pass", "note": "not relevant"},
            "rate_limits": {"status": "not_applicable", "note": "not relevant"},
            "permissions": {"status": "pass", "note": "not relevant"},
            "dangerous_exec": {"status": "pass", "note": "not relevant"},
            "dependency_risk": {"status": "not_applicable", "note": "not relevant"},
            "environment_exposure": {"status": "pass", "note": "not relevant"},
        },
        "findings": [],
    }


def titles_for(code: str):
    return normalize_verdict_payload(base_payload(), code, "route.ts")["findings"]


def assert_finding(code: str, title: str, severity: str, cwe: str | None = None):
    findings = titles_for(code)
    match = next((finding for finding in findings if finding.get("title") == title), None)
    assert match is not None, findings
    assert match["severity"] == severity
    if cwe:
        assert match["cwe"] == cwe
    return match


def test_path_traversal_from_user_controlled_file_path():
    finding = assert_finding("fs.readFileSync(req.query.path)", "PATH_TRAVERSAL", "HIGH", "CWE-22")
    assert "Untrusted user-controlled file path reaches filesystem access." in finding["description"]


def test_eval_remote_code_execution():
    assert_finding("eval(req.body.code)", "REMOTE_CODE_EXECUTION", "CRITICAL", "CWE-94")


def test_user_controlled_exec_is_command_injection():
    assert_finding("exec(req.body.cmd)", "COMMAND_INJECTION", "CRITICAL", "CWE-78")


def test_static_exec_is_low_risk_process_execution():
    payload = normalize_verdict_payload(base_payload(), 'exec("npm run build")', "build.js")
    assert payload["risk_score"] == 20
    assert_finding('exec("npm run build")', "UNSAFE_PROCESS_EXECUTION", "LOW", "CWE-78")


def test_env_secret_read_alone_is_not_a_finding():
    payload = normalize_verdict_payload(base_payload(), "export const secret = process.env.JWT_SECRET", "config.ts")
    assert payload["findings"] == []
    assert payload["risk_score"] == 0


def test_env_secret_returned_to_client_is_exposed_secret():
    assert_finding("res.json({ apiKey: process.env.OPENAI_API_KEY })", "EXPOSED_SECRET", "CRITICAL", "CWE-798")


def test_template_sql_with_req_query_is_sql_injection():
    assert_finding("db.query(`SELECT * FROM users WHERE id=${req.query.id}`)", "SQL_INJECTION", "CRITICAL", "CWE-89")


def test_parameterized_sql_query_is_not_a_finding():
    payload = normalize_verdict_payload(base_payload(), 'db.query("SELECT * FROM users WHERE id = ?", [req.query.id])', "db.js")
    assert payload["findings"] == []
    assert payload["risk_score"] == 0


def test_dangerously_set_inner_html_from_query_is_xss():
    assert_finding("return <div dangerouslySetInnerHTML={{__html:req.query.html}} />", "XSS", "HIGH", "CWE-79")


def test_fetch_user_controlled_url_is_ssrf():
    assert_finding("fetch(req.body.url)", "SSRF", "HIGH", "CWE-918")
