"""Curation Sprint 001 — batch 6: additional real cases (margin above +50)."""
from __future__ import annotations

import json

from training.sprint_data.sprint001_batch1 import (
    CWE_OPENREDIR, CWE_SSTI, OUT_DIR, case,
)

CASES = [
    case(source_type="cve", source_ref="CVE-2014-0160 Heartbleed (OpenSSL) dependency",
         lang="text", framework="apt", filename="Dockerfile",
         code="RUN apt-get install -y openssl=1.0.1f\n",
         category="DEPENDENCY_RISK",
         description="OpenSSL 1.0.1f is vulnerable to Heartbleed (CVE-2014-0160) out-of-bounds read.",
         exploit="A malformed TLS heartbeat leaks up to 64KB of process memory (keys, sessions) per request.",
         patch="-RUN apt-get install -y openssl=1.0.1f\n+RUN apt-get install -y openssl=1.0.1g  # Heartbleed fixed in 1.0.1g",
         severity="HIGH",
         references={"cwe": "CWE-125", "owasp": "A06:2021-Vulnerable and Outdated Components",
                     "cve": "CVE-2014-0160"},
         reviewer_notes="CVE-2014-0160 verified (OpenSSL 1.0.1-1.0.1f, fixed 1.0.1g). CWE-125 OOB read."),
    case(source_type="semgrep", source_ref="SSTI via render_template_string / CWE-1336",
         lang="python", framework="flask", filename="page.py",
         code="@app.route('/p')\ndef p():\n    return render_template_string('Hello ' + request.args.get('name',''))\n",
         category="XSS",
         description="User input concatenated into a Jinja template string (server-side template injection).",
         exploit="?name={{config}} or {{7*7}} confirms SSTI; payloads escalate to RCE on Flask/Jinja2.",
         patch="-    return render_template_string('Hello ' + request.args.get('name',''))\n+    return render_template('hello.html', name=request.args.get('name',''))",
         severity="HIGH",
         references={"cwe": "CWE-1336", "owasp": "A03:2021-Injection", "cve": None},
         reviewer_notes="SSTI classified under XSS/injection dimension; render fixed template with autoescape. CWE-1336."),
    case(source_type="semgrep", source_ref="open redirect / CWE-601",
         lang="python", framework="flask", filename="redirect.py",
         code="@app.route('/go')\ndef go():\n    return redirect(request.args.get('next'))\n",
         category="SSRF",
         description="Unvalidated redirect target (open redirect).",
         exploit="?next=https://evil.example phishes users by redirecting from a trusted domain.",
         patch="-    return redirect(request.args.get('next'))\n+    nxt = request.args.get('next','/')\n+    if not nxt.startswith('/') or nxt.startswith('//'): nxt = '/'\n+    return redirect(nxt)",
         severity="MEDIUM",
         references={"cwe": "CWE-601", "owasp": "A01:2021-Broken Access Control", "cve": None},
         reviewer_notes="Open redirect grouped with SSRF/URL-trust; allow only local paths. CWE-601."),
    case(source_type="vibecoded", source_ref="nullsec-scanner: AI-generated insecure deserialization",
         lang="python", framework="flask", filename="session.py",
         code="import pickle\n@app.route('/load')\ndef load():\n    return str(pickle.loads(base64.b64decode(request.cookies['s'])))\n",
         category="DANGEROUS_SHELL_COMMAND",
         description="Untrusted cookie deserialized with pickle (arbitrary code execution).",
         exploit="A crafted pickle in the 's' cookie executes code on load via __reduce__.",
         patch="-import pickle\n-    return str(pickle.loads(base64.b64decode(request.cookies['s'])))\n+import json\n+    return str(json.loads(base64.b64decode(request.cookies['s'])))",
         severity="CRITICAL",
         references={"cwe": "CWE-502", "owasp": "A08:2021-Software and Data Integrity Failures", "cve": None},
         reviewer_notes="pickle->json; CWE-502 insecure deserialization. Real vibecoded pattern."),
]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "sprint001_batch6.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for c in CASES:
            fh.write(json.dumps(c) + "\n")
    print(f"staged {len(CASES)} records -> {out}")


if __name__ == "__main__":
    main()
