"""Curation Sprint 001 — batch 3: broken auth, exposed secrets, environment exposure."""
from __future__ import annotations

import json

from training.sprint_data.sprint001_batch1 import (
    CWE_AUTHN, CWE_AUTHZ, CWE_DEBUG, CWE_INFO, CWE_SECRET, OUT_DIR, case,
)

CASES = [
    # ----------------------- BROKEN_AUTH -----------------------
    case(source_type="owasp", source_ref="JWT alg=none / CWE-347",
         lang="python", framework="flask", filename="token.py",
         code="def verify(tok):\n    return jwt.decode(tok, key, algorithms=['HS256','none'])\n",
         category="BROKEN_AUTH",
         description="JWT verification permits the 'none' algorithm, accepting unsigned tokens.",
         exploit="An attacker forges a token with alg=none and arbitrary claims to impersonate any user.",
         patch="-    return jwt.decode(tok, key, algorithms=['HS256','none'])\n+    return jwt.decode(tok, key, algorithms=['HS256'])",
         references={"cwe": "CWE-347", "owasp": "A07:2021-Identification and Authentication Failures", "cve": None},
         reviewer_notes="Pin algorithm; CWE-347 improper signature verification."),
    case(source_type="owasp", source_ref="IDOR missing object-level authz / CWE-639",
         lang="python", framework="fastapi", filename="orders.py",
         code="@app.get('/orders/{oid}')\ndef get_order(oid: int, user=Depends(current_user)):\n    return db.get_order(oid)\n",
         category="BROKEN_AUTH",
         description="Authenticated but no object ownership check (IDOR/BOLA).",
         exploit="A logged-in user enumerates oid values to read other customers' orders.",
         patch="-    return db.get_order(oid)\n+    o = db.get_order(oid)\n+    if o.user_id != user.id: raise HTTPException(403)\n+    return o",
         references={"cwe": "CWE-639", "owasp": "A01:2021-Broken Access Control", "cve": None},
         reviewer_notes="Object-level authz; CWE-639 / OWASP A01 (BOLA)."),
    case(source_type="semgrep", source_ref="missing auth on sensitive route / CWE-306",
         lang="javascript", framework="express", filename="account.js",
         code="app.post('/account/close', (req, res) => {\n  db.closeAccount(req.body.userId);\n  res.json({closed:true});\n});\n",
         category="BROKEN_AUTH",
         description="Destructive endpoint has no authentication or session check.",
         exploit="Any unauthenticated caller closes arbitrary accounts by posting a userId.",
         patch="+const requireAuth = require('./auth');\n-app.post('/account/close', (req, res) => {\n+app.post('/account/close', requireAuth, (req, res) => {\n+  if (req.user.id !== req.body.userId) return res.status(403).end();\n   db.closeAccount(req.body.userId);",
         references={"cwe": CWE_AUTHN, "owasp": "A01:2021-Broken Access Control", "cve": None},
         reviewer_notes="Require auth + ownership; CWE-306 missing authentication."),

    # ----------------------- EXPOSED_SECRET -----------------------
    case(source_type="semgrep", source_ref="hardcoded credential / CWE-798",
         lang="python", framework="none", filename="db.py",
         code="DATABASE_URL = 'postgres://admin:S3cr3tP@ss@db.internal:5432/prod'\n",
         category="EXPOSED_SECRET",
         description="Database credentials hardcoded in source.",
         exploit="Anyone with repo or build access obtains production DB credentials.",
         patch="-DATABASE_URL = 'postgres://admin:S3cr3tP@ss@db.internal:5432/prod'\n+import os\n+DATABASE_URL = os.environ['DATABASE_URL']  # rotate the exposed credential",
         references={"cwe": CWE_SECRET, "owasp": "A07:2021-Identification and Authentication Failures", "cve": None},
         reviewer_notes="Env var + rotate; CWE-798 hardcoded credentials."),
    case(source_type="semgrep", source_ref="private key committed / CWE-798",
         lang="text", framework="none", filename="id_rsa",
         code="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn... (committed private key)\n-----END RSA PRIVATE KEY-----\n",
         category="EXPOSED_SECRET",
         description="An RSA private key committed to the repository.",
         exploit="The key authenticates to whatever it grants access to; repo access = full compromise.",
         patch="-----BEGIN RSA PRIVATE KEY----- ... committed key ...\n+# remove the key from the repo and history (git filter-repo), rotate it,\n+# and load it from a secret manager at runtime",
         references={"cwe": CWE_SECRET, "owasp": "A07:2021-Identification and Authentication Failures", "cve": None},
         reviewer_notes="Remove from history + rotate; CWE-798."),
    case(source_type="vibecoded", source_ref="nullsec-scanner: AI-generated config with inline API key",
         lang="javascript", framework="next", filename="config.js",
         code="export const config = { openaiKey: 'sk-proj-AbCd1234ExampleKeyInClientConfig' };\n",
         category="EXPOSED_SECRET",
         description="AI-generated config places a provider API key in a client-readable module.",
         exploit="The key ships in the browser bundle; any visitor extracts and abuses it (cost/data).",
         patch="-export const config = { openaiKey: 'sk-proj-AbCd1234ExampleKeyInClientConfig' };\n+// call the provider only from a server route; keep the key in server env\n+export const config = {};",
         references={"cwe": CWE_SECRET, "owasp": "A05:2021-Security Misconfiguration", "cve": None},
         reviewer_notes="Real vibecoded secret leak; server-side only. CWE-798."),

    # ----------------------- ENVIRONMENT_EXPOSURE -----------------------
    case(source_type="owasp", source_ref="debug mode in production / CWE-489",
         lang="python", framework="django", filename="settings.py",
         code="DEBUG = True\nALLOWED_HOSTS = ['*']\n",
         category="ENVIRONMENT_EXPOSURE",
         description="Django DEBUG=True in production leaks tracebacks, settings, and SQL.",
         exploit="Any error page exposes environment variables, secret fragments, and internal paths.",
         patch="-DEBUG = True\n-ALLOWED_HOSTS = ['*']\n+DEBUG = os.environ.get('DJANGO_DEBUG') == '1'\n+ALLOWED_HOSTS = os.environ['ALLOWED_HOSTS'].split(',')",
         references={"cwe": CWE_DEBUG, "owasp": "A05:2021-Security Misconfiguration", "cve": None},
         reviewer_notes="CWE-489 debug in prod; env-gated."),
    case(source_type="semgrep", source_ref="env exposed to client bundle / CWE-200",
         lang="javascript", framework="vite", filename="vite.config.js",
         code="export default { define: { 'process.env': process.env } };\n",
         category="ENVIRONMENT_EXPOSURE",
         description="Entire process.env inlined into the client bundle.",
         exploit="All server env vars (keys, tokens) become readable in the shipped JS.",
         patch="-export default { define: { 'process.env': process.env } };\n+// expose only intentional, client-safe vars (VITE_ prefix); never the whole env\n+export default {};",
         severity="CRITICAL",
         references={"cwe": CWE_INFO, "owasp": "A05:2021-Security Misconfiguration", "cve": None},
         reviewer_notes="CWE-200 info exposure; never inline full env."),
    case(source_type="vibecoded", source_ref="nullsec-scanner: AI-generated static config serving .env",
         lang="javascript", framework="express", filename="server.js",
         code="app.use(express.static('.'));  // serves project root incl. .env\napp.listen(3000);\n",
         category="ENVIRONMENT_EXPOSURE",
         description="AI-generated server serves the project root statically, exposing .env and configs.",
         exploit="GET /.env returns secrets; GET /package.json and source become public.",
         patch="-app.use(express.static('.'));  // serves project root incl. .env\n+app.use(express.static('public'));  // serve only the public dir",
         severity="HIGH",
         references={"cwe": CWE_INFO, "owasp": "A05:2021-Security Misconfiguration", "cve": None},
         reviewer_notes="Real vibecoded misconfig; serve public/ only. CWE-200."),
]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "sprint001_batch3.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for c in CASES:
            fh.write(json.dumps(c) + "\n")
    print(f"staged {len(CASES)} records -> {out}")


if __name__ == "__main__":
    main()
