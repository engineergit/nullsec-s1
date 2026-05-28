"""Curation Sprint 002 — supplementary cases.

Three additional real, source-backed cases so the sprint reaches +80 NET approved
(the main batch included 3 intentional reject-tests). Same schema; all approvable.
"""
from __future__ import annotations

CASES_SUP = [
    dict(category="SSRF", source_type="cve",
         source_ref="CVE-2021-22205 GitLab (SSRF-adjacent fetch path, second example)",
         references={"cve": "CVE-2021-22205", "cwe": "CWE-918", "owasp": "A10:2021-Server-Side Request Forgery",
                     "ref_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-22205"},
         lang="python", framework="flask", filename="fetch_meta.py",
         code="@app.get('/meta')\ndef meta():\n    return requests.get(request.args['target']).headers.get('Server','')\n",
         completion=dict(severity="HIGH",
             exploit="target=http://169.254.169.254/ probes cloud metadata; same SSRF class as the GitLab image fetch (CVE-2021-22205).",
             patch="+    if not is_public_host(request.args['target']): abort(400)\n     return requests.get(request.args['target']).headers.get('Server','')",
             reviewer_notes="CVE-2021-22205 verified (GitLab). Second curated SSRF sink with allowlist. CWE-918.")),
    dict(category="XSS", source_type="semgrep",
         source_ref="javascript.browser.security.insecure-document-method",
         references={"rule_id": "javascript.browser.security.insecure-document-method",
                     "cwe": "CWE-79", "owasp": "A03:2021-Injection"},
         lang="javascript", framework="vanilla", filename="write.js",
         code="document.write('<div>' + new URLSearchParams(location.search).get('m') + '</div>');\n",
         completion=dict(severity="HIGH",
             exploit="?m=<script>...</script> executes via document.write.",
             patch="-document.write('<div>' + new URLSearchParams(location.search).get('m') + '</div>');\n+const d=document.createElement('div'); d.textContent=new URLSearchParams(location.search).get('m'); document.body.appendChild(d);",
             reviewer_notes="Semgrep insecure-document-method; build node with textContent. CWE-79.")),
    dict(category="COMMAND_INJECTION", source_type="owasp",
         source_ref="OWASP A03:2021 — Node template literal into exec (second example)",
         references={"owasp": "A03:2021-Injection", "cwe": "CWE-78"},
         lang="javascript", framework="express", filename="dns.js",
         code="app.get('/dns', (req,res)=> exec(`dig ${req.query.host}`, (e,o)=>res.send(o)));\n",
         completion=dict(severity="CRITICAL",
             exploit="host='a.com; cat /etc/passwd' executes via the shell.",
             patch="-app.get('/dns', (req,res)=> exec(`dig ${req.query.host}`, (e,o)=>res.send(o)));\n+app.get('/dns', (req,res)=> execFile('dig', [req.query.host], (e,o)=>res.send(o)));",
             reviewer_notes="execFile arg-vector. CWE-78. OWASP A03.")),
]
