"""Web-surface examples: missing rate limits, unsafe admin routes, unsafe file upload."""
from corpus.builder import vuln

EXAMPLES = [
    # ---- missing rate limit ----
    vuln(
        id="ratelimit-login",
        lang="python", framework="fastapi", file="login.py", line=2,
        code=(
            "@app.post('/login')\n"
            "def login(body: Creds):\n"
            "    return issue_token(check_password(body.user, body.pw))\n"
        ),
        category="MISSING_RATE_LIMIT",
        description="Login endpoint has no rate limiting or lockout.",
        exploit="Attacker brute-forces passwords at full speed with no throttling.",
        fix="Apply per-IP and per-account rate limiting with backoff/lockout.",
        patch="+from .ratelimit import limiter\n @app.post('/login')\n+@limiter.limit('5/minute')\n def login(body: Creds):\n     return issue_token(check_password(body.user, body.pw))",
        severity="MEDIUM",
    ),
    vuln(
        id="ratelimit-otp",
        lang="javascript", framework="express", file="otp.js", line=2,
        code=(
            "app.post('/verify-otp', (req, res) => {\n"
            "  res.json({ ok: req.body.code === session.otp });\n"
            "});\n"
        ),
        category="MISSING_RATE_LIMIT",
        description="OTP verification has no attempt limit.",
        exploit="A 6-digit code is brute-forced in minutes without throttling or attempt caps.",
        fix="Cap attempts per code, expire after N failures, and rate-limit the route.",
        patch="+const otpLimiter = rateLimit({ windowMs: 600000, max: 5 });\n-app.post('/verify-otp', (req, res) => {\n+app.post('/verify-otp', otpLimiter, (req, res) => {",
        severity="MEDIUM",
    ),
    vuln(
        id="ratelimit-expensive-ai",
        lang="python", framework="fastapi", file="generate.py", line=2,
        code=(
            "@app.post('/generate')\n"
            "def generate(prompt: str):\n"
            "    return llm.complete(prompt)  # paid model call, unauthenticated, unthrottled\n"
        ),
        category="MISSING_RATE_LIMIT",
        description="Expensive paid LLM endpoint is unauthenticated and unthrottled.",
        exploit="An attacker loops requests to run up cost and exhaust quota (denial of wallet).",
        fix="Require auth and apply per-key rate and budget limits.",
        patch="+@limiter.limit('20/minute')\n @app.post('/generate')\n-def generate(prompt: str):\n+def generate(prompt: str, key=Depends(api_key)):\n     return llm.complete(prompt)",
        severity="MEDIUM",
        fail_dims=("auth",),
    ),
    # ---- unsafe admin route ----
    vuln(
        id="admin-debug-open",
        lang="python", framework="flask", file="admin.py", line=2,
        code=(
            "@app.get('/admin/exec')\n"
            "def admin_exec(cmd):\n"
            "    return subprocess.check_output(cmd, shell=True)\n"
        ),
        category="UNSAFE_ADMIN_ROUTE",
        description="Admin route runs shell commands with no authentication or authorization.",
        exploit="Anyone hitting /admin/exec?cmd=... gets remote code execution.",
        fix="Remove the route; if essential, require admin auth and never pass to a shell.",
        patch="-@app.get('/admin/exec')\n-def admin_exec(cmd):\n-    return subprocess.check_output(cmd, shell=True)\n+# removed: arbitrary command endpoint is never acceptable",
        extra_findings=None,
        fail_dims=("auth", "dangerous_exec"),
    ),
    vuln(
        id="admin-role-from-client",
        lang="javascript", framework="express", file="admin.js", line=2,
        code=(
            "app.post('/admin/delete-user', (req, res) => {\n"
            "  if (req.body.role === 'admin') db.deleteUser(req.body.id);\n"
            "});\n"
        ),
        category="UNSAFE_ADMIN_ROUTE",
        description="Privileged action authorized by a client-supplied 'role' field.",
        exploit="Any client posts role=admin to delete arbitrary users.",
        fix="Derive role from the authenticated server-side session, never from the request body.",
        patch="-  if (req.body.role === 'admin') db.deleteUser(req.body.id);\n+  if (req.session.user?.role === 'admin') db.deleteUser(req.body.id);\n+  else res.status(403).end();",
        fail_dims=("auth",),
    ),
    vuln(
        id="admin-actuator-exposed",
        lang="yaml", framework="spring", file="application.yml", line=2,
        code=(
            "management:\n"
            "  endpoints:\n"
            "    web:\n"
            "      exposure:\n"
            "        include: '*'   # all actuator endpoints public\n"
        ),
        category="UNSAFE_ADMIN_ROUTE",
        description="All Spring Boot actuator endpoints exposed publicly, including /env and /heapdump.",
        exploit="/actuator/env leaks secrets; /actuator/heapdump dumps memory to any caller.",
        fix="Expose only health/info and secure the rest behind authentication.",
        patch="-        include: '*'\n+        include: 'health,info'",
        severity="HIGH",
        fail_dims=("environment_exposure",),
    ),
    # ---- unsafe file upload ----
    vuln(
        id="upload-no-validation",
        lang="python", framework="flask", file="upload.py", line=2,
        code=(
            "@app.post('/upload')\n"
            "def upload():\n"
            "    f = request.files['file']\n"
            "    f.save('/var/www/uploads/' + f.filename)\n"
        ),
        category="UNSAFE_FILE_UPLOAD",
        description="Upload saved with attacker-controlled filename, no type/extension checks, into a web-served dir.",
        exploit="Uploading shell.php (or ../../ path traversal) yields web-root code execution.",
        fix="Validate content type, generate a random server-side name, store outside the web root.",
        patch="-    f.save('/var/www/uploads/' + f.filename)\n+    if f.mimetype not in ALLOWED: abort(415)\n+    name = secrets.token_hex(16) + ext_for(f.mimetype)\n+    f.save(os.path.join(PRIVATE_UPLOAD_DIR, name))",
    ),
    vuln(
        id="upload-svg-stored-xss",
        lang="javascript", framework="express", file="avatar.js", line=2,
        code=(
            "app.post('/avatar', upload.single('img'), (req, res) => {\n"
            "  fs.writeFileSync(`public/avatars/${req.file.originalname}`, req.file.buffer);\n"
            "});\n"
        ),
        category="UNSAFE_FILE_UPLOAD",
        description="Avatar upload accepts any type and original name; SVGs serve as stored XSS.",
        exploit="A crafted .svg with embedded script executes when other users view the avatar.",
        fix="Restrict to raster image types, re-encode, and randomize the stored filename.",
        patch="-  fs.writeFileSync(`public/avatars/${req.file.originalname}`, req.file.buffer);\n+  if (!['image/png','image/jpeg'].includes(req.file.mimetype)) return res.status(415).end();\n+  const buf = await sharp(req.file.buffer).png().toBuffer();\n+  fs.writeFileSync(`public/avatars/${crypto.randomUUID()}.png`, buf);",
        severity="HIGH",
    ),
    vuln(
        id="upload-zip-slip",
        lang="python", framework="none", file="extract.py", line=2,
        code=(
            "def extract(zf, dest):\n"
            "    zipfile.ZipFile(zf).extractall(dest)  # trusts archive paths\n"
        ),
        category="UNSAFE_FILE_UPLOAD",
        description="Zip extraction trusts entry paths (Zip Slip path traversal).",
        exploit="An archive entry named ../../etc/cron.d/x writes outside dest to a sensitive location.",
        fix="Reject or sanitize entries that resolve outside the destination directory.",
        patch="-    zipfile.ZipFile(zf).extractall(dest)\n+    z = zipfile.ZipFile(zf)\n+    for m in z.namelist():\n+        target = os.path.realpath(os.path.join(dest, m))\n+        if not target.startswith(os.path.realpath(dest) + os.sep): raise ValueError('zip slip')\n+    z.extractall(dest)",
        severity="HIGH",
    ),
]
