"""Injection examples: SQL injection, XSS, SSRF."""
from corpus.builder import vuln

EXAMPLES = [
    # ---- SQL injection ----
    vuln(
        id="sqli-fstring",
        lang="python", framework="flask", file="users.py", line=2,
        code=(
            "def find(uid):\n"
            "    cur.execute(f\"SELECT * FROM users WHERE id = '{uid}'\")\n"
            "    return cur.fetchone()\n"
        ),
        category="SQL_INJECTION",
        description="User id interpolated directly into SQL via f-string.",
        exploit="uid=\"' OR '1'='1\" returns all rows; \"'; DROP TABLE users;--\" destroys data.",
        fix="Use a parameterized query.",
        patch="-    cur.execute(f\"SELECT * FROM users WHERE id = '{uid}'\")\n+    cur.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))",
    ),
    vuln(
        id="sqli-node-concat",
        lang="javascript", framework="express", file="search.js", line=2,
        code=(
            "app.get('/search', (req, res) => {\n"
            "  const q = 'SELECT * FROM items WHERE name LIKE \\'%' + req.query.q + '%\\'';\n"
            "  db.query(q, (e, rows) => res.json(rows));\n"
            "});\n"
        ),
        category="SQL_INJECTION",
        description="Search term concatenated into SQL string.",
        exploit="q=%' UNION SELECT password FROM users-- exfiltrates credentials.",
        fix="Use placeholders and pass the term as a bound parameter.",
        patch="-  const q = 'SELECT * FROM items WHERE name LIKE \\'%' + req.query.q + '%\\'';\n-  db.query(q, (e, rows) => res.json(rows));\n+  db.query('SELECT * FROM items WHERE name LIKE ?', ['%' + req.query.q + '%'], (e, rows) => res.json(rows));",
    ),
    vuln(
        id="sqli-orm-raw-format",
        lang="python", framework="django", file="reports.py", line=2,
        code=(
            "def by_status(status):\n"
            "    return Order.objects.raw('SELECT * FROM orders WHERE status = %s' % status)\n"
        ),
        category="SQL_INJECTION",
        description="Python % formatting used instead of the ORM's parameter binding in raw().",
        exploit="status carries SQL that runs verbatim, e.g. a stacked subquery returning other tables.",
        fix="Pass parameters as the second argument to raw() so the driver binds them.",
        patch="-    return Order.objects.raw('SELECT * FROM orders WHERE status = %s' % status)\n+    return Order.objects.raw('SELECT * FROM orders WHERE status = %s', [status])",
    ),
    # ---- XSS ----
    vuln(
        id="xss-react-dangerous",
        lang="javascript", framework="react", file="Comment.jsx", line=2,
        code=(
            "function Comment({ text }) {\n"
            "  return <div dangerouslySetInnerHTML={{ __html: text }} />;\n"
            "}\n"
        ),
        category="XSS",
        description="User comment rendered via dangerouslySetInnerHTML without sanitization.",
        exploit="A comment containing <img src=x onerror=fetch('/steal?c='+document.cookie)> runs in every viewer's session.",
        fix="Render as text, or sanitize with a vetted allowlist sanitizer first.",
        patch="-  return <div dangerouslySetInnerHTML={{ __html: text }} />;\n+  return <div>{text}</div>;",
    ),
    vuln(
        id="xss-express-reflected",
        lang="javascript", framework="express", file="hello.js", line=2,
        code=(
            "app.get('/hello', (req, res) => {\n"
            "  res.send('<h1>Hello ' + req.query.name + '</h1>');\n"
            "});\n"
        ),
        category="XSS",
        description="Reflected XSS: query parameter echoed into HTML response unescaped.",
        exploit="?name=<script>...</script> executes in the victim's browser when they open a crafted link.",
        fix="HTML-escape user input before interpolation, or use a templating engine with auto-escaping.",
        patch="+const escape = require('escape-html');\n-  res.send('<h1>Hello ' + req.query.name + '</h1>');\n+  res.send('<h1>Hello ' + escape(req.query.name) + '</h1>');",
    ),
    vuln(
        id="xss-innerhtml",
        lang="javascript", framework="vanilla", file="profile.js", line=2,
        code=(
            "const bio = new URLSearchParams(location.search).get('bio');\n"
            "document.getElementById('bio').innerHTML = bio;\n"
        ),
        category="XSS",
        description="DOM XSS: URL parameter assigned to innerHTML.",
        exploit="A crafted ?bio= payload injects an event-handler element that runs attacker JS.",
        fix="Assign to textContent, not innerHTML.",
        patch="-document.getElementById('bio').innerHTML = bio;\n+document.getElementById('bio').textContent = bio;",
    ),
    # ---- SSRF ----
    vuln(
        id="ssrf-requests-get",
        lang="python", framework="flask", file="fetch.py", line=2,
        code=(
            "@app.post('/fetch')\n"
            "def fetch():\n"
            "    url = request.json['url']\n"
            "    return requests.get(url).text  # arbitrary URL\n"
        ),
        category="SSRF",
        description="Server fetches an arbitrary user-supplied URL.",
        exploit="url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ leaks cloud credentials.",
        fix="Validate against an allowlist of hosts/schemes and block link-local/internal ranges.",
        patch="+from .net import is_allowed_url\n     url = request.json['url']\n+    if not is_allowed_url(url):\n+        abort(400)\n     return requests.get(url).text",
        severity="HIGH",
    ),
    vuln(
        id="ssrf-node-proxy",
        lang="javascript", framework="express", file="proxy.js", line=2,
        code=(
            "app.get('/img', async (req, res) => {\n"
            "  const r = await fetch(req.query.src);\n"
            "  r.body.pipe(res);\n"
            "});\n"
        ),
        category="SSRF",
        description="Image proxy fetches any URL the client supplies.",
        exploit="src=http://localhost:6379/ or an internal admin URL reaches services not exposed publicly.",
        fix="Resolve the host, reject private/loopback IPs, and restrict to http(s) on public addresses.",
        patch="+const { assertPublicHttpUrl } = require('./net');\n-  const r = await fetch(req.query.src);\n+  await assertPublicHttpUrl(req.query.src);\n+  const r = await fetch(req.query.src);",
        severity="HIGH",
    ),
    vuln(
        id="ssrf-webhook",
        lang="python", framework="fastapi", file="webhooks.py", line=3,
        code=(
            "@app.post('/webhooks/test')\n"
            "def test_webhook(target: str):\n"
            "    # delivers a test payload to a user-configured endpoint\n"
            "    return httpx.post(target, json={'ping': True}).status_code\n"
        ),
        category="SSRF",
        description="Webhook tester posts to an unvalidated user-controlled target.",
        exploit="target=http://metadata.internal/ pivots into internal services from the server's network position.",
        fix="Allowlist destination hosts and block internal address ranges before the request.",
        patch="+    if not is_public_host(target):\n+        raise HTTPException(400, 'target not allowed')\n     return httpx.post(target, json={'ping': True}).status_code",
        severity="HIGH",
    ),
]
