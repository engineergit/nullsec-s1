"""Dependency-risk examples and clean/secure counterparts."""
from corpus.builder import secure, vuln

EXAMPLES = [
    # ---- dependency risk ----
    vuln(
        id="dep-unpinned-latest",
        lang="json", framework="npm", file="package.json", line=3,
        code=(
            "{\n"
            "  \"dependencies\": {\n"
            "    \"left-pad\": \"*\",\n"
            "    \"event-stream\": \"latest\"\n"
            "  }\n"
            "}\n"
        ),
        category="DEPENDENCY_RISK",
        description="Dependencies pinned to '*'/'latest', pulling arbitrary future (possibly malicious) versions.",
        exploit="A compromised release (as happened to event-stream) is auto-installed on the next build.",
        fix="Pin exact versions and commit a lockfile; update deliberately with review.",
        patch="-    \"left-pad\": \"*\",\n-    \"event-stream\": \"latest\"\n+    \"left-pad\": \"1.3.0\",\n+    \"event-stream\": \"4.0.1\"",
        severity="MEDIUM",
    ),
    vuln(
        id="dep-known-cve",
        lang="text", framework="pip", file="requirements.txt", line=1,
        code=(
            "requests==2.19.1\n"
            "PyYAML==3.13\n"
        ),
        category="DEPENDENCY_RISK",
        description="Pinned to versions with known CVEs (e.g. PyYAML 3.13 unsafe load CVE-2017-18342).",
        exploit="yaml.load on untrusted input enables arbitrary object construction / code execution.",
        fix="Upgrade to patched versions and audit with a vulnerability scanner in CI.",
        patch="-requests==2.19.1\n-PyYAML==3.13\n+requests==2.32.3\n+PyYAML==6.0.2",
        severity="MEDIUM",
    ),
    vuln(
        id="dep-typosquat",
        lang="text", framework="pip", file="requirements.txt", line=1,
        code=(
            "python-dateutil==2.8.2\n"
            "django==3.2  # typo of 'django'\n"
        ),
        category="DEPENDENCY_RISK",
        description="A typosquatted package name ('django') risks installing a malicious lookalike.",
        exploit="A squatter publishes 'django' with install-time code that runs during pip install.",
        fix="Correct the name, verify packages, and use a curated index/allowlist.",
        patch="-django==3.2\n+Django==3.2.25",
        severity="MEDIUM",
    ),
    # ---- clean / secure (production_ready True) ----
    secure(
        id="secure-parametrized-query",
        lang="python", framework="flask", file="users.py",
        code=(
            "def find(uid):\n"
            "    cur.execute('SELECT id, name FROM users WHERE id = %s', (uid,))\n"
            "    return cur.fetchone()\n"
        ),
        summary="Parameterized query; input bound by the driver. No injection surface.",
    ),
    secure(
        id="secure-authed-route",
        lang="python", framework="fastapi", file="routes.py",
        code=(
            "@app.get('/api/me/ssn')\n"
            "def my_ssn(user=Depends(current_user)):\n"
            "    return db.fetch_ssn(user.id)\n"
        ),
        summary="Endpoint requires an authenticated user and only returns the caller's own record.",
    ),
    secure(
        id="secure-env-secret",
        lang="python", framework="boto3", file="s3sync.py",
        code=(
            "import boto3, os\n"
            "client = boto3.client('s3')  # credentials from the instance role / env\n"
        ),
        summary="No hardcoded credentials; the SDK resolves them from the environment/instance role.",
        na_dims=("input_validation", "rate_limits"),
    ),
    secure(
        id="secure-execfile",
        lang="javascript", framework="node", file="convert.js",
        code=(
            "function convert(file) {\n"
            "  execFile('convert', [file, 'out.png'], cb); // no shell\n"
            "}\n"
        ),
        summary="Uses execFile with an argument vector; no shell interpolation, so no command injection.",
        na_dims=("rate_limits",),
    ),
    secure(
        id="secure-capped-transfer",
        lang="javascript", framework="solana-web3.js", file="pay.js",
        code=(
            "async function pay(to, lamports) {\n"
            "  if (lamports > MAX_LAMPORTS) throw new Error('cap');\n"
            "  if (!ALLOWED.has(to.toBase58())) throw new Error('recipient');\n"
            "  const tx = new Transaction().add(SystemProgram.transfer({ fromPubkey: wallet.publicKey, toPubkey: to, lamports }));\n"
            "  return sendAndConfirm(tx, [wallet]);\n"
            "}\n"
        ),
        summary="Transfer enforces a per-tx cap and a recipient allowlist before signing.",
        na_dims=("input_validation",),
    ),
]
