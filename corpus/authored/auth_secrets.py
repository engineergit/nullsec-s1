"""Authentication-bypass and exposed-secret examples."""
from corpus.builder import vuln

EXAMPLES = [
    vuln(
        id="auth-jwt-alg-none",
        lang="python", framework="flask", file="auth.py", line=6,
        code=(
            "import jwt\n"
            "def verify(token):\n"
            "    # accepts whatever algorithm the token header declares\n"
            "    data = jwt.decode(token, key, algorithms=['HS256', 'none'])\n"
            "    return data['user']\n"
        ),
        category="BROKEN_AUTH",
        description="JWT verification accepts the 'none' algorithm, allowing unsigned tokens.",
        exploit="Attacker crafts a token with alg=none and arbitrary claims; signature is never checked, so any user can be impersonated.",
        fix="Pin a single expected algorithm and reject 'none'.",
        patch="-    data = jwt.decode(token, key, algorithms=['HS256', 'none'])\n+    data = jwt.decode(token, key, algorithms=['HS256'])",
    ),
    vuln(
        id="auth-missing-decorator",
        lang="python", framework="fastapi", file="routes.py", line=3,
        code=(
            "@app.get('/api/users/{uid}/ssn')\n"
            "def get_ssn(uid: str):\n"
            "    return db.fetch_ssn(uid)  # no auth, no ownership check\n"
        ),
        category="BROKEN_AUTH",
        description="Sensitive endpoint exposes SSN with no authentication or ownership check.",
        exploit="Any unauthenticated caller enumerates uids and reads every user's SSN.",
        fix="Require an authenticated session and verify the caller owns the resource.",
        patch="+from .deps import current_user\n @app.get('/api/users/{uid}/ssn')\n-def get_ssn(uid: str):\n+def get_ssn(uid: str, user=Depends(current_user)):\n+    if user.id != uid:\n+        raise HTTPException(403)\n     return db.fetch_ssn(uid)",
        fail_dims=("permissions",),
    ),
    vuln(
        id="auth-timing-token-compare",
        lang="javascript", framework="express", file="middleware.js", line=2,
        code=(
            "function checkApiKey(req, res, next) {\n"
            "  if (req.headers['x-api-key'] === process.env.API_KEY) return next();\n"
            "  res.status(401).end();\n"
            "}\n"
        ),
        category="BROKEN_AUTH",
        description="API key compared with == which short-circuits and leaks length/prefix via timing.",
        exploit="Attacker measures response timing to recover the key byte-by-byte.",
        fix="Use a constant-time comparison.",
        patch="-  if (req.headers['x-api-key'] === process.env.API_KEY) return next();\n+  const a = Buffer.from(req.headers['x-api-key'] || '');\n+  const b = Buffer.from(process.env.API_KEY);\n+  if (a.length === b.length && crypto.timingSafeEqual(a, b)) return next();",
        severity="HIGH",
    ),
    vuln(
        id="secret-hardcoded-aws",
        lang="python", framework="boto3", file="s3sync.py", line=3,
        code=(
            "import boto3\n"
            "client = boto3.client('s3',\n"
            "    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',\n"
            "    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')\n"
        ),
        category="EXPOSED_SECRET",
        description="Hardcoded long-lived AWS credentials in source.",
        exploit="Anyone with repo access (or a leaked build) gains the AWS account's S3 permissions.",
        fix="Load credentials from the environment or an instance role; rotate the exposed key.",
        patch="-client = boto3.client('s3',\n-    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',\n-    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')\n+client = boto3.client('s3')  # credentials from env / instance role",
        fail_dims=("environment_exposure",),
    ),
    vuln(
        id="secret-client-side-key",
        lang="javascript", framework="react", file="api.js", line=1,
        code=(
            "const STRIPE_SECRET = 'STRIPE_SECRET_KEY_PLACEHOLDER';\n"
            "export const charge = (amt) =>\n"
            "  fetch('https://api.stripe.com/v1/charges', { headers: { Authorization: `Bearer ${STRIPE_SECRET}` }, ... });\n"
        ),
        category="EXPOSED_SECRET",
        description="Stripe secret key embedded in client-side bundle shipped to the browser.",
        exploit="Any visitor reads the bundle and uses the live secret key to issue charges/refunds.",
        fix="Never ship secret keys to the client; call Stripe from a server endpoint.",
        patch="-const STRIPE_SECRET = 'sk_live_...';\n-export const charge = (amt) => fetch('https://api.stripe.com/v1/charges', ...)\n+export const charge = (amt) => fetch('/api/charge', { method: 'POST', body: JSON.stringify({ amt }) });",
        fail_dims=("environment_exposure",),
    ),
    vuln(
        id="secret-private-key-in-config",
        lang="python", framework="none", file="config.py", line=1,
        code=(
            "SOLANA_KEYPAIR = [12,93,201,...]  # full 64-byte secret key inline\n"
            "RPC = 'https://api.mainnet-beta.solana.com'\n"
        ),
        category="EXPOSED_SECRET",
        description="Solana wallet secret key committed inline in config.",
        exploit="Repo access exposes the wallet's private key; funds can be drained immediately.",
        fix="Load the keypair from a secret manager / env file outside version control; rotate the wallet.",
        patch="-SOLANA_KEYPAIR = [12,93,201,...]\n+import os, json\n+SOLANA_KEYPAIR = json.loads(os.environ['SOLANA_KEYPAIR'])",
        fail_dims=("environment_exposure",),
    ),
]
