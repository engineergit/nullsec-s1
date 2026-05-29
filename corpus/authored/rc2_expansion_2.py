"""RC2 / v1.1 curated expansion, batch 2 — hand-authored examples.

A second genuinely-distinct batch, broadening category coverage (notably XSS,
oracle/NFT-approval contract risk, CI/Docker supply-chain) toward the v1.1 target.
All hand_authored, all Safety-Layer-consistent, real patches — no padding.
"""
from corpus.builder import vuln

EXAMPLES = [
    # ---- XSS --------------------------------------------------------------
    vuln(
        id="rc2-xss-stored-comment",
        lang="javascript", framework="react", file="Comment.jsx", line=1,
        code=(
            "export function Comment({ body }) {\n"
            "  return <div dangerouslySetInnerHTML={{ __html: body }} />;  // stored comment, unsanitized\n"
            "}\n"
        ),
        category="XSS",
        description="Stored user comment rendered as raw HTML, enabling persistent XSS.",
        exploit="A comment containing <img src=x onerror=fetch('/steal?c='+document.cookie)> runs for every viewer.",
        fix="Render as text, or sanitize with a vetted sanitizer before dangerouslySetInnerHTML.",
        patch="-  return <div dangerouslySetInnerHTML={{ __html: body }} />;\n+  return <div>{body}</div>;  // React escapes text by default",
    ),
    vuln(
        id="rc2-xss-angular-bypass",
        lang="typescript", framework="angular", file="view.ts", line=2,
        code=(
            "this.html = this.sanitizer.bypassSecurityTrustHtml(userContent);\n"
        ),
        category="XSS",
        description="Angular's built-in sanitization is explicitly bypassed for user content.",
        exploit="userContent with a <script>/onerror payload executes because trust was forced.",
        fix="Do not bypass the sanitizer for untrusted input; bind it as text or sanitize.",
        patch="-this.html = this.sanitizer.bypassSecurityTrustHtml(userContent);\n+this.text = userContent;  // bind with {{ text }} so Angular escapes it",
    ),
    vuln(
        id="rc2-xss-ejs-unescaped",
        lang="javascript", framework="express", file="profile.ejs", line=1,
        code=(
            "<h1>Welcome <%- user.displayName %></h1>\n"
        ),
        category="XSS",
        description="EJS <%- %> outputs unescaped HTML for a user-controlled display name.",
        exploit="A display name of <script>...</script> executes in every viewer's browser.",
        fix="Use the escaping tag <%= %> for untrusted values.",
        patch="-<h1>Welcome <%- user.displayName %></h1>\n+<h1>Welcome <%= user.displayName %></h1>",
    ),
    vuln(
        id="rc2-xss-jquery-html",
        lang="javascript", framework="jquery", file="search.js", line=1,
        code=(
            "$('#results').html('Results for ' + location.search.slice(1));\n"
        ),
        category="XSS",
        description="DOM XSS: query string written into the DOM via .html().",
        exploit="?<img src=x onerror=alert(document.domain)> executes from a crafted link.",
        fix="Use .text() for untrusted content.",
        patch="-$('#results').html('Results for ' + location.search.slice(1));\n+$('#results').text('Results for ' + new URLSearchParams(location.search).get('q'));",
    ),
    # ---- SSRF -------------------------------------------------------------
    vuln(
        id="rc2-ssrf-avatar-import",
        lang="javascript", framework="node", file="avatar.js", line=2,
        code=(
            "app.post('/avatar/import', async (req, res) => {\n"
            "  const r = await fetch(req.body.imageUrl);  // no host validation\n"
            "  res.type('png').send(Buffer.from(await r.arrayBuffer()));\n"
            "});\n"
        ),
        category="SSRF",
        description="Avatar import fetches an arbitrary user URL server-side.",
        exploit="imageUrl=http://169.254.169.254/latest/meta-data/ exfiltrates cloud metadata.",
        fix="Allowlist schemes/hosts and block private/link-local ranges before fetching.",
        patch="+  if (!isPublicHttpUrl(req.body.imageUrl)) return res.status(400).end();\n   const r = await fetch(req.body.imageUrl);",
        severity="HIGH",
    ),
    # ---- SQL injection ----------------------------------------------------
    vuln(
        id="rc2-sqli-knex-raw",
        lang="javascript", framework="node", file="search.js", line=1,
        code=(
            "const rows = await knex.raw(`SELECT * FROM products WHERE name LIKE '%${q}%'`);\n"
        ),
        category="SQL_INJECTION",
        description="knex.raw with a template literal interpolates user input into SQL.",
        exploit="q=%' UNION SELECT password FROM users-- exfiltrates credentials.",
        fix="Use parameter bindings instead of string interpolation.",
        patch="-const rows = await knex.raw(`SELECT * FROM products WHERE name LIKE '%${q}%'`);\n+const rows = await knex.raw('SELECT * FROM products WHERE name LIKE ?', [`%${q}%`]);",
    ),
    vuln(
        id="rc2-sqli-go-sprintf",
        lang="go", framework="net/http", file="user.go", line=2,
        code=(
            "q := fmt.Sprintf(\"SELECT * FROM users WHERE email = '%s'\", r.URL.Query().Get(\"email\"))\n"
            "rows, _ := db.Query(q)\n"
        ),
        category="SQL_INJECTION",
        description="Query built with fmt.Sprintf from a request parameter.",
        exploit="email=' OR '1'='1 returns all users; stacked queries may modify data.",
        fix="Use parameterized queries with placeholders.",
        patch="-q := fmt.Sprintf(\"SELECT * FROM users WHERE email = '%s'\", r.URL.Query().Get(\"email\"))\n-rows, _ := db.Query(q)\n+rows, _ := db.Query(\"SELECT * FROM users WHERE email = $1\", r.URL.Query().Get(\"email\"))",
    ),
    # ---- Command injection ------------------------------------------------
    vuln(
        id="rc2-cmdi-ruby-interp",
        lang="ruby", framework="rails", file="export.rb", line=1,
        code=(
            "system(\"pg_dump #{params[:db]} > /tmp/out.sql\")\n"
        ),
        category="COMMAND_INJECTION",
        description="Shell command built by interpolating a request parameter.",
        exploit="db='x; rm -rf /' injects a second command into the shell.",
        fix="Pass arguments as an array so no shell parsing occurs.",
        patch="-system(\"pg_dump #{params[:db]} > /tmp/out.sql\")\n+system('pg_dump', params[:db], out: '/tmp/out.sql')",
    ),
    # ---- Exposed secret ---------------------------------------------------
    vuln(
        id="rc2-secret-gcp-sa-json",
        lang="json", framework="none", file="service-account.json", line=1,
        code=(
            "{\"type\":\"service_account\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nMIIEv...EXAMPLE\\n-----END PRIVATE KEY-----\",\"client_email\":\"svc@proj.iam.gserviceaccount.com\"}\n"
        ),
        category="EXPOSED_SECRET",
        description="GCP service-account private key committed to the repository.",
        exploit="Repo access grants the service account's cloud permissions (storage, compute, etc.).",
        fix="Remove from VCS, load via Workload Identity / secret manager, and rotate the key.",
        patch="-// service-account.json committed with private_key\n+// load credentials from GOOGLE_APPLICATION_CREDENTIALS / Workload Identity; file removed and key rotated",
        fail_dims=("environment_exposure",),
    ),
    # ---- Broken auth ------------------------------------------------------
    vuln(
        id="rc2-auth-firebase-callable-noctx",
        lang="javascript", framework="firebase", file="functions.js", line=2,
        code=(
            "exports.setBalance = functions.https.onCall((data) => {\n"
            "  return db.doc('accounts/'+data.uid).set({ balance: data.balance });  // ignores context.auth\n"
            "});\n"
        ),
        category="BROKEN_AUTH",
        description="Callable function never checks context.auth, so anyone can set any balance.",
        exploit="An unauthenticated client calls setBalance with any uid and amount.",
        fix="Require context.auth and authorize the specific operation.",
        patch="-exports.setBalance = functions.https.onCall((data) => {\n+exports.setBalance = functions.https.onCall((data, context) => {\n+  if (!context.auth || !context.auth.token.admin) throw new functions.https.HttpsError('permission-denied','no');\n   return db.doc('accounts/'+data.uid).set({ balance: data.balance });",
        severity="HIGH",
    ),
    vuln(
        id="rc2-auth-jwt-no-expiry-check",
        lang="python", framework="fastapi", file="deps.py", line=2,
        code=(
            "data = jwt.decode(token, KEY, algorithms=['HS256'], options={'verify_exp': False})\n"
            "return data['sub']\n"
        ),
        category="BROKEN_AUTH",
        description="JWT verification disables expiry checking, so old/stolen tokens never expire.",
        exploit="A leaked token from months ago still authenticates indefinitely.",
        fix="Verify expiry (the default); do not disable verify_exp.",
        patch="-data = jwt.decode(token, KEY, algorithms=['HS256'], options={'verify_exp': False})\n+data = jwt.decode(token, KEY, algorithms=['HS256'])  # verify_exp defaults to True",
        severity="HIGH",
    ),
    # ---- MCP tool abuse ---------------------------------------------------
    vuln(
        id="rc2-mcp-env-dump-tool",
        lang="python", framework="mcp", file="server.py", line=2,
        code=(
            "@mcp.tool()\n"
            "def get_config() -> dict:\n"
            "    return dict(os.environ)  # exposes every secret to the model/agent\n"
        ),
        category="MCP_TOOL_ABUSE",
        description="MCP tool returns the entire process environment to the model.",
        exploit="A prompt-injected agent calls get_config and exfiltrates API keys and tokens.",
        fix="Return only specific, non-secret config keys explicitly.",
        patch="-    return dict(os.environ)\n+    return {'region': os.environ.get('REGION'), 'tier': os.environ.get('TIER')}",
        severity="HIGH",
    ),
    # ---- Wallet / Web3 ----------------------------------------------------
    vuln(
        id="rc2-wallet-setapprovalforall",
        lang="typescript", framework="ethers", file="list.ts", line=1,
        code=(
            "await nft.setApprovalForAll(operatorFromQuery, true);  // operator from untrusted source\n"
        ),
        category="WALLET_TRANSACTION_RISK",
        description="setApprovalForAll grants an untrusted operator control over ALL of the user's NFTs.",
        exploit="A malicious 'list for sale' flow approves an operator that then transfers every NFT out.",
        fix="Approve a single tokenId to a known marketplace, or use a pinned operator allowlist.",
        patch="-await nft.setApprovalForAll(operatorFromQuery, true);\n+await nft.approve(KNOWN_MARKETPLACE, tokenId);",
    ),
    vuln(
        id="rc2-wallet-permit-no-deadline",
        lang="typescript", framework="ethers", file="permit.ts", line=1,
        code=(
            "const sig = await signPermit({ spender, value: MaxUint256, deadline: MaxUint256 });\n"
        ),
        category="WALLET_TRANSACTION_RISK",
        description="EIP-2612 permit signs an unlimited value with an effectively infinite deadline.",
        exploit="The signature is a standing, never-expiring unlimited allowance the spender can use anytime.",
        fix="Sign the exact value with a short deadline.",
        patch="-const sig = await signPermit({ spender, value: MaxUint256, deadline: MaxUint256 });\n+const sig = await signPermit({ spender, value: exactAmount, deadline: now + 3600 });",
    ),
    # ---- Smart contract ---------------------------------------------------
    vuln(
        id="rc2-sc-spot-price-oracle",
        lang="solidity", framework="foundry", file="Lend.sol", line=2,
        code=(
            "uint price = pair.getReserves1() * 1e18 / pair.getReserves0();  // spot price from a single DEX\n"
            "uint maxBorrow = collateral * price;\n"
        ),
        category="SMART_CONTRACT_RISK",
        description="Borrow limit uses an instantaneous single-pool spot price, manipulable via flash loans.",
        exploit="Attacker flash-swaps to skew the reserves, inflates collateral value, and over-borrows.",
        fix="Use a time-weighted average price (TWAP) or a robust oracle.",
        patch="-uint price = pair.getReserves1() * 1e18 / pair.getReserves0();\n+uint price = twapOracle.consult(token, 30 minutes);",
    ),
    vuln(
        id="rc2-sc-missing-nonreentrant",
        lang="solidity", framework="hardhat", file="Bank.sol", line=2,
        code=(
            "function withdraw() external {\n"
            "    uint amt = bal[msg.sender];\n"
            "    (bool ok,) = msg.sender.call{value: amt}('');\n"
            "    require(ok);\n"
            "    bal[msg.sender] = 0;  // state updated AFTER the external call\n"
            "}\n"
        ),
        category="SMART_CONTRACT_RISK",
        description="Checks-effects-interactions violated: balance zeroed after the external call (reentrancy).",
        exploit="A malicious receiver re-enters withdraw() before bal is zeroed and drains the contract.",
        fix="Zero the balance before the call, and add a nonReentrant guard.",
        patch="-    (bool ok,) = msg.sender.call{value: amt}('');\n-    require(ok);\n-    bal[msg.sender] = 0;\n+    bal[msg.sender] = 0;\n+    (bool ok,) = msg.sender.call{value: amt}('');\n+    require(ok);",
    ),
    # ---- Dependency / supply chain ---------------------------------------
    vuln(
        id="rc2-dep-gha-unpinned-master",
        lang="yaml", framework="github-actions", file="ci.yml", line=2,
        code=(
            "steps:\n"
            "  - uses: some-org/deploy-action@master  # mutable ref, not pinned to a SHA\n"
        ),
        category="DEPENDENCY_RISK",
        description="GitHub Action pinned to a mutable @master ref instead of a commit SHA.",
        exploit="A compromise of the action's master branch runs attacker code in your CI with its secrets.",
        fix="Pin third-party actions to a full commit SHA.",
        patch="-  - uses: some-org/deploy-action@master\n+  - uses: some-org/deploy-action@a1b2c3d4e5f6...  # pinned SHA",
        severity="MEDIUM",
    ),
    vuln(
        id="rc2-shell-dockerfile-curl-bash",
        lang="bash", framework="docker", file="Dockerfile", line=3,
        code=(
            "RUN curl -fsSL https://get.example.com/install.sh | bash\n"
        ),
        category="DANGEROUS_SHELL_COMMAND",
        description="Dockerfile pipes a remote script straight into bash at build time.",
        exploit="If the URL or its host is compromised, arbitrary code runs in the image build.",
        fix="Download to a file, verify a checksum, then execute.",
        patch="-RUN curl -fsSL https://get.example.com/install.sh | bash\n+RUN curl -fsSL https://get.example.com/install.sh -o /tmp/i.sh \\\n+ && echo \"<sha256>  /tmp/i.sh\" | sha256sum -c - \\\n+ && bash /tmp/i.sh",
    ),
    # ---- Environment exposure --------------------------------------------
    vuln(
        id="rc2-env-django-debug-allowhosts",
        lang="python", framework="django", file="settings.py", line=1,
        code=(
            "DEBUG = True\n"
            "ALLOWED_HOSTS = ['*']\n"
        ),
        category="ENVIRONMENT_EXPOSURE",
        description="Django runs with DEBUG=True and wildcard ALLOWED_HOSTS in production.",
        exploit="Unhandled errors render full tracebacks with settings/secrets to any visitor.",
        fix="Set DEBUG=False and restrict ALLOWED_HOSTS to your domains in production.",
        patch="-DEBUG = True\n-ALLOWED_HOSTS = ['*']\n+DEBUG = os.environ.get('DEBUG') == '1'\n+ALLOWED_HOSTS = ['app.example.com']",
    ),
    vuln(
        id="rc2-upload-content-type-trust",
        lang="python", framework="fastapi", file="upload.py", line=2,
        code=(
            "async def up(file: UploadFile):\n"
            "    assert file.content_type == 'image/png'  # client-set header, trivially spoofed\n"
            "    (UP / file.filename).write_bytes(await file.read())\n"
        ),
        category="UNSAFE_FILE_UPLOAD",
        description="Upload trusts the client-supplied Content-Type and writes the client filename.",
        exploit="Attacker sets Content-Type: image/png on shell.php and saves an executable file.",
        fix="Validate magic bytes, force a safe extension, and generate a server-side filename.",
        patch="-    assert file.content_type == 'image/png'\n-    (UP / file.filename).write_bytes(await file.read())\n+    data = await file.read()\n+    if not data.startswith(b'\\x89PNG\\r\\n'):\n+        raise HTTPException(400, 'not a png')\n+    (UP / f'{uuid4().hex}.png').write_bytes(data)",
        severity="HIGH",
    ),
]
