"""Environment / configuration exposure examples."""
from corpus.builder import vuln

EXAMPLES = [
    vuln(
        id="env-dotenv-in-public",
        lang="javascript", framework="vite", file="vite.config.js", line=3,
        code=(
            "export default defineConfig({\n"
            "  publicDir: '.',           // serves the project root, including .env\n"
            "  build: { outDir: 'dist' }\n"
            "});\n"
        ),
        category="ENVIRONMENT_EXPOSURE",
        description="Static server publicDir set to the project root, so .env is served to anyone.",
        exploit="GET /.env returns the file with database URLs, API keys, and signing secrets.",
        fix="Serve a dedicated public/ directory and keep .env outside any served path.",
        patch="-  publicDir: '.',\n+  publicDir: 'public',",
    ),
    vuln(
        id="env-secrets-in-frontend-bundle",
        lang="javascript", framework="next", file="next.config.js", line=2,
        code=(
            "module.exports = {\n"
            "  env: { DATABASE_URL: process.env.DATABASE_URL, STRIPE_SECRET: process.env.STRIPE_SECRET }\n"
            "};\n"
        ),
        category="ENVIRONMENT_EXPOSURE",
        description="Server secrets inlined into the client bundle via the public env config.",
        exploit="The secrets are compiled into the JS shipped to browsers; any visitor reads them in devtools.",
        fix="Keep server secrets server-side; only expose values intentionally prefixed for the client.",
        patch="-  env: { DATABASE_URL: process.env.DATABASE_URL, STRIPE_SECRET: process.env.STRIPE_SECRET }\n+  // secrets stay server-side; access them only in server code / API routes",
        severity="CRITICAL",
    ),
    vuln(
        id="env-debug-in-prod",
        lang="python", framework="flask", file="app.py", line=2,
        code=(
            "app = Flask(__name__)\n"
            "app.run(host='0.0.0.0', debug=True)  # production\n"
        ),
        category="ENVIRONMENT_EXPOSURE",
        description="Debug mode enabled in production exposes the Werkzeug console and config/stack traces.",
        exploit="An unhandled error exposes an interactive debugger (RCE) and leaks environment/config details.",
        fix="Disable debug in production and gate it behind an explicit, non-default env flag.",
        patch="-app.run(host='0.0.0.0', debug=True)\n+app.run(host='0.0.0.0', debug=os.environ.get('FLASK_DEBUG') == '1')",
    ),
]
