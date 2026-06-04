# Nullsec S1 CLI

Nullsec S1 CLI and MCP call your configured Nullsec S1 API to review
AI-generated apps, agent tools, and MCP configs.

Run a scan from any local project:

```bash
npx @s1-clm/s1 scan
npx @s1-clm/s1 scan .
npx @s1-clm/s1 scan ./src/app.ts
echo 'app.get("/admin", (req,res)=>res.send("ok"))' | npx @s1-clm/s1 scan --stdin
npx @s1-clm/s1 health
npx @s1-clm/s1 scan-mcp ./examples/example-mcp-config.json
```

Default backend:

```text
https://s1.trynullsec.com/api
```

Override the API URL:

```bash
NULLSEC_S1_API_URL=http://localhost:8000 npx @s1-clm/s1 scan .
npx @s1-clm/s1 scan . --api http://localhost:8000
npx @s1-clm/s1 scan --path ./apps/web
npx @s1-clm/s1 scan --json
```

Run without network access:

```bash
npx @s1-clm/s1 scan --no-network
npx @s1-clm/s1 scan --local
```

No-network mode is heuristic-only. It does not use the Nullsec S1 model.

Exit codes:

- `0`: no high or critical issues
- `1`: high or critical issues found
- `2`: runtime, config, collection, or API error

## MCP Server

Start the stdio MCP server:

```bash
npx -p @s1-clm/s1 nullsec-s1-mcp
```

The published binary name is:

```text
nullsec-s1-mcp
```

It exposes:

- `nullsec_s1_scan_text`
- `nullsec_s1_scan_file`
- `nullsec_s1_scan_project`
- `nullsec_s1_scan_mcp_config`

The MCP server uses `NULLSEC_S1_API_URL` or defaults to `https://s1.trynullsec.com/api`.

Cursor MCP config:

```json
{
  "mcpServers": {
    "nullsec-s1": {
      "command": "nullsec-s1-mcp",
      "env": {
        "NULLSEC_S1_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

Claude Desktop MCP config:

```json
{
  "mcpServers": {
    "nullsec-s1": {
      "command": "nullsec-s1-mcp",
      "env": {
        "NULLSEC_S1_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

## Local Model Backend

The npm package includes the CLI and the Python FastAPI serving source needed to
run a local Nullsec S1 backend:

```bash
npx @s1-clm/s1 doctor
npx @s1-clm/s1 serve
```

Then scan through the local backend:

```bash
npx @s1-clm/s1 scan --local-model
```

The package does not embed multi-GB model weights. The backend loads the base
model and PEFT adapter from Hugging Face by default:

```text
NULLSEC_BASE_MODEL=Qwen/Qwen2.5-Coder-7B-Instruct
NULLSEC_ADAPTER_PATH=Trynullsec/nullsec-s1
```

For local model serving, install the Python GPU stack first:

```bash
python -m pip install -r runtime/requirements-train-cu121.txt
```

## Ignore Paths

Add a `.nullsecignore` file at the scan root:

```gitignore
benchmarks/
corpus/
training/
taxonomy/
*.egg-info/
```

You can also exclude paths for a single run:

```bash
npx @s1-clm/s1 scan --exclude corpus --exclude benchmarks
```

## Default Skips

The CLI skips common dependency, cache, virtualenv, build, generated, private,
binary, archive, model-weight, real `.env`, and private-key files by default.

Examples include `node_modules`, `.git`, `.next`, `.venv`, `site-packages`,
`__pycache__`, `.pytest_cache`, `dist`, `build`, real `.env` files,
`*.pem`, `*.safetensors`, archives, images, videos, and large lockfiles during
directory scans. Use `--include-lockfiles` to include lockfiles in a directory
scan, or pass a lockfile path directly.
