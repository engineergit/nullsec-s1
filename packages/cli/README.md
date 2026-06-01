# Nullsec S1 CLI

Run a Nullsec S1 security scan from any local project:

```bash
npx @s1-clm/s1 scan
```

Default backend:

```text
https://s1.trynullsec.com/api
```

Use a local backend:

```bash
NULLSEC_API_URL=http://localhost:8000 npx @s1-clm/s1 scan
```

Run without network access:

```bash
npx @s1-clm/s1 scan --no-network
```

No-network mode is heuristic-only. It does not use the Nullsec S1 model.

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
`*.pem`, `*.safetensors`, archives, images, and videos.
