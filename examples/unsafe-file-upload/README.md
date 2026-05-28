# Example — Unsafe file upload / path traversal (Flask)

**File:** [`upload.py`](upload.py) · **Category:** `UNSAFE_FILE_UPLOAD` · **Failing dimension:** `input_validation`

A Flask endpoint that saves an uploaded file using the **client-supplied
filename** directly, with no extension allowlist, no size cap, and no
content-type validation — and writes into a **web-served** directory.

## Why it is unsafe

- **Path traversal:** `f.filename` like `../../etc/cron.d/x` escapes `UPLOAD_DIR`.
- **Webshell upload:** a `.php`/`.jsp` file lands in a path the server executes.
- **No limits:** no size cap (DoS) and no MIME/extension checks.

## Expected category

`UNSAFE_FILE_UPLOAD` (default severity **HIGH**, CWE-434 / CWE-22). Maps to the
`input_validation` check dimension.

## Expected verdict (illustrative — not model output)

```jsonc
{
  "production_ready": false,        // Safety Layer: R2 (input_validation=fail) + R3 (HIGH) + R6
  "severity": "HIGH",
  "checks_performed": {
    "input_validation": { "status": "fail", "note": "client filename used unsanitized; no type/size checks" }
  },
  "findings": [
    { "category": "UNSAFE_FILE_UPLOAD", "severity": "HIGH", "file": "upload.py", "line": 20 }
  ]
}
```

## Exploit scenario

An attacker uploads `shell.php`; it is saved under a web-served directory and then
requested directly to execute arbitrary code. Alternatively, a `../`-laden
filename overwrites a sensitive file outside the upload directory.

## Secure patch direction

Generate a server-side filename, enforce an extension/content-type allowlist and a
size cap, and store uploads **outside** any executable web root.

```python
import uuid
from werkzeug.utils import secure_filename

ALLOWED = {".png", ".jpg", ".jpeg", ".pdf"}
MAX_BYTES = 5 * 1024 * 1024
STORAGE_DIR = "/srv/app-data/uploads"  # not web-served, not executable

@app.post("/upload")
def upload():
    f = request.files["file"]
    ext = os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in ALLOWED:
        return {"error": "unsupported type"}, 400
    f.seek(0, os.SEEK_END)
    if f.tell() > MAX_BYTES:
        return {"error": "too large"}, 413
    f.seek(0)
    name = f"{uuid.uuid4().hex}{ext}"            # server-controlled name
    f.save(os.path.join(STORAGE_DIR, name))
    return {"saved": name}
```

Serve uploads through a handler that sets a safe `Content-Type` and never executes
stored files.
