# upload.py
# VULNERABLE EXAMPLE — a Flask upload endpoint that trusts the client-supplied
# filename and writes it under a web-served directory, with no type or size
# checks. This enables path traversal and webshell upload.

import os
from flask import Flask, request

app = Flask(__name__)
UPLOAD_DIR = "/var/www/app/static/uploads"


@app.post("/upload")
def upload():
    f = request.files["file"]

    # DANGER: f.filename is attacker-controlled. "../../etc/cron.d/x" escapes the
    # upload dir; "shell.php" lands an executable file in a web-served path. No
    # extension allowlist, no size cap, no content-type validation.
    dest = os.path.join(UPLOAD_DIR, f.filename)
    f.save(dest)

    return {"saved": dest}
