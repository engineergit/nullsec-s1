#!/usr/bin/env python3
"""nullsec1 — command-line interface.

  nullsec1 analyze ./app          # walk a directory, audit each source file
  nullsec1 analyze file.ts        # audit one file
  nullsec1 patch file.ts          # audit + print secure patches
  nullsec1 serve                  # launch the FastAPI server

Exit code is non-zero when any audited file is NOT production-ready, so the CLI
doubles as a CI gate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SOURCE_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".sol", ".go", ".rs", ".rb",
    ".java", ".php", ".sh", ".json", ".yaml", ".yml", ".env",
}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
_LANG = {".py": "python", ".js": "javascript", ".ts": "typescript", ".sol": "solidity"}


def _iter_files(target: Path):
    if target.is_file():
        yield target
        return
    for p in sorted(target.rglob("*")):
        if p.is_file() and p.suffix in SOURCE_EXTS:
            if not any(part in SKIP_DIRS for part in p.parts):
                yield p


def _engine():
    from nullsec.core.engine import NullsecPipeline, PipelineConfig

    return NullsecPipeline(PipelineConfig()).load()


def _print_verdict(path: Path, payload: dict, show_patches: bool) -> bool:
    safety = payload.get("_safety_layer", {})
    pr = safety.get("production_ready", payload.get("production_ready"))
    badge = "PASS" if pr else "BLOCK"
    print(f"\n[{badge}] {path}  risk={payload['risk_score']} severity={payload['severity']}")
    for f in payload.get("findings", []):
        print(f"  - {f['severity']:8} {f['category']:22} L{f.get('line','?')}: {f['description']}")
        if show_patches and f.get("secure_patch"):
            print("    patch:")
            for ln in f["secure_patch"].splitlines():
                print(f"      {ln}")
    if not pr and safety.get("blocking_reasons"):
        print(f"    blocked by: {', '.join(safety['blocking_reasons'][:3])}"
              + (" ..." if len(safety["blocking_reasons"]) > 3 else ""))
    return bool(pr)


def cmd_analyze(args, show_patches: bool = False) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"error: {target} not found", file=sys.stderr)
        return 2
    engine = _engine()
    all_ready = True
    results = []
    for fp in _iter_files(target):
        try:
            code = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if not code.strip():
            continue
        from nullsec.safety import VerdictParseError

        try:
            res = engine.analyze(fp.name, code, _LANG.get(fp.suffix, ""))
            payload = json.loads(engine.to_json(res))
        except VerdictParseError as e:
            print(f"\n[ERROR] {fp}: model output invalid ({e})", file=sys.stderr)
            all_ready = False
            continue
        ready = _print_verdict(fp, payload, show_patches)
        all_ready = all_ready and ready
        results.append(payload)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2))
    print(f"\n{'ALL PRODUCTION-READY' if all_ready else 'NOT PRODUCTION-READY'}")
    return 0 if all_ready else 1


def cmd_serve(args) -> int:
    import uvicorn

    uvicorn.run("serving.server:app", host=args.host, port=args.port, reload=False)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nullsec1")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="audit a file or directory")
    a.add_argument("target")
    a.add_argument("--json-out", default=None)
    a.set_defaults(func=lambda args: cmd_analyze(args, show_patches=False))

    pt = sub.add_parser("patch", help="audit and print secure patches")
    pt.add_argument("target")
    pt.add_argument("--json-out", default=None)
    pt.set_defaults(func=lambda args: cmd_analyze(args, show_patches=True))

    s = sub.add_parser("serve", help="launch the inference server")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(func=cmd_serve)
    return p


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
