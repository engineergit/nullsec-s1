#!/usr/bin/env python3
"""Validate which public claims the repo is currently allowed to make.

Claims are permitted only when the artifacts that make them true exist on disk
(a trained adapter, a real-model benchmark report, passing safety probes, a
release bundle). Run with no arguments for a status table:

    python scripts/validate_claims.py
    python scripts/validate_claims.py --adapter outputs/nullsec1-7b-qlora

With --check, scan README.md and RELEASE_SUMMARY.md for phrases that assert a
claim the artifacts do not yet support, and exit non-zero if any are found. This
is what lets CI enforce honesty automatically.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts._artifacts import ROOT, evaluate_claims, gather_state

# Phrases that, if present in public docs, assert a gated claim.
# Each maps to the claim name in evaluate_claims that must be allowed.
# Patterns are matched against lowercased text and are assertion-shaped on
# purpose: instructional text like "cut a release candidate" must not trip them,
# only a statement that Nullsec-1 *is* one.
CLAIM_PHRASES = {
    "trained model": [
        r"\bis a trained specialized security llm\b",
        r"\bnullsec-1\.0 is a trained\b",
        r"\bis now a trained model\b",
    ],
    "benchmarked": [
        r"\bhas been benchmarked\b",
        r"\bbenchmarks?\s+(show|shows|demonstrate|demonstrates|prove|proves|confirm|confirms)\b",
        r"\bachieves?\s+an?\s+f1\b",
    ],
    "evaluated with real model outputs": [
        r"\bevaluated with (the )?real model\b",
        r"\breal-model evaluation (shows|confirms|gives)\b",
    ],
    "release candidate": [
        r"\bis (a|the|now a) release candidate\b",
        r"\bnullsec-1\.0 release candidate is ready\b",
    ],
    "production-ready": [
        r"\bproduction[- ]ready model\b",
        r"\bmodel is production[- ]ready\b",
        r"\bready for production use\b",
    ],
}
# Superlatives are always flagged as unverifiable when stated as fact.
SUPERLATIVE_PHRASES = [
    r"\bthe first llm\b", r"\bfirst llm purpose-built\b",
    r"\bthe only llm\b", r"\bworld'?s first\b", r"\bbest[- ]in[- ]class\b",
]

DOCS_TO_SCAN = ["README.md", "RELEASE_SUMMARY.md", "releases/nullsec-1.0/RELEASE_SUMMARY.md"]


def status_table(claims) -> str:
    width = max(len(c.name) for c in claims)
    lines = ["", "Nullsec-1 — permitted public claims", "=" * 60]
    for c in claims:
        mark = "ALLOWED " if c.allowed else "FORBIDDEN"
        lines.append(f"[{mark}] {c.name.ljust(width)}  — {c.reason}")
    lines.append("")
    return "\n".join(lines)


def scan_docs(claims) -> list[str]:
    allowed = {c.name: c.allowed for c in claims}
    violations: list[str] = []
    for rel in DOCS_TO_SCAN:
        path = ROOT / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        low = text.lower()
        for claim_name, patterns in CLAIM_PHRASES.items():
            if allowed.get(claim_name):
                continue  # claim is substantiated; phrasing is fine
            for pat in patterns:
                if re.search(pat, low):
                    violations.append(
                        f"{rel}: asserts '{claim_name}' (matched /{pat}/) but artifacts do not support it"
                    )
        for pat in SUPERLATIVE_PHRASES:
            if re.search(pat, low):
                violations.append(
                    f"{rel}: superlative (/{pat}/) is unverifiable from artifacts — support it independently or remove it"
                )
    return violations


def main():
    ap = argparse.ArgumentParser(description="Validate public claims against real artifacts")
    ap.add_argument("--adapter", default=None, help="adapter path to check for a trained model")
    ap.add_argument("--report", default=None, help="benchmark report path (defaults to release/standard locations)")
    ap.add_argument("--check", action="store_true", help="scan docs and fail on unsubstantiated claims")
    args = ap.parse_args()

    st = gather_state(adapter=args.adapter, report=args.report)
    claims = evaluate_claims(st)
    print(status_table(claims))

    if args.check:
        violations = scan_docs(claims)
        if violations:
            print("HONESTY CHECK FAILED:\n  - " + "\n  - ".join(violations))
            sys.exit(1)
        print("HONESTY CHECK PASSED: public docs make no unsubstantiated claims.")
    sys.exit(0)


if __name__ == "__main__":
    main()
