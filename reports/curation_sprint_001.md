# Curation Sprint 001 — Audit Report

**Goal:** add the first real batch of curated `curated_ingested` training examples
to the Nullsec-1 corpus, entirely through the staged → review → approve pipeline.
Target: +50 approved. **Result: +52 approved, 0 rejected.**

No fake volume was generated. Every example is a real, documented vulnerability
pattern carried through `training/curate_ingested.py` and validated by
`training/validate_corpus.py` (real secure patch, complete `checks_performed`,
Safety Layer consistency) before it became `curated_ingested`.

## Counts

| Stage | Count |
|---|---|
| Staged (raw imported) | 52 |
| Pending review (after sprint) | 0 |
| Approved (`curated_ingested`) | 52 |
| Rejected | 0 |
| Still pending | 0 |

All 52 candidates passed approval validation on the first pass because each was
authored complete (vulnerable code, secure patch, full checks, exploit scenario,
references) before staging. The pipeline still enforced the gate on every one —
an incomplete candidate would have been blocked, as proven by the workflow tests.

## Source types used

| Source type | Count |
|---|---|
| OWASP patterns (Web/LLM/Smart-Contract Top 10) | 21 |
| Semgrep rule-backed patterns | 17 |
| Real vibecoded failure cases (Nullsec scanner-style) | 10 |
| CVE-anchored | 4 |

### CVEs cited (verified)
- **CVE-2021-44228** — Log4Shell, Apache Log4j2 JNDI RCE (CWE-502). Vulnerable 2.0-beta9–2.14.1; fixed 2.15.0+ (patch pins 2.17.1).
- **CVE-2017-5638** — Apache Struts2 Jakarta Multipart OGNL RCE (CWE-20). Fixed in 2.3.32 / 2.5.10.1.
- **CVE-2024-3094** — XZ Utils supply-chain backdoor (CWE-506), 5.6.0/5.6.1.
- **CVE-2014-0160** — Heartbleed, OpenSSL out-of-bounds read (CWE-125), fixed 1.0.1g.

Reference identifiers (CVE/CWE/OWASP/Semgrep rule/SWC) are attached per example in
the `references` field of each `corpus/ingested/*.jsonl` record. Where a specific
CVE could not be stated accurately, the `cve` field is `null` and the case is
anchored by stable CWE/OWASP/rule references instead — no CVE numbers or commit
hashes were invented.

## Categories added (approved this sprint)

| Category | Added |
|---|---|
| SQL_INJECTION | 3 |
| COMMAND_INJECTION | 3 |
| DANGEROUS_SHELL_COMMAND | 4 |
| XSS | 4 |
| SSRF | 4 |
| UNSAFE_FILE_UPLOAD | 3 |
| BROKEN_AUTH | 3 |
| EXPOSED_SECRET | 3 |
| ENVIRONMENT_EXPOSURE | 3 |
| MISSING_RATE_LIMIT | 3 |
| UNSAFE_ADMIN_ROUTE | 3 |
| DEPENDENCY_RISK | 4 |
| PROMPT_INJECTION | 3 |
| MCP_TOOL_ABUSE | 3 |
| WALLET_TRANSACTION_RISK | 3 |
| SMART_CONTRACT_RISK | 3 |

All 16 taxonomy categories received new curated examples.

## Release threshold progress

| Metric | Before | After | Target |
|---|---|---|---|
| Curated examples | 63 | 115 | 500 |
| Per-category minimum (min across cats) | 3 | 6 | 25 |
| Eval split size | 12 | 23 | 100 |
| Safety Layer consistency | 100% | 100% | 100% |
| Threshold result | BLOCKED | **BLOCKED** | PASS |

The gate was **not** weakened and still blocks (`release_threshold.py
--include-ingested` exits non-zero at 115/500). This is the intended outcome:
the sprint proves the corpus can grow with real, reviewed, source-backed data
without faking the gate. ~385 more curated examples (and ≥25/category, ≥100 eval)
remain before a real Nullsec-1.0 training run is justified.

## Verification commands (all pass)

```
python training/validate_corpus.py --include-ingested      # 115/115 accepted, PASS
python training/dataset_stats.py --include-ingested        # 115 total, 100% consistency
python training/release_threshold.py --include-ingested    # BLOCKED (exit 1), gate intact
python scripts/validate_claims.py --check                  # HONESTY CHECK PASSED
pytest -q                                                  # 40 passed
```

## Provenance & honesty notes

- Approved examples carry `provenance: curated_ingested` and only count toward the
  curated thresholds with `--include-ingested`. Without that flag the curated count
  remains the 63 hand-authored examples.
- The staged raw inputs live under `data/raw/` (git-ignored, not training-eligible);
  the approved curated records live in `corpus/ingested/*.jsonl` (committed).
- Re-running an import is idempotent (candidate ids are content-hashed), so the
  sprint can be reproduced without creating duplicates.
