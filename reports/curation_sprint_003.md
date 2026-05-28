# Curation Sprint 003 — Audit Report (AI-Generated App Failure Focus)

**Goal:** grow the corpus with real, source-backed `curated_ingested` examples
that make Nullsec-1 clearly different from generic AppSec — focused on
AI-generated / vibecoded apps, agent-built software, MCP tools, wallet flows, and
production-readiness failures. Target: +100 net approved, push minimum category
coverage from 11 toward 17+.

**Result: +97 net approved, 3 rejected. Minimum category coverage 11 → 17.**

Same raw-first loop as Sprint 002: skeletal findings staged (code + source +
references, no patch/exploit, dimensions `not_checked`), curated in a separate
review step, then approved only after validation + Safety Layer consistency.
Weak-provenance candidates were rejected with reasons.

## Pipeline counts (this sprint)

| Stage | Count |
|---|---|
| Staged (raw, skeletal) | 100 |
| Imported as pending candidates | 100 |
| Approved (`curated_ingested`) | 97 |
| Rejected (during execution) | 3 |
| Still pending | 0 |

> **Note on the packaged repo.** `data/raw/`, `data/ingest_candidates/`, and
> `data/ingest_rejected/` are transient, git-ignored local working state and were
> cleaned before packaging. The 3 rejection reasons are preserved in this report.
> In the packaged repo `python training/ingestion_stats.py` therefore reports
> **0 rejected** and **229 approved `curated_ingested`** examples (52 from Sprint
> 001 + 80 from Sprint 002 + 97 from Sprint 003).

## AI-generated / vibecoded focus

This sprint is deliberately weighted to the Nullsec-1 wedge. **50 of the 97
approved examples are `vibecoded_failure`** — real AI-generated app failure
patterns, including every scenario requested:

- AI-generated auth that checks login but not ownership (IDOR) — `VIBE-AUTH-101`
- delete-account route with no ownership/CSRF — `VIBE-AUTH-102`
- admin routes generated without role checks — `VIBE-ADMIN-101/103`
- frontend-exposed Supabase **service_role** key — `VIBE-SECRET-101`
- Next.js / Vercel env leakage (next.config `env`, health route dumping env) — `VIBE-ENV-101/102`
- generated Stripe webhook with no signature verification — `VIBE-RATE-101`
- file upload route with no MIME/type/size validation — `VIBE-UPLOAD-101/102`
- generated API route with no rate limit (LLM proxy, signup, contact) — `VIBE-RATE-102/103/104`
- MCP tool that reads arbitrary files — `VIBE-MCP-101`
- MCP tool with shell execution and no command allowlist — `VIBE-MCP-102`
- agent workflow spending from a wallet with no approval limit — `VIBE-WALLET-101`
- wallet approval UI hiding spender/amount risk — `VIBE-WALLET-102`
- contract wrapper trusting a user-supplied contract address — `VIBE-SC-101`
- prompt-injection path where user content controls tool execution — `VIBE-PI-101`
- debug route shipped to production — `VIBE-ADMIN-102`
- source maps / debug configs leaking internals — `VIBE-ENV-103`, `VIBE-ENV-104`

## Source type breakdown (97 approved this sprint)

| Source type | Count | Target |
|---|---|---|
| vibecoded_failure | 50 | ≥35 ✓ |
| OWASP / CWE / CVE anchored | 20 (19 OWASP + 1 CVE) | ≥20 ✓ |
| Semgrep / SARIF | 27 (16 Semgrep + 11 SARIF) | ≥15 ✓ |
| MCP / agent-tool abuse (MCP + prompt-injection) | 13 | ≥10 ✓ |
| Web3 / wallet / smart-contract | 12 | ≥10 ✓ |

(Categories overlap the source-mix buckets by design — e.g. MCP and Web3 cases
are also counted under their source types.)

All CVE references in the corpus remain verified; the one new CVE cited this
sprint, **CVE-2021-23337** (lodash `<4.17.21` command injection via template,
CWE-94, fixed 4.17.21), was verified before use. No CVE IDs, commit SHAs, or repo
paths were invented; where a stable CVE could not be cited, the case is anchored
by CWE / OWASP / Semgrep-rule / SWC references.

## Rejections (with reasons)

| Candidate | source_type | Reason |
|---|---|---|
| cve-some-SQL-injection-no-id | cve | no real CVE ID (provenance requires `CVE-YYYY-NNNN`) |
| semgrep-common-vulnerability | semgrep | no `rule_id`; vague reference "common vulnerability" |
| vibecoded_failure-known-issue | vibecoded_failure | no `case_id` and no AI-failure notes; vague reference "known issue" |

These exercised provenance enforcement across three source types and were
excluded from training.

## Category coverage — before / after

| Category | Before | Added | After |
|---|---|---|---|
| EXPOSED_SECRET | 11 | 6 | 17 |
| BROKEN_AUTH | 12 | 7 | 19 |
| MISSING_RATE_LIMIT | 11 | 7 | 18 |
| UNSAFE_ADMIN_ROUTE | 12 | 7 | 19 |
| SQL_INJECTION | 12 | 6 | 18 |
| XSS | 13 | 6 | 19 |
| SSRF | 13 | 6 | 19 |
| COMMAND_INJECTION | 13 | 5 | 18 |
| UNSAFE_FILE_UPLOAD | 11 | 6 | 17 |
| PROMPT_INJECTION | 11 | 6 | 17 |
| MCP_TOOL_ABUSE | 12 | 7 | 19 |
| DANGEROUS_SHELL_COMMAND | 11 | 6 | 17 |
| WALLET_TRANSACTION_RISK | 12 | 6 | 18 |
| SMART_CONTRACT_RISK | 12 | 6 | 18 |
| DEPENDENCY_RISK | 13 | 4 | 17 |
| ENVIRONMENT_EXPOSURE | 11 | 6 | 17 |

**Minimum category coverage: 11 → 17.** Category balance kept strict (every
category landed in the 17–19 band).

## Release threshold progress

| Metric | Before | After | Target |
|---|---|---|---|
| Curated examples | 195 | 292 | 500 |
| Per-category minimum | 11 | 17 | 25 |
| Eval split size | 39 | 58 | 100 |
| Safety Layer consistency | 100% | 100% | 100% |
| Threshold result | BLOCKED | **BLOCKED** | PASS |

**Remaining gap to 500: 208 curated examples** (and ≥25/category, ≥100 eval).
The threshold was **not** weakened and still blocks
(`release_threshold.py --include-ingested` exits non-zero).

## Verification commands (all pass)

```
pytest -q                                                  # 50 passed
python training/validate_corpus.py --include-ingested      # 292/292 accepted, PASS
python training/dataset_stats.py --include-ingested        # 292 total, 100% consistency
python training/release_threshold.py --include-ingested    # BLOCKED (exit 1)
python scripts/validate_claims.py --check                  # HONESTY CHECK PASSED (trained/benchmarked/RC still FORBIDDEN)
python training/ingestion_stats.py                         # packaged repo: 229 approved curated_ingested, 0 rejected (see note)
python -m benchmarks.safety_probes                         # passed
python benchmarks/safety_probes.py                         # passed
```

## Honesty notes

- Claim validator still **forbids** "trained model", "benchmarked", and "release
  candidate" — no adapter or benchmark report exists.
- **Safety Layer consistency remains 100%** (292/292).
- Approved examples carry `provenance: curated_ingested` and count toward curated
  thresholds only with `--include-ingested`.
- The sprint is reproducible: re-staging/importing is idempotent (content-hashed
  ids), and curation completions live in `training/sprint_data/sprint003_*` so a
  reviewer can inspect exactly what was added to each candidate.
- As in prior sprints, the curation completions were authored in code (so the run
  is reproducible and inspectable); the pipeline's enforcement is what is being
  demonstrated — raw candidates cannot pass, and weak-provenance candidates are
  rejected. Running the same loop on externally-sourced scanner/CVE feeds you did
  not author is the stronger production version.
