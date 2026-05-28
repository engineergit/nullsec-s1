# Curation Sprint 004 — Audit Report (Threshold Positioning Sprint)

**Goal:** make the corpus **category-complete** (every taxonomy category ≥25
curated) while the corpus still **honestly blocks release** (total <500, eval
<100). Add exactly 8 source-backed `curated_ingested` examples per category (+128),
weighted to the Nullsec S1 wedge: AI-generated / vibecoded SaaS, MCP tool abuse,
agent permissions, wallet/contract risk, prompt-injection-to-tool-execution, and
missing production-readiness checks.

**Result: +128 net approved, 4 rejected. Every category reached 25+. Threshold
still BLOCKS.**

Raw-first loop unchanged from Sprints 002–003: skeletal findings staged (code +
source + references, no patch/exploit, dimensions `not_checked`), curated in a
separate review step, approved only after validation + Safety Layer consistency,
weak-provenance candidates rejected with reasons.

## New this sprint: `review_quality` field

Every example approved this sprint carries an auditable `review_quality` block,
computed at approval time from the candidate (not free-form):

| Flag | Meaning |
|---|---|
| `source_backed` | candidate carries structured `references` (CVE/CWE/OWASP/rule_id/case_id) |
| `patch_reviewed` | the finding has a real, non-empty `secure_patch` |
| `safety_layer_consistent` | passed `validate_example` (verdict ↔ dimensions ↔ taxonomy) at approval |
| `category_confirmed` | a category was confirmed during curation |

All 128 Sprint 004 examples have all four flags true. (The 229 approved in
Sprints 001–003 predate the field and do not carry it — they were approved before
it existed, which is left as-is rather than backfilled.)

## Pipeline counts (this sprint)

| Stage | Count |
|---|---|
| Staged (raw, skeletal) | 132 |
| Imported as pending candidates | 132 |
| Approved (`curated_ingested`) | 128 |
| Rejected (during execution) | 4 |
| Still pending | 0 |

> **Note on the packaged repo.** `data/raw/`, `data/ingest_candidates/`, and
> `data/ingest_rejected/` are transient, git-ignored local working state and were
> cleaned before packaging. The 4 rejection reasons are preserved in this report.
> In the packaged repo `python training/ingestion_stats.py` reports **0 rejected**
> and **357 approved `curated_ingested`** examples (52 + 80 + 97 + 128 across
> Sprints 001–004).

## AI-generated / vibecoded focus

**53 of the 128 approved examples are `vibecoded_failure`** — real AI-generated
app failure patterns across Next.js / Vercel / Supabase / Firebase, MCP/agent
tooling, and Web3. Highlights:

- Supabase table read keyed on a query param with RLS off (`VIBE-AUTH-201`); wide-open Firebase rules (`VIBE-AUTH-202`); auth middleware matcher that misses `/api` (`VIBE-AUTH-203)`
- Next.js client-only admin guard (`VIBE-ADMIN-201`); unauth cron/job trigger (`VIBE-ADMIN-202`); Supabase edge function using the service role with no JWT check (`VIBE-ADMIN-203`)
- `NEXT_PUBLIC_` / `VITE_` secrets shipped to the client (`VIBE-SECRET-201/202`); secrets echoed in an API response (`VIBE-SECRET-203`); secret baked into a Docker layer (`VIBE-SECRET-204`)
- Next.js debug endpoint dumping `process.env` (`VIBE-ENV-201`); Vite inlining the whole env (`VIBE-ENV-202`); `.env` served as a static asset (`VIBE-ENV-203`); CI uploading the whole workspace as an artifact (`VIBE-ENV-204`)
- Insecure generated API routes: unthrottled login / image-gen / magic-link (`VIBE-RATE-201/202/204`); Prisma `$queryRawUnsafe` and a Supabase `run_sql` RPC (`VIBE-SQLI-201/202`)
- MCP tool abuse: generic `execute`/`delete`/`send_email` tools (`VIBE-MCP-201/202/203`), trusting untrusted tool descriptions (`VIBE-MCP-204`)
- Wallet/agent: trading agent with no per-trade cap (`VIBE-WALLET-201`); `setApprovalForAll` hidden in UI (`VIBE-WALLET-202`); hot-wallet withdraw with no auth/limit (`VIBE-WALLET-203`); unlimited faucet (`VIBE-WALLET-204`)
- Contract wrappers: arbitrary-call router (`VIBE-SC-201`); spot-price oracle (`VIBE-SC-202`); mint price not multiplied by quantity (`VIBE-SC-203`)
- Prompt-injection-to-tool-execution: email-driven agent with live tools (`VIBE-PI-201`); RAG over fetched web content (`VIBE-PI-202`); PR bot that auto-merges on a model verdict from diff text (`VIBE-PI-203`)

## Source type breakdown (128 approved this sprint)

| Source type | Count | Target |
|---|---|---|
| vibecoded_failure | 53 | ≥50 ✓ |
| Semgrep / SARIF | 36 (20 Semgrep + 16 SARIF) | ≥25 ✓ |
| OWASP / CWE / CVE anchored | 39 (32 OWASP + 7 CVE) | ≥20 ✓ |
| MCP / agent-tool abuse (MCP + prompt-injection) | 16 | ≥15 ✓ |
| Web3 / wallet / smart-contract | 16 | ≥15 ✓ |

(Categories overlap the buckets by design — MCP and Web3 cases are also counted
under their source types.)

### CVE-backed examples (7, all verified before use)

Only CVEs that can be stated accurately were used:

- **CVE-2023-34362** — MOVEit Transfer SQL injection (unauth DB access; fixed 2021.0.6 / 2021.1.4 / 2022.0.4 / 2022.1.5 / 2023.0.1), CWE-89
- **CVE-2018-1000861** — Jenkins Stapler unauth method access (pre-2.138.2), CWE-862
- **CVE-2017-5638** — Apache Struts2 Jakarta Multipart OGNL RCE (fixed 2.3.32 / 2.5.10.1), CWE-20
- **CVE-2021-22205** — GitLab image-processing fetch (SSRF class; fixed 13.10.3), CWE-918
- **CVE-2021-44228** — Log4Shell (Log4j2 2.0-beta9–2.14.1; fixed 2.15+), CWE-502
- **CVE-2021-23337** — lodash command injection via `_.template` (<4.17.21; fixed 4.17.21), CWE-94
- **CVE-2024-3094** — XZ Utils backdoor (5.6.0 / 5.6.1), CWE-506

No CVE IDs, commit SHAs, or repo paths were invented.

## Rejections (with reasons)

| Candidate | source_type | Reason |
|---|---|---|
| cve-a-SQL-injection-bug-no-identifier | cve | no real CVE ID |
| owasp-common-vulnerability | owasp | no OWASP category reference; vague reference "common vulnerability" |
| semgrep-known-issue | semgrep | no `rule_id`; vague reference "known issue" |
| vibecoded_failure-some-blog | vibecoded_failure | no `case_id` and no AI-failure notes; vague reference "some blog" |

These exercised provenance enforcement across four source types and were excluded
from training (they do not count toward any category's 8).

## Category coverage — before / after

| Category | Before | Added | After |
|---|---|---|---|
| EXPOSED_SECRET | 17 | 8 | 25 |
| BROKEN_AUTH | 19 | 8 | 27 |
| MISSING_RATE_LIMIT | 18 | 8 | 26 |
| UNSAFE_ADMIN_ROUTE | 19 | 8 | 27 |
| SQL_INJECTION | 18 | 8 | 26 |
| XSS | 19 | 8 | 27 |
| SSRF | 19 | 8 | 27 |
| COMMAND_INJECTION | 18 | 8 | 26 |
| UNSAFE_FILE_UPLOAD | 17 | 8 | 25 |
| PROMPT_INJECTION | 17 | 8 | 25 |
| MCP_TOOL_ABUSE | 19 | 8 | 27 |
| DANGEROUS_SHELL_COMMAND | 17 | 8 | 25 |
| WALLET_TRANSACTION_RISK | 18 | 8 | 26 |
| SMART_CONTRACT_RISK | 18 | 8 | 26 |
| DEPENDENCY_RISK | 17 | 8 | 25 |
| ENVIRONMENT_EXPOSURE | 17 | 8 | 25 |

**Exactly 8 added per category. Every category reached 25+ (range 25–27).
Minimum category coverage: 17 → 25.**

## Release threshold progress

| Metric | Before | After | v1.0 target |
|---|---|---|---|
| Curated examples | 292 | 420 | 500 |
| Per-category minimum | 17 | **25** | 25 |
| Eval split size | 58 | 84 | 100 |
| Safety Layer consistency | 100% | 100% | 100% |
| Threshold result | BLOCKED | **BLOCKED** | PASS |

**Remaining gap to 500: 80 curated examples** (and eval needs to reach 100).
The per-category requirement (≥25) is now satisfied for all 16 categories, but the
**total count and eval count gates still block** — exactly the intended position.
The threshold was **not** weakened (`release_threshold.py --include-ingested`
exits non-zero).

## Verification commands (all pass)

```
pytest -q                                                  # 50 passed
python training/validate_corpus.py --include-ingested      # 420/420 accepted, PASS
python training/dataset_stats.py --include-ingested        # 420 total, 100% consistency, every category 25+
python training/release_threshold.py --include-ingested    # BLOCKED (exit 1): need 80 more + >=100 eval
python scripts/validate_claims.py --check                  # HONESTY CHECK PASSED (trained/benchmarked/RC/production-ready/first-only all FORBIDDEN)
python training/ingestion_stats.py                         # packaged repo: 357 approved curated_ingested, 0 rejected (see note)
python -m benchmarks.safety_probes                         # passed
python benchmarks/safety_probes.py                         # passed
```

## Honesty notes

- The corpus is now **category-complete (≥25 each) but not release-ready**: the
  500-total and 100-eval gates still block, which is the whole point of a
  "threshold positioning" sprint.
- Claim validator still **forbids** "trained model", "benchmarked", "release
  candidate", "production-ready", and "first/only/best" — no adapter or benchmark
  exists, and superlatives are unverifiable from local artifacts.
- **Safety Layer consistency remains 100%** (420/420).
- `review_quality` makes each approved example's curation checks auditable at a
  glance.
- As in prior sprints, curation completions were authored in code (so the run is
  reproducible and inspectable) and the pipeline's **enforcement** is what is
  demonstrated: raw candidates cannot pass, and weak-provenance candidates are
  rejected across all four source types. Running the same loop on externally
  sourced scanner/CVE feeds you did not author is the stronger production version;
  the machinery is ready for it.
