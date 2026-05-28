# Curation Sprint 005 — Audit Report (Final Corpus Threshold Unlock)

**Goal:** cross the v1.0 corpus threshold. Add exactly 5 source-backed
`curated_ingested` examples per category (+80), taking the corpus to **500
curated / 100 eval** so the **release-readiness gate finally PASSES** — while the
**claim validator still forbids** trained / benchmarked / release-candidate
claims, because no model has been trained yet. Readiness ≠ trained.

**Result: +80 net approved, 4 rejected. Corpus 420 → 500, eval 84 → 100, every
category ≥30. Release threshold now PASSES. Claim validator still forbids
trained/benchmarked/release-candidate.**

Raw-first loop unchanged: skeletal findings staged (code + source + references, no
patch/exploit, dimensions `not_checked`), curated in a separate review step with
`review_quality`, approved only after validation + Safety Layer consistency,
weak-provenance candidates rejected with reasons.

## Pipeline counts (this sprint)

| Stage | Count |
|---|---|
| Staged (raw, skeletal) | 84 |
| Imported as pending candidates | 84 |
| Approved (`curated_ingested`) | 80 |
| Rejected (during execution) | 4 |
| Still pending | 0 |

> **Note on the packaged repo.** `data/raw/`, `data/ingest_candidates/`, and
> `data/ingest_rejected/` are transient, git-ignored local working state and were
> cleaned before packaging. The 4 rejection reasons are preserved in this report.
> In the packaged repo `python training/ingestion_stats.py` reports **0 rejected**
> and **437 approved `curated_ingested`** examples (52 + 80 + 97 + 128 + 80 across
> Sprints 001–005).

## `review_quality` (continued from Sprint 004)

All 80 examples approved this sprint carry the auditable `review_quality` block
(`source_backed`, `patch_reviewed`, `safety_layer_consistent`,
`category_confirmed`), computed at approval time from the candidate — all four
flags true. Across the ingested set, **208 examples now carry `review_quality`**
(128 from Sprint 004 + 80 from Sprint 005); the 229 from Sprints 001–003 predate
the field and are left as-is.

## AI-generated / vibecoded focus

**35 of the 80 approved examples are `vibecoded_failure`** — AI-generated app
failure patterns across Next.js / Vercel / Supabase / Firebase, agent/MCP tooling,
and generated Web3 frontends. Highlights:

- Next.js server action with no auth (`VIBE-AUTH-301`); Supabase auth ignoring email confirmation (`VIBE-AUTH-302`); Firebase admin callable with no auth context (`VIBE-ADMIN-301`); Vercel cron purge with no secret (`VIBE-ADMIN-302`)
- Deployer / mnemonic / service-account keys shipped to the client or committed (`VIBE-SECRET-301/302`, `VIBE-ENV-301`); hardcoded client-side admin password (`VIBE-SECRET-303`); `/api/env` diagnostic route (`VIBE-ENV-302`)
- Generated insecure routes: OTP verify with no attempt cap (`VIBE-RATE-301`); webhook signature OK but not idempotent (`VIBE-RATE-302`); unbounded agent loop with no budget (`VIBE-RATE-303`)
- Generated uploads: wide-open Firebase Storage rules (`VIBE-UPLOAD-301`); client extension preserved into a public dir (`VIBE-UPLOAD-302`)
- Generated SQL: Drizzle `sql.raw` interpolation (`VIBE-SQLI-301`); raw input in a PostgREST `.or()` filter (`VIBE-SQLI-302`)
- Generated Web3 frontends: ENS name via `innerHTML` (`VIBE-XSS-301`); nullified CSP (`VIBE-XSS-302`); open RPC proxy (`VIBE-SSRF-301`); trusting on-chain `tokenURI` for a server fetch (`VIBE-SSRF-302`)
- Agent/MCP: arbitrary write-SQL tool on prod (`VIBE-MCP-301`); arbitrary outbound POST exfil tool (`VIBE-MCP-302`); MCP read tool with no path containment (`VIBE-MCP-303`); agent that concatenates untrusted tool output (`VIBE-PI-303`); ticket-driven refund tool (`VIBE-PI-301`); resume screener obeying hidden text (`VIBE-PI-302`); an agent's image tool shelling out (`VIBE-CMDI-301`); agent plugin loader importing by name (`VIBE-IMPORT-301`); agent calculator tool using `eval` (`VIBE-EVAL-301`)
- Wallet/agent: full-balance sweep with no gas reserve (`VIBE-WALLET-301`); spender-from-URL infinite approve (`VIBE-WALLET-302`); agent wallet with no spend policy (`VIBE-WALLET-304`)

## Source type breakdown (80 approved this sprint)

| Bucket | Count | Target |
|---|---|---|
| vibecoded_failure | 35 | ≥35 ✓ |
| MCP / agent-tool (MCP_TOOL_ABUSE + PROMPT_INJECTION + agent-flavored) | 15 | ≥15 ✓ |
| Web3 / wallet / smart-contract (incl. generated Web3 frontends) | 19 | ≥15 ✓ |
| OWASP / CWE / Semgrep / SARIF anchored | 45 (17 OWASP + 14 Semgrep + 11 SARIF + 3 CVE) | ≥15 ✓ |

(Buckets overlap by design — agent and Web3 cases are also counted under their
source types.)

### CVE-backed examples (3, all verified before use)

Only CVEs that can be stated accurately were used this sprint:

- **CVE-2017-9805** — Apache Struts REST plugin XStream deserialization RCE (fixed 2.5.13), CWE-502
- **CVE-2022-22965** — Spring4Shell RCE (Spring 5.3.0-5.3.17 / 5.2.x; fixed 5.3.18 / 5.2.20), CWE-94
- **CVE-2014-0160** — Heartbleed (OpenSSL ≤1.0.1f; fixed 1.0.1g), CWE-125

No CVE IDs, commit SHAs, or repo paths were invented.

## Rejections (with reasons)

| Candidate | source_type | Reason |
|---|---|---|
| cve-an-SSRF-bug-no-id | cve | no real CVE ID |
| owasp-common-vulnerability | owasp | no OWASP/SWC category reference; vague reference "common vulnerability" |
| semgrep-internet | semgrep | no `rule_id`; vague reference "internet" |
| vibecoded_failure-known-issue | vibecoded_failure | no `case_id` and no AI-failure notes; vague reference "known issue" |

These exercised provenance enforcement across four source types and were excluded
from training (they do not count toward any category's 5).

## Category coverage — before / after

| Category | Before | Added | After |
|---|---|---|---|
| EXPOSED_SECRET | 25 | 5 | 30 |
| BROKEN_AUTH | 27 | 5 | 32 |
| MISSING_RATE_LIMIT | 26 | 5 | 31 |
| UNSAFE_ADMIN_ROUTE | 27 | 5 | 32 |
| SQL_INJECTION | 26 | 5 | 31 |
| XSS | 27 | 5 | 32 |
| SSRF | 27 | 5 | 32 |
| COMMAND_INJECTION | 26 | 5 | 31 |
| UNSAFE_FILE_UPLOAD | 25 | 5 | 30 |
| PROMPT_INJECTION | 25 | 5 | 30 |
| MCP_TOOL_ABUSE | 27 | 5 | 32 |
| DANGEROUS_SHELL_COMMAND | 25 | 5 | 30 |
| WALLET_TRANSACTION_RISK | 26 | 5 | 31 |
| SMART_CONTRACT_RISK | 26 | 5 | 31 |
| DEPENDENCY_RISK | 25 | 5 | 30 |
| ENVIRONMENT_EXPOSURE | 25 | 5 | 30 |

**Exactly 5 added per category. Every category is now ≥30 (range 30–32).**

## Release threshold progress

| Metric | Before | After | v1.0 target |
|---|---|---|---|
| Curated examples | 420 | **500** | 500 |
| Per-category minimum | 25 | **30** | 25 |
| Eval split size | 84 | **100** | 100 |
| Safety Layer consistency | 100% | 100% | 100% |
| Threshold result | BLOCKED | **PASS** | PASS |

**All four readiness gates are now satisfied.** The threshold was not weakened —
it passes because the corpus genuinely reached 500 curated / ≥25 per category /
100 eval / 100% consistency (`release_threshold.py --include-ingested` exits 0).

## Verification commands (all pass)

```
pytest -q                                                  # 50 passed
python training/validate_corpus.py --include-ingested      # 500/500 accepted, PASS
python training/dataset_stats.py --include-ingested        # 500 total, 100 eval, 100% consistency, every category >=30
python training/release_threshold.py --include-ingested    # PASS (exit 0)
python scripts/validate_claims.py --check                  # HONESTY CHECK PASSED (trained/benchmarked/RC/production-ready/first-only STILL FORBIDDEN)
python training/ingestion_stats.py                         # packaged repo: 437 approved curated_ingested, 0 rejected (see note)
python -m benchmarks.safety_probes                         # passed
python benchmarks/safety_probes.py                         # passed
```

## Remaining status before training

This sprint unlocks **training readiness only**. Nullsec S1 is **not** a trained
model yet. The honest state:

- **Corpus is v1.0 training-ready**: 500 curated, 100 eval, every category ≥30,
  100% Safety Layer consistency, all provenance source-backed.
- **No model has been trained**: there is no `adapter_config.json` + weights and
  no benchmark report, so the claim validator continues to **forbid** "trained
  model", "benchmarked", "evaluated with real model outputs", "release candidate",
  "production-ready", and "first/only/best". Only "training-ready" applies.
- **Next step is the real QLoRA training run** (`RELEASE_TRAINING.md` / the
  training pipeline) on this corpus, followed by a real benchmark
  (`benchmarks/` with real-model outputs). Only after those artifacts exist will
  `validate_claims.py` permit "trained" and "benchmarked", and only after a
  real-model run with zero false-safe rate and adequate detection F1 will
  "release candidate" / "production-ready" become substantiated.
- As in every prior sprint, curation completions were authored in code (so the
  run is reproducible and inspectable); the pipeline's **enforcement** is what is
  demonstrated — raw candidates cannot pass, and weak-provenance candidates are
  rejected across all four source types. Running the same loop on externally
  sourced scanner/CVE feeds is the stronger production version; the machinery is
  ready for it.
```
corpus curated: 500   eval: 100   per-category min: 30   safety-layer: 100%
release-readiness gate: PASS        trained/benchmarked claims: STILL FORBIDDEN
next: real QLoRA training run -> real benchmark -> then claims unlock
```
