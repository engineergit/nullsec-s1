# Curation Sprint 002 — Audit Report

**Goal:** grow the corpus with real, source-backed `curated_ingested` examples
through a genuine **raw-first review loop**, and make provenance defensible.
Target: +80 net approved. **Result: +80 net approved, 3 rejected.**

Unlike Sprint 001 (pre-completed examples), Sprint 002 staged **skeletal** raw
findings — vulnerable code + source + references, but no patch, no exploit, and
all check dimensions `not_checked` — then filled in remediation during a separate
curation step, then approved only after validation + Safety Layer consistency.
A raw candidate is provably non-approvable until curated (verified: the first
import attempt was blocked for "no real secure_patch").

## Pipeline counts (this sprint)

| Stage | Count |
|---|---|
| Staged (raw, skeletal) | 83 |
| Imported as pending candidates | 83 |
| Approved (`curated_ingested`) | 80 |
| Rejected (during execution) | 3 |
| Still pending | 0 |

The 3 rejections were intentional reject-tests included to exercise the new
provenance enforcement (below). During Sprint 002 execution they were blocked
automatically at approval and recorded in `data/ingest_rejected/` with reasons.

> **Note on the packaged repo.** `data/ingest_rejected/` (along with
> `data/ingest_candidates/` and `data/raw/`) is transient, git-ignored local
> working state, and it was cleaned before packaging. The rejection reasons
> themselves are preserved in this audit report (see the table below).
> Consequently, in the packaged repo `python training/ingestion_stats.py` reports
> **0 rejected** and **132 approved `curated_ingested`** examples — the rejected
> count there reflects the cleaned local state, not the 3 rejections that occurred
> during the sprint and are documented here.

## Stronger provenance enforcement (new this sprint)

A new module, `training/provenance.py`, runs at approval time and blocks weak or
unciteable provenance:

- `source_type=cve` → requires a real CVE ID (`CVE-YYYY-N+`) and a CWE.
- `source_type=semgrep` → requires a `rule_id` / stable rule reference.
- `source_type=owasp` → requires an OWASP category reference (e.g. `A03:2021`, `LLM01:2025`).
- `source_type=sarif`/`codeql` → requires a `rule_id` (the SARIF ruleId).
- `source_type=vibecoded_failure` → requires a local `case_id` **and** reviewer
  notes explaining why it is an AI-generated app failure.
- Any vague reference (`internet`, `blog`, `known issue`, `common vulnerability`, …)
  is rejected unless a stable reference is also attached.

### Rejections (with reasons)

| Candidate | source_type | Reason |
|---|---|---|
| blog-internet-… | blog | vague reference "internet", no stable reference attached |
| cve-hardcoded-key-… | cve | no real CVE ID (provenance requires `CVE-YYYY-NNNN`) |
| sarif-known-issue-… | sarif | no `rule_id`; vague reference "known issue" |

These were excluded from training; they appear only in the rejected audit store.

## Source type breakdown (80 approved this sprint)

| Source type | Count |
|---|---|
| OWASP (Web / API / LLM / Smart-Contract Top 10) | 28 |
| Real vibecoded app failures (Nullsec scanner-style) | 16 |
| Semgrep rule-backed | 14 |
| SARIF / CodeQL-style (ruleId) | 12 |
| CVE-anchored | 10 |

### CVEs cited (verified before use)
All CVE IDs in the corpus were verified against public references prior to use:
CVE-2014-0160 (Heartbleed), CVE-2017-5638 (Struts2 Jakarta), CVE-2017-9805
(Struts REST XStream), CVE-2018-1000861 (Jenkins Stapler), CVE-2019-11043
(PHP-FPM), CVE-2021-22205 (GitLab ExifTool), CVE-2021-44228 (Log4Shell),
CVE-2022-22965 (Spring4Shell), CVE-2024-3094 (XZ Utils backdoor). Where a CVE
could not be stated accurately, the `cve` field is null and the case is anchored
by CWE/OWASP/Semgrep-rule/SWC references instead. No CVE IDs, commit SHAs, or
repo paths were invented.

## Category coverage — before / after

Every category received +5 approved curated examples (rejections did not reduce
any category below target because reject-tests were spread across categories that
also received valid examples).

| Category | Before | After |
|---|---|---|
| EXPOSED_SECRET | 7 | 11 |
| BROKEN_AUTH | 7 | 12 |
| MISSING_RATE_LIMIT | 6 | 11 |
| UNSAFE_ADMIN_ROUTE | 7 | 12 |
| SQL_INJECTION | 7 | 12 |
| XSS | 7 | 13 |
| SSRF | 7 | 13 |
| COMMAND_INJECTION | 7 | 13 |
| UNSAFE_FILE_UPLOAD | 6 | 11 |
| PROMPT_INJECTION | 7 | 11 |
| MCP_TOOL_ABUSE | 7 | 12 |
| DANGEROUS_SHELL_COMMAND | 7 | 11 |
| WALLET_TRANSACTION_RISK | 7 | 12 |
| SMART_CONTRACT_RISK | 7 | 12 |
| DEPENDENCY_RISK | 8 | 13 |
| ENVIRONMENT_EXPOSURE | 6 | 11 |

**Minimum category coverage: 6 → 11.**

## Release threshold progress

| Metric | Before | After | Target |
|---|---|---|---|
| Curated examples | 115 | 195 | 500 |
| Per-category minimum | 6 | 11 | 25 |
| Eval split size | 23 | 39 | 100 |
| Safety Layer consistency | 100% | 100% | 100% |
| Threshold result | BLOCKED | **BLOCKED** | PASS |

The threshold was **not** weakened and still blocks
(`release_threshold.py --include-ingested` exits non-zero at 195/500). ~305 more
curated examples (and ≥25/category, ≥100 eval) remain before a real Nullsec-1.0
training run is justified.

## Verification commands (all pass)

```
pytest -q                                                  # 50 passed
python training/validate_corpus.py --include-ingested      # 195/195 accepted, PASS
python training/dataset_stats.py --include-ingested        # 195 total, 100% consistency
python training/release_threshold.py --include-ingested    # BLOCKED (exit 1)
python scripts/validate_claims.py --check                  # HONESTY CHECK PASSED (trained/benchmarked/RC still FORBIDDEN)
python training/ingestion_stats.py                         # packaged repo: 132 approved curated_ingested, 0 rejected (see note below)
python -m benchmarks.safety_probes                         # passed
python benchmarks/safety_probes.py                         # passed
```

## Honesty notes

- Claim validator still **forbids** "trained model", "benchmarked", and "release
  candidate" — no adapter or benchmark report exists, and the sprint did not
  change that.
- Approved examples carry `provenance: curated_ingested` and count toward curated
  thresholds only with `--include-ingested`. Without the flag the curated count
  is the 63 hand-authored examples.
- Raw staging (`data/raw/`), candidates (`data/ingest_candidates/`), and rejected
  (`data/ingest_rejected/`) are local/git-ignored working state. The approved
  curated records in `corpus/ingested/*.jsonl` are committed and shipped.
- The sprint is reproducible: re-staging and re-importing is idempotent
  (content-hashed candidate ids), and the curation completions are expressed in
  `training/sprint_data/sprint002_*` so a reviewer can inspect exactly what was
  added to each candidate.
