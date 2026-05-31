# Nullsec S1 — Roadmap

This roadmap is ambitious but honest. RC2/v1.1 has passed as a real-model release
candidate and is published as GitHub Release [`v1.0.0-rc25`](https://github.com/trynullsec/nullsec-s1/releases/tag/v1.0.0-rc25).
Trained artifacts are distributed as Release assets, not committed to source.

Legend: ✅ done · ▶ next · ◻ planned

---

## Phase 0 — Corpus + safety foundation ✅

The deterministic, model-independent foundation.

- 16-category security taxonomy mapped to 8 check dimensions.
- Security Alignment Layer + Nullsec Safety Layer with adversarial probes.
- Curated corpus (now 1,741: 1,304 hand-authored + 437 curated-ingested), every
  category ≥ 60, 100% Safety Layer consistency.
- v1.0 and RC2/v1.1 data thresholds pass; claim validator enforces honesty.

**Exit criteria (met):** `pytest`, `validate_corpus.py`, `release_threshold.py`,
`safety_probes`, and `validate_claims.py --check` all pass.

---

## Phase 1 — First QLoRA training run ✅ (RC1)

The first real `Nullsec-1.0` adapter was trained from the curated corpus on a
RunPod **A100 80GB** box with the hardened CUDA 12.1 stack (`torch==2.5.1+cu121`).

**Status:** adapter (`adapter_config.json` + `adapter_model.safetensors`) produced
and **published as a GitHub Release asset** (not committed to source). On the GPU
box, `validate_claims.py` permitted `trained model` against those artifacts.

---

## Phase 2 — Real model evaluation ✅ (RC1)

The benchmark suite was run against the live RC1 model (`run_mode: "model"`).

RC1 used the previous 12-case benchmark. RC2/v1.1 supersedes it with the expanded
111-case suite and the `v1.0.0-rc25` release artifacts, so current public
benchmark claims should cite RC2/v1.1 rather than historical RC1 numbers.

---

## Phase 3 — Release candidate ✅ (RC1, RC2/v1.1)

**RC1:** `scripts/release_candidate.py` produced a release bundle (adapter +
real-model benchmark + passing safety probes), published as the RC1 Release.

**RC2/v1.1:** `v1.0.0-rc25` passed the stricter RC2 bar on the 111-case
real-model benchmark: `111/111` outputs, detection F1 `0.9245`, false-safe rate
`0.0`, safety probes passed. Release assets contain the adapter, benchmark
reports, release bundle, metrics, and pipeline log.

---

## RC2 / v1.1 ✅

A stronger, more serious run than RC1:

- **Corpus:** 1,741 curated, all 16 categories ≥ 60, 100% Safety Layer consistency.
- **Benchmark → 100+ cases** across all 16 categories, with clean/benign, hard
  unsafe, MCP/tool-abuse, Web3/wallet, and Next.js/Supabase/Vercel/Stripe/Auth
  cases. **Done: 111 cases.**
- **Hardened B200 / CUDA 12.8 training path** was used for the final release run.
- **Stricter production-ready gate** (separate from v1.0): real-model release
  candidate + ≥ 100 benchmark cases + zero false-safe + detection F1 ≥ 0.90.

The RC2/v1.1 gate is met by the `v1.0.0-rc25` release artifacts.

---

## Phase 4 — Hosted web scanner ◻

Launch the hosted scanner at `s1.trynullsec.com`.

---

## Phase 5 — API backend for scans ◻

Production API backend for upload/scan workflows, release-backed model loading,
and persisted audit reports.

---

## Phase 6 — GitHub Action / PR guard ◻

Make the `nullsec1` CI gate robust and easy to adopt: a published GitHub Action,
PR-diff-scoped analysis, machine-readable SARIF output, and configurable risk
thresholds per repo.

---

## Phase 7 — CLI scanner hardening ◻

Improve the `nullsec1` CLI scanner UX, output formats, SARIF export, and local
repository workflows.

---

## Phase 8 — Dashboard / audit reports ◻

A reviewer-facing surface: verdict history, blocking-reason breakdowns,
per-repository risk trends, and exportable audit reports backed by the fingerprint
for reproducibility.

---

## Phase 9 — Larger benchmark suite + framework coverage ◻

Scale the corpus with more real CVE/scanner ingestion and AI-generated failure
cases, deepen per-category coverage, and offer larger model variants (e.g. the
14B config) with their own real benchmarks.

---

## Phase 10 — Base / Web3-specific eval suites ◻

Dedicated evaluation suites for on-chain and wallet code: smart-contract risk,
transaction safety, signing flows, and generated Web3 frontends — measured
separately so Web3 recall is reported on its own terms.

---

## Phase 11 — MCP / tool-risk runtime integration ◻

Runtime integration for agent ecosystems: evaluate MCP tool definitions and tool
call flows as they are registered, flag over-permissioned tools and
prompt-injection-to-tool-execution paths before an agent can act on them.

---

## Principle

Each phase unlocks public claims **only** when its artifacts exist. The repo will
never describe a later phase as done before it is — that constraint is enforced in
code, not just intention. See [`NON_CLAIMS.md`](NON_CLAIMS.md).
