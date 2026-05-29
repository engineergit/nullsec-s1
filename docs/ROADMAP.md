# Nullsec S1 — Roadmap

This roadmap is ambitious but honest. Phase 0 is verifiable from this repo's
committed artifacts. RC1 (Phases 1–3) ran for real on a GPU; its artifacts are
published as a **GitHub Release**, not committed to source, so the in-repo claim
validator (`scripts/validate_claims.py`) stays conservative on this checkout by
design. RC2 (v1.1) is the next, larger run.

Legend: ✅ done · ▶ next · ◻ planned

---

## Phase 0 — Corpus + safety foundation ✅

The deterministic, model-independent foundation.

- 16-category security taxonomy mapped to 8 check dimensions.
- Security Alignment Layer + Nullsec Safety Layer with adversarial probes.
- Curated corpus (now 556: 119 hand-authored + 437 curated-ingested), ≥ 31 curated
  per category, 100% Safety Layer consistency.
- v1.0 release-readiness threshold passes; claim validator enforces honesty.

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

**RC1 reported results** (source of truth: the `SUITE.json` in the published RC1
Release bundle — these numbers are not re-verified by this source checkout):

| Metric | RC1 |
|--------|-----|
| detection F1 | 0.9091 |
| precision | 1.0 |
| recall | 0.8333 |
| false_safe_rate | 0.0 |
| hallucination_rate | 0.0 |
| patch_correctness | 0.7 |
| secure_generation_score | 0.6 |
| OWASP coverage | 1.0 |

RC1 used the previous 12-case benchmark. RC2 re-runs evaluation on the expanded
111-case suite, where these numbers will be re-measured (and may move).

---

## Phase 3 — Release candidate ✅ (RC1) / ▶ (RC2)

**RC1:** `scripts/release_candidate.py` produced a release bundle (adapter +
real-model benchmark + passing safety probes), published as the RC1 Release.

**RC2:** a fresh release candidate on the larger corpus + 111-case benchmark, gated
by the stricter RC2 production-ready bar (≥ 100 benchmark cases, F1 ≥ 0.90, zero
false-safe). Tracked below.

---

## RC2 / v1.1 — current focus ▶

A stronger, more serious run than RC1:

- **Corpus → 1,000 curated** (currently 556), all 16 categories ≥ 60 (currently
  ≥ 31). Honest gap: see `training/release_threshold.py --profile rc2`.
- **Benchmark → 100+ cases** across all 16 categories, with clean/benign, hard
  unsafe, MCP/tool-abuse, Web3/wallet, and Next.js/Supabase/Vercel/Stripe/Auth
  cases. **Done: 111 cases.**
- **Hardened CUDA 12.1 training stack** (`requirements-train-cu121.txt`,
  preflight Torch/CUDA mismatch detection, `max_length`, resume support).
- **Stricter production-ready gate** (separate from v1.0): real-model release
  candidate + ≥ 100 benchmark cases + zero false-safe + detection F1 ≥ 0.90.

Neither RC2 gate is met yet on this checkout; both report BLOCKED honestly until
the corpus reaches the v1.1 target.

---

## Phase 4 — CLI / GitHub Action hardening ◻

Make the `nullsec1` CI gate robust and easy to adopt: a published GitHub Action,
PR-diff-scoped analysis, machine-readable SARIF output, and configurable risk
thresholds per repo.

---

## Phase 5 — Hosted Nullsec S1 API ◻

A hosted endpoint mirroring `serving/server.py` so teams can call the enforced
verdict pipeline without standing up a GPU. Same single enforcement path; the
Safety Layer runs in front.

---

## Phase 6 — Dashboard / audit reports ◻

A reviewer-facing surface: verdict history, blocking-reason breakdowns,
per-repository risk trends, and exportable audit reports backed by the fingerprint
for reproducibility.

---

## Phase 7 — Larger corpus + stronger model variants ◻

Scale the corpus with more real CVE/scanner ingestion and AI-generated failure
cases, deepen per-category coverage, and offer larger model variants (e.g. the
14B config) with their own real benchmarks.

---

## Phase 8 — Base / Web3-specific eval suites ◻

Dedicated evaluation suites for on-chain and wallet code: smart-contract risk,
transaction safety, signing flows, and generated Web3 frontends — measured
separately so Web3 recall is reported on its own terms.

---

## Phase 9 — MCP / tool-risk runtime integration ◻

Runtime integration for agent ecosystems: evaluate MCP tool definitions and tool
call flows as they are registered, flag over-permissioned tools and
prompt-injection-to-tool-execution paths before an agent can act on them.

---

## Principle

Each phase unlocks public claims **only** when its artifacts exist. The repo will
never describe a later phase as done before it is — that constraint is enforced in
code, not just intention. See [`NON_CLAIMS.md`](NON_CLAIMS.md).
