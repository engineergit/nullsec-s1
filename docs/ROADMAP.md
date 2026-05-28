# Nullsec S1 — Roadmap

This roadmap is ambitious but honest. Phase 0 is genuinely complete and verifiable
from repo artifacts. Everything after it is planned work, and the project's claim
validator (`scripts/validate_claims.py`) will keep public wording in step with
whatever artifacts actually exist at each phase.

Legend: ✅ done · ▶ next · ◻ planned

---

## Phase 0 — Corpus + safety foundation ✅

The deterministic, model-independent foundation.

- 16-category security taxonomy mapped to 8 check dimensions.
- Security Alignment Layer + Nullsec Safety Layer with adversarial probes.
- 500 curated examples (63 hand-authored + 437 curated-ingested), 400/100 split,
  ≥ 30 curated per category, 100% Safety Layer consistency.
- Release-readiness threshold passes; claim validator enforces honesty.

**Exit criteria (met):** `pytest`, `validate_corpus.py`, `release_threshold.py`,
`safety_probes`, and `validate_claims.py --check` all pass.

---

## Phase 1 — First QLoRA training run ▶

Produce the first real `Nullsec-1.0` adapter from the curated corpus.

**Exit criteria:** `outputs/nullsec1-7b-qlora/adapter_config.json` + weights exist
from a real GPU run; `preflight_train.py` passes on the GPU box; the claim
validator permits `trained model`.

---

## Phase 2 — Real model evaluation ◻

Run the benchmark suite against the live model.

**Exit criteria:** `benchmarks/reports/SUITE.json` with `run_mode: "model"` and
non-empty results; the claim validator permits `benchmarked` and real-model
evaluation. A case with no output is a real miss, never a synthetic pass.

---

## Phase 3 — Release candidate ◻

Assemble a release bundle from real artifacts only.

**Exit criteria:** `scripts/release_candidate.py` succeeds (adapter + real-model
benchmark + passing probes + bundle); `releases/nullsec-1.0/safety_probes.json`
shows `passed: true`; the claim validator permits `release candidate`.

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
