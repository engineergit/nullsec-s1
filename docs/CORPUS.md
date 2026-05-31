# The Nullsec S1 Corpus

`corpus/` is the **single source of truth** for Nullsec S1 training data. Every
data-side tool — `prepare_dataset.py`, `dataset_stats.py`, `validate_corpus.py`,
`release_threshold.py` — reads it through the same `corpus.load_corpus()` loader,
so the number of examples used for training always matches what the stats and the
threshold report (for the same flags).

> **Current snapshot:** 1,741 curated examples (1,304 `hand_authored` + 437
> `curated_ingested`), 1,393 train / 348 eval, all 16 categories with ≥ 60
> curated examples, 100% Safety Layer consistency. Reproduce with
> `python training/dataset_stats.py --include-ingested`.

---

## 1. Example schema

Each corpus example is a dictionary with this shape (see `corpus/builder.py` for
the authoring helpers and `data/schemas/verdict.schema.json` for the embedded
verdict contract):

```jsonc
{
  "id": "ing-vibecoded_failure-...-80b025093f60",   // unique, stable
  "lang": "python",                                  // source language
  "framework": "mcp",                                // framework / ecosystem
  "code": "…the vulnerable or secure source…",       // the reviewed code
  "expected_production_ready": false,                // label the Safety Layer must reproduce
  "provenance": "curated_ingested",                  // see §2
  "source": "ingested",                              // "authored" | "ingested" | "synthetic"
  "references": {                                     // auditable provenance (ingested)
    "case_id": "VIBE-MCP-018",
    "cwe": "CWE-22",
    "owasp": "LLM06:2025-Excessive Agency"
  },
  "reviewer_notes": "why this is an AI-generated app failure …",
  "review_quality": {                                 // present on later-sprint approvals
    "source_backed": true,
    "patch_reviewed": true,
    "safety_layer_consistent": true,
    "category_confirmed": true
  },
  "verdict": {                                        // the structured verdict (schema-valid)
    "risk_score": 90,
    "production_ready": false,
    "severity": "CRITICAL",
    "confidence": "HIGH",
    "reasoning_summary": "…",
    "exploit_scenario": "…",
    "affected_files": ["server.py"],
    "checks_performed": { "auth": {"status": "fail", "note": "…"}, "...": "…" },
    "findings": [ { "category": "MCP_TOOL_ABUSE", "severity": "HIGH", "secure_patch": "…", "...": "…" } ]
  }
}
```

The embedded `verdict` always validates against the verdict schema, and
`expected_production_ready` must equal what the Safety Layer computes for that
verdict — this is what "Safety Layer consistency" measures.

---

## 2. Provenance

Provenance is tracked explicitly and **never blurred**. `corpus.is_curated()`
treats only the first two as curated:

| Provenance | Meaning | Counts as curated? |
|------------|---------|--------------------|
| `hand_authored` | Original example written for this repo (`corpus/authored/`). | ✅ yes |
| `curated_ingested` | CVE / scanner / real-failure record that passed human review and provenance enforcement (`corpus/ingested/*.jsonl`). | ✅ yes |
| `synthetic_variant` | Labeled, structure-preserving augmentation from `synthesize_corpus.py` (`corpus/synthetic/*.jsonl`). | ❌ never |

Two more states exist in the pipeline but are **never training-eligible** and do
not live in `corpus/`:

- **`raw_imported`** — staged raw findings (CVE/NVD, Semgrep, SARIF/CodeQL, real
  vibecoded snippets) in a git-ignored working area. Uncurated; training never
  reads them.
- **`rejected`** — candidates a reviewer rejected (e.g. weak/unciteable
  provenance). Moved to a rejected store training never reads; rejection reasons
  are preserved in the sprint reports.

---

## 3. Curation workflow

New data does **not** go into any seed file. It passes through staging → human
review → curated:

1. **Stage raw findings** into a git-ignored working area (`data/raw/` by
   default). Importers exist for CVE/NVD (`nullsec.ingest.import_cve`) and
   Semgrep/SARIF/CodeQL (`nullsec.ingest.import_scanners`). These are
   `raw_imported` and not training-eligible.
2. **Build review candidates** with `training/curate_ingested.py import …`. Each
   candidate starts as `needs_human_review`, status `pending`. Importing approves
   nothing.
3. **Review** each candidate (code, source type and reference, suggested
   category/severity, exploit scenario, checks, proposed verdict, proposed
   patch) and:
   - `approve <id>` — validates the candidate (requires a real secure patch and
     complete `checks_performed`, and runs Safety Layer consistency), and only on
     success writes it to `corpus/ingested/*.jsonl` as `curated_ingested`; or
   - `reject <id> --reason "…"` — moves it to the rejected store.
4. **It counts only after validation** — a `curated_ingested` example counts
   toward curated thresholds only when it passes `validate_corpus.py` and only
   when `--include-ingested` is explicitly passed.

Provenance enforcement (`training/provenance.py`) rejects vague, unciteable
sources: a `cve` candidate needs a real CVE ID (and CWE), `semgrep`/`sarif` need
a `rule_id`, `owasp` needs an OWASP category, and `vibecoded_failure` needs a
local `case_id` plus reviewer notes explaining why it is an AI-generated failure.

---

## 4. `review_quality`

Examples approved from Sprint 004 onward carry an auditable `review_quality`
block, computed at approval time:

- `source_backed` — has a stable, citeable reference
- `patch_reviewed` — the secure patch was inspected
- `safety_layer_consistent` — the verdict's label matches Safety Layer output
- `category_confirmed` — the taxonomy category was confirmed

All four are `true` for approved examples that carry the block. Earlier-sprint
approvals predate the field and are left as-is (their consistency is still
verified by `validate_corpus.py`).

---

## 5. Release threshold

`training/release_threshold.py` is the data-side honesty gate. It blocks a v1.0
training run unless **all** hold (synthetic never counts toward curated):

| Criterion | Requirement | Current |
|-----------|-------------|---------|
| Curated total | ≥ 500 | 500 |
| Per-category curated | ≥ 25 each | ≥ 30 each |
| Eval split | ≥ 100 | 100 |
| Safety Layer consistency | exactly 100% | 100% |

```bash
python training/release_threshold.py --include-ingested   # PASS (exit 0)
```

The threshold is **not weakened** to pass — it passes because the corpus genuinely
reached those numbers. It is the data-side analogue of
`scripts/validate_claims.py`.

---

## 6. Category coverage

All 16 taxonomy categories are covered, each with ≥ 30 curated examples (current
range 30–32):

```
EXPOSED_SECRET 30   BROKEN_AUTH 32   MISSING_RATE_LIMIT 31   UNSAFE_ADMIN_ROUTE 32
SQL_INJECTION 31    XSS 32           SSRF 32                 COMMAND_INJECTION 31
UNSAFE_FILE_UPLOAD 30  PROMPT_INJECTION 30  MCP_TOOL_ABUSE 32  DANGEROUS_SHELL_COMMAND 30
WALLET_TRANSACTION_RISK 31  SMART_CONTRACT_RISK 31  DEPENDENCY_RISK 30  ENVIRONMENT_EXPOSURE 30
```

Severity coverage (snapshot): CRITICAL 165, HIGH 227, MEDIUM 97, LOW 5, INFO 6.
The corpus deliberately includes a small number of clean, `production_ready: true`
examples (6) so it is not 100% positive.

---

## 7. Quality validation

Three commands gate the corpus; all run with `--include-ingested` to score the
full curated set:

```bash
python training/validate_corpus.py  --include-ingested   # rejects poison; PASS = 0 rejected
python training/dataset_stats.py    --include-ingested   # full breakdown
python training/release_threshold.py --include-ingested  # the v1.0 gate
```

`validate_corpus.py` rejects any example that would poison training: missing
required fields, a vulnerable finding with no real `secure_patch`, a finding that
contradicts a `pass` dimension, a `production_ready` label the Safety Layer would
not reproduce, a verdict that cannot be aligned, or a duplicate id.

---

## 8. Known gaps

- 1,741 curated examples is a strong RC2/v1.1 corpus, but recall on arbitrary
  real-world variety still grows with broader external coverage and evaluation.
- Languages are weighted toward Python, JS/TS, and Solidity; Go/Rust/Java/PHP
  depth is lighter.
- Scanner/CVE imports inherit the upstream tool's biases and false-positive
  profile, which is why every ingested record is human-reviewed before it counts.

Auditable, per-sprint detail (counts, rejections with reasons, source-type
breakdowns) lives in [`../reports/`](../reports/). The original dataset card is
[`dataset_card.md`](dataset_card.md).
