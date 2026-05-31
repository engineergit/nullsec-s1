# Dataset Card — Nullsec-1 Training Corpus

## Composition
`corpus/` is the **single source of truth** for training data. `training/prepare_dataset.py`,
`training/dataset_stats.py`, `training/validate_corpus.py`, and `training/release_threshold.py`
all read it through the same `corpus.load_corpus()` loader, so the number of examples used for
training matches what stats and the threshold report (unless `--include-synthetic` /
`--include-ingested` are explicitly passed).

1. **Curated corpus** (`corpus/authored/`) — hand-authored vulnerable and secure examples with full structured verdicts, built via `corpus/builder.py`. Provenance `hand_authored`. This includes the examples migrated from the former `data/seed/seed_examples.py` (now removed; the corpus is the single source).
2. **Curated ingested** (`corpus/ingested/*.jsonl`, opt-in) — CVE/scanner/real-failure records that have been validated and human-curated. Provenance `curated_ingested`. Raw ingestion output is staged elsewhere (e.g. `data/raw/`) and is **not** training-eligible until curated into `corpus/ingested/`.
3. **Synthetic variants** (`corpus/synthetic/*.jsonl`, opt-in) — labeled, structure-preserving augmentations produced by `training/synthesize_corpus.py`, provenance `synthetic_variant`. Never counts as curated.

Every example, regardless of source, is run through the **same Security Alignment Layer and Nullsec Safety Layer** as the live serving layer before entering training. Malformed or enforcement-inconsistent verdicts are dropped. This guarantees Nullsec-1 is only ever trained on targets that satisfy the deterministic contract.

## Schema
Each training record is chat-formatted:
```json
{"messages": [
  {"role": "system", "content": "<Nullsec system prompt>"},
  {"role": "user", "content": "Audit the following code... FILE: q.py ```python ...```"},
  {"role": "assistant", "content": "<gated verdict JSON>"}
]}
```
The assistant content always validates against `data/schemas/verdict.schema.json`.

## Scaling the corpus: the curated ingestion workflow
`corpus/` is the single source of truth, so new data does **not** go into any seed file
(the former `data/seed/seed_examples.py` is removed). All new data passes through a
staging → human review → curated pipeline. Nothing staged is training-eligible.

**Step 1 — Stage raw findings (not training-eligible).** Put raw CVE/NVD, Semgrep,
SARIF/CodeQL output, and real vibecoded failure cases into a staging folder
(`data/raw/` by default). These are uncurated and never read by training.

- **CVE / NVD:** `python -m nullsec.ingest.import_cve --feed nvdcve-2.0.json --out data/raw/cve.jsonl`
  Maps CWE→category and CVSS→severity. Produces description-level skeletons; attach real patch commits for patch-quality signal.
- **Semgrep:** `python -m nullsec.ingest.import_scanners --semgrep results.json --out data/raw/semgrep.jsonl`
- **SARIF / CodeQL:** `python -m nullsec.ingest.import_scanners --sarif codeql.sarif --out data/raw/codeql.jsonl`
- **Vibecoded failures / repo snippets:** add `{filename, lang, code, verdict}` records as `data/raw/*.jsonl`.

**Step 2 — Build review candidates.** `python training/curate_ingested.py import data/raw/*.jsonl`
converts staged records into review candidates under `data/ingest_candidates/`, each starting
as `provenance: needs_human_review`, reviewer status `pending`. Importing never approves anything.

**Step 3 — Human review.** A reviewer inspects each candidate (vulnerable code, source type and
reference, suggested category/severity, exploit scenario, checks performed, proposed verdict,
proposed secure patch) and approves or rejects it:

- `python training/curate_ingested.py approve <candidate_id>` — validates the candidate (requires a
  real secure patch and complete `checks_performed`, runs Safety Layer consistency), and only on
  success writes it to `corpus/ingested/*.jsonl` with `provenance: curated_ingested`.
- `python training/curate_ingested.py reject <candidate_id> --reason "..."` — moves it to a rejected
  store that training never reads.

**Step 4 — It counts only after validation.** A `curated_ingested` example counts toward the
curated release thresholds only when it passes `training/validate_corpus.py` (run with
`--include-ingested`) and only when `--include-ingested` is explicitly passed to
`dataset_stats.py` / `release_threshold.py` / `prepare_dataset.py`. Synthetic variants never count.

Use `python training/ingestion_stats.py` to see counts across raw-imported, pending, approved
(`curated_ingested`), and rejected, plus categories covered and how many approved examples count
toward the 500-curated threshold.

## Quality validation, stats, and the release threshold
The corpus is gated by three real commands:

- `python training/validate_corpus.py` — rejects incomplete examples, findings without a real secure patch, `checks_performed` that contradict findings (a finding whose dimension is marked `pass`), verdicts that cannot be aligned, and any example whose labeled `production_ready` disagrees with the Safety Layer. Also enforces per-category minimum coverage. Runs in CI.
- `python training/dataset_stats.py` — reports total, train/eval split, category coverage (curated and total), severity coverage, language/framework coverage, the `production_ready` true/false ratio, the Safety Layer consistency rate, and the provenance breakdown.
- `python training/release_threshold.py` — blocks a Nullsec-1.0 training run unless at least 500 **curated** examples exist, every taxonomy category has at least 25 curated examples, the eval split has at least 100 examples, and Safety Layer consistency is exactly 100%. Synthetic variants never count toward the curated thresholds. This gate **currently PASSES**. The stricter RC2/v1.1 profile (`--profile rc2`) also passes with the current 1,741-example corpus (every category ≥60, eval ≥200, 100% consistency, benchmark ≥100 cases, all 16 categories covered).

## Known biases & gaps
- The curated set is now the RC2/v1.1 corpus (1,741 curated: 1,304 hand-authored + 437 curated-ingested). It covers every category with ≥ 60 examples each, but recall on arbitrary real-world variety still improves with broader external coverage.
- Further scaling relies on real CVE/scanner ingestion plus real AI-generated failure cases and continued authoring — not synthetic padding.
- Scanner/CVE imports inherit the upstream tool's biases and false-positive profile.
- Languages over-represented: Python, JS/TS, Solidity. Expand for Go/Rust/Java/PHP coverage.

## Provenance & licensing
- Seed examples are original, written for this repo.
- When ingesting third-party data (CVE feeds, scanner outputs, public repos), respect the source license and attribution requirements.
