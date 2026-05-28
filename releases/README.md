# Releases

This directory holds **generated** Nullsec-1 release bundles. It ships empty by
design: a bundle is created only by a real release run, and contains only real
artifacts. No bundle is committed with hand-written or placeholder numbers.

Create one with:

```bash
python scripts/release_candidate.py --adapter outputs/nullsec-s1-qlora \
    --dataset benchmarks/datasets/detection.json
```

That writes `releases/nullsec-1.0/`:

```
nullsec-1.0/
├── adapter_config.json        # copied from the trained adapter
├── <tokenizer files>          # copied if present alongside the adapter
├── fingerprint.txt            # SHA-256 over the security-defining artifacts
├── safety_layer_version.txt
├── taxonomy_version.txt
├── training_config.yaml       # snapshot of the training config used
├── MODEL_CARD.md              # snapshot of the model card
├── DATASET_CARD.md            # snapshot of the dataset card
├── safety_probes.json         # adversarial Safety Layer bypass results
├── benchmark/
│   ├── SUITE.json             # all benchmark numbers (from the real run)
│   └── raw_outputs.jsonl      # the captured model outputs the numbers came from
├── release_summary.json
└── RELEASE_SUMMARY.md         # human-readable summary, generated from measurements
```

The release run aborts (writes nothing) unless the adapter exists, the model
loads, the dataset produces real outputs, the benchmark sections are non-empty,
and the adversarial Safety Layer probes all pass. See `RELEASE_TRAINING.md`.

Everything in this directory except this README is git-ignored.
