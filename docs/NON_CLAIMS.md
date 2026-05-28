# What Nullsec S1 Does Not Claim

Nullsec S1 aims to be taken seriously because it is **rigorous**, not because it
exaggerates. This document states plainly what the project does *not* claim today.
Most of these constraints are enforced in code by `scripts/validate_claims.py`,
which scans public docs and fails CI on any unsubstantiated assertion.

---

## Not trained from scratch

Nullsec S1 fine-tunes an open code model (`Qwen/Qwen2.5-Coder-7B-Instruct`,
Apache 2.0) with QLoRA. It does **not** pretrain a foundation model from scratch,
and it does not claim to.

## Not yet a trained model release

As of this snapshot there is **no trained adapter** on disk
(`outputs/.../adapter_config.json` + weights). The system is *training-ready*: the
pipeline, corpus, schema, and safety layers are real and runnable. Until a real
GPU training run produces an adapter, the claim validator **forbids** "trained
model" wording and the repo will not assert it.

## Not yet benchmarked with real model outputs

There is **no real-model benchmark report**. The benchmark suite produces numbers
only from real runs (`--mode model`, or `--mode replay` over captured real
outputs), and a case with no output is scored as a real miss. No precomputed
metrics ship with the repo. Until a real run exists, the claim validator
**forbids** "benchmarked" and real-model evaluation wording. In particular, the
repo states **no** detection F1, precision, recall, false-safe rate, or any other
performance number — because none have been measured.

## Not a replacement for human security review

Nullsec S1 is an additional, security-native layer. It does **not** replace human
security engineers, manual penetration testing, threat modeling, or established
SAST/DAST tooling. Use it alongside them, not instead of them.

## Not guaranteed to catch every vulnerability

A clean verdict reduces risk; it does **not** prove the absence of
vulnerabilities. False negatives are possible. The deterministic Safety Layer
guarantees a consistent, non-bypassable *decision rule* over a verdict — it does
not guarantee the model found every issue worth finding.

## No "first / only / best" claims

Statements about being the "first", "only", or "best" LLM/system of its kind
**cannot** be validated from repository artifacts — no local file can substantiate
a claim about the rest of the world. The claim validator never auto-permits these.
They are not made here and would need independent support if ever stated.

## "Production-ready model" requires real evidence

The strongest claim — that the *model* is suitable for production use — is gated
on the highest bar: a trained adapter, a real-model benchmark, a zero false-safe
rate, and adequate detection quality, plus independent review. None of that exists
yet, so the claim is forbidden. (Note: the verdict field `production_ready` is a
separate, well-defined per-analysis decision computed by the Safety Layer; it is
not a claim about the model itself.)

---

## How this is enforced

```bash
python scripts/validate_claims.py          # status table of permitted/forbidden claims
python scripts/validate_claims.py --check   # fails if README/RELEASE_SUMMARY overclaim
```

The set of permitted claims is derived purely from artifacts on disk
(`scripts/_artifacts.py`): a trained adapter, a real-model benchmark report with a
non-empty result set and `run_mode: "model"`, passing safety probes, and a release
bundle. As those artifacts come into existence (see [`ROADMAP.md`](ROADMAP.md)),
the corresponding claims unlock — and not before.
