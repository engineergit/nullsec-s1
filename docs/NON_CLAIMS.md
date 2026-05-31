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

## Release assets, not source commits

The trained adapter and benchmark reports for RC2/v1.1 are published as GitHub
Release assets (`v1.0.0-rc25`). They are deliberately **not committed** to this
source repo (trained weights ship as release assets; the repo stays lightweight).
The in-repo claim validator gates on what is present on disk: an unpacked release
bundle permits release-backed claims locally; a fresh source checkout without the
adapter/report remains conservative. This is intentional.

## Benchmark numbers are release-artifact claims

README benchmark numbers are tied to the `v1.0.0-rc25` release artifacts, not to
hand-entered source files. Benchmark numbers come only from real runs
(`--mode model`, or `--mode replay` over captured real outputs); a case with no
output is scored as a real miss, never a synthetic pass. The source repo does not
commit large result bundles or trained weights.

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
rate, adequate detection quality, and independent review. RC2/v1.1 satisfies this
bar on the included release benchmark suite. That does not make the model a
guarantee for arbitrary real-world code. (Note: the verdict field
`production_ready` is a separate, well-defined per-analysis decision computed by
the Safety Layer; it is not an absolute security guarantee.)

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
