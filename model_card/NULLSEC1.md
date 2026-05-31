# Model Card — Nullsec-1

| | |
|---|---|
| **Model name** | Nullsec-1 |
| **Release** | Nullsec-1.0 RC2/v1.1 (`version` 1.0.0), GitHub tag `v1.0.0-rc25` |
| **Type** | Security-native LLM (specialized security review model) |
| **Training base** | Qwen/Qwen2.5-Coder-7B-Instruct (Apache 2.0), config-swappable to 14B |
| **Training method** | QLoRA (4-bit NF4) supervised fine-tuning + deterministic security alignment |
| **Adapter format** | PEFT / QLoRA adapter; `adapter_model.safetensors` in the RC2/v1.1 release asset |
| **Context window** | configurable (2048 default for 24GB training; up to base limit when served) |
| **License** | Apache 2.0 |
| **Identity endpoint** | `GET /v1/model` (also `python -m nullsec.core.version`) |

## Summary

Nullsec-1 is a specialized security LLM purpose-built for securing AI-generated applications. It reviews source code and emits a single structured security verdict: vulnerabilities found (typed against the Nullsec taxonomy), severity, exploit scenario, recommended fix, and a secure patch. It is purpose-built for the failure modes of vibecoded software, autonomous agents, and MCP tooling.

**Nullsec-1 is not trained from scratch.** It is fine-tuned from an open code model and aligned with a deterministic Security Alignment Layer and Nullsec Safety Layer. Nullsec-1 proposes a verdict; the Safety Layer enforces production-readiness. The model never has the final word on whether code is safe to ship.

This model card describes the published RC2/v1.1 release assets (`v1.0.0-rc25`), not a source-only checkout. The trained adapter is distributed as a GitHub Release asset and is not committed to the source repository. Its real-model benchmark report records `111/111` outputs, detection F1 `0.9245`, false-safe rate `0.0`, and passing safety probes on the included RC2/v1.1 benchmark suite.

## Architecture and loading

Nullsec-S1 RC2/v1.1 is loaded as:

1. base model `Qwen/Qwen2.5-Coder-7B-Instruct`;
2. PEFT QLoRA adapter from `outputs/nullsec-s1-qlora`;
3. tokenizer/chat template from the adapter directory when present.

The release artifact includes `adapter_config.json`, `adapter_model.safetensors`,
tokenizer files, and `chat_template.jinja`. The simplest local inference path is
`python inference.py --file <path>` after unpacking the release artifact and
setting `NULLSEC_ADAPTER_PATH=outputs/nullsec-s1-qlora`.

Nullsec-S1 does not expose or require a hidden reasoning trace format. It emits a
final structured JSON security audit that is then passed through deterministic
alignment and Safety Layer enforcement.

## Intended use

- Pre-merge / pre-deploy security review of AI-generated and human-written code.
- Guardrail for autonomous coding agents: a non-bypassable check before generated code is shipped.
- Auditing MCP tools, wallet/transaction code, and smart contracts.
- CI security gate (`nullsec1 analyze` exits non-zero when code is not production-ready).

## Out of scope

- Not a general assistant, chatbot, or code generator (beyond secure patches for findings).
- Not a replacement for SAST/DAST tooling, manual penetration testing, or a security team. Use it as an additional, security-native layer.
- A clean verdict reduces but does not eliminate risk; see limitations.

## How production-readiness is decided

The model's `production_ready` output is advisory. The Nullsec Safety Layer (`nullsec/safety/enforcement.py`) recomputes it deterministically and permits `true` only when:

- all eight check dimensions (`auth, secrets, input_validation, rate_limits, permissions, dangerous_exec, dependency_risk, environment_exposure`) are `pass` or `not_applicable` — never `not_checked` or `fail`;
- no finding is HIGH or CRITICAL;
- `risk_score` is at or below the production threshold;
- no finding contradicts a dimension reported as `pass`.

Severity and risk are floored upward to the worst finding, so Nullsec-1 cannot under-report.

For RC2/v1.1, "production-ready" means the released adapter passed the Nullsec internal release gate on the included 111-case benchmark suite. It is not a guarantee for arbitrary real-world software and does not remove the need for independent review on critical systems.

## Training objective

Supervised fine-tuning with completion-only loss: given a system instruction defining the strict reviewer role and a user message containing code, Nullsec-1 learns to produce the verdict JSON (and only the verdict JSON). Loss is computed on the verdict tokens, not the prompt. Targets are drawn exclusively from verdicts that pass the same Security Alignment + Safety Layers used at serving time, so the training signal is internally consistent with deterministic enforcement.

## Capabilities

`GET /v1/capabilities` reports the live capability set. Nullsec-1 performs vulnerability detection, severity classification, exploit-scenario reasoning, secure-patch generation, and production-readiness enforcement across 16 taxonomy categories and 8 check dimensions. Supported languages and frameworks are listed in `nullsec/core/version.py` and at `GET /v1/model`.

## Limitations and risks

- **Release-candidate scope.** RC2/v1.1 is benchmarked on the included 111-case suite; performance on arbitrary real-world systems can differ.
- **False negatives are possible.** A clean verdict is not proof of safety.
- **False positives** can block legitimate code; the risk threshold is tunable.
- **Patch verification is structural.** The benchmark verifies patches are well-formed and do not reintroduce known-insecure patterns; compile/run/test verification is future work.
- Auto-ingested CVE/scanner examples require curation before they are used as training targets.

## Evaluation

The benchmark suite (`benchmarks/`) measures detection accuracy, false-safe rate, hallucination rate, OWASP coverage, patch correctness, and secure-generation score. Reports are produced only from real runs against real datasets. The RC2/v1.1 report is included in the `v1.0.0-rc25` GitHub Release assets. Methodology is documented in the technical report.

Security benchmarks are the focus for this release. General academic benchmarks
such as MMLU or GSM8K are not the primary target because Nullsec-S1 is designed
for application-security verdicts, not broad general knowledge or math reasoning.

## Provenance and reproducibility

Each release carries a SHA-256 fingerprint over the artifacts that define its security behavior (taxonomy, verdict schema, system instruction, Safety Layer version, and trained adapter config when present), exposed at `GET /v1/model`. Training and evaluation are reproducible from `training/config.yaml` and the benchmark runners.
