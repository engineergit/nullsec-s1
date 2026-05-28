"""Nullsec-1 model identity and versioning.

Centralizes everything that identifies a Nullsec-1 release: semantic version,
the security taxonomy version, the Safety Layer version, supported languages and
frameworks, context window, the base it is fine-tuned from, and a reproducible
fingerprint.

The fingerprint is a SHA-256 over the deterministic artifacts that define
Nullsec-1's security behavior — the taxonomy, the verdict contract schema, the
system instruction, and the Safety Layer version. Two checkouts that produce the
same fingerprint enforce the same security contract. If a trained adapter is
present, its config is folded into the fingerprint so weight changes are
reflected as well.
"""
from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path

from nullsec.core.prompts import SYSTEM_PROMPT
from nullsec.safety.enforcement import SAFETY_LAYER_VERSION
from taxonomy import load_taxonomy

_ROOT = Path(__file__).resolve().parents[2]

# --- release identity --------------------------------------------------------
MODEL_NAME = "Nullsec-1"
MODEL_VERSION = "1.0.0"
RELEASE_TAG = "Nullsec-1.0"

# Nullsec-1 is a specialized security model fine-tuned from an open code model
# and aligned with a deterministic Security Alignment + Safety Layer. It is not
# trained from scratch.
TRAINING_BASE = os.environ.get(
    "NULLSEC_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct"
)
TRAINING_METHOD = "QLoRA (4-bit NF4) supervised fine-tuning + deterministic security alignment"

MAX_CONTEXT = int(os.environ.get("NULLSEC_MAX_CONTEXT", "32768"))

SUPPORTED_LANGUAGES = [
    "python",
    "javascript",
    "typescript",
    "solidity",
    "go",
    "rust",
    "java",
    "php",
    "ruby",
    "bash",
    "json",
    "yaml",
]

# Frameworks / ecosystems Nullsec-1 is oriented toward — AI-generated apps,
# agents, MCP tooling, and on-chain code.
SUPPORTED_FRAMEWORKS = [
    "fastapi",
    "flask",
    "express",
    "next.js",
    "react",
    "node",
    "supabase",
    "mcp",
    "langchain",
    "solana-web3.js",
    "anchor",
    "solidity-foundry",
    "hardhat",
]


@lru_cache(maxsize=1)
def taxonomy_version() -> str:
    return load_taxonomy().get("version", "unknown")


@lru_cache(maxsize=1)
def fingerprint() -> str:
    """SHA-256 of the artifacts that define Nullsec-1's security behavior."""
    h = hashlib.sha256()

    # Security taxonomy (categories + dimensions).
    tax_path = _ROOT / "taxonomy" / "taxonomy.json"
    h.update(tax_path.read_bytes())

    # Verdict contract schema.
    schema_path = _ROOT / "data" / "schemas" / "verdict.schema.json"
    h.update(schema_path.read_bytes())

    # System instruction and Safety Layer version.
    h.update(SYSTEM_PROMPT.encode("utf-8"))
    h.update(SAFETY_LAYER_VERSION.encode("utf-8"))
    h.update(MODEL_VERSION.encode("utf-8"))

    # Fold in the trained adapter config if one is mounted.
    adapter = os.environ.get("NULLSEC_ADAPTER_PATH")
    if adapter:
        cfg = Path(adapter) / "adapter_config.json"
        if cfg.exists():
            h.update(cfg.read_bytes())

    return "sha256:" + h.hexdigest()


def capabilities() -> dict:
    """Structured description of what this Nullsec-1 release can do."""
    tax = load_taxonomy()
    return {
        "detects": [c["id"] for c in tax["categories"]],
        "check_dimensions": tax["check_dimensions"],
        "actions": [
            "vulnerability_detection",
            "severity_classification",
            "exploit_scenario_reasoning",
            "secure_patch_generation",
            "production_readiness_enforcement",
        ],
        "outputs": ["structured_json_verdict", "secure_patch", "safety_layer_decision"],
        "streaming": True,
        "deterministic_safety_enforcement": True,
    }


def model_info() -> dict:
    """Payload served at GET /v1/model."""
    return {
        "model_name": MODEL_NAME,
        "version": MODEL_VERSION,
        "release_tag": RELEASE_TAG,
        "taxonomy_version": taxonomy_version(),
        "safety_layer_version": SAFETY_LAYER_VERSION,
        "fingerprint": fingerprint(),
        "training_base": TRAINING_BASE,
        "training_method": TRAINING_METHOD,
        "max_context": MAX_CONTEXT,
        "supported_languages": SUPPORTED_LANGUAGES,
        "supported_frameworks": SUPPORTED_FRAMEWORKS,
        "category_count": len(load_taxonomy()["categories"]),
    }


if __name__ == "__main__":
    print(json.dumps({**model_info(), "capabilities": capabilities()}, indent=2))
