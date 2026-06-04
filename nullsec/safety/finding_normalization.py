"""Deterministic response normalization for common security sink confusions.

This layer runs after model/rule output is aligned and before API responses are
returned. It does not replace model analysis; it corrects high-confidence sink
classification mistakes and removes a few known false positives.
"""
from __future__ import annotations

import copy
import re
from typing import Any

Severity = str

_RISK_BY_SEVERITY = {
    "CRITICAL": 90,
    "HIGH": 70,
    "MEDIUM": 40,
    "LOW": 20,
    "INFO": 0,
}
_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

_UNTRUSTED = r"(?:req\.(?:body|query|params)|params\b|request\.(?:body|query|params))"
_FILESYSTEM_SINK_RE = re.compile(
    rf"(?:fs\.(?:readFileSync|readFile|createReadStream)\s*\(\s*{_UNTRUSTED}"
    rf"|(?:^|[^\w])open\s*\(\s*{_UNTRUSTED}"
    rf"|path\.(?:join|resolve|normalize)\s*\([^)]*{_UNTRUSTED})",
    re.IGNORECASE | re.DOTALL,
)
_EVAL_RCE_RE = re.compile(
    rf"(?:\beval\s*\(\s*{_UNTRUSTED}"
    rf"|\bnew\s+Function\s*\(\s*{_UNTRUSTED}"
    rf"|\bFunction\s*\(\s*{_UNTRUSTED}"
    rf"|\bvm\.runInNewContext\s*\(\s*{_UNTRUSTED})",
    re.IGNORECASE | re.DOTALL,
)
_COMMAND_INJECTION_RE = re.compile(
    rf"(?:\bexec(?:Sync)?\s*\(\s*{_UNTRUSTED}"
    rf"|\bspawn\s*\([^)]*{_UNTRUSTED}"
    rf"|\bchild_process\.(?:exec|execSync|spawn)\s*\([^)]*{_UNTRUSTED})",
    re.IGNORECASE | re.DOTALL,
)
_STATIC_EXEC_RE = re.compile(
    r"\bexec\s*\(\s*(['\"])(?P<cmd>(?:npm run build|git status))\1\s*\)",
    re.IGNORECASE,
)
_HARDCODED_SECRET_RE = re.compile(
    r"(?:sk-[A-Za-z0-9][A-Za-z0-9_\-]{8,}|ghp_[A-Za-z0-9_]{8,}|xoxb-[A-Za-z0-9\-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)
_ENV_SECRET_RE = re.compile(r"process\.env\.[A-Z0-9_]*(?:SECRET|TOKEN|API_KEY|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*")
_ENV_SECRET_RESPONSE_RE = re.compile(
    r"(?:res\.json|response\.json|Response\.json)\s*\([^)]*process\.env\.[A-Z0-9_]+",
    re.IGNORECASE | re.DOTALL,
)
_CLIENT_ENV_SECRET_RE = re.compile(
    r"(?:['\"]use client['\"]|NEXT_PUBLIC_|PUBLIC_)[\s\S]{0,200}process\.env\.[A-Z0-9_]+",
    re.IGNORECASE,
)
_SQLI_RE = re.compile(
    rf"(?:\b(?:db\.)?(?:query|execute|raw)\s*\(\s*`[^`]*\$\{{\s*{_UNTRUSTED}[\s\S]*?`"
    rf"|\b(?:db\.)?(?:query|execute|raw)\s*\(\s*['\"][^'\"]*(?:SELECT|UPDATE|DELETE|INSERT)[^'\"]*['\"]\s*\+[^)]*{_UNTRUSTED})",
    re.IGNORECASE | re.DOTALL,
)
_XSS_RE = re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{[^}]*__html\s*:\s*req\.", re.IGNORECASE | re.DOTALL)
_SSRF_RE = re.compile(r"\bfetch\s*\(\s*(?:req\.(?:body|query|params)|params\b)", re.IGNORECASE | re.DOTALL)


def _line_for(content: str, index: int) -> int:
    return content[:index].count("\n") + 1


def _finding(
    *,
    title: str,
    category: str,
    severity: Severity,
    cwe: str,
    file: str,
    line: int,
    description: str,
    recommendation: str,
) -> dict[str, Any]:
    return {
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": "HIGH",
        "file": file,
        "line": line,
        "description": description,
        "cwe": cwe,
        "exploit_scenario": description,
        "recommended_fix": recommendation,
        "recommendation": recommendation,
        "secure_patch": "",
    }


def _rule_findings(file_content: str, filename: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if match := _FILESYSTEM_SINK_RE.search(file_content):
        findings.append(
            _finding(
                title="PATH_TRAVERSAL",
                category="UNSAFE_FILE_UPLOAD",
                severity="HIGH",
                cwe="CWE-22",
                file=filename,
                line=_line_for(file_content, match.start()),
                description="Untrusted user-controlled file path reaches filesystem access.",
                recommendation="Normalize and restrict paths to an allowed base directory; reject ../ and absolute paths.",
            )
        )

    if match := _EVAL_RCE_RE.search(file_content):
        findings.append(
            _finding(
                title="REMOTE_CODE_EXECUTION",
                category="COMMAND_INJECTION",
                severity="CRITICAL",
                cwe="CWE-94",
                file=filename,
                line=_line_for(file_content, match.start()),
                description="User-controlled input reaches dynamic code execution.",
                recommendation="Never execute user-controlled code. Use a sandboxed allowlisted interpreter if absolutely required.",
            )
        )

    if match := _COMMAND_INJECTION_RE.search(file_content):
        findings.append(
            _finding(
                title="COMMAND_INJECTION",
                category="COMMAND_INJECTION",
                severity="CRITICAL",
                cwe="CWE-78",
                file=filename,
                line=_line_for(file_content, match.start()),
                description="User-controlled input reaches OS command execution.",
                recommendation="Do not pass user-controlled input to shell commands; use fixed commands with validated argument arrays.",
            )
        )
    elif match := _STATIC_EXEC_RE.search(file_content):
        findings.append(
            _finding(
                title="UNSAFE_PROCESS_EXECUTION",
                category="DANGEROUS_SHELL_COMMAND",
                severity="LOW",
                cwe="CWE-78",
                file=filename,
                line=_line_for(file_content, match.start()),
                description="Static shell command execution detected. Lower risk because no user-controlled input is used, but prefer spawnFile/spawn with arg arrays.",
                recommendation="Prefer spawnFile/spawn with fixed executable and argument arrays; avoid shell parsing where possible.",
            )
        )

    if _HARDCODED_SECRET_RE.search(file_content) or _ENV_SECRET_RESPONSE_RE.search(file_content) or _CLIENT_ENV_SECRET_RE.search(file_content):
        match = _HARDCODED_SECRET_RE.search(file_content) or _ENV_SECRET_RESPONSE_RE.search(file_content) or _CLIENT_ENV_SECRET_RE.search(file_content)
        findings.append(
            _finding(
                title="EXPOSED_SECRET",
                category="EXPOSED_SECRET",
                severity="CRITICAL",
                cwe="CWE-798",
                file=filename,
                line=_line_for(file_content, match.start()) if match else 1,
                description="A secret or environment credential is exposed to client-visible output.",
                recommendation="Keep secrets server-side only; never return secret environment values to clients.",
            )
        )

    if match := _SQLI_RE.search(file_content):
        findings.append(
            _finding(
                title="SQL_INJECTION",
                category="SQL_INJECTION",
                severity="CRITICAL",
                cwe="CWE-89",
                file=filename,
                line=_line_for(file_content, match.start()),
                description="User-controlled input is interpolated into a SQL query.",
                recommendation="Use parameterized queries or query builders that bind values separately from SQL text.",
            )
        )

    if match := _XSS_RE.search(file_content):
        findings.append(
            _finding(
                title="XSS",
                category="XSS",
                severity="HIGH",
                cwe="CWE-79",
                file=filename,
                line=_line_for(file_content, match.start()),
                description="User-controlled HTML reaches dangerouslySetInnerHTML.",
                recommendation="Avoid raw HTML sinks; sanitize with a trusted sanitizer and prefer escaped rendering.",
            )
        )

    if match := _SSRF_RE.search(file_content):
        findings.append(
            _finding(
                title="SSRF",
                category="SSRF",
                severity="HIGH",
                cwe="CWE-918",
                file=filename,
                line=_line_for(file_content, match.start()),
                description="User-controlled URL reaches a server-side fetch call.",
                recommendation="Allowlist outbound destinations and reject private, loopback, and metadata IP ranges.",
            )
        )

    return findings


def _signature(finding: dict[str, Any]) -> tuple[str, str, int | None]:
    label = str(finding.get("title") or finding.get("category") or "")
    return label, str(finding.get("file") or ""), finding.get("line")


def _is_env_secret_false_positive(finding: dict[str, Any], file_content: str) -> bool:
    label = str(finding.get("title") or finding.get("category") or "").upper()
    if label != "EXPOSED_SECRET":
        return False
    if not _ENV_SECRET_RE.search(file_content):
        return False
    return not (
        _HARDCODED_SECRET_RE.search(file_content)
        or _ENV_SECRET_RESPONSE_RE.search(file_content)
        or _CLIENT_ENV_SECRET_RE.search(file_content)
    )


def normalizeFinding(finding: dict[str, Any], fileContent: str, filename: str = "input") -> dict[str, Any] | None:  # noqa: N802
    """Normalize one model finding against file content.

    Returns None when a finding is a deterministic false positive, currently for
    env-secret reads that are not exposed or hardcoded.
    """
    if _is_env_secret_false_positive(finding, fileContent):
        return None

    normalized = copy.deepcopy(finding)
    normalized.setdefault("title", normalized.get("category", "Security finding"))
    normalized.setdefault("recommendation", normalized.get("recommended_fix", ""))

    rule_findings = _rule_findings(fileContent, str(normalized.get("file") or filename))
    if not rule_findings:
        return normalized

    current_label = str(normalized.get("title") or normalized.get("category") or "").upper()
    for rule in rule_findings:
        if rule["title"] in {
            current_label,
            "PATH_TRAVERSAL" if current_label in {"DANGEROUS_SHELL_COMMAND", "UNSAFE_FILE_UPLOAD"} else "",
            "REMOTE_CODE_EXECUTION" if current_label in {"COMMAND_INJECTION", "DANGEROUS_SHELL_COMMAND"} else "",
            "UNSAFE_PROCESS_EXECUTION" if current_label in {"COMMAND_INJECTION", "DANGEROUS_SHELL_COMMAND"} else "",
        }:
            return rule
    return normalized


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | None]] = set()
    for finding in findings:
        sig = _signature(finding)
        if sig in seen:
            continue
        seen.add(sig)
        out.append(finding)
    return out


def _recalculate_risk(payload: dict[str, Any]) -> None:
    findings = payload.get("findings") or []
    if not findings:
        payload["risk_score"] = 0
        payload["severity"] = "INFO"
        payload["production_ready"] = True
        if isinstance(payload.get("_safety_layer"), dict):
            payload["_safety_layer"]["production_ready"] = True
            payload["_safety_layer"]["blocking_reasons"] = []
        return

    max_sev = max((str(f.get("severity", "INFO")).upper() for f in findings), key=lambda sev: _SEVERITY_ORDER.get(sev, 0))
    payload["severity"] = max_sev
    payload["risk_score"] = _RISK_BY_SEVERITY.get(max_sev, 0)
    if _SEVERITY_ORDER.get(max_sev, 0) >= _SEVERITY_ORDER["HIGH"]:
        payload["production_ready"] = False
        if isinstance(payload.get("_safety_layer"), dict):
            payload["_safety_layer"]["production_ready"] = False


def normalize_verdict_payload(payload: dict[str, Any], file_content: str, filename: str = "input") -> dict[str, Any]:
    """Apply deterministic finding normalization and risk recalculation."""
    normalized = copy.deepcopy(payload)
    existing: list[dict[str, Any]] = []
    for finding in normalized.get("findings") or []:
        clean = normalizeFinding(finding, file_content, filename)
        if clean is not None:
            existing.append(clean)

    deterministic = _rule_findings(file_content, filename)
    normalized["findings"] = _dedupe([*existing, *deterministic])
    normalized["affected_files"] = sorted({str(f.get("file") or filename) for f in normalized["findings"]})
    _recalculate_risk(normalized)
    return normalized
