"""Metrics for benchmarking a Nullsec verdict against labeled ground truth.

Pure functions, no ML dependency, so the metrics are unit-testable on their own.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from nullsec.core.models import Verdict
from taxonomy import severity_rank


@dataclass
class CaseScore:
    case_id: str
    json_valid: bool
    detected: set[str] = field(default_factory=set)
    expected: set[str] = field(default_factory=set)
    true_pos: int = 0
    false_pos: int = 0
    false_neg: int = 0
    severity_ok: bool = False
    verdict_ok: bool = False
    patch_quality: float = 0.0  # 0..1 heuristic


def score_case(case: dict, verdict: Verdict | None, json_valid: bool) -> CaseScore:
    expected = set(case.get("expected_categories", []))
    cs = CaseScore(case_id=case["id"], json_valid=json_valid, expected=expected)
    if not json_valid or verdict is None:
        cs.false_neg = len(expected)
        return cs

    detected = {f.category for f in verdict.findings}
    cs.detected = detected
    cs.true_pos = len(detected & expected)
    cs.false_pos = len(detected - expected)
    cs.false_neg = len(expected - detected)

    # Severity: model's overall severity must be >= expected_min_severity.
    exp_sev = case.get("expected_min_severity", "INFO")
    cs.severity_ok = severity_rank(verdict.severity) >= severity_rank(exp_sev)

    # Verdict (production-readiness) accuracy.
    cs.verdict_ok = verdict.production_ready == case["expected_production_ready"]

    # Patch quality heuristic: fraction of findings carrying a non-trivial,
    # diff-shaped secure_patch.
    if verdict.findings:
        good = sum(
            1
            for f in verdict.findings
            if len(f.secure_patch.strip()) > 10
            and any(tok in f.secure_patch for tok in ("+", "-", "def ", "=", "("))
        )
        cs.patch_quality = good / len(verdict.findings)
    else:
        cs.patch_quality = 1.0 if not expected else 0.0
    return cs


@dataclass
class Aggregate:
    n: int = 0
    json_valid: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    severity_ok: int = 0
    verdict_ok: int = 0
    patch_quality_sum: float = 0.0

    def add(self, cs: CaseScore) -> None:
        self.n += 1
        self.json_valid += int(cs.json_valid)
        self.tp += cs.true_pos
        self.fp += cs.false_pos
        self.fn += cs.false_neg
        self.severity_ok += int(cs.severity_ok)
        self.verdict_ok += int(cs.verdict_ok)
        self.patch_quality_sum += cs.patch_quality

    def report(self) -> dict:
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0
        recall = self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        return {
            "cases": self.n,
            "json_validity": round(self.json_valid / self.n, 4) if self.n else 0,
            "detection_precision": round(precision, 4),
            "detection_recall": round(recall, 4),
            "detection_f1": round(f1, 4),
            "false_positives": self.fp,
            "false_negatives": self.fn,
            "severity_accuracy": round(self.severity_ok / self.n, 4) if self.n else 0,
            "verdict_accuracy": round(self.verdict_ok / self.n, 4) if self.n else 0,
            "avg_patch_quality": round(self.patch_quality_sum / self.n, 4)
            if self.n
            else 0,
        }


# ---------------------------------------------------------------------------
# Extended metric families for the productized benchmark suite.
# Every function below computes over REAL Nullsec-1 outputs supplied by the
# harness. None of them fabricate or assume results.
# ---------------------------------------------------------------------------
from taxonomy import category_index  # noqa: E402


def detection_over(cases, verdicts) -> dict:
    """Vulnerability detection accuracy across a labeled dataset.

    `verdicts` maps case_id -> (Verdict|None, aligned_bool).
    """
    agg = Aggregate()
    for case in cases:
        v, ok = verdicts.get(case["id"], (None, False))
        agg.add(score_case(case, v, ok))
    return agg.report()


def false_safe_rate(cases, verdicts) -> dict:
    """Fraction of genuinely-unsafe cases that ended up marked production_ready.

    This is the most safety-critical metric: a false-safe is Nullsec-1 (after the
    Safety Layer) declaring vulnerable code shippable. The Safety Layer is
    designed to drive this to zero.
    """
    unsafe = [c for c in cases if not c["expected_production_ready"]]
    false_safe = 0
    unscored = 0
    for c in unsafe:
        v, ok = verdicts.get(c["id"], (None, False))
        if not ok or v is None:
            unscored += 1
            continue
        if v.production_ready:  # Safety-Layer-enforced value
            false_safe += 1
    scored = len(unsafe) - unscored
    return {
        "unsafe_cases": len(unsafe),
        "scored": scored,
        "unscored_no_output": unscored,
        "false_safe_count": false_safe,
        "false_safe_rate": round(false_safe / scored, 4) if scored else None,
    }


def hallucination_rate(cases, verdicts) -> dict:
    """Rate at which Nullsec-1 reports findings on code with no expected
    vulnerability (i.e. invents issues). Computed only over cases labeled clean
    (no expected categories)."""
    clean = [c for c in cases if not c.get("expected_categories")]
    flagged = 0
    hallucinated_findings = 0
    scored = 0
    for c in clean:
        v, ok = verdicts.get(c["id"], (None, False))
        if not ok or v is None:
            continue
        scored += 1
        if v.findings:
            flagged += 1
            hallucinated_findings += len(v.findings)
    return {
        "clean_cases": len(clean),
        "scored": scored,
        "clean_cases_flagged": flagged,
        "hallucinated_findings": hallucinated_findings,
        "hallucination_rate": round(flagged / scored, 4) if scored else None,
    }


def owasp_coverage(cases, verdicts) -> dict:
    """Per-OWASP-Top-10 detection recall. Each case carries an `owasp` tag.
    Coverage = fraction of represented OWASP categories with recall > 0."""
    by_owasp: dict[str, dict] = {}
    for c in cases:
        tag = c.get("owasp")
        if not tag or not c.get("expected_categories"):
            continue
        v, ok = verdicts.get(c["id"], (None, False))
        detected = {f.category for f in v.findings} if (ok and v) else set()
        expected = set(c["expected_categories"])
        slot = by_owasp.setdefault(tag, {"expected": 0, "detected": 0, "cases": 0})
        slot["cases"] += 1
        slot["expected"] += len(expected)
        slot["detected"] += len(detected & expected)
    per = {
        tag: {
            "cases": s["cases"],
            "recall": round(s["detected"] / s["expected"], 4) if s["expected"] else None,
        }
        for tag, s in sorted(by_owasp.items())
    }
    represented = len(per)
    covered = sum(1 for s in per.values() if (s["recall"] or 0) > 0)
    return {
        "owasp_categories_represented": represented,
        "owasp_categories_with_detection": covered,
        "coverage": round(covered / represented, 4) if represented else None,
        "per_category": per,
    }


def patch_correctness(cases, verdicts) -> dict:
    """Structural patch-correctness over findings that should carry a fix.

    Without a sandbox we verify structure, not runtime behavior: a patch counts
    as structurally correct when it is non-trivial, diff- or code-shaped, and
    does not re-introduce a known-insecure signal token for its category. Deeper
    semantic/compile/test verification of patches is tracked as future work.
    """
    total = 0
    structurally_correct = 0
    for c in cases:
        v, ok = verdicts.get(c["id"], (None, False))
        if not ok or v is None:
            continue
        for f in v.findings:
            total += 1
            patch = (f.secure_patch or "").strip()
            if len(patch) <= 10:
                continue
            shaped = any(tok in patch for tok in ("+", "-", "def ", "=", "(", "{"))
            signals = category_index().get(f.category, {}).get("signals", [])
            reintroduces = any(sig and sig in patch for sig in signals)
            if shaped and not reintroduces:
                structurally_correct += 1
    return {
        "findings_with_required_patch": total,
        "structurally_correct": structurally_correct,
        "patch_correctness": round(structurally_correct / total, 4) if total else None,
        "note": "structural check only; runtime/compile verification is future work",
    }


def per_category_recall(cases, verdicts) -> dict:
    """Detection recall per taxonomy category, over cases that expect it.

    For each category, recall = (cases where the category was expected AND
    detected) / (cases where it was expected). Surfaces exactly which categories
    the model is weak on, which OWASP coverage alone does not show.
    """
    expected_by_cat: dict[str, int] = {}
    detected_by_cat: dict[str, int] = {}
    for c in cases:
        v, ok = verdicts.get(c["id"], (None, False))
        detected = {f.category for f in v.findings} if (ok and v) else set()
        for cat in c.get("expected_categories", []):
            expected_by_cat[cat] = expected_by_cat.get(cat, 0) + 1
            if cat in detected:
                detected_by_cat[cat] = detected_by_cat.get(cat, 0) + 1
    per = {
        cat: {
            "expected": n,
            "detected": detected_by_cat.get(cat, 0),
            "recall": round(detected_by_cat.get(cat, 0) / n, 4) if n else None,
        }
        for cat, n in sorted(expected_by_cat.items())
    }
    weak = sorted(cat for cat, s in per.items() if (s["recall"] or 0) < 1.0)
    return {
        "categories_evaluated": len(per),
        "per_category": per,
        "categories_below_full_recall": weak,
    }


def failed_case_ids(cases, verdicts) -> dict:
    """List case ids the model got wrong, with the reason, for triage.

    A case fails if: it produced no alignable output, missed an expected
    category, hallucinated a category on a clean case, or the Safety-Layer
    production_ready verdict disagrees with ground truth.
    """
    failures: list[dict] = []
    for c in cases:
        v, ok = verdicts.get(c["id"], (None, False))
        expected = set(c.get("expected_categories", []))
        reasons: list[str] = []
        if not ok or v is None:
            reasons.append("no_alignable_output")
            failures.append({"id": c["id"], "reasons": reasons})
            continue
        detected = {f.category for f in v.findings}
        missed = expected - detected
        if missed:
            reasons.append(f"missed:{sorted(missed)}")
        if not expected and detected:
            reasons.append(f"hallucinated:{sorted(detected)}")
        if v.production_ready != c["expected_production_ready"]:
            reasons.append(
                f"verdict:{v.production_ready}!=expected:{c['expected_production_ready']}"
            )
        if reasons:
            failures.append({"id": c["id"], "reasons": reasons})
    return {"failed_count": len(failures), "failed": failures}


def secure_generation_score(cases, verdicts) -> dict:
    """Whether the secure code Nullsec-1 generates (its patches) is free of known
    insecure signal tokens from the taxonomy. A proxy for not introducing new
    vulnerabilities while fixing one."""
    patches = 0
    clean = 0
    all_signals = []
    for cat in category_index().values():
        all_signals.extend(cat.get("signals", []))
    for c in cases:
        v, ok = verdicts.get(c["id"], (None, False))
        if not ok or v is None:
            continue
        for f in v.findings:
            patch = (f.secure_patch or "").strip()
            if len(patch) <= 10:
                continue
            patches += 1
            # only inspect added lines (those starting with '+') when diff-shaped
            added = "\n".join(
                ln for ln in patch.splitlines() if ln.startswith("+") or not ln.startswith("-")
            )
            if not any(sig and sig in added for sig in all_signals):
                clean += 1
    return {
        "patches_evaluated": patches,
        "clean_of_insecure_signals": clean,
        "secure_generation_score": round(clean / patches, 4) if patches else None,
    }
