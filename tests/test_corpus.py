"""Regression tests for the training corpus and its quality gate."""
import json

from corpus import is_curated, load_corpus, split
from nullsec.safety import align_and_enforce
from taxonomy import load_taxonomy
from training.validate_corpus import validate_example


def test_corpus_loads_and_is_nontrivial():
    ex = load_corpus()
    assert len(ex) >= 50
    assert all(is_curated(e) for e in ex)  # authored corpus is curated


def test_every_example_passes_quality_validation():
    for e in load_corpus():
        issues = validate_example(e)
        assert not issues, f"{e['id']}: {issues}"


def test_safety_layer_consistency_is_total():
    for e in load_corpus():
        res = align_and_enforce(json.dumps(e["verdict"]))
        assert res.production_ready == e["expected_production_ready"], e["id"]


def test_all_taxonomy_categories_covered():
    cats = {c["id"] for c in load_taxonomy()["categories"]}
    covered = set()
    for e in load_corpus():
        for f in e["verdict"].get("findings", []):
            covered.add(f["category"])
    assert cats <= covered, f"uncovered: {cats - covered}"


def test_corpus_has_negative_examples():
    # a corpus that is 100% vulnerable teaches the model to always flag.
    ex = load_corpus()
    secure = [e for e in ex if e["expected_production_ready"]]
    assert secure, "no production_ready (secure) examples present"


def test_split_is_deterministic():
    ex = load_corpus()
    a_tr, a_ev = split(ex, 0.2, 42)
    b_tr, b_ev = split(ex, 0.2, 42)
    assert [e["id"] for e in a_ev] == [e["id"] for e in b_ev]
    assert len(a_ev) + len(a_tr) == len(ex)


def test_validator_rejects_missing_patch():
    ex = load_corpus()
    bad = json.loads(json.dumps(next(e for e in ex if e["verdict"]["findings"])))
    bad["verdict"]["findings"][0]["secure_patch"] = ""
    assert any("secure_patch" in i for i in validate_example(bad))


def test_stats_count_equals_prepared_dataset_count():
    """Single source of truth: training sees exactly what stats reports."""
    from training.dataset_stats import compute
    from training.prepare_dataset import build_records

    examples = load_corpus()
    stats = compute(examples, 0.2, 42)
    records = build_records()  # default flags: curated only

    assert stats["total_examples"] == len(examples)
    assert len(records) == len(examples), "every curated example must yield a record (no silent drops)"
    assert len(records) == stats["total_examples"]


def test_prepared_split_matches_stats_split():
    from training.dataset_stats import compute
    from corpus import split

    examples = load_corpus()
    stats = compute(examples, 0.2, 42)
    train_ex, eval_ex = split(examples, 0.2, 42)
    assert len(train_ex) == stats["train_eval_split"]["train"]
    assert len(eval_ex) == stats["train_eval_split"]["eval"]


def test_environment_exposure_category_present_and_covered():
    from taxonomy import category_ids
    assert "ENVIRONMENT_EXPOSURE" in category_ids()
    covered = {f["category"] for e in load_corpus() for f in e["verdict"].get("findings", [])}
    assert "ENVIRONMENT_EXPOSURE" in covered


def test_no_input_validation_category():
    # INPUT_VALIDATION is a dimension, not a category.
    from taxonomy import category_ids
    assert "INPUT_VALIDATION" not in category_ids()


def test_curated_ingested_examples_are_valid_and_sourced():
    """Any shipped curated_ingested example must validate and carry provenance +
    a source reference (auditability of the curation sprint output)."""
    from corpus import load_corpus
    ingested = [e for e in load_corpus(include_ingested=True)
                if e.get("provenance") == "curated_ingested"]
    for e in ingested:
        assert not validate_example(e), f"{e['id']}: {validate_example(e)}"
        assert e.get("source"), f"{e['id']} missing source"
        # references block present (may have null fields, but must exist)
        assert "references" in e, f"{e['id']} missing references"


def test_ingested_only_counts_as_curated_with_flag():
    from corpus import load_corpus
    base = load_corpus()
    with_ing = load_corpus(include_ingested=True)
    # if any ingested data is present it must not leak into the default load
    assert all(e.get("provenance") != "curated_ingested" for e in base)
    assert len(with_ing) >= len(base)
