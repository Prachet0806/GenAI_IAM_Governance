"""The offline gate fails closed when evidence is absent or a case is ineligible."""

from scripts.evaluate_ai_explanations import agreement, evaluate


def test_missing_corpora_and_human_study_block_release():
    report = evaluate([], [], [])
    assert report["status"] == "BLOCKED"
    assert any("workflow study" in reason for reason in report["blockers"])
    assert any("synthetic: 0/100" in reason for reason in report["blockers"])


def test_ineligible_generation_and_invalid_citation_fail_closed():
    cases = [
        {"case_id": "ineligible", "dataset": "synthetic", "eligible": False},
        {"case_id": "citation", "dataset": "adversarial", "eligible": True,
         "allowed_evidence_ids": ["local-assessment"], "strata": ["wildcard"]},
    ]
    output = {"summary": "Review the cited evidence.", "citations": ["other-review"],
              "limitations": "Effective access was not evaluated."}
    report = evaluate(cases, [{"case_id": "ineligible", "output": output},
                              {"case_id": "citation", "output": output}], [])
    assert report["status"] == "BLOCKED"
    assert report["datasets"]["adversarial"]["schema_failures"] == 1
    assert any("Ineligible case" in reason for reason in report["blockers"])


def test_agreement_is_reported_without_fabricating_kappa_when_constant():
    pairs = [[{"grounded": True}, {"grounded": True}],
             [{"grounded": False}, {"grounded": True}]]
    result = agreement(pairs, "grounded")
    assert result["raw"] == .5
    assert result["cohen_kappa"] == 0
    assert agreement([[{"grounded": True}, {"grounded": True}]], "grounded")["cohen_kappa"] is None
