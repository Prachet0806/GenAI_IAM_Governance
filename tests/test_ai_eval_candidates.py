"""Structural probes for the unreviewed candidate evaluation corpus."""

from collections import Counter

import pytest

from common import ai_artifacts
from common.ai import provider_controls
from scripts.build_ai_eval_candidates import ATTACKS, STRATA, build_candidates
from scripts.evaluate_ai_explanations import evaluate, fixture_sha256, read_jsonl
from scripts.run_ai_eval_candidates import run, validate_cases
from tests.test_ai_artifacts import _SuccessfulClient, ai_review
from pathlib import Path


def test_candidate_corpus_is_reproducible_and_cannot_pass_release_screen():
    generated = build_candidates()
    on_disk = read_jsonl(Path("tests/fixtures/ai_eval/candidate_cases.jsonl"))
    assert generated == on_disk
    assert len({case["case_id"] for case in generated}) == 198
    assert Counter(case["dataset"] for case in generated if case["eligible"]) == {
        "synthetic": 160, "adversarial": 25,
    }
    assert {stratum: sum(stratum in case["strata"] for case in generated
                         if case["dataset"] == "synthetic" and case["eligible"])
            for stratum in STRATA} == {stratum: 20 for stratum in STRATA}
    assert sum(case["case_id"].startswith("ineligible-") for case in generated) == 8
    report = evaluate(generated, [], [])
    assert report["status"] == "BLOCKED"
    assert any("not independently reviewed" in blocker for blocker in report["blockers"])


def test_thirty_adversarial_candidate_probes_are_blocked_or_omitted():
    attacks = [case for case in build_candidates() if case["dataset"] == "adversarial"]
    assert Counter(case["attack_class"] for case in attacks) == {attack: 5 for attack in ATTACKS}
    for case in attacks:
        probe = case["probe"]
        context = case["context"]
        if probe["kind"] == "account_substitution":
            with pytest.raises(provider_controls.ApprovalRejected):
                provider_controls.provider_payload(context)
        elif "attempted_output" in probe:
            with pytest.raises(ValueError):
                ai_artifacts.validate_output(probe["attempted_output"], case["allowed_evidence_ids"])
        else:
            payload = provider_controls.provider_payload(context)
            assert all(sentinel not in str(payload) for sentinel in case["privacy_sentinels"])


def test_runner_uses_worker_boundary_only_after_review(ai_review):
    candidate = build_candidates()[0]
    with pytest.raises(ValueError, match="independent review"):
        validate_cases([candidate])
    approved_case = {**candidate, "reviewed": True}
    validate_cases([approved_case])
    approval = provider_controls.current_approval(
        model="gemini-3.8-flash", prompt=provider_controls.PROMPT_PREFIX,
    )
    fake = _SuccessfulClient()
    manifest, outputs = run([approved_case], fake, approval, "gemini-3.8-flash")
    assert manifest["fixture_sha256"] == outputs[0]["fixture_sha256"]
    assert outputs[0]["usage"]["approval_version"] == approval["approval_version"]
    assert len(outputs[0]["usage"]["provider_input_sha256"]) == 64
    assert len(fake.prompts) == 1


def test_runner_rejects_unknown_or_changed_frozen_cases():
    case = {**build_candidates()[0], "reviewed": True}
    with pytest.raises(ValueError, match="Unknown evaluation dataset"):
        validate_cases([{**case, "dataset": "other"}])
    with pytest.raises(ValueError, match="input hash"):
        validate_cases([{**case, "context": {**case["context"], "risk_level": "LOW"}}])


def test_evaluator_requires_real_adversarial_probe_coverage():
    cases = [{**case, "reviewed": True} for case in build_candidates()]
    report = evaluate(cases, [], [])
    assert not any("Adversarial probe failed" in blocker for blocker in report["blockers"])
    changed = [dict(case) for case in cases]
    attack = next(case for case in changed if case.get("attack_class") == "fabricated_citation")
    attack["probe"] = {"kind": "fabricated_citation", "attempted_output": {
        "summary": "Inspect the frozen assessment.",
        "citations": [attack["risk_assessment_id"]],
        "limitations": "Effective access was not evaluated.",
    }}
    report = evaluate(changed, [], [])
    assert any("Adversarial probe failed" in blocker for blocker in report["blockers"])


def test_evaluator_recomputes_final_provider_payload_hash():
    case = {**build_candidates()[0], "reviewed": True}
    manifest = {
        "commit_sha": "test", "worker": "lambdas.ai_explanation.handler",
        "model": "test-model", "region": "global",
        "prompt_version": case["prompt_version"], "schema_version": case["schema_version"],
        "approval_version": "test-v1", "fixture_sha256": fixture_sha256([case]),
    }
    output = {
        "case_id": case["case_id"], "input_sha256": case["input_sha256"],
        **{key: manifest[key] for key in (
            "model", "region", "prompt_version", "schema_version",
            "approval_version", "fixture_sha256",
        )},
        "output": {
            "summary": "Inspect the frozen assessment.",
            "citations": [case["risk_assessment_id"]],
            "limitations": "Effective access was not evaluated.",
        },
        "usage": {
            "approval_version": "test-v1", "provider_region": "global",
            "provider_input_sha256": "0" * 64,
            "prompt_sha256": provider_controls.prompt_sha256(provider_controls.PROMPT_PREFIX),
        },
    }
    report = evaluate([case], [output], [], run_manifest=manifest)
    assert report["datasets"]["synthetic"]["provenance_failures"] == 1
