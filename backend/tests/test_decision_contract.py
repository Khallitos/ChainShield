"""Decision-contract tests.

These tests prove the *contract shape*: validated typed finite bounded inputs, two
distinct legacy policies (evaluation vs runtime), a separately versioned revised
policy, mandatory evidence that ML cannot downgrade, honest model status, and parity
across the three real consumers (evaluator adapter, runtime scorer, install hook).

Scope note (honest): tests that feed numeric ML scores validate POLICY ARITHMETIC,
not the original learned RandomForest. No serialised model object is ever
unpickled on the host (see BLOCKERS B1); a synthetic provider fixture is used only
where inference is required, and it is labelled as such.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

import pytest

from app.policy.decision_contract import (
    POLICY_LEGACY_EVAL,
    POLICY_LEGACY_RUNTIME,
    POLICY_REVISED,
    POLICY_VERSION_LEGACY_EVAL,
    POLICY_VERSION_LEGACY_RUNTIME,
    POLICY_VERSION_REVISED,
    Action,
    Evidence,
    EvidenceError,
    MandatoryViolation,
    ModelStatus,
    Policy,
    PolicyError,
    Verdict,
    VerdictLevel,
    decide,
)


# ── Slice A: validated typed finite bounded inputs ────────────────────────────

def test_rule_score_above_one_rejected():
    with pytest.raises(EvidenceError):
        Evidence(rule_score=1.5, ml_score=None, model_status=ModelStatus.ABSENT)


def test_rule_score_nan_rejected():
    with pytest.raises(EvidenceError):
        Evidence(rule_score=float("nan"), ml_score=None, model_status=ModelStatus.ABSENT)


def test_ml_score_inf_rejected():
    with pytest.raises(EvidenceError):
        Evidence(rule_score=0.1, ml_score=float("inf"), model_status=ModelStatus.LOADED)


def test_ml_score_out_of_range_rejected():
    with pytest.raises(EvidenceError):
        Evidence(rule_score=0.1, ml_score=1.2, model_status=ModelStatus.LOADED)


def test_loaded_status_requires_ml_score():
    """model_status='loaded' with no score is contradictory → explicit error."""
    with pytest.raises(EvidenceError):
        Evidence(rule_score=0.1, ml_score=None, model_status=ModelStatus.LOADED)


def test_ml_score_with_absent_status_rejected():
    with pytest.raises(EvidenceError):
        Evidence(rule_score=0.1, ml_score=0.5, model_status=ModelStatus.ABSENT)


def test_negative_score_rejected():
    with pytest.raises(EvidenceError):
        Evidence(rule_score=-0.01, ml_score=None, model_status=ModelStatus.ABSENT)


# ── Slice B: two distinct legacy policies + revised policy ────────────────────

def test_legacy_eval_has_no_post_fusion_cap_and_single_cut():
    """Evaluation hybrid: 0.4*rule+0.6*ml, one 0.60 cut, NO trusted cap.

    rule=0.88, ml=0.10 -> fused 0.412 < 0.60 (a fused miss), while the same rule
    score alone is >= 0.60 (a rule-cut hit). This is the corrected FN logic: a
    fused miss is NOT by construction a rule miss.
    """
    ev = Evidence(rule_score=0.88, ml_score=0.10, model_status=ModelStatus.LOADED)
    v = decide(ev, POLICY_LEGACY_EVAL)
    assert v.policy_version == POLICY_VERSION_LEGACY_EVAL
    assert v.score == pytest.approx(0.412)
    assert v.verdict == VerdictLevel.ALLOW

    rule_only = Evidence(rule_score=0.88, ml_score=None, model_status=ModelStatus.ABSENT)
    assert decide(rule_only, POLICY_LEGACY_EVAL).verdict == VerdictLevel.BLOCK


def test_legacy_eval_has_no_trusted_cap():
    """Same fused score under exact-trusted must NOT be capped in eval policy."""
    ev = Evidence(
        rule_score=0.90,
        ml_score=0.90,
        model_status=ModelStatus.LOADED,
        baseline_signals={"exact_trusted_match": True},
    )
    v = decide(ev, POLICY_LEGACY_EVAL)
    assert v.score == pytest.approx(0.90)  # no cap
    assert v.verdict == VerdictLevel.BLOCK


def test_legacy_runtime_applies_trusted_cap():
    """Production runtime: exact-trusted with no drift signals is capped to 0.25."""
    ev = Evidence(
        rule_score=0.90,
        ml_score=0.90,
        model_status=ModelStatus.LOADED,
        baseline_signals={"exact_trusted_match": True},
    )
    v = decide(ev, POLICY_LEGACY_RUNTIME)
    assert v.policy_version == POLICY_VERSION_LEGACY_RUNTIME
    assert v.score == pytest.approx(0.25)
    assert v.verdict == VerdictLevel.ALLOW


def test_legacy_runtime_cap_not_applied_when_drift_present():
    ev = Evidence(
        rule_score=0.90,
        ml_score=0.90,
        model_status=ModelStatus.LOADED,
        baseline_signals={"exact_trusted_match": True, "baseline_drift": True},
    )
    assert decide(ev, POLICY_LEGACY_RUNTIME).verdict == VerdictLevel.BLOCK


def test_legacy_runtime_block_and_warn_thresholds():
    assert decide(
        Evidence(rule_score=0.88, ml_score=0.90, model_status=ModelStatus.LOADED),
        POLICY_LEGACY_RUNTIME,
    ).verdict == VerdictLevel.BLOCK
    assert decide(
        Evidence(rule_score=0.70, ml_score=0.60, model_status=ModelStatus.LOADED),
        POLICY_LEGACY_RUNTIME,
    ).verdict == VerdictLevel.WARN


def test_legacy_runtime_missing_model_falls_back_to_rules_only():
    """Legacy runtime fallback (today's behaviour): no ML -> rules-only fusion."""
    v = decide(
        Evidence(rule_score=0.70, ml_score=None, model_status=ModelStatus.ABSENT),
        POLICY_LEGACY_RUNTIME,
    )
    assert v.score == pytest.approx(0.70)
    assert v.verdict == VerdictLevel.WARN


def test_legacy_and_revised_versions_are_distinct():
    assert POLICY_VERSION_LEGACY_EVAL != POLICY_VERSION_LEGACY_RUNTIME
    assert POLICY_VERSION_LEGACY_RUNTIME != POLICY_VERSION_REVISED
    assert POLICY_REVISED.ml_required is True
    assert POLICY_LEGACY_RUNTIME.ml_required is False


# ── Slice C: score separated from action; deterministic serialization ─────────

def test_score_is_separate_from_action_under_monitoring_override():
    ev = Evidence(rule_score=0.99, ml_score=0.99, model_status=ModelStatus.LOADED)
    v_enforce = decide(ev, POLICY_REVISED)
    v_monitor = decide(ev, POLICY_REVISED, enforcement="monitor")
    assert v_enforce.verdict == VerdictLevel.BLOCK
    assert v_enforce.action == Action.BLOCK
    # monitoring override changes the ACTION, not the detector truth
    assert v_monitor.verdict == VerdictLevel.BLOCK
    assert v_monitor.action == Action.MONITOR
    assert v_monitor.score == v_enforce.score


def test_serialization_is_deterministic_and_json_stable():
    ev = Evidence(
        rule_score=0.9,
        ml_score=0.1,
        model_status=ModelStatus.LOADED,
        evidence_source="unit-test",
        hints={"typosquat_high": True},
    )
    v1 = decide(ev, POLICY_LEGACY_EVAL)
    v2 = decide(ev, POLICY_LEGACY_EVAL)
    d1 = v1.to_dict()
    d2 = v2.to_dict()
    assert d1 == d2
    assert list(d1.keys()) == [
        "policy_version",
        "evidence_source",
        "layer",
        "rule_score",
        "ml_score",
        "model_status",
        "mandatory_violations",
        "score",
        "verdict",
        "action",
        "reasons",
    ]
    # round-trips through JSON unchanged
    assert json.loads(json.dumps(d1)) == d1


# ── Slice D: mandatory evidence (narrow, provenance-gated, ML-proof) ──────────

def _mv(code="approved_registry_violation", provenance="install", **fields):
    return MandatoryViolation.create(code, provenance, **fields)


def test_mandatory_violation_survives_zero_ml():
    """A verified mandatory violation blocks even when ML says 0.0."""
    ev = Evidence(
        rule_score=0.10,
        ml_score=0.0,
        model_status=ModelStatus.LOADED,
        evidence_source="install",
        mandatory_violations=(_mv(registry="npmjs.com"),),
    )
    v = decide(ev, POLICY_REVISED)
    assert v.verdict == VerdictLevel.BLOCK
    assert v.action == Action.BLOCK
    assert [m.code for m in v.mandatory_violations] == ["approved_registry_violation"]


def test_mandatory_violation_blocks_when_model_absent():
    """Mandatory evidence blocks even when the fused score is unknown."""
    ev = Evidence(
        rule_score=0.05,
        ml_score=None,
        model_status=ModelStatus.ABSENT,
        evidence_source="install",
        mandatory_violations=(_mv(code="trusted_policy_digest_mismatch", digest="deadbeef"),),
    )
    v = decide(ev, POLICY_REVISED)
    assert v.verdict == VerdictLevel.BLOCK
    assert v.score is None  # honest: fused score unknown, violation still enforced


def test_trusted_cap_cannot_hide_mandatory_violation():
    ev = Evidence(
        rule_score=0.90,
        ml_score=0.90,
        model_status=ModelStatus.LOADED,
        evidence_source="install",
        baseline_signals={"exact_trusted_match": True},
        mandatory_violations=(_mv(registry="npmjs.com"),),
    )
    v = decide(ev, POLICY_REVISED)
    assert v.verdict == VerdictLevel.BLOCK
    assert v.score == pytest.approx(0.90)  # cap NOT applied over a mandatory violation


def test_unknown_mandatory_code_rejected():
    with pytest.raises(EvidenceError):
        MandatoryViolation.create("because-i-say-so", "install")


def test_mandatory_provenance_must_be_allowed():
    with pytest.raises(EvidenceError):
        MandatoryViolation.create("approved_registry_violation", "client-supplied", registry="x")


def test_mandatory_requires_required_field():
    with pytest.raises(EvidenceError):
        MandatoryViolation.create("approved_registry_violation", "install")  # missing 'registry'


def test_freeform_client_dict_is_not_accepted_as_mandatory():
    """A bare dict / bool 'mandatory' can never enter the contract as evidence."""
    with pytest.raises(EvidenceError):
        Evidence(
            rule_score=0.1,
            ml_score=None,
            model_status=ModelStatus.ABSENT,
            mandatory_violations=({"code": "approved_registry_violation", "mandatory": True},),
        )


# ── Slice E: honest model status (never ALLOW-as-safe) ───────────────────────

def test_model_error_is_never_allow_as_safe():
    ev = Evidence(rule_score=0.05, ml_score=None, model_status=ModelStatus.ERROR, evidence_source="install")
    v = decide(ev, POLICY_REVISED)
    assert v.verdict == VerdictLevel.HOLD
    assert v.action == Action.HOLD
    assert v.action != Action.ALLOW


def test_model_disabled_reports_incomplete_hold():
    ev = Evidence(rule_score=0.80, ml_score=None, model_status=ModelStatus.DISABLED, evidence_source="install")
    v = decide(ev, POLICY_REVISED)
    assert v.verdict == VerdictLevel.HOLD
    assert v.score is None
    assert v.model_status is ModelStatus.DISABLED


def test_required_model_missing_under_revised_is_not_allow():
    for status in (ModelStatus.ABSENT, ModelStatus.ERROR, ModelStatus.DISABLED):
        v = decide(
            Evidence(rule_score=0.0, ml_score=None, model_status=status),
            POLICY_REVISED,
        )
        assert v.action != Action.ALLOW


def test_name_and_version_hints_are_advisory_not_mandatory():
    ev = Evidence(
        rule_score=0.88,
        ml_score=0.10,
        model_status=ModelStatus.LOADED,
        evidence_source="runtime",
        hints={"typosquat_high": True, "public_high_version": True, "version_gap_score": 0.95},
    )
    v = decide(ev, POLICY_REVISED)
    assert v.mandatory_violations == ()
    assert any(r.startswith("advisory:") for r in v.reasons)
    # fused 0.412 < 0.60 -> ALLOW: heuristics did not silently become mandatory
    assert v.verdict == VerdictLevel.ALLOW


def test_contract_source_contains_no_demo_package_names():
    from pathlib import Path

    import app.policy.decision_contract as dc

    src = Path(dc.__file__).read_text(encoding="utf-8")
    assert "training-leder" not in src
    assert "corp-internal-ledger-api" not in src


# ── Slice F: three real consumers share one core payload ─────────────────────

BENIGN_DEPS = {"left-pad": "1.0.0"}


def test_three_consumers_share_the_same_core_payload():
    from app.policy.decision_contract import core_payload
    from app.policy.evaluator_adapter import predict_row
    from app.services import hybrid_scorer
    from app.services import protection_service

    provider = hybrid_scorer.StaticModelProvider(0.42, ModelStatus.LOADED)

    ev_runtime = hybrid_scorer.evidence_from_manifest(BENIGN_DEPS, provider=provider, source="runtime")
    ev_install = hybrid_scorer.evidence_from_manifest(BENIGN_DEPS, provider=provider, source="install")

    # normalization parity: same inputs -> same evidence fields (except source tag)
    assert ev_runtime.rule_score == ev_install.rule_score
    assert dict(ev_runtime.baseline_signals) == dict(ev_install.baseline_signals)
    assert dict(ev_runtime.hints) == dict(ev_install.hints)
    assert ev_runtime.ml_score == ev_install.ml_score == 0.42

    v_runtime = hybrid_scorer.hybrid_decide(ev_runtime, POLICY_REVISED)
    v_install = protection_service.decision_for_install(
        "left-pad", "1.0.0", provider=provider, policy=POLICY_REVISED, enforcement="enforce"
    )
    v_eval = predict_row(
        ev_runtime.rule_score,
        ev_runtime.ml_score,
        ev_runtime.model_status,
        POLICY_REVISED,
        source="evaluator",
        baseline_signals=dict(ev_runtime.baseline_signals),
        hints=dict(ev_runtime.hints),
    )

    assert core_payload(v_runtime) == core_payload(v_install) == core_payload(v_eval)
    # transport identity differs by design
    assert {v_runtime.layer, v_install.layer, v_eval.layer} == {"runtime", "install", "evaluator"}


def test_runtime_adapter_matches_direct_decide_on_same_evidence():
    from app.policy.decision_contract import core_payload
    from app.services import hybrid_scorer

    provider = hybrid_scorer.StaticModelProvider(0.77, ModelStatus.LOADED)
    ev = hybrid_scorer.evidence_from_manifest(BENIGN_DEPS, provider=provider, source="runtime")
    assert core_payload(hybrid_scorer.hybrid_decide(ev, POLICY_REVISED)) == core_payload(
        decide(ev, POLICY_REVISED)
    )


def test_evaluator_adapter_reproduces_legacy_eval_binary_cut():
    from app.policy.evaluator_adapter import legacy_eval_binary, predict_row

    hit = predict_row(0.90, 0.10, ModelStatus.LOADED, POLICY_LEGACY_EVAL, source="evaluator")
    # fused 0.42 < 0.60 -> not malicious even though the rule score alone is high
    assert legacy_eval_binary(hit) == 0
    strong = predict_row(0.90, 0.90, ModelStatus.LOADED, POLICY_LEGACY_EVAL, source="evaluator")
    assert legacy_eval_binary(strong) == 1


def test_install_hold_when_inference_disabled():
    from app.services import protection_service
    from app.services.hybrid_scorer import reset_model_provider

    reset_model_provider()  # default host provider: no unpickle, status disabled/absent
    v = protection_service.decision_for_install("left-pad", "1.0.0", policy=POLICY_REVISED)
    assert v.verdict == VerdictLevel.HOLD
    assert v.action == Action.HOLD


def test_install_is_not_force_blocked_by_demo_name(monkeypatch):
    """With benign evidence, a demo name must NOT be force-blocked."""
    from app.policy.decision_contract import POLICY_REVISED, Evidence as Ev, decide
    from app.services import protection_service
    from app.services.hybrid_scorer import EvaluationBundle

    benign = Ev(rule_score=0.05, ml_score=0.1, model_status=ModelStatus.LOADED, evidence_source="install")
    # Re-seamed after the single-inference refactor: evaluate_package now obtains its
    # verdict from evaluate_manifest_bundle (one extraction+one inference), so the
    # benign-evidence injection targets that seam. Same intended assertion as before.
    bundle = EvaluationBundle(
        verdict=decide(benign, POLICY_REVISED),
        evidence=benign,
        reasons=[],
        baseline_drift=False,
        triggers=[],
    )
    monkeypatch.setattr(
        protection_service, "evaluate_manifest_bundle", lambda *a, **k: bundle
    )
    res = protection_service.evaluate_package("training-leder", "1.0.0")
    assert res["engine"]["decision_detail"]["mandatory_violations"] == []
    assert res["blocked"] is False  # not blocked by name alone
    # the inert demo-label set still exists, but is not a decision input
    assert "training-leder" in protection_service.LAB_ATTACK_PACKAGES


# ── Slice G: tripwire, no unpickling anywhere; routes stay honest ───────────

def test_application_code_never_imports_a_pickle_loader():
    """The model ships as plain arrays, so no module may import joblib or pickle."""
    app_dir = Path(__file__).resolve().parents[1] / "app"
    offenders = [
        path.relative_to(app_dir).as_posix()
        for path in app_dir.rglob("*.py")
        if re.search(r"^\s*(import|from)\s+(joblib|pickle|cloudpickle)\b",
                     path.read_text(encoding="utf-8"), re.MULTILINE)
    ]
    assert offenders == []


def test_model_info_route_is_honest_without_a_provider():
    from fastapi.testclient import TestClient

    from app.main import app
    from app.services.hybrid_scorer import reset_model_provider

    reset_model_provider()
    client = TestClient(app)
    resp = client.get("/v1/ml/model-info")
    assert resp.status_code == 200
    data = resp.json()
    assert data["model_status"] in ("disabled", "absent", "error")
    assert data["inference_enabled"] is False
    assert data["model_loaded"] is False


def test_score_route_holds_without_a_model():
    from fastapi.testclient import TestClient

    from app.main import app
    from app.services.hybrid_scorer import reset_model_provider

    reset_model_provider()
    client = TestClient(app)
    resp = client.post(
        "/v1/score",
        json={"input_type": "manifest", "payload": {"dependencies": {"left-pad": "1.0.0"}}},
    )
    assert resp.status_code == 200
    detail = resp.json()["decision_detail"]
    # Intended-behaviour change (B-A fix): /v1/score must use the ONE shared runtime
    # policy (revised, fail-closed HOLD), not the legacy-runtime default.
    from app.policy.decision_contract import DEFAULT_RUNTIME_POLICY

    assert detail["policy_version"] == DEFAULT_RUNTIME_POLICY.policy_version
    assert detail["model_status"] in ("disabled", "absent", "error")
    assert detail["verdict"] == "hold"
    assert detail["score"] is None


def test_scan_manifest_route_exposes_decision_detail():
    from fastapi.testclient import TestClient

    from app.main import app
    from app.services.hybrid_scorer import reset_model_provider

    reset_model_provider()
    client = TestClient(app)
    resp = client.post(
        "/v1/scan/manifest",
        json={"dependencies": {"left-pad": "1.0.0"}, "source": "unit-test"},
    )
    assert resp.status_code == 200
    dd = resp.json()["decision_detail"]
    assert set(dd) >= {"policy_version", "rule_score", "ml_score", "model_status", "verdict", "action"}
