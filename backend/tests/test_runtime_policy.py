"""Regression tests: one shared runtime policy, single inference,
explicit HOLD (unknown), fail-closed invalid input, provider class alignment and deep
immutable evidence.

These are the production-suite equivalents of the independent adversarial tests
(REVIEW_TESTS.py) minus the superseded A3 substring check (replaced by
test_evaluate_revised_cli.py, a behaviour test). They run as part of the normal
pytest suite.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.policy.decision_contract import (
    DEFAULT_RUNTIME_POLICY,
    Evidence,
    ModelStatus,
)
from app.schemas.scan_report import DefenseMode
from app.services import protection_service
from app.services.hybrid_scorer import (
    ModelInference,
    ModelProvider,
    StaticModelProvider,
    get_model_provider,
    reset_model_provider,
    set_model_provider,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def _restore_provider():
    yield
    reset_model_provider()


# ── A. one shared runtime policy across consumers ───────────────────────────


def test_default_runtime_policy_is_the_fail_closed_package_policy():
    # Camera-ready: the shared default is the package-layer policy calibrated on the NPMStudy
    # training split. It stays fail-closed (a required-but-missing model is HOLD).
    assert DEFAULT_RUNTIME_POLICY.policy_version == "package-v3-1.0.0"
    assert DEFAULT_RUNTIME_POLICY.ml_required is True


def test_api_score_uses_the_same_default_runtime_policy_as_install():
    r = client.post(
        "/v1/score",
        json={"input_type": "manifest", "payload": {"dependencies": {"left-pad": "1.0.0"}}},
    )
    assert r.status_code == 200, r.text
    api_policy = r.json()["decision_detail"]["policy_version"]
    v_install = protection_service.decision_for_install(
        "left-pad", "1.0.0", provider=StaticModelProvider(0.5, ModelStatus.LOADED)
    )
    assert api_policy == DEFAULT_RUNTIME_POLICY.policy_version
    assert api_policy == v_install.policy_version


def test_scan_manifest_endpoint_policy_matches_install():
    r = client.post("/v1/scan/manifest", json={"dependencies": {"left-pad": "1.0.0"}})
    assert r.status_code == 200, r.text
    dd = r.json()["decision_detail"]
    v_install = protection_service.decision_for_install(
        "left-pad", "1.0.0", provider=StaticModelProvider(0.5, ModelStatus.LOADED)
    )
    assert dd["policy_version"] == DEFAULT_RUNTIME_POLICY.policy_version
    assert dd["policy_version"] == v_install.policy_version


# ── D. cross-boundary consistency / single inference ────────────────────────


def test_summary_risk_score_equals_decision_detail_score():
    set_model_provider(StaticModelProvider(0.111111, ModelStatus.LOADED))
    from app.services.scan_service import scan_manifest_unified

    report = scan_manifest_unified({"left-pad": "1.0.0"}, "unit-test", DefenseMode.HYBRID)
    assert report.summary.risk_score == report.decision_detail["score"], (
        f"score rounded across boundaries: summary={report.summary.risk_score} "
        f"detail={report.decision_detail['score']}"
    )


def test_one_request_performs_one_inference():
    calls = {"n": 0}

    class CountingProvider(ModelProvider):
        label = "counting-fixture"

        def status(self):
            return ModelStatus.LOADED

        def infer(self, vector):
            calls["n"] += 1
            return ModelInference(ModelStatus.LOADED, 0.42, self.label)

    set_model_provider(CountingProvider())
    from app.services.scan_service import scan_manifest_unified

    scan_manifest_unified({"left-pad": "1.0.0"}, "unit-test", DefenseMode.HYBRID)
    assert calls["n"] == 1, f"inference called {calls['n']}x for one scan (duplicate inference)"


def test_hold_does_not_expose_a_benign_numeric_risk_score():
    # Default provider disabled -> revised policy cannot decide -> HOLD.
    res = protection_service.evaluate_package("training-leder", "1.0.0")
    eng = res["engine"]
    assert eng["decision"] == "hold", eng
    assert eng["risk_score"] is None, eng
    # The raw rule score is still surfaced separately (not as the fused risk_score).
    assert eng["decision_detail"]["score"] is None


# ── E. fail-closed invalid input ─────────────────────────────────────────────


def test_empty_package_name_fails_closed():
    res = protection_service.evaluate_package("", "*")
    assert res["blocked"] is True
    res2 = protection_service.evaluate_package("   ", "*")
    assert res2["blocked"] is True


# ── D. default provider gives no ML evidence (the model is loaded from plain arrays) ──


def test_default_provider_reports_absent_and_no_score():
    reset_model_provider()
    inf = get_model_provider().infer([0.0] * 11)
    assert inf.model_status is ModelStatus.ABSENT
    assert inf.ml_score is None


def test_evidence_nested_mappings_are_deeply_immutable():
    ev = Evidence(
        rule_score=0.1,
        ml_score=None,
        model_status=ModelStatus.ABSENT,
        hints={"nested": ["mutable"]},
        baseline_signals={"deep": {"flag": True}},
    )
    with pytest.raises((TypeError, AttributeError)):
        ev.hints["nested"].append("injected")
    with pytest.raises((TypeError, AttributeError)):
        ev.baseline_signals["deep"]["flag"] = False


def test_evidence_rejects_non_finite_nested_signal():
    from app.policy.decision_contract import EvidenceError

    with pytest.raises(EvidenceError):
        Evidence(
            rule_score=0.1,
            ml_score=None,
            model_status=ModelStatus.ABSENT,
            hints={"typosquat_high": float("nan")},
        )


# ── composite propagates unknown, known blocker wins ─────────────────────────


def test_composite_propagates_unknown_risk_score_when_any_layer_hold():
    from app.data.demo_scan_payloads import DEMO_SBOM, DEMO_WORKFLOW
    from app.services.scan_service import run_composite_scan

    # Default provider disabled -> manifest/workflow/sbom all HOLD -> unknown score.
    res = run_composite_scan(
        source="unit-test",
        defense_mode=DefenseMode.HYBRID,
        dependencies={"left-pad": "1.0.0"},
        sbom=DEMO_SBOM,
        workflow=DEMO_WORKFLOW,
        compare_defense_modes=False,
    )
    assert res.summary.risk_score is None
    # hold is a distinct incomplete state, never coerced to warn/allow.
    assert res.summary.decision.value in ("hold", "block")
