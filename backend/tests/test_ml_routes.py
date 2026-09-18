"""Tests for the ML API routes.

`/model-info` must be honest about inference availability and must never claim a model it
cannot use; `/metrics` reports the released research summary, so it answers 200 when the
artifact's results are present.
"""
import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.policy.decision_contract import DEFAULT_RUNTIME_POLICY

client = TestClient(app)
SUMMARY = Path(__file__).resolve().parents[2] / "research" / "results" / "summary_v3.json"


def test_ml_model_info():
    resp = client.get("/v1/ml/model-info")
    assert resp.status_code == 200
    data = resp.json()
    assert data["model_version"]
    assert data["model_status"] in ("loaded", "absent", "error", "disabled")
    assert data["model_loaded"] == data["inference_enabled"]
    assert data["hybrid_blend"] == {
        "rules_weight": DEFAULT_RUNTIME_POLICY.rule_weight,
        "ml_weight": DEFAULT_RUNTIME_POLICY.ml_weight,
    }
    assert data["policy_version"] == DEFAULT_RUNTIME_POLICY.policy_version
    assert data["model_format"].startswith("numpy arrays")
    if data["model_loaded"]:
        assert data["content_features_count"] > 0
    else:
        # honest degraded status, not a fabricated result
        assert data["inference_note"]


def test_ml_metrics_reports_the_released_summary():
    resp = client.get("/v1/ml/metrics")
    if not SUMMARY.is_file():
        assert resp.status_code == 404
        assert "reproduce" in json.dumps(resp.json())
        return
    assert resp.status_code == 200
    data = resp.json()
    arms = data["test_arms"]["hybrid_warn_or_block"]
    for key in ("precision", "recall", "f1"):
        assert 0.0 <= arms[key] <= 1.0
    assert data["policy_version"] == DEFAULT_RUNTIME_POLICY.policy_version
