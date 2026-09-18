"""Correctness of package_registry security findings.

Guarantees:
  - No security alert may claim a CVE without a concrete CVE id + advisory/evidence
    source (never a bare fabricated "CVE vulnerability").
  - PyPI name-set heuristics (pickle/eval) are always labelled as unverified
    heuristics, never asserted as fact ("Obfuscated code").
  - An unknown/absent risk score stays unknown (None scores), never a fabricated
    0 or the previous hardcoded default 0.15.
  - No test in this module performs network access (`_get` is monkeypatched where
    a fetch path is exercised).
"""
import pytest

from app.services import package_registry as pr


def _joined_alert_text(alerts):
    return " ".join(
        (a.get("title", "") + " " + a.get("message", "") + " " + a.get("severity", ""))
        for a in alerts
    ).lower()


def _cve_references(alerts):
    text = _joined_alert_text(alerts)
    return "cve" in text


class TestAlertHonesty:
    def test_high_risk_alert_never_claims_cve(self):
        alerts = pr._alerts_for_package("react", 0.95, "npm")
        assert alerts, "expected at least one high-risk alert for a 0.95 risk"
        assert not _cve_references(alerts), (
            "high-risk alert must not fabricate a CVE without an id/source"
        )

    def test_high_risk_alert_is_labelled_heuristic_and_sourced(self):
        alerts = pr._alerts_for_package("react", 0.95, "npm")
        labelled = [
            a
            for a in alerts
            if any(k in _joined_alert_text([a]) for k in ("unverified", "heuristic"))
            or a.get("cve_id")
            or a.get("advisory_url")
            or a.get("source")
        ]
        assert labelled, "every high-risk alert must be unverified/heuristic or carry an advisory source"

    def test_pypi_pickle_is_labelled_heuristic_never_obfuscated(self):
        alerts = pr._alerts_for_package("pickle", 0.5, "pypi")
        name_alerts = [a for a in alerts if "pickle" in _joined_alert_text([a])] or alerts
        text = _joined_alert_text(alerts)
        assert "obfuscated code" not in text, '"Obfuscated code" must not be asserted as fact'
        assert any(
            k in text for k in ("unverified", "heuristic")
        ), "name-based signal must be labelled an unverified heuristic"

    def test_lab_package_alert_is_labelled_demo_heuristic(self):
        alerts = pr._alerts_for_package("training-leder", 0.9, "npm")
        lab_alerts = [a for a in alerts if "training-leder" in _joined_alert_text([a])]
        assert lab_alerts
        text = _joined_alert_text(alerts)
        assert not _cve_references(alerts), "lab alert must not claim a CVE"
        assert any(k in text for k in ("unverified", "heuristic", "demo", "lab")), (
            "lab alert must be explicitly labelled as lab/demo/heuristic"
        )

    def test_low_risk_clean_package_has_no_fabricated_alerts(self):
        alerts = pr._alerts_for_package("express", 0.2, "npm")
        # A genuinely low-risk, non-special package should not be handed invented alerts.
        assert not _cve_references(alerts)


class TestRiskUnknownPreservation:
    def test_risk_scores_none_returns_unknown_not_zero(self):
        scores = pr._risk_scores(None)
        for key in ("supply_chain", "vulnerability", "quality", "maintenance", "license", "overall"):
            assert scores[key] is None, f"{key} must be unknown (None) for unknown risk, not a number"

    def test_risk_scores_known_still_numeric(self):
        scores = pr._risk_scores(0.62)
        assert isinstance(scores["overall"], int)
        assert 0 <= scores["overall"] <= 100


@pytest.fixture
def npm_payload():
    return {
        "name": "express",
        "dist-tags": {"latest": "4.18.0"},
        "versions": {
            "4.18.0": {
                "description": "fast web framework",
                "license": "MIT",
                "repository": {"url": "git+https://github.com/expressjs/express.git"},
            }
        },
        "time": {"4.18.0": "2023-01-01T00:00:00Z", "created": "2010-01-01T00:00:00Z"},
        "readme": "# express\n\nhello",
        "maintainers": [{"name": "a"}],
        "repository": {"url": "git+https://github.com/expressjs/express.git"},
    }


@pytest.mark.parametrize("risk", [0.95, 0.0, None])
def test_fetch_npm_detail_alerts_never_fabricate_cve(monkeypatch, npm_payload, risk):
    monkeypatch.setattr(pr, "_get", lambda url: npm_payload)
    detail = pr.fetch_npm_detail("express", version="4.18.0", risk_score=risk)
    assert detail["ok"] is True
    assert not _cve_references(detail["alerts"]), "package detail alerts must not fabricate a CVE"

    if risk is None:
        for key in ("supply_chain", "vulnerability", "quality", "maintenance", "license", "overall"):
            assert detail["scores"][key] is None, f"{key} must be unknown, not a defaulted number"
    else:
        assert detail["scores"]["overall"] is not None


def test_fetch_npm_detail_default_risk_is_unknown(monkeypatch, npm_payload):
    monkeypatch.setattr(pr, "_get", lambda url: npm_payload)
    detail = pr.fetch_npm_detail("express")
    # The default (no risk supplied) is UNKNOWN, never the old hardcoded 0.15.
    default = pr.fetch_package_detail.__kwdefaults__
    assert default is not None and default.get("risk_score") is None, (
        "fetch_package_detail must default risk_score to None (unknown)"
    )
    for key in ("supply_chain", "vulnerability", "quality", "maintenance", "license", "overall"):
        assert detail["scores"][key] is None, f"{key} must be unknown when risk is not supplied"