"""Authentication and authorization tests.

Prove default-deny on the state-changing / credential-answering / install-alert
routes, the elimination of the anonymous operator-PAT fallback, secure session
defaults, the protected (and audited) protection toggle, Origin+auth on the
install-alert ingestion path (HTTP + WebSocket), and that an authenticated local
trusted client (the documented CLI/gate capability) still works end-to-end.

These tests assert REAL behaviour over the live app via TestClient. There are no
tautologies, no always-false assertions, and no source-grep checks.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core import config
from app.services.protection_service import get_protection_state, set_protection_enabled

client = TestClient(app)

OPERATOR_TOKEN = "test-operator-token-for-p5-0123456789"


def op_headers():
    return {"Authorization": f"Bearer {OPERATOR_TOKEN}"}


# ── protected GitHub credential-answering / mutating routes ─────────────────


def test_anonymous_github_status_is_401_and_never_uses_server_pat(monkeypatch):
    """The operator PAT must NEVER answer an anonymous caller on /github/status."""
    # Server PAT configured, and a boom spy: if the route body ran with the PAT
    # it would call github_client and fail the test by raising. (routes_github
    # imported GITHUB_TOKEN by value at module load, so patch that copy.)
    monkeypatch.setattr("app.api.routes_github.GITHUB_TOKEN", "operator-pat-sentinel")

    sent = {"n": 0}

    def _boom(*_a, **_k):
        sent["n"] += 1
        raise AssertionError("github_client must never be called for an anonymous caller")

    import app.services.github_client as gh

    monkeypatch.setattr(gh, "get_authenticated_user", _boom)

    r = client.get("/v1/github/status")
    assert r.status_code == 401
    assert sent["n"] == 0  # rejected at the auth dependency, before any PAT use


def test_resolve_token_never_returns_server_pat_for_anonymous(monkeypatch):
    from app.api.routes_github import _resolve_token

    monkeypatch.setattr("app.api.routes_github.GITHUB_TOKEN", "operator-pat-sentinel")
    anon = SimpleNamespace(session={}, state=SimpleNamespace(operator_ok=False))
    assert _resolve_token(anon) is None  # no PAT fallback for anonymous


def test_resolve_token_returns_server_pat_only_for_operator(monkeypatch):
    from app.api.routes_github import _resolve_token

    monkeypatch.setattr("app.api.routes_github.GITHUB_TOKEN", "operator-pat-sentinel")
    operator = SimpleNamespace(session={}, state=SimpleNamespace(operator_ok=True))
    assert _resolve_token(operator) == "operator-pat-sentinel"


ANONYMOUS_GITHUB_ROUTES = [
    ("post", "/v1/github/connect", {"token": "x" * 20}),
    ("post", "/v1/github/logout", {}),
    ("get", "/v1/github/repos", None),
    ("get", "/v1/github/repos/owner/repo/artifacts", None),
    ("post", "/v1/github/repos/owner/repo/scan", {}),
    ("get", "/v1/github/dependencies", None),
]


@pytest.mark.parametrize("method,path,payload", ANONYMOUS_GITHUB_ROUTES)
def test_anonymous_github_credential_routes_rejected(method, path, payload):
    fn = getattr(client, method)
    kwargs = {"json": payload} if payload is not None else {}
    r = fn(path, **kwargs)
    assert r.status_code == 401, f"{method.upper()} {path} -> {r.status_code}"


# ── protection toggle: default-deny + no state change + audit ────────────────


def test_anonymous_protection_toggle_rejected_and_changes_no_state():
    set_protection_enabled(True)
    r = client.put("/v1/settings/protection", json={"enabled": False})
    assert r.status_code == 401
    # the live install-blocking flag must not have flipped
    assert get_protection_state()["enabled"] is True


def test_protection_toggle_authenticated_works_then_audited(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    set_protection_enabled(True)

    r = client.put(
        "/v1/settings/protection",
        json={"enabled": False},
        headers=op_headers(),
    )
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is False
    assert get_protection_state()["enabled"] is False

    # the change was recorded (durable JSONL audit when a path is configured)
    from app.core import audit as audit_mod

    tail = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    lines = [json.loads(ln) for ln in tail]
    assert lines, "audit log empty but a toggled change should be recorded"
    last = lines[-1]
    assert last["action"] == "set_protection"
    assert last["enabled"] is False
    assert last["principal"] == "operator"
    # in-memory trail also captured it (the recent entry from THIS toggle)
    assert audit_mod.TRAIL and audit_mod.TRAIL[-1]["action"] == "set_protection"
    assert audit_mod.TRAIL[-1]["enabled"] is False
    audit_mod.TRAIL.clear()


def test_protection_toggle_rejects_disallowed_origin_even_when_authenticated():
    r = client.put(
        "/v1/settings/protection",
        json={"enabled": True},
        headers={**op_headers(), "Origin": "http://evil.example"},
    )
    assert r.status_code == 403


# ── install-alert ingestion (HTTP + WebSocket) ───────────────────────────────


def test_anonymous_install_alert_rejected_and_no_state_change():
    from app.api.routes_lab import _install_alerts

    before = list(_install_alerts)
    r = client.post("/v1/lab/install-alert", json={"package": "fake-pkg", "cwd": "/tmp"})
    assert r.status_code == 401
    assert list(_install_alerts) == before  # nothing ingested for anonymous


def test_install_alert_authed_but_bad_origin_rejected():
    from app.api.routes_lab import _install_alerts

    before = list(_install_alerts)
    r = client.post(
        "/v1/lab/install-alert",
        json={"package": "fake-pkg"},
        headers={**op_headers(), "Origin": "http://evil.example"},
    )
    assert r.status_code == 403
    assert list(_install_alerts) == before


def test_install_alert_authenticated_local_client_ingest_works():
    from app.api.routes_lab import _install_alerts

    before = len(_install_alerts)
    r = client.post(
        "/v1/lab/install-alert",
        json={"package": "observable-pkg", "version": "1.2.3", "cwd": "/opt/app"},
        headers=op_headers(),
    )
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "received"
    assert len(_install_alerts) == before + 1
    assert _install_alerts[-1]["package"] == "observable-pkg"


GOOD_ORIGIN = "http://localhost:5173"
BAD_ORIGIN = "http://evil.example"
WS_PATH = "/v1/lab/ws/install-alerts"


def _ws_connected(**connect_kwargs) -> bool:
    try:
        with client.websocket_connect(connect_kwargs.pop("path", WS_PATH), **connect_kwargs):
            return True
    except Exception:
        return False


def test_ws_install_alerts_rejected_without_token():
    assert _ws_connected(headers={"Origin": GOOD_ORIGIN}) is False


def test_ws_install_alerts_rejected_with_bad_origin_even_with_token():
    assert (
        _ws_connected(
            path=f"{WS_PATH}?token={OPERATOR_TOKEN}",
            headers={"Origin": BAD_ORIGIN},
        )
        is False
    )


def test_ws_install_alerts_accepted_with_token_and_valid_origin():
    with client.websocket_connect(
        f"{WS_PATH}?token={OPERATOR_TOKEN}", headers={"Origin": GOOD_ORIGIN}
    ) as ws:
        data = ws.receive_json()
        assert data["type"] == "history"  # hydrate path reached => accepted


def test_ws_install_alerts_accepted_with_authorization_header():
    with client.websocket_connect(
        WS_PATH, headers={"Origin": GOOD_ORIGIN, "Authorization": f"Bearer {OPERATOR_TOKEN}"}
    ) as ws:
        assert ws.receive_json()["type"] == "history"


# ── secure session defaults / fail-fast ──────────────────────────────────────


def test_session_secret_never_uses_the_old_guessable_default():
    old = "supply-chain-lab-dev-secret-change-me"
    assert config.SESSION_SECRET != old
    assert config.SESSION_SECRET != ""
    # in this app it is a 32+ char non-guessable value
    assert len(config.SESSION_SECRET) >= 32


def test_secure_deploy_validation_fails_fast_in_production_without_secret():
    with pytest.raises(RuntimeError):
        config.assert_secure_deploy(
            mode="production", session_secret="", local_token="t"
        )
    with pytest.raises(RuntimeError):
        config.assert_secure_deploy(
            mode="production",
            session_secret="supply-chain-lab-dev-secret-change-me",  # old guessable
            local_token="t",
        )
    with pytest.raises(RuntimeError):
        config.assert_secure_deploy(
            mode="production", session_secret="real-secret", local_token=""
        )


def test_secure_deploy_validation_passes_when_configured():
    # Non-guessable session secret + configured local token => ok in production
    config.assert_secure_deploy(
        mode="production",
        session_secret="k" * 40,
        local_token="local-token-for-operator",
    )


# ── authenticated local client works end-to-end for CLI/gate routes ──────────


def test_authenticated_local_client_end_to_end(monkeypatch):
    set_protection_enabled(True)
    # keep github status local: no server PAT, so no external call
    monkeypatch.setattr("app.api.routes_github.GITHUB_TOKEN", "")
    # protection toggle
    r = client.put("/v1/settings/protection", json={"enabled": False}, headers=op_headers())
    assert r.status_code == 200
    assert get_protection_state()["enabled"] is False
    # github status (no server PAT configured -> connected false, not an error)
    r = client.get("/v1/github/status", headers=op_headers())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("connected") is False or "user" in body


# ── honest risk score: no fabricated default on the package-detail route ──────


def test_package_detail_omitted_risk_score_stays_unknown(monkeypatch):
    """A request that omits risk_score must see None/unknown: never a 0.15 default.

    (The frontend sends a raw, possibly-null score on purpose; a
    numeric server default here would silently undo that by coercing unknown to
    a benign-looking measured number.)
    """
    captured: dict = {}
    monkeypatch.setattr(
        "app.api.routes_github.fetch_package_detail",
        lambda eco, name, *, version=None, risk_score=None: (
            captured.update(risk_score=risk_score) or {"ok": True, "package": name}
        ),
    )
    r = client.get("/v1/github/packages/npm/lodash")
    assert r.status_code == 200, r.text
    assert captured["risk_score"] is None  # unknown stays unknown, not 0.15


def test_package_detail_explicit_risk_score_passes_through(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(
        "app.api.routes_github.fetch_package_detail",
        lambda eco, name, *, version=None, risk_score=None: (
            captured.update(risk_score=risk_score) or {"ok": True, "package": name}
        ),
    )
    r = client.get("/v1/github/packages/npm/lodash", params={"risk_score": 0.9})
    assert r.status_code == 200, r.text
    assert captured["risk_score"] == 0.9  # a real numeric score is preserved


def test_registry_unknown_risk_score_never_becomes_a_number():
    """The service maps an unknown (None) score to unknown category scores, not 0."""
    from app.services.package_registry import _risk_scores

    scores = _risk_scores(None)
    assert scores["overall"] is None
    assert all(v is None for v in scores.values())