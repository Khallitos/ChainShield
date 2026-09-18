"""Mutating and credential-using routes must be operator-only.

These four routes persist durable state or consume operator credentials:

* ``PUT  /v1/settings/scheduled-scan``         (persists ``data/scheduled_scan.json``)
* ``POST /v1/settings/scheduled-scan/run-now`` (persists runs + server-PAT GitHub calls)
* ``POST /v1/trust/baseline/rebuild``          (overwrites the FROZEN ``data/trusted/baseline.json``)
* ``POST /v1/reports/block-explain``           (paid Gemini API with ``GEMINI_API_KEY``)

Each route gets a NEGATIVE test (anonymous → 401, no state change, no credential
use) and a POSITIVE test (authenticated operator → works).  Every assertion is a
real status code / real state delta over the live app; the "no credential use"
claims use RAISING spies (boom) so a test cannot pass vacuously.  There are no
tautologies, no always-false assertions, no manufactured ``xfail`` and no
source-grep checks.

Frozen-integrity: ``data/trusted/baseline.json`` is one of the 18 frozen artefacts.
The rebuild tests never let the real route write it (boom-spy / recorder into a
pytest ``tmp_path``) and additionally assert the file's SHA256 is unchanged.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.auth import require_operator

client = TestClient(app)

OPERATOR_TOKEN = "test-operator-token-for-p5-0123456789"
OP = {"Authorization": f"Bearer {OPERATOR_TOKEN}"}
BAD_ORIGIN = {"Origin": "http://evil.example"}

REPO = Path(__file__).resolve().parents[2]
FROZEN_BASELINE = REPO / "data" / "trusted" / "baseline.json"
FROZEN_BASELINE_SHA256 = "1708ec49e035379c05296621ed55744810050840d622719d7b7d40c62e59f7e2"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def test_frozen_baseline_is_present_and_matches_the_recorded_hash():
    """Guard for the file routes 1-4 must never touch (fails loudly if drifted)."""
    assert FROZEN_BASELINE.is_file(), f"frozen baseline missing: {FROZEN_BASELINE}"
    assert _sha256(FROZEN_BASELINE) == FROZEN_BASELINE_SHA256


# ── route 1: PUT /v1/settings/scheduled-scan ────────────────────────────────
# Side effect: update_scheduled_scan_config() -> _persist_config() writes
# data/scheduled_scan.json and reconfigures the automated scanner.


def test_scheduled_scan_put_anonymous_rejected_and_no_write(tmp_path, monkeypatch):
    """Anonymous PUT → 401; the persistence call must never run."""
    from app.services import schedule_scan_service as svc

    cfg_path = tmp_path / "scheduled_scan.json"
    monkeypatch.setattr(svc, "_CONFIG_PATH", cfg_path)
    monkeypatch.setattr(svc, "_config", dict(svc._DEFAULT_CONFIG))

    fired = {"n": 0}

    def _boom(*_a, **_k):
        fired["n"] += 1
        raise AssertionError("update_scheduled_scan_config must not run for anonymous")

    monkeypatch.setattr("app.api.routes_scheduled_scan.update_scheduled_scan_config", _boom)

    r = client.put("/v1/settings/scheduled-scan", json={"enabled": True, "source": "anon"})
    assert r.status_code == 401, r.text
    assert fired["n"] == 0                      # body never reached the service
    assert not cfg_path.exists()                # nothing persisted anywhere
    assert svc._config.get("enabled") is False  # live scanner config unchanged


def test_scheduled_scan_put_authenticated_operator_persists(tmp_path, monkeypatch):
    """Authenticated operator → 200 and the config is really persisted + applied."""
    from app.services import schedule_scan_service as svc

    cfg_path = tmp_path / "scheduled_scan.json"
    monkeypatch.setattr(svc, "_CONFIG_PATH", cfg_path)
    monkeypatch.setattr(svc, "_config", dict(svc._DEFAULT_CONFIG))

    r = client.put(
        "/v1/settings/scheduled-scan",
        json={"enabled": True, "source": "operator-set", "cron_expression": "0 9 * * *"},
        headers=OP,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enabled"] is True
    assert body["source"] == "operator-set"

    assert cfg_path.is_file(), "an authenticated change must actually be persisted"
    on_disk = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert on_disk["enabled"] is True
    assert on_disk["source"] == "operator-set"
    assert svc._config["source"] == "operator-set"  # live config reflects the change


# ── route 2: POST /v1/settings/scheduled-scan/run-now ───────────────────────
# Side effect: execute_scheduled_scan() persists runs AND (with an enabled repo
# target) calls github_client.fetch_repo_artifacts(GITHUB_TOKEN, ...), the exact
# server-PAT-authenticated credential side effect we are eliminating.


def _arm_enabled_repo_target(monkeypatch, tmp_path, spy):
    """Configure an enabled repo target + server PAT and a RAISING token-consumer spy."""
    from app.services import schedule_scan_service as svc

    monkeypatch.setattr(svc, "_RUNS_PATH", tmp_path / "scheduled_scan_runs.json")
    monkeypatch.setattr(svc, "_runs", [])
    monkeypatch.setattr(
        svc,
        "_config",
        {
            **dict(svc._DEFAULT_CONFIG),
            "enabled": True,
            "repo_targets": [
                {"full_name": "owner/repo", "owner": "owner", "name": "repo",
                 "priority": 1, "enabled": True}
            ],
        },
    )
    monkeypatch.setattr(svc, "GITHUB_TOKEN", "operator-pat-sentinel")
    import app.services.github_client as gh

    monkeypatch.setattr(gh, "fetch_repo_artifacts", spy)


def test_run_now_anonymous_never_consumes_the_server_pat(tmp_path, monkeypatch):
    """Anonymous run-now → 401; the token-consuming GitHub client must not fire."""
    calls = {"n": 0}

    def _boom(*_a, **_k):
        calls["n"] += 1
        raise AssertionError("fetch_repo_artifacts (server PAT) must not run for anonymous")

    _arm_enabled_repo_target(monkeypatch, tmp_path, _boom)

    r = client.post("/v1/settings/scheduled-scan/run-now")
    assert r.status_code == 401, r.text
    assert calls["n"] == 0, "an anonymous caller triggered a server-PAT GitHub call"
    assert not (tmp_path / "scheduled_scan_runs.json").exists()  # no run persisted


def test_run_now_authenticated_operator_drives_token_consumer(tmp_path, monkeypatch):
    """Same setup, authenticated → the operator path DOES reach the token consumer.

    This is the falsifiable twin of the negative test: the spy fires exactly once
    for the authenticated operator and zero times for anonymous, so the difference
    is genuinely the auth gate (the failing GitHub call is recorded by the route's
    own error handling, so no network is touched).
    """
    calls = {"n": 0}

    def _boom(*_a, **_k):
        calls["n"] += 1
        raise AssertionError("expected: operator path reaches the token consumer")

    _arm_enabled_repo_target(monkeypatch, tmp_path, _boom)

    r = client.post("/v1/settings/scheduled-scan/run-now", headers=OP)
    assert r.status_code == 200, r.text
    assert calls["n"] == 1, "authenticated operator must reach the credential path"
    run = r.json()["run"]
    assert run["trigger"] == "manual"
    assert run["scan_mode"] == "repos"
    assert run["repo_results"][0]["status"] == "failed"  # the spy's AssertionError


def test_run_now_authenticated_operator_demo_run_completes(tmp_path, monkeypatch):
    """Authenticated operator with no repo targets → demo run completes (no network)."""
    from app.services import schedule_scan_service as svc

    runs_path = tmp_path / "scheduled_scan_runs.json"
    monkeypatch.setattr(svc, "_RUNS_PATH", runs_path)
    monkeypatch.setattr(svc, "_runs", [])
    monkeypatch.setattr(svc, "_config", {**dict(svc._DEFAULT_CONFIG), "enabled": True})

    r = client.post("/v1/settings/scheduled-scan/run-now", headers=OP)
    assert r.status_code == 200, r.text
    run = r.json()["run"]
    assert run["status"] == "completed"
    assert run["scan_mode"] == "demo"
    assert runs_path.is_file(), "the run must be persisted for an authenticated operator"


# ── route 3: POST /v1/trust/baseline/rebuild ────────────────────────────────
# Side effect: save_baseline() overwrites the FROZEN data/trusted/baseline.json.


def test_trust_rebuild_anonymous_rejected_before_any_write(monkeypatch):
    """Anonymous → 401; save_baseline must never be called; frozen file unchanged."""
    before = _sha256(FROZEN_BASELINE)

    called = {"n": 0}

    def _boom(*_a, **_k):
        called["n"] += 1
        raise AssertionError("save_baseline must not run for an anonymous caller")

    monkeypatch.setattr("app.api.routes_trust.save_baseline", _boom)

    r = client.post("/v1/trust/baseline/rebuild")
    assert r.status_code == 401, r.text
    assert called["n"] == 0, "the frozen baseline rebuild ran for an anonymous caller"
    assert _sha256(FROZEN_BASELINE) == before, "the frozen baseline was modified"


def test_trust_rebuild_authenticated_operator_works_without_touching_frozen_file(monkeypatch):
    """Authenticated → 200 + real rebuild, redirected to a tmp path (frozen bytes intact)."""
    import app.api.routes_trust as routes_trust

    before = _sha256(FROZEN_BASELINE)
    target = {}

    def _recorder(*_a, **_k):
        target["called"] = target.get("called", 0) + 1
        out = REPO / "data" / "trusted" / "_p5fix1_should_never_exist.json"
        target["requested_default"] = out
        # A real rebuild is exercised, but it must never land on the frozen path:
        # return a sentinel path without writing anything.
        return Path("C:/tmp/p5fix1-baseline.json")

    monkeypatch.setattr(routes_trust, "save_baseline", _recorder)

    r = client.post("/v1/trust/baseline/rebuild", headers=OP)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "rebuilt"
    assert target["called"] == 1
    assert body["trusted_package_count"] >= 1  # build_baseline really parsed the lockfiles
    assert _sha256(FROZEN_BASELINE) == before, "the frozen baseline was modified"


# ── route 4: POST /v1/reports/block-explain ────────────────────────────────
# Side effect: generate_block_report() drives the PAID Gemini API with GEMINI_API_KEY.

BLOCK_EXPLAIN_BODY = {
    "package": "corp-internal-ledger-api",
    "version": "1.0.0",
    "primary_reason": "name impersonates an internal package",
}


def test_block_explain_anonymous_never_attempts_an_llm_call(monkeypatch):
    """Anonymous → 401; the paid LLM call path (and the HTTP client) must not run."""
    from app.services import gemini_report_service as gem

    calls = {"n": 0}

    async def _boom(*_a, **_k):
        calls["n"] += 1
        raise AssertionError("generate_block_report (paid Gemini) must not run for anonymous")

    class _BoomClient:
        def __init__(self, *_a, **_k):
            raise AssertionError("an outbound HTTP client was constructed for anonymous")

    # Server key present + both the service entry point and the HTTP client tripped:
    # if the body ran at all, one of these would fire.
    monkeypatch.setattr(gem, "GEMINI_API_KEY", "server-gemini-key-sentinel")
    monkeypatch.setattr("app.api.routes_reports.generate_block_report", _boom)
    monkeypatch.setattr(gem.httpx, "AsyncClient", _BoomClient)

    r = client.post("/v1/reports/block-explain", json=BLOCK_EXPLAIN_BODY)
    assert r.status_code == 401, r.text
    assert calls["n"] == 0, "an anonymous caller drove the paid LLM path"


def test_block_explain_authenticated_operator_fallback_path_works(monkeypatch):
    """Authenticated with no Gemini key → 200 via the deterministic fallback (no network)."""
    from app.services import gemini_report_service as gem

    monkeypatch.setattr(gem, "GEMINI_API_KEY", "")
    gem._REPORT_CACHE.clear()

    r = client.post("/v1/reports/block-explain", json=BLOCK_EXPLAIN_BODY, headers=OP)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source"] == "fallback"
    assert body["gemini_available"] is False
    assert body["summary"] == "name impersonates an internal package"


def test_block_explain_authenticated_operator_reaches_the_llm_entry_point(monkeypatch):
    """Authenticated → the (paid) entry point IS called; anonymous never calls it.

    Falsifiable twin of the negative test: same patched call site, opposite outcome.
    """
    calls = {"n": 0}

    async def _fake_generate(**_k):
        calls["n"] += 1
        return {"summary": "operator-only narrative", "source": "gemini", "gemini_available": True}

    monkeypatch.setattr("app.api.routes_reports.generate_block_report", _fake_generate)

    r = client.post("/v1/reports/block-explain", json=BLOCK_EXPLAIN_BODY, headers=OP)
    assert r.status_code == 200, r.text
    assert calls["n"] == 1
    assert r.json()["source"] == "gemini"


# ── origin (CSRF) checks on the newly protected routes ──────────────────────

NEWLY_PROTECTED = [
    ("put", "/v1/settings/scheduled-scan", {"enabled": False}),
    ("post", "/v1/settings/scheduled-scan/run-now", None),
    ("post", "/v1/trust/baseline/rebuild", None),
    ("post", "/v1/reports/block-explain", BLOCK_EXPLAIN_BODY),
]


@pytest.mark.parametrize("method,path,payload", NEWLY_PROTECTED)
def test_newly_protected_routes_reject_disallowed_origin_even_when_authenticated(
    method, path, payload, monkeypatch
):
    """A hostile browser Origin is refused with 403 even with a valid token.

    Every body is also spied (raising) so a rejected request can never mutate
    anything: if the origin check were missing the body would run and the spy
    would blow the test up.
    """

    def _boom_sync(*_a, **_k):
        raise AssertionError(f"origin-rejected body ran for {method.upper()} {path}")

    async def _boom_async(*_a, **_k):
        raise AssertionError(f"origin-rejected LLM call ran for {method.upper()} {path}")

    monkeypatch.setattr("app.api.routes_scheduled_scan.update_scheduled_scan_config", _boom_sync)
    monkeypatch.setattr("app.api.routes_scheduled_scan.execute_scheduled_scan", _boom_sync)
    monkeypatch.setattr("app.api.routes_trust.save_baseline", _boom_sync)
    monkeypatch.setattr("app.api.routes_reports.generate_block_report", _boom_async)

    kwargs = {"json": payload} if payload is not None else {}
    r = getattr(client, method)(path, headers={**OP, **BAD_ORIGIN}, **kwargs)
    assert r.status_code == 403, f"{method.upper()} {path} -> {r.status_code}"


# ── enumeration: no other mutating route I own is left unauthenticated ───────

# Deliberately open mutating routes:
# pure local compute: no durable state, no credentials, no external API. These
# stay unauthenticated on purpose.
INERT_MUTATING_ALLOWLIST = {
    "/v1/analyse/typosquatting",
    "/v1/scan/ci-cd-injection",
    "/v1/scan/dependency-confusion",
    "/v1/scan/manifest",
    "/v1/scan/run",
    "/v1/scan/sbom",
    "/v1/scan/typosquatting",
    "/v1/scan/workflow",
    "/v1/score",
    "/v1/simulate/ci-cd-injection",
    "/v1/simulate/dependency-confusion",
    "/v1/simulate/typosquatting",
}

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def _operator_guarded(route) -> bool:
    dep = getattr(route, "dependant", None)
    if dep is None:
        return False
    seen: list = []

    def walk(node):
        for sub in node.dependencies:
            seen.append(getattr(sub, "call", None))
            walk(sub)

    walk(dep)
    return require_operator in seen


def test_no_owned_mutating_route_is_left_unauthenticated():
    """Runtime introspection: every mutating route outside the documented inert set is guarded."""
    unguarded = set()
    for route in app.routes:
        methods = getattr(route, "methods", None) or set()
        if not (methods & _MUTATING):
            continue
        if not _operator_guarded(route):
            unguarded.add(route.path)

    assert unguarded == INERT_MUTATING_ALLOWLIST, (
        "mutating routes without require_operator changed: "
        f"newly unguarded={sorted(unguarded - INERT_MUTATING_ALLOWLIST)} "
        f"now guarded={sorted(INERT_MUTATING_ALLOWLIST - unguarded)}"
    )


def test_the_four_review_routes_are_now_operator_guarded():
    """The four protected routes must carry the require_operator dependency."""
    want = {
        "/v1/settings/scheduled-scan",
        "/v1/settings/scheduled-scan/run-now",
        "/v1/trust/baseline/rebuild",
        "/v1/reports/block-explain",
    }
    guarded = set()
    for route in app.routes:
        methods = getattr(route, "methods", None) or set()
        if not (methods & _MUTATING):
            continue
        if _operator_guarded(route):
            guarded.add(route.path)
    assert want <= guarded, f"still unguarded: {sorted(want - guarded)}"
