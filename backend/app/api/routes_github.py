"""GitHub account connection: OAuth, repo listing, artifact fetch."""
from __future__ import annotations

import secrets
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from app.core.auth import check_origin, require_operator
from app.core.config import (
    FRONTEND_URL,
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_OAUTH_REDIRECT_URI,
    GITHUB_TOKEN,
    GITHUB_OAUTH_ENABLED,
)
from app.services import github_client
from app.services.dependency_inventory import (
    collect_dependency_inventory,
    demo_dependency_inventory,
    get_cached_inventory,
)
from app.services.package_registry import fetch_package_detail
from app.schemas.scan_report import CompositeScanResponse, DefenseMode
from app.services.scan_service import run_composite_scan
from app.data.demo_scan_payloads import DEMO_ATTACK_DEPS, DEMO_SBOM, DEMO_WORKFLOW

router = APIRouter(prefix="/github", tags=["GitHub"])


class GitHubConnectBody(BaseModel):
    token: str = Field(min_length=10, description="GitHub personal access token")


def _resolve_token(request: Request):
    """Return the caller's GitHub credential, or the server PAT only for operators.

    The server-side operator PAT (`GITHUB_TOKEN`) must NEVER
    answer an anonymous caller. It is returned only when the request already
    passed `require_operator` (recorded as `request.state.operator_ok`). The
    browser/OAuth session token is returned for its own caller as before.
    """
    session_token = request.session.get("github_token")
    if session_token:
        return session_token
    if getattr(request.state, "operator_ok", False):
        return GITHUB_TOKEN or None
    return None


def _require_token(request: Request) -> str:
    token = _resolve_token(request)
    if not token:
        raise HTTPException(
            status_code=401,
            detail={
                "message": "GitHub not connected",
                "hint": "Set GITHUB_TOKEN in backend/.env or use Connect GitHub (OAuth).",
            },
        )
    return token


@router.get("/status")
def github_status(request: Request, _: None = Depends(require_operator)) -> dict:
    token = _resolve_token(request)
    out = {
        "connected": bool(token),
        "oauth_enabled": GITHUB_OAUTH_ENABLED,
        "pat_configured": bool(GITHUB_TOKEN),
        "session_connected": bool(request.session.get("github_token")),
        "login_url": "/v1/github/login",
        "setup_docs": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token",
    }
    if not token:
        return out

    user = github_client.get_authenticated_user(token)
    out["user"] = user if user.get("ok") else None
    out["connected"] = user.get("ok", False)
    if not user.get("ok"):
        out["error"] = user.get("error")
    return out


@router.post("/connect")
def github_connect(
    body: GitHubConnectBody, request: Request, _: None = Depends(require_operator)
) -> dict:
    """
    Connect GitHub using a personal access token (stored in session cookie only).
    Create token: https://github.com/settings/tokens, scopes: repo, read:user
    """
    check_origin(request)
    token = body.token.strip()
    user = github_client.get_authenticated_user(token)
    if not user.get("ok"):
        raise HTTPException(
            status_code=401,
            detail={
                "message": "Invalid GitHub token",
                "hint": "Check the token and ensure repo + read:user scopes.",
                "error": user.get("error"),
            },
        )
    request.session["github_token"] = token
    return {
        "ok": True,
        "connected": True,
        "user": user,
        "method": "pat_session",
    }


@router.get("/login")
def github_login(request: Request):
    if not GITHUB_OAUTH_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="OAuth not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in backend/.env",
        )
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_OAUTH_REDIRECT_URI,
        "scope": "read:user repo",
        "state": state,
    }
    return RedirectResponse(f"https://github.com/login/oauth/authorize?{urlencode(params)}")


@router.get("/callback")
def github_callback(request: Request, code: str = "", state: str = ""):
    if not GITHUB_OAUTH_ENABLED:
        raise HTTPException(status_code=503, detail="OAuth not configured")
    expected = request.session.get("oauth_state")
    if not expected or state != expected:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    result = github_client.exchange_oauth_code(
        GITHUB_CLIENT_ID,
        GITHUB_CLIENT_SECRET,
        code,
        GITHUB_OAUTH_REDIRECT_URI,
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    request.session["github_token"] = result["access_token"]
    request.session.pop("oauth_state", None)
    return RedirectResponse(f"{FRONTEND_URL}/?github=connected")


@router.post("/logout")
def github_logout(request: Request, _: None = Depends(require_operator)) -> dict:
    check_origin(request)
    request.session.pop("github_token", None)
    request.session.pop("oauth_state", None)
    return {"ok": True, "connected": bool(GITHUB_TOKEN)}


@router.get("/repos")
def github_repos(
    request: Request,
    _: None = Depends(require_operator),
    page: int = 1,
    per_page: int = 100,
    all_repos: bool = Query(default=True, alias="all"),
) -> dict:
    token = _require_token(request)
    if all_repos:
        result = github_client.list_all_repositories(token)
    else:
        result = github_client.list_repositories(token, page=page, per_page=per_page)
    if not result.get("ok"):
        raise HTTPException(status_code=502, detail=result.get("error"))
    return result


@router.get("/repos/{owner}/{repo}/artifacts")
def github_repo_artifacts(
    owner: str, repo: str, request: Request, _: None = Depends(require_operator)
) -> dict:
    token = _require_token(request)
    artifacts = github_client.fetch_repo_artifacts(token, owner, repo)
    if not artifacts.get("dependencies") and not artifacts.get("workflow"):
        artifacts["warning"] = (
            "No package.json dependencies or GitHub Actions workflows found in common paths."
        )
    return artifacts


@router.post("/repos/{owner}/{repo}/scan", response_model=CompositeScanResponse)
def github_repo_scan(
    owner: str,
    repo: str,
    request: Request,
    _: None = Depends(require_operator),
    defense_mode: str = Query(default="hybrid"),
    compare_defense_modes: bool = Query(default=True),
    internal_namespaces: str = Query(default="", description="Comma-separated internal package prefixes"),
) -> CompositeScanResponse:
    """
    Fetch repo artifacts from GitHub and run the full scan pipeline dynamically.
    Falls back to lab demo payloads when manifest/workflow files are missing.
    """
    check_origin(request)
    try:
        mode = DefenseMode(defense_mode)
    except ValueError:
        mode = DefenseMode.HYBRID

    token = _require_token(request)
    artifacts = github_client.fetch_repo_artifacts(token, owner, repo)
    full_name = artifacts.get("full_name") or f"{owner}/{repo}"

    dependencies = artifacts.get("dependencies") or {}
    workflow = artifacts.get("workflow")
    sbom = artifacts.get("sbom")
    demo_fallback = False

    if not dependencies:
        dependencies = DEMO_ATTACK_DEPS
        demo_fallback = True
    if not sbom:
        sbom = DEMO_SBOM
        demo_fallback = True
    if not workflow:
        workflow = DEMO_WORKFLOW
        demo_fallback = True

    from app.policy.project_context import lab_context, project_context

    context = (
        lab_context()
        if demo_fallback
        else project_context(
            artifacts.get("lockfile"),
            [p for p in internal_namespaces.split(",") if p.strip()],
        )
    )
    return run_composite_scan(
        context=context,
        extra_workflows=artifacts.get("extra_workflows") or [],
        source=full_name,
        defense_mode=mode,
        dependencies=dependencies,
        sbom=sbom,
        workflow=workflow,
        compare_defense_modes=compare_defense_modes,
        manifest_path=artifacts.get("manifest_path"),
        workflow_path=artifacts.get("workflow_path"),
        from_github=True,
        demo_fallback=demo_fallback,
    )


@router.get("/dependencies")
def github_dependencies(
    request: Request,
    _: None = Depends(require_operator),
    max_repos: int = Query(default=50, ge=1, le=100),
    defense_mode: str = Query(default="hybrid"),
    demo: bool = Query(default=False),
    fast: bool = Query(default=True),
    refresh: bool = Query(default=False),
) -> dict:
    """
    Aggregate dependencies across GitHub repositories (npm + pip).
    fast=true uses quick scoring; refresh=true bypasses server cache.
    """
    try:
        mode = DefenseMode(defense_mode)
    except ValueError:
        mode = DefenseMode.HYBRID

    if demo:
        return demo_dependency_inventory(mode)

    token = _resolve_token(request)
    if not token:
        return demo_dependency_inventory(mode)

    if not refresh:
        cached = get_cached_inventory(token, max_repos, mode, fast)
        if cached:
            return cached

    result = collect_dependency_inventory(
        token,
        max_repos=max_repos,
        defense_mode=mode,
        fast=fast,
        use_cache=not refresh,
    )
    if not result.get("ok"):
        raise HTTPException(status_code=502, detail=result.get("error"))
    return result


@router.get("/packages/{ecosystem}/{package_name:path}")
def github_package_detail(
    ecosystem: str,
    package_name: str,
    version: Optional[str] = Query(default=None),
    risk_score: Optional[float] = Query(default=None, ge=0.0, le=1.0),
) -> dict:
    """Registry metadata + risk scores for package detail view (supports scoped npm names).

    Honesty: `risk_score` is OPTIONAL with NO numeric default. An omitted/unknown
    risk score stays None end-to-end: it is never coerced back to a fabricated
    number (e.g. the old 0.15), so downstream gauges/alerts never present an
    unknown score as a benign measured value.
    """
    # FastAPI :path preserves @scope/pkg; decode in case of double-encoding
    from urllib.parse import unquote
    name = unquote(package_name).strip()
    detail = fetch_package_detail(ecosystem, name, version=version, risk_score=risk_score)
    if not detail.get("ok"):
        raise HTTPException(status_code=404, detail=detail.get("error", "Package not found"))
    return detail
