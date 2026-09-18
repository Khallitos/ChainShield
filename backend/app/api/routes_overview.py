"""Overview dashboard API: dynamic charts from backend analytics."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query, Request

from app.api.routes_github import _resolve_token
from app.schemas.scan_report import DefenseMode
from app.services.overview_service import SCORE_CATEGORIES, build_overview_dashboard

router = APIRouter(prefix="/overview", tags=["Overview"])


@router.get("/dashboard")
def get_overview_dashboard(
    request: Request,
    defense_mode: str = Query(default="hybrid"),
    max_repos: int = Query(default=50, ge=1, le=100),
    fast: bool = Query(default=True),
    demo: bool = Query(default=False),
    refresh: bool = Query(default=False),
    owner: Optional[str] = Query(default=None),
    repo: Optional[str] = Query(default=None),
) -> dict:
    try:
        mode = DefenseMode(defense_mode)
    except ValueError:
        mode = DefenseMode.HYBRID

    token = _resolve_token(request)
    use_demo = demo or not token

    return build_overview_dashboard(
        token=token,
        defense_mode=mode,
        max_repos=max_repos,
        fast=fast,
        demo=use_demo,
        use_cache=not refresh,
        owner=owner,
        repo=repo,
    )


@router.get("/score-categories")
def get_score_categories() -> dict:
    return {"categories": [{"key": k, "label": label} for k, label in SCORE_CATEGORIES]}
