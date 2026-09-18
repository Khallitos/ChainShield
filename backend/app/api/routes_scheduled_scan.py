"""Scheduled scan settings API."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.core.auth import check_origin, require_operator
from app.services.schedule_scan_service import (
    execute_scheduled_scan,
    get_scheduled_scan_config,
    list_scheduled_runs,
    update_scheduled_scan_config,
    validate_cron,
)

router = APIRouter(prefix="/settings/scheduled-scan", tags=["Settings"])


class RepoTargetBody(BaseModel):
    full_name: str = Field(..., min_length=1, max_length=200)
    owner: Optional[str] = None
    name: Optional[str] = None
    priority: int = Field(default=1, ge=1, le=9999)
    enabled: bool = False


class ScheduledScanBody(BaseModel):
    enabled: bool | None = None
    cron_expression: str | None = Field(default=None, min_length=1, max_length=120)
    source: str | None = Field(default=None, min_length=1, max_length=120)
    repo_targets: List[RepoTargetBody] | None = None


@router.get("")
def get_schedule() -> dict:
    return get_scheduled_scan_config()


@router.put("")
def put_schedule(
    body: ScheduledScanBody,
    request: Request,
    _: None = Depends(require_operator),
) -> dict:
    """Reconfigure the automated scanner: operator-auth + origin only.

    This route persists ``data/scheduled_scan.json`` and changes what the background
    scheduler will scan, so an anonymous caller must get 401 before this body runs.
    """
    check_origin(request)
    try:
        return update_scheduled_scan_config(body.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/runs")
def get_runs(limit: int = Query(default=20, ge=1, le=100)) -> dict:
    return list_scheduled_runs(limit)


@router.post("/run-now")
def run_now(
    request: Request,
    _: None = Depends(require_operator),
) -> dict:
    """Run a scheduled scan immediately: operator-auth + origin only.

    This route persists run state AND, when enabled repo targets exist, makes
    server-PAT-authenticated GitHub calls; an anonymous caller must be rejected at
    the auth dependency before either side effect is reachable.
    """
    check_origin(request)
    run = execute_scheduled_scan(trigger="manual")
    return {"run": run}


@router.get("/validate-cron")
def validate_cron_expr(expression: str = Query(..., min_length=1)) -> dict:
    ok = validate_cron(expression.strip())
    return {"valid": ok, "expression": expression.strip()}
