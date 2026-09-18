"""AI-generated block reports (Gemini), grounded on hybrid engine output."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.auth import check_origin, require_operator
from app.services.gemini_report_service import gemini_configured, generate_block_report

router = APIRouter(prefix="/reports", tags=["Reports"])


class BlockExplainRequest(BaseModel):
    package: str = Field(..., min_length=1)
    version: str = "*"
    attack_type: Optional[str] = None
    source: Optional[str] = None
    primary_reason: Optional[str] = None
    canonical: Optional[str] = None
    hostname: Optional[str] = None
    cwd: Optional[str] = None
    audience: str = "developer"
    engine: Optional[Dict[str, Any]] = None


class BlockExplainResponse(BaseModel):
    summary: str
    training_platform_note: str = ""
    business_impact: str = ""
    technical_impact: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    source: str = "gemini"
    model: Optional[str] = None
    gemini_available: bool = False
    gemini_error: Optional[str] = None
    cached: bool = False
    grounding: Optional[Dict[str, Any]] = None


@router.get("/gemini/status")
def gemini_status() -> dict:
    return {
        "configured": gemini_configured(),
        "role": "interpreter",
        "note": "Gemini explains hybrid engine decisions; it does not block packages.",
    }


@router.post("/block-explain", response_model=BlockExplainResponse)
async def block_explain(
    body: BlockExplainRequest,
    request: Request,
    _: None = Depends(require_operator),
) -> BlockExplainResponse:
    """Generate a human-readable block report from hybrid ML + rule engine evidence.

    Operator-auth + origin only: this drives the PAID Gemini API
    with the server's ``GEMINI_API_KEY``, so an anonymous caller (who could burn the
    operator's LLM quota/cost) must be rejected before any LLM call is attempted.
    """
    check_origin(request)
    if not body.engine and not body.primary_reason:
        raise HTTPException(
            status_code=400,
            detail="Provide engine evidence or primary_reason from the hybrid scorer.",
        )

    report = await generate_block_report(
        package=body.package,
        version=body.version,
        attack_type=body.attack_type,
        source=body.source,
        engine=body.engine,
        primary_reason=body.primary_reason,
        canonical=body.canonical,
        hostname=body.hostname,
        cwd=body.cwd,
        audience=body.audience,
    )
    return BlockExplainResponse(**report)
