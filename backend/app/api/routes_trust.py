"""Trust baseline API: data-derived graph from lockfiles."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.auth import check_origin, require_operator
from app.services.baseline_builder import build_baseline, load_baseline, save_baseline

router = APIRouter(prefix="/trust", tags=["Trust"])


@router.get("/baseline")
def get_baseline() -> dict:
    """Return the current trust graph (built from project lockfiles)."""
    return load_baseline()


@router.post("/baseline/rebuild")
def rebuild_baseline(
    request: Request,
    _: None = Depends(require_operator),
) -> dict:
    """Rebuild trust graph from lockfiles and persist to data/trusted/baseline.json.

    Operator-auth + origin only: this overwrites the trust
    baseline that backs the install decision, so an anonymous caller must be
    rejected at the auth dependency before `save_baseline()` (the write) runs.
    """
    check_origin(request)
    path = save_baseline()
    baseline = build_baseline()
    return {
        "status": "rebuilt",
        "path": str(path),
        "trusted_package_count": len(baseline.get("trusted_packages", {})),
        "sources": baseline.get("sources", []),
    }
