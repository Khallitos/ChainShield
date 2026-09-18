"""ML model metrics API."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.services.ml_service import get_metrics, get_model_info

router = APIRouter(prefix="/ml", tags=["ML"])


@router.get("/model-info")
def model_info() -> dict:
    return get_model_info()


@router.get("/metrics")
def metrics() -> dict:
    try:
        return get_metrics()
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={
                "message": "No evaluation metrics available",
                "hint": "Run: python research/reproduce.py",
            },
        )
