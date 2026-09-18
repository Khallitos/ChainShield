"""Model metadata and evaluation metrics for the API.

The deployed model is the package-content classifier exported as plain arrays
(``backend/ml/models/package_content_v3.{npz,json}``); its sidecar records the family, the
training split and the decision policy. Evaluation metrics come from the released research
summary (``research/results/summary_v3.json``), so the API never reports numbers that the
artifact cannot reproduce.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from app.ml.package_model import MODEL_DIR, MODEL_NAME
from app.policy.decision_contract import DEFAULT_RUNTIME_POLICY
from app.services.hybrid_scorer import ModelStatus, get_model_provider, model_version

_BACKEND = Path(__file__).resolve().parents[2]
_SIDECAR = MODEL_DIR / f"{MODEL_NAME}.json"
_ARRAYS = MODEL_DIR / f"{MODEL_NAME}.npz"
_SUMMARY = _BACKEND.parent / "research" / "results" / "summary_v3.json"


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def get_model_info() -> Dict[str, Any]:
    """Public model card for /v1/ml/model-info (honest about inference availability)."""
    sidecar = _read_json(_SIDECAR)
    summary = _read_json(_SUMMARY)
    provider = get_model_provider()
    status = provider.status()
    inference_enabled = status is ModelStatus.LOADED
    policy = DEFAULT_RUNTIME_POLICY

    out: Dict[str, Any] = {
        "model_version": model_version(),
        # model_loaded is honest: True ONLY when an inference provider is actually live.
        "model_loaded": inference_enabled,
        "model_available": _ARRAYS.is_file(),
        "model_status": status.value,  # loaded | absent | error | disabled
        "inference_enabled": inference_enabled,
        "inference_provider": provider.label,
        "model_path": str(_ARRAYS.relative_to(_BACKEND)) if _ARRAYS.is_file() else None,
        "model_format": "numpy arrays with recorded SHA-256 (no serialised objects)",
        "algorithm": (sidecar or {}).get("family"),
        "trained_on": (sidecar or {}).get("trained_on"),
        "content_features_count": len((sidecar or {}).get("columns") or []),
        "signal_slots_count": 11,
        "policy_version": policy.policy_version,
        "hybrid_blend": {"rules_weight": policy.rule_weight, "ml_weight": policy.ml_weight},
        "thresholds": {"warn": policy.warn_threshold, "block": policy.block_threshold},
        "dataset": "NPMStudy benchmark (Guo et al.), npm registry, 6,420 malicious / 7,024 benign",
        "evaluation_command": "python research/reproduce.py",
    }

    if not inference_enabled:
        # Honest, non-fabricated status. No pretend ML results are produced.
        if status is ModelStatus.ERROR:
            out["inference_note"] = (
                "The package archive or the model could not be read; package decisions hold "
                "instead of allowing."
            )
        elif status is ModelStatus.DISABLED:
            out["inference_note"] = (
                "Package-content inference is configured off on this host; package decisions "
                "hold under the default policy."
            )
        else:
            out["inference_note"] = (
                "No package-content provider is installed; package decisions hold under the "
                "default policy."
            )

    if summary:
        out["metrics_summary"] = summary.get("test_arms")
        out["operational_impact_per_1000"] = summary.get("test_per_1000")
        out["dataset_summary"] = summary.get("dataset")

    return out


def get_metrics() -> Dict[str, Any]:
    """Full evaluation metrics for /v1/ml/metrics (from the released research summary)."""
    summary = _read_json(_SUMMARY)
    if not summary:
        raise FileNotFoundError("research/results/summary_v3.json missing")
    info = get_model_info()
    return {
        **summary,
        "model_loaded": info["model_loaded"],
        "model_version": info["model_version"],
        "policy_version": info["policy_version"],
        "hybrid_blend": info["hybrid_blend"],
    }
