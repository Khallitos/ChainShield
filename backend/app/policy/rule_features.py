"""Pure feature -> rule-score mapping, shared by the evaluator adapter and the
runtime scorer.

This reproduces exactly the legacy ``hybrid_scorer._rule_score_from_features``
score arithmetic so the evaluator and runtime cannot drift. It contains no I/O.
"""
from __future__ import annotations

from typing import Dict

__all__ = ["rule_score_from_features"]


def rule_score_from_features(v: Dict[str, float]) -> float:
    """Deterministic rule score in [0, 0.99] for a feature vector dict.

    Copied verbatim from the original ``app/services/hybrid_scorer.py``
    (rule-only arm); it is the fused-score input, not a learned-model output.
    """
    score = 0.05
    if v.get("typosquat_high"):
        score = max(score, 0.88)
    if v.get("baseline_drift"):
        score = max(score, 0.75)
    if v.get("public_high_version"):
        score = max(score, 0.92)
    if v.get("version_gap_score", 0) >= 0.55:
        score = max(score, 0.85)
    if v.get("dep_confusion_signal", 0) >= 0.5:
        score = max(score, 0.80)
    if v.get("workflow_injection_signal", 0) >= 0.3:
        # Camera-ready: non-critical workflow findings (unpinned tags, broad token permissions)
        # are hardening gaps and land in the warn band; only critical findings block (below).
        # Measured on 2,722 real workflows (research/results/workflow_layer_v3.json).
        score = max(score, 0.70)
    if v.get("ci_critical_count", 0) >= 1:
        score = max(score, 0.95)
    if v.get("exact_trusted_match") and score < 0.5:
        score = min(score, 0.15)
    return min(score, 0.99)
