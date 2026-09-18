"""Evaluator adapter for the decision contract.

This adapter lets an evaluator (and the tests) run legacy-eval and revised policies
through the SAME contract the runtime and install hook use.

It takes numeric rule/ML scores as *inputs*: it never loads the stored model, so
anything it computes is policy arithmetic on supplied scores: NOT a reproduction
of the original learned RandomForest's predictions.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from app.policy.decision_contract import (
    Evidence,
    MandatoryViolation,
    ModelStatus,
    Policy,
    Verdict,
    VerdictLevel,
    decide,
)

__all__ = ["row_evidence", "predict_row", "legacy_eval_binary"]


def row_evidence(
    rule_score: float,
    ml_score: Optional[float],
    model_status: ModelStatus,
    *,
    source: str = "evaluator",
    baseline_signals: Optional[Mapping[str, Any]] = None,
    hints: Optional[Mapping[str, Any]] = None,
    mandatory: Iterable[MandatoryViolation] = (),
) -> Evidence:
    """Build normalized evidence from a frozen-dataset feature row's scores."""
    return Evidence(
        rule_score=rule_score,
        ml_score=ml_score,
        model_status=model_status,
        evidence_source=source,
        baseline_signals=dict(baseline_signals or {}),
        hints=dict(hints or {}),
        mandatory_violations=tuple(mandatory),
    )


def predict_row(
    rule_score: float,
    ml_score: Optional[float],
    model_status: ModelStatus,
    policy: Policy,
    **kwargs: Any,
) -> Verdict:
    """Evaluator consumer: contract decision for one supplied (rule, ml) row."""
    evidence = row_evidence(rule_score, ml_score, model_status, **kwargs)
    return decide(evidence, policy)


def legacy_eval_binary(verdict: Verdict) -> int:
    """Binary label for the legacy-eval single 0.60 cut (1 = malicious)."""
    return 1 if verdict.verdict in (VerdictLevel.BLOCK, VerdictLevel.WARN) else 0
