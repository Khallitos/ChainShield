"""Pure, versioned decision contract for ChainShield.

This module is the single owner of "what does the evidence mean". It is a pure
function: ``decide(evidence, policy) -> Verdict``. It performs **no** I/O, loads
**no** model, reads **no** trust graph, and mutates **no** global state.

Design:

* ``Evidence`` is validated, typed, finite and bounded. ``rule_score`` and
  ``ml_score`` live in ``[0, 1]``; ``NaN``/``inf`` are rejected; a
  ``model_status='loaded'`` with no score (or a score with a non-loaded status)
  is a contradiction and is rejected explicitly.
* ``Policy`` is an immutable, versioned decision table. Three policies ship here:
  ``POLICY_LEGACY_EVAL`` (evaluation: ``0.4*rule + 0.6*ml``, one ``0.60`` cut,
  **no** post-fusion cap), ``POLICY_LEGACY_RUNTIME`` (production runtime:
  ``0.85`` BLOCK / ``0.60`` WARN **with** the ``0.25`` exact-trusted cap), and
  ``POLICY_REVISED`` (separate version, ML required, honest unknown handling).
  These legacy policies are *not* the same policy and must not be merged.
* ``MandatoryViolation`` is a narrow, explicit, provenance-validated evidence
  set. It forces a decisive action that ML cannot downgrade and that the
  exact-trusted cap cannot conceal. Free-form client booleans/strings such as
  ``"mandatory": true`` never enter here, only registry codes via a source
  adapter.
* Advisories (name/version heuristics, workflow regex findings) are advisory
  only; they are surfaced in ``reasons`` and never elevated to mandatory.
* ``model_status`` in ``{absent, error, disabled}`` is never "safe". Under the
  revised policy a required-but-missing model yields HOLD, never ALLOW.
* ``score`` and ``action`` are separate: ``score`` is the fused detector value,
  ``action`` is the enforced outcome. A monitoring/unblocked override changes the
  action, never the detector truth.

No demo/attack package name appears anywhere in this module.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Optional, Sequence, Tuple

__all__ = [
    "Action",
    "EvidenceError",
    "Evidence",
    "MandatoryViolation",
    "ModelStatus",
    "PolicyError",
    "Policy",
    "VerdictLevel",
    "Verdict",
    "decide",
    "core_payload",
    "ALLOWED_PROVENANCE",
    "MANDATORY_EVIDENCE_REGISTRY",
    "POLICY_LEGACY_EVAL",
    "POLICY_LEGACY_RUNTIME",
    "POLICY_REVISED",
    "POLICY_PACKAGE_V3",
    "POLICY_WORKFLOW_RULES",
    "POLICY_RULES_ONLY",
    "DEFAULT_RUNTIME_POLICY",
    "POLICY_VERSION_LEGACY_EVAL",
    "POLICY_VERSION_LEGACY_RUNTIME",
    "POLICY_VERSION_REVISED",
]


def _deep_freeze(value: Any) -> Any:
    """Recursively make nested containers immutable (mappings/list/tuple/set)."""
    if isinstance(value, Mapping):
        return MappingProxyType({k: _deep_freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(v) for v in value)
    if isinstance(value, set):
        return frozenset(_deep_freeze(v) for v in value)
    return value


def _reject_non_finite_nested(value: Any, path: str = "signal") -> None:
    """Reject any non-finite (NaN/inf) numeric value inside a nested structure.

    Booleans are excluded: a boolean flag is not a numeric magnitude. This prevents
    a NaN sneaking into a ``bool(signal)`` truthiness check (NaN is truthy) and being
    treated as a cap/conflict trigger.
    """
    if isinstance(value, Mapping):
        for k, v in value.items():
            _reject_non_finite_nested(v, f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _reject_non_finite_nested(v, f"{path}[{i}]")
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(float(value)):
            raise EvidenceError(f"{path} contains non-finite number {value!r}")


# ── errors ────────────────────────────────────────────────────────────────────

class EvidenceError(ValueError):
    """Raised when evidence is malformed, non-finite, out of range or contradictory."""


class PolicyError(ValueError):
    """Raised when a policy or enforcement mode is malformed."""


# ── enums ─────────────────────────────────────────────────────────────────────

class ModelStatus(str, Enum):
    """Honest model availability. `disabled` = present but inference intentionally off."""

    LOADED = "loaded"
    ABSENT = "absent"
    ERROR = "error"
    DISABLED = "disabled"


class VerdictLevel(str, Enum):
    """Detector truth classification. HOLD = cannot decide safely (incomplete)."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    HOLD = "hold"


class Action(str, Enum):
    """Enforced outcome. May differ from the verdict under an override."""

    ALLOW = "allow"
    MONITOR = "monitor"
    WARN = "warn"
    BLOCK = "block"
    HOLD = "hold"


# ── mandatory evidence registry (narrow, explicit, provenance-gated) ──────────

# code -> required field names (each must be a non-empty string)
MANDATORY_EVIDENCE_REGISTRY: Mapping[str, FrozenSet[str]] = MappingProxyType(
    {
        "trusted_policy_digest_mismatch": frozenset({"digest"}),
        "approved_registry_violation": frozenset({"registry"}),
        # a workflow rule of critical severity (e.g. untrusted input reaching a shell step)
        "critical_workflow_finding": frozenset({"rule"}),
    }
)

# Provenance values a source adapter may use. Anything else is rejected, so a
# caller cannot invent a "mandatory" signal from arbitrary client input.
ALLOWED_PROVENANCE: FrozenSet[str] = frozenset(
    {"evaluator", "runtime", "install", "api", "scan_service", "unit-test"}
)


@dataclass(frozen=True)
class MandatoryViolation:
    """A verified, narrowly-scoped policy violation that ML cannot downgrade."""

    code: str
    provenance: str
    fields: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.code not in MANDATORY_EVIDENCE_REGISTRY:
            raise EvidenceError(
                f"unknown mandatory code {self.code!r}; allowed: "
                f"{sorted(MANDATORY_EVIDENCE_REGISTRY)}"
            )
        if self.provenance not in ALLOWED_PROVENANCE:
            raise EvidenceError(
                f"unknown mandatory provenance {self.provenance!r}; allowed: "
                f"{sorted(ALLOWED_PROVENANCE)}"
            )
        required = MANDATORY_EVIDENCE_REGISTRY[self.code]
        missing = {
            k
            for k in required
            if not isinstance(self.fields.get(k), str) or not self.fields.get(k).strip()
        }
        if missing:
            raise EvidenceError(
                f"mandatory {self.code!r} missing required non-empty field(s): {sorted(missing)}"
            )
        object.__setattr__(self, "fields", _deep_freeze(self.fields))

    @classmethod
    def create(cls, code: str, provenance: str, **fields: str) -> "MandatoryViolation":
        return cls(code=code, provenance=provenance, fields=dict(fields))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "provenance": self.provenance,
            "fields": {k: self.fields[k] for k in sorted(self.fields)},
        }


# ── evidence ──────────────────────────────────────────────────────────────────

def _check_score(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceError(f"{name} must be a real number, got {type(value).__name__}")
    f = float(value)
    if not math.isfinite(f):
        raise EvidenceError(f"{name} must be finite, got {value!r}")
    if f < 0.0 or f > 1.0:
        raise EvidenceError(f"{name} must be in [0, 1], got {value!r}")
    return f


@dataclass(frozen=True)
class Evidence:
    """Normalized, validated evidence for one decision row."""

    rule_score: float
    ml_score: Optional[float]
    model_status: ModelStatus
    evidence_source: str = "unknown"
    findings: Tuple[Mapping[str, Any], ...] = ()
    baseline_signals: Mapping[str, Any] = field(default_factory=dict)
    hints: Mapping[str, Any] = field(default_factory=dict)
    mandatory_violations: Tuple[MandatoryViolation, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_score", _check_score(self.rule_score, "rule_score"))
        if self.ml_score is not None:
            object.__setattr__(self, "ml_score", _check_score(self.ml_score, "ml_score"))

        try:
            status = ModelStatus(self.model_status)
        except ValueError as exc:
            raise EvidenceError(f"unknown model_status {self.model_status!r}") from exc
        object.__setattr__(self, "model_status", status)

        # explicit contradiction checks
        if status is ModelStatus.LOADED and self.ml_score is None:
            raise EvidenceError("model_status='loaded' requires a numeric ml_score")
        if status is not ModelStatus.LOADED and self.ml_score is not None:
            raise EvidenceError(
                f"model_status={status.value!r} must not carry an ml_score"
            )

        if not isinstance(self.evidence_source, str) or not self.evidence_source.strip():
            raise EvidenceError("evidence_source must be a non-empty string")

        mv = tuple(self.mandatory_violations)
        for item in mv:
            if not isinstance(item, MandatoryViolation):
                raise EvidenceError("mandatory_violations must be MandatoryViolation instances")
        object.__setattr__(self, "mandatory_violations", mv)
        object.__setattr__(self, "findings", _deep_freeze(tuple(self.findings)))
        _reject_non_finite_nested(self.baseline_signals, "baseline_signals")
        _reject_non_finite_nested(self.hints, "hints")
        object.__setattr__(self, "baseline_signals", _deep_freeze(self.baseline_signals))
        object.__setattr__(self, "hints", _deep_freeze(self.hints))


# ── policy ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Policy:
    """Immutable, versioned decision table."""

    policy_version: str
    rule_weight: float = 0.4
    ml_weight: float = 0.6
    block_threshold: float = 0.85
    warn_threshold: float = 0.60
    trusted_cap: Optional[float] = 0.25
    cap_conflict_keys: Tuple[str, ...] = (
        "baseline_drift",
        "typosquat_high",
        "dep_confusion_signal",
        "workflow_injection_signal",
    )
    ml_required: bool = False
    model_missing_verdict: VerdictLevel = VerdictLevel.HOLD
    model_missing_action: Action = Action.HOLD
    mandatory_action: Action = Action.BLOCK
    mandatory_codes: FrozenSet[str] = frozenset(MANDATORY_EVIDENCE_REGISTRY)
    description: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise PolicyError("policy_version must be a non-empty string")
        for name in ("rule_weight", "ml_weight", "block_threshold", "warn_threshold"):
            v = getattr(self, name)
            try:
                fv = float(v)
            except (TypeError, ValueError) as exc:
                raise PolicyError(f"{name} must be numeric") from exc
            if not math.isfinite(fv) or fv < 0.0 or fv > 1.0:
                raise PolicyError(f"{name} must be finite in [0, 1], got {v!r}")
        if self.block_threshold < self.warn_threshold:
            raise PolicyError("block_threshold must be >= warn_threshold")
        if self.trusted_cap is not None:
            cap = float(self.trusted_cap)
            if not math.isfinite(cap) or cap < 0.0 or cap > 1.0:
                raise PolicyError(f"trusted_cap must be finite in [0, 1], got {self.trusted_cap!r}")
        unknown = set(self.mandatory_codes) - set(MANDATORY_EVIDENCE_REGISTRY)
        if unknown:
            raise PolicyError(f"policy references unknown mandatory codes: {sorted(unknown)}")


# ── shipped policies ──────────────────────────────────────────────────────────

POLICY_VERSION_LEGACY_EVAL = "legacy-eval-0.1.0"
POLICY_VERSION_LEGACY_RUNTIME = "legacy-runtime-0.1.0"
POLICY_VERSION_REVISED = "revised-0.1.0"

# scripts/evaluate_all.py `_predict_hybrid`: 0.4*rule+0.6*ml, one 0.60 cut, no cap.
POLICY_LEGACY_EVAL = Policy(
    policy_version=POLICY_VERSION_LEGACY_EVAL,
    rule_weight=0.4,
    ml_weight=0.6,
    block_threshold=0.60,
    warn_threshold=0.60,
    trusted_cap=None,
    ml_required=False,
    description=(
        "Legacy evaluation policy: fused 0.4*rule+0.6*ml at a single 0.60 cut, "
        "NO post-fusion trusted cap (evaluate_all.py). Binary label only."
    ),
)

# app/services/hybrid_scorer.py: 0.85 BLOCK / 0.60 WARN with 0.25 trusted cap.
POLICY_LEGACY_RUNTIME = Policy(
    policy_version=POLICY_VERSION_LEGACY_RUNTIME,
    rule_weight=0.4,
    ml_weight=0.6,
    block_threshold=0.85,
    warn_threshold=0.60,
    trusted_cap=0.25,
    ml_required=False,  # legacy falls back to rules-only when ML is unavailable
    description=(
        "Legacy production runtime: 0.85 BLOCK / 0.60 WARN with the 0.25 "
        "exact-trusted cap; missing ML falls back to rules-only (today's behaviour)."
    ),
)

# Revised runtime policy: separately versioned, ML required, honest unknown.
POLICY_REVISED = Policy(
    policy_version=POLICY_VERSION_REVISED,
    rule_weight=0.4,
    ml_weight=0.6,
    block_threshold=0.85,
    warn_threshold=0.60,
    trusted_cap=0.25,  # kept, but mandatory/conflict evidence bypasses it
    ml_required=True,
    model_missing_verdict=VerdictLevel.HOLD,
    model_missing_action=Action.HOLD,
    mandatory_action=Action.BLOCK,
    description=(
        "Revised policy: required-but-missing/error model is HOLD (never ALLOW); a "
        "verified mandatory violation BLOCKS and cannot be capped or downgraded; "
        "name/version heuristics stay advisory."
    ),
)

POLICY_VERSION_PACKAGE_V3 = "package-v3-1.0.0"
POLICY_VERSION_WORKFLOW_RULES = "workflow-rules-1.0.0"
POLICY_VERSION_RULES_ONLY = "rules-only-1.0.0"

# Package layer (manifest / SBOM). Weights and thresholds were selected on out-of-fold scores of
# the NPMStudy TRAIN split (research/scripts/05_train_select_evaluate.py, results/evaluation_v3.json)
# before the test split was scored; tests assert they match the exported model sidecar.
POLICY_PACKAGE_V3 = Policy(
    policy_version=POLICY_VERSION_PACKAGE_V3,
    rule_weight=0.3,
    ml_weight=0.7,
    block_threshold=0.38,
    warn_threshold=0.34,
    # The cap applies only to the exact artifact the project lockfile already records (name AND
    # version, see trust_graph); a new release of a trusted name is scored on its content.
    trusted_cap=0.25,
    ml_required=True,
    model_missing_verdict=VerdictLevel.HOLD,
    model_missing_action=Action.HOLD,
    mandatory_action=Action.BLOCK,
    description=(
        "Package layer: 0.3*rule + 0.7*P(malicious | package content); warn/block cuts selected "
        "on training-split cross-validation; confirmed confusion against declared internal names "
        "is mandatory; missing model or unreadable package is HOLD."
    ),
)

# Workflow layer. No learned model exists for workflows (there is no labelled malicious-workflow
# corpus), so the rule score decides alone and a critical rule finding is mandatory.
POLICY_WORKFLOW_RULES = Policy(
    policy_version=POLICY_VERSION_WORKFLOW_RULES,
    rule_weight=1.0,
    ml_weight=0.0,
    block_threshold=0.85,
    warn_threshold=0.60,
    trusted_cap=None,
    ml_required=False,
    mandatory_action=Action.BLOCK,
    description="Workflow layer: rule score only; critical workflow finding blocks.",
)

# Rules-only operating mode (Sect. 3.3 of the paper): the rule score decides alone with
# warn 0.45 / block 0.75, the cuts of the rules-only evaluation arm. No model is required,
# so this mode never holds for lack of one; mandatory violations still block.
POLICY_RULES_ONLY = Policy(
    policy_version=POLICY_VERSION_RULES_ONLY,
    rule_weight=1.0,
    ml_weight=0.0,
    block_threshold=0.75,
    warn_threshold=0.45,
    trusted_cap=0.25,
    ml_required=False,
    mandatory_action=Action.BLOCK,
    description="Rules-only mode: rule score alone, warn 0.45, block 0.75; no model required.",
)

# The ONE shared runtime policy: used by /v1/score, every /v1/scan/* route (manifest,
# workflow, sbom) and the install hook for the same evidence. Legacy policies remain
# reachable ONLY by explicit original-replay callers (scripts/evaluate_all.py and the
# legacy-compatible tuple adapter). Under this default, a required-but-unavailable ML
# model yields HOLD (fail-closed), never ALLOW-as-safe.
DEFAULT_RUNTIME_POLICY = POLICY_PACKAGE_V3


# ── core ──────────────────────────────────────────────────────────────────────

_ENFORCEMENTS = ("enforce", "monitor", "unblocked")
_ACTION_FOR_VERDICT = {
    VerdictLevel.ALLOW: Action.ALLOW,
    VerdictLevel.WARN: Action.WARN,
    VerdictLevel.BLOCK: Action.BLOCK,
    VerdictLevel.HOLD: Action.HOLD,
}


def _fuse(evidence: Evidence, policy: Policy) -> Optional[float]:
    """Fused detector score, or None when a required model is unavailable."""
    if evidence.ml_score is None:
        if policy.ml_required:
            return None  # incomplete: ML required but absent/error/disabled
        return evidence.rule_score  # legacy rules-only fallback
    return policy.rule_weight * evidence.rule_score + policy.ml_weight * evidence.ml_score


def _apply_trusted_cap(score: float, evidence: Evidence, policy: Policy) -> float:
    if policy.trusted_cap is None:
        return score
    signals = evidence.baseline_signals
    if not signals.get("exact_trusted_match"):
        return score
    for key in policy.cap_conflict_keys:
        if signals.get(key):
            return score  # conflicting evidence: the cap must not conceal it
    return min(score, float(policy.trusted_cap))


def _classify(score: float, policy: Policy) -> VerdictLevel:
    if score >= policy.block_threshold:
        return VerdictLevel.BLOCK
    if score >= policy.warn_threshold:
        return VerdictLevel.WARN
    return VerdictLevel.ALLOW


@dataclass(frozen=True)
class Verdict:
    """Immutable decision result. Serialises to a stable, ordered dict."""

    policy_version: str
    evidence_source: str
    layer: str
    rule_score: float
    ml_score: Optional[float]
    model_status: ModelStatus
    score: Optional[float]
    verdict: VerdictLevel
    action: Action
    mandatory_violations: Tuple[MandatoryViolation, ...] = ()
    reasons: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "evidence_source": self.evidence_source,
            "layer": self.layer,
            "rule_score": round(self.rule_score, 6),
            "ml_score": None if self.ml_score is None else round(self.ml_score, 6),
            "model_status": self.model_status.value,
            "mandatory_violations": [m.to_dict() for m in self.mandatory_violations],
            "score": None if self.score is None else round(self.score, 6),
            "verdict": self.verdict.value,
            "action": self.action.value,
            "reasons": list(self.reasons),
        }


def core_payload(verdict: Verdict) -> Dict[str, Any]:
    """The consumer-independent core of a verdict (excludes transport identity).

    Consumers may attach their own source/layer/timestamps/scan ids; the core must
    be byte-identical for the same normalized evidence + policy.
    """
    return {
        "policy_version": verdict.policy_version,
        "rule_score": round(verdict.rule_score, 6),
        "ml_score": None if verdict.ml_score is None else round(verdict.ml_score, 6),
        "model_status": verdict.model_status.value,
        "mandatory_violations": [m.to_dict() for m in verdict.mandatory_violations],
        "score": None if verdict.score is None else round(verdict.score, 6),
        "verdict": verdict.verdict.value,
        "action": verdict.action.value,
    }


def _advisory_reasons(evidence: Evidence) -> Tuple[str, ...]:
    out = []
    for key in sorted(evidence.hints):
        if evidence.hints.get(key):
            out.append(f"advisory:{key}")
    return tuple(out)


def decide(
    evidence: Evidence,
    policy: Policy,
    *,
    enforcement: str = "enforce",
) -> Verdict:
    """Pure decision. Same normalized evidence + policy => same core payload.

    ``enforcement`` is an explicit *override* applied last:
      * ``enforce`` (default): action follows the verdict.
      * ``monitor``: install is allowed but recorded (action=monitor).
      * ``unblocked``: explicit, non-default bypass (action=allow).
    Neither override changes the detector truth (``verdict``/``score``).
    """
    if not isinstance(evidence, Evidence):
        raise EvidenceError("evidence must be an Evidence instance")
    if not isinstance(policy, Policy):
        raise PolicyError("policy must be a Policy instance")
    if enforcement not in _ENFORCEMENTS:
        raise PolicyError(f"unknown enforcement {enforcement!r}; allowed: {_ENFORCEMENTS}")

    reasons = list(_advisory_reasons(evidence))
    mandatory = tuple(evidence.mandatory_violations)

    fused = _fuse(evidence, policy)

    if mandatory:
        # Mandatory evidence dominates: ML cannot downgrade it and the trusted cap
        # must not conceal it. It blocks even when the model is absent/errored.
        for mv in mandatory:
            reasons.append(f"mandatory:{mv.code}@{mv.provenance}")
        verdict = VerdictLevel.BLOCK
        action = policy.mandatory_action
        score = fused  # may be None (unknown) when a required model is unavailable
        if fused is None:
            reasons.append(
                f"model_status={evidence.model_status.value}: fused score unknown; "
                "mandatory violation still enforced"
            )
    elif fused is None:
        # Required ML unavailable: report incomplete/unknown, never ALLOW-as-safe.
        verdict = policy.model_missing_verdict
        action = policy.model_missing_action
        score = None
        reasons.append(
            f"model_status={evidence.model_status.value}: ML required by policy "
            f"{policy.policy_version}; decision incomplete"
        )
    else:
        score = _apply_trusted_cap(fused, evidence, policy)
        verdict = _classify(score, policy)
        action = _ACTION_FOR_VERDICT[verdict]

    # explicit enforcement override, applied last
    if enforcement == "unblocked":
        action = Action.ALLOW
    elif enforcement == "monitor" and verdict is not VerdictLevel.ALLOW:
        action = Action.MONITOR

    return Verdict(
        policy_version=policy.policy_version,
        evidence_source=evidence.evidence_source,
        layer=evidence.evidence_source,
        rule_score=evidence.rule_score,
        ml_score=evidence.ml_score,
        model_status=evidence.model_status,
        score=score,
        verdict=verdict,
        action=action,
        mandatory_violations=mandatory,
        reasons=tuple(reasons),
    )
