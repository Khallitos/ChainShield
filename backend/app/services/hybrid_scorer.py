"""Hybrid decision engine: a thin adapter over the pure decision contract.

Public tuple/JSON shape is preserved (``score_manifest_hybrid`` still returns
``(score, Decision, reasons, baseline_drift, triggers)``), but the *decision* is
owned by ``app.policy.decision_contract``.

Model access is routed through an explicit, injectable provider. The default provider
reports ``absent`` and yields no ML score, so a policy that requires a model holds instead
of allowing. The deployed provider is ``PackageContentModelProvider``, which loads the
package-content model from plain arrays (``app.ml.package_model``); no serialised Python
object is ever loaded, so loading a model cannot execute code.
"""
from __future__ import annotations

import json
import math
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from app.ml.feature_extractor import FEATURE_NAMES, extract_manifest_features, extract_workflow_features
from app.policy.decision_contract import (
    DEFAULT_RUNTIME_POLICY,
    POLICY_LEGACY_RUNTIME,
    POLICY_PACKAGE_V3,
    POLICY_RULES_ONLY,
    POLICY_WORKFLOW_RULES,
    Action,
    Evidence,
    MandatoryViolation,
    ModelStatus,
    Policy,
    Verdict,
    decide,
)
from app.policy.rule_features import rule_score_from_features as _rule_score_from_features
from app.schemas.scan_report import Decision, DefenseMode, Reason
from dataclasses import dataclass, field

__all__ = [
    "ModelStatus",
    "ModelInference",
    "ModelProvider",
    "NoModelProvider",
    "StaticModelProvider",
    "PackageContentModelProvider",
    "get_model_provider",
    "set_model_provider",
    "reset_model_provider",
    "model_version",
    "rule_score_from_features",
    "_rule_score_from_features",
    "_ml_score",
    "evidence_from_manifest",
    "evidence_from_workflow",
    "hybrid_decide",
    "EvaluationBundle",
    "evaluate_manifest_bundle",
    "evaluate_workflow_bundle",
    "score_manifest_hybrid",
    "score_workflow_hybrid",
]

# ── model provider seam (no implicit unpickle) ────────────────────────────────

class ModelInference:
    """Result of a provider inference attempt."""

    __slots__ = ("model_status", "ml_score", "label")

    def __init__(self, model_status: ModelStatus, ml_score: Optional[float], label: str) -> None:
        self.model_status = model_status
        self.ml_score = ml_score
        self.label = label


class ModelProvider:
    """Explicit model provider. Implementations must not load anything implicitly."""

    label = "base"

    def status(self) -> ModelStatus:  # pragma: no cover - overridden
        raise NotImplementedError

    def infer(self, vector: List[float]) -> ModelInference:  # pragma: no cover
        raise NotImplementedError

    def infer_packages(self, dependencies: Dict[str, str], vector: List[float]) -> ModelInference:
        """Manifest-level inference. Providers without a package model score the signal vector."""
        return self.infer(vector)


class NoModelProvider(ModelProvider):
    """Default provider: no learned model configured, so no ML evidence."""

    label = "no-model"

    def status(self) -> ModelStatus:
        return ModelStatus.ABSENT

    def infer(self, vector: List[float]) -> ModelInference:
        return ModelInference(ModelStatus.ABSENT, None, self.label)


class StaticModelProvider(ModelProvider):
    """Fixed-score provider for TESTS. Labelled as a fixture: never the real RF."""

    def __init__(self, ml_score: Optional[float], model_status: ModelStatus = ModelStatus.LOADED,
                 label: str = "synthetic-fixture-not-original-rf") -> None:
        self._ml = ml_score
        self._status = model_status
        self.label = label

    def status(self) -> ModelStatus:
        return self._status

    def infer(self, vector: List[float]) -> ModelInference:
        return ModelInference(self._status, self._ml, self.label)


class PackageContentModelProvider(ModelProvider):
    """The deployed package-layer model: P(malicious) from each package's own content.

    Loads the pickle-free tree ensemble (``app.ml.package_model``), fetches each dependency's
    published archive read-only, computes the content features and returns the highest
    per-package probability for the manifest. A package that cannot be fetched or read makes
    the manifest's ML evidence unavailable (``error``), which the package policy turns into
    HOLD rather than ALLOW.
    """

    def __init__(self, fetcher=None, ensemble=None) -> None:
        from app.ml.package_model import MODEL_NAME, default_ensemble
        from app.services.package_fetcher import fetch_npm_tarball

        self._fetch = fetcher or fetch_npm_tarball
        self._ensemble = ensemble if ensemble is not None else default_ensemble()
        self.label = MODEL_NAME

    def status(self) -> ModelStatus:
        return ModelStatus.LOADED if self._ensemble is not None else ModelStatus.ABSENT

    def infer(self, vector: List[float]) -> ModelInference:
        # A signal vector carries no package content; this provider cannot score it.
        status = ModelStatus.DISABLED if self._ensemble is not None else ModelStatus.ABSENT
        return ModelInference(status, None, self.label)

    # A published name@version never changes, so its score is cached per model and source.
    # Reading a large package takes seconds to minutes (next: ~77 MB of JavaScript); the
    # manifest and SBOM layers of one scan, and every later scan, then reuse the score. Scores
    # from the real fetchers are also kept on disk so a backend restart does not recompute
    # them. The key always holds the exact version (a range such as "^4" is resolved first,
    # as npm would). Failures are not cached.
    _SCORE_CACHE: Dict[Tuple[str, str, str, str], float] = {}
    _SCORE_CACHE_MAX = 5000
    _DISK_FETCHERS = ("fetch_npm_tarball", "lab_first_fetcher")
    _DISK_LOCK = threading.Lock()
    _DISK_LOADED = False

    @staticmethod
    def _disk_path() -> Optional[Path]:
        setting = os.getenv("CHAINSHIELD_SCORE_CACHE", "")
        if setting.lower() in ("off", "0", "false"):
            return None
        return Path(setting) if setting else Path(__file__).resolve().parents[2] / ".cache" / "package_scores.json"

    @classmethod
    def _disk_load(cls) -> None:
        if cls._DISK_LOADED:
            return
        cls._DISK_LOADED = True
        path = cls._disk_path()
        if path is None or not path.is_file():
            return
        try:
            for k, v in json.loads(path.read_text(encoding="utf-8")).items():
                cls._SCORE_CACHE[tuple(k.split("|", 3))] = float(v)
        except (OSError, ValueError):
            pass

    @classmethod
    def _disk_store(cls) -> None:
        path = cls._disk_path()
        if path is None:
            return
        rows = {"|".join(k): v for k, v in cls._SCORE_CACHE.items() if k[1] in cls._DISK_FETCHERS}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(rows), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            pass

    def package_probability(self, name: str, version: str) -> Optional[float]:
        from app.ml.package_content import feature_vector, features_from_tarball
        from app.services.package_fetcher import resolve_npm_version

        fetcher = getattr(self._fetch, "__qualname__", repr(self._fetch))
        persistent = fetcher in self._DISK_FETCHERS
        if persistent:
            with self._DISK_LOCK:
                self._disk_load()
            version = resolve_npm_version(name, version) or str(version)
        key = (str(self._ensemble.metadata.get("arrays_sha256", "")), fetcher, name, str(version))
        cached = self._SCORE_CACHE.get(key)
        if cached is not None:
            return cached
        data = self._fetch(name, version)
        if data is None:
            return None
        try:
            feats = features_from_tarball(data)
        except Exception:
            return None
        row = feature_vector(feats, self._ensemble.columns)
        score = float(self._ensemble.predict_proba_malicious([row])[0])
        with self._DISK_LOCK:
            if len(self._SCORE_CACHE) >= self._SCORE_CACHE_MAX:
                self._SCORE_CACHE.clear()
            self._SCORE_CACHE[key] = score
            if persistent:
                self._disk_store()
        return score

    def prefetch(self, dependencies: Dict[str, str], workers: int = 4) -> None:
        """Score a manifest's packages concurrently (downloads overlap; large packages use the
        feature extractor's process pool). The per-package decisions then read the cache."""
        if self._ensemble is None or len(dependencies) < 2:
            return
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(lambda item: self.package_probability(*item), dependencies.items()))

    def infer_packages(self, dependencies: Dict[str, str], vector: List[float]) -> ModelInference:
        if self._ensemble is None:
            return ModelInference(ModelStatus.ABSENT, None, self.label)
        if not dependencies:
            return ModelInference(ModelStatus.LOADED, 0.0, self.label)
        scores = []
        for name, version in dependencies.items():
            p = self.package_probability(name, version)
            if p is None:
                return ModelInference(ModelStatus.ERROR, None, self.label)
            scores.append(p)
        return ModelInference(ModelStatus.LOADED, max(scores), self.label)


_DEFAULT_PROVIDER: ModelProvider = NoModelProvider()
_model_provider: ModelProvider = _DEFAULT_PROVIDER


def get_model_provider() -> ModelProvider:
    return _model_provider


def set_model_provider(provider: ModelProvider) -> None:
    global _model_provider
    if not isinstance(provider, ModelProvider):
        raise TypeError("provider must be a ModelProvider")
    _model_provider = provider


def reset_model_provider() -> None:
    global _model_provider
    _model_provider = _DEFAULT_PROVIDER


def model_version() -> str:
    """Honest model version label without loading anything."""
    st = _model_provider.status()
    if st is ModelStatus.LOADED:
        return _model_provider.label
    return "scr_rules_v0"


def _ml_score(vector: List[float]) -> Optional[float]:
    """ML probability via the injected provider, or None when unavailable."""
    return _model_provider.infer(vector).ml_score


# ── evidence builders ─────────────────────────────────────────────────────────

_CAP_SIGNAL_KEYS = (
    "exact_trusted_match",
    "baseline_drift",
    "typosquat_high",
    "dep_confusion_signal",
    "workflow_injection_signal",
)


def _baseline_signals(v: Dict[str, float]) -> Dict[str, Any]:
    return {k: v.get(k) for k in _CAP_SIGNAL_KEYS}


def _advisory_hints(v: Dict[str, float]) -> Dict[str, Any]:
    return {
        "typosquat_high": bool(v.get("typosquat_high")),
        "public_high_version": bool(v.get("public_high_version")),
        "version_gap_score": float(v.get("version_gap_score", 0.0)),
        "dep_confusion_signal": float(v.get("dep_confusion_signal", 0.0)),
        "workflow_injection_signal": float(v.get("workflow_injection_signal", 0.0)),
        "ci_critical_count": float(v.get("ci_critical_count", 0.0)),
    }


def _evidence_from_features(
    v: Dict[str, float],
    *,
    ml_score: Optional[float],
    model_status: ModelStatus,
    source: str,
    mandatory: Sequence[MandatoryViolation] = (),
) -> Evidence:
    return Evidence(
        rule_score=_rule_score_from_features(v),
        ml_score=ml_score,
        model_status=model_status,
        evidence_source=source,
        baseline_signals=_baseline_signals(v),
        hints=_advisory_hints(v),
        mandatory_violations=tuple(mandatory),
    )


def evidence_from_manifest(
    dependencies: Dict[str, str],
    *,
    provider: Optional[ModelProvider] = None,
    source: str = "runtime",
    use_ml: bool = True,
) -> Evidence:
    """Real feature extraction -> normalized Evidence (no side effects beyond reads)."""
    feat = extract_manifest_features(dependencies)
    return _evidence_for_vector(feat["vector_dict"], feat["vector"], provider, source, use_ml)


def evidence_from_workflow(
    workflow: Dict[str, Any],
    *,
    provider: Optional[ModelProvider] = None,
    source: str = "runtime",
    use_ml: bool = True,
) -> Evidence:
    feat = extract_workflow_features(workflow)
    return _evidence_for_vector(feat["vector_dict"], feat["vector"], provider, source, use_ml)


def _evidence_for_vector(
    v: Dict[str, float],
    vector: List[float],
    provider: Optional[ModelProvider],
    source: str,
    use_ml: bool,
    dependencies: Optional[Dict[str, str]] = None,
    mandatory: Sequence[MandatoryViolation] = (),
) -> Evidence:
    if not use_ml:
        return _evidence_from_features(
            v, ml_score=None, model_status=ModelStatus.ABSENT, source=source, mandatory=mandatory
        )
    chosen = provider or _model_provider
    inf = chosen.infer_packages(dependencies, vector) if dependencies is not None else chosen.infer(vector)
    return _evidence_from_features(
        v, ml_score=inf.ml_score, model_status=inf.model_status, source=source, mandatory=mandatory
    )


def _mandatory_from_dc(dc_findings: List[Dict[str, Any]]) -> List[MandatoryViolation]:
    """Confirmed confusion (declared internal name resolved from the public registry)."""
    return [
        MandatoryViolation(
            code="approved_registry_violation",
            provenance="scan_service",
            fields={"registry": str(f["resolved_url"]), "package": str(f.get("package", ""))},
        )
        for f in dc_findings
        if f.get("resolved_url")
    ]


def _mandatory_from_workflow(ci_result: Any) -> List[MandatoryViolation]:
    return [
        MandatoryViolation(code="critical_workflow_finding", provenance="scan_service",
                           fields={"rule": str(f.rule_id)})
        for f in ci_result.findings
        if f.severity == "critical"
    ]


def hybrid_decide(
    evidence: Evidence,
    policy: Policy = POLICY_LEGACY_RUNTIME,
    *,
    enforcement: str = "enforce",
) -> Verdict:
    """Runtime consumer adapter: contract call owned by the runtime layer."""
    return decide(evidence, policy, enforcement=enforcement)


# ── legacy-compatible tuple API ───────────────────────────────────────────────

def _decision_from_action(action: Action) -> Decision:
    if action is Action.BLOCK:
        return Decision.BLOCK
    if action is Action.HOLD:
        return Decision.HOLD  # cannot-evaluate is surfaced, never hidden as WARN
    if action is Action.WARN:
        return Decision.WARN
    if action is Action.MONITOR:
        return Decision.WARN  # monitor is a WARN-level action (recorded, not blocked)
    return Decision.ALLOW


def _triggers_from_features(v: Dict[str, float]) -> List[str]:
    triggers: List[str] = []
    if v.get("typosquat_high"):
        triggers.append("typosquatting")
    if v.get("dep_confusion_signal", 0) >= 0.5:
        triggers.append("dependency_confusion")
    if v.get("workflow_injection_signal", 0) > 0:
        triggers.append("ci_cd_injection")
    if v.get("baseline_drift"):
        triggers.append("baseline_drift")
    return triggers


@dataclass
class EvaluationBundle:
    """Result of a single feature-extraction + single inference for one layer.

    Consumers derive BOTH the legacy tuple view and the decision_detail from the SAME
    ``verdict``/``evidence`` so no second inference is ever performed per layer.
    """

    verdict: Verdict
    evidence: Evidence
    reasons: List[Reason]
    baseline_drift: bool
    triggers: List[str]
    # Project-mode manifests: the verdict each package received on its own evidence.
    package_actions: Dict[str, str] = field(default_factory=dict)


def _bundle_for_vector(
    v: Dict[str, float],
    vector: List[float],
    *,
    layer: str,
    defense_mode: DefenseMode,
    policy: Policy,
    provider: Optional[ModelProvider],
    enforcement: Optional[str] = None,
    dependencies: Optional[Dict[str, str]] = None,
    mandatory: Sequence[MandatoryViolation] = (),
    use_ml: Optional[bool] = None,
) -> EvaluationBundle:
    # BASELINE is the intentional rules-only labelled mode (legacy policy, no ML).
    if use_ml is None:
        use_ml = defense_mode != DefenseMode.BASELINE
    evidence = _evidence_for_vector(
        v, vector, provider, layer, use_ml=use_ml, dependencies=dependencies, mandatory=mandatory
    )
    if enforcement is None:
        enforcement = "unblocked" if defense_mode == DefenseMode.UNBLOCKED else "enforce"
    verdict = decide(evidence, policy, enforcement=enforcement)
    return EvaluationBundle(
        verdict=verdict,
        evidence=evidence,
        reasons=_reasons_from_features(v, evidence.ml_score),
        baseline_drift=bool(v.get("baseline_drift")),
        triggers=_triggers_from_features(v),
    )


def evaluate_manifest_bundle(
    dependencies: Dict[str, str],
    defense_mode: DefenseMode = DefenseMode.HYBRID,
    *,
    policy: Optional[Policy] = None,
    provider: Optional[ModelProvider] = None,
    enforcement: Optional[str] = None,
    context: Optional[Any] = None,
) -> EvaluationBundle:
    """One feature extraction + one inference for a manifest layer.

    With a scan ``context`` (API scans) the package layer uses the project baseline, the
    package-content model and ``POLICY_PACKAGE_V3``; a confirmed confusion against declared
    internal names is mandatory. Without one, the laboratory path is unchanged.
    """
    if policy is None and defense_mode == DefenseMode.BASELINE:
        policy = POLICY_RULES_ONLY  # rules-only mode must not wait for a model
    if context is None:
        feat = extract_manifest_features(dependencies)
        return _bundle_for_vector(
            feat["vector_dict"],
            feat["vector"],
            layer="manifest",
            defense_mode=defense_mode,
            policy=policy or DEFAULT_RUNTIME_POLICY,
            provider=provider,
            enforcement=enforcement,
        )
    if context.mode == "lab":
        provider = _lab_provider(provider)
    policy = policy or POLICY_PACKAGE_V3
    chosen = provider or _model_provider
    if policy.ml_required and isinstance(chosen, PackageContentModelProvider):
        chosen.prefetch(dependencies)
    if len(dependencies) <= 1:
        feat = extract_manifest_features(dependencies, context=context)
        return _bundle_for_vector(
            feat["vector_dict"],
            feat["vector"],
            layer="manifest",
            defense_mode=defense_mode,
            policy=policy,
            provider=provider,
            enforcement=enforcement,
            dependencies=dependencies,
            mandatory=_mandatory_from_dc(feat["dc_findings"]),
        )
    # Each package is scored on its OWN rule signals and its OWN content probability, exactly as
    # the model was evaluated (one package per row); the worst package decides the layer. Fusing
    # the highest rule score of one package with the highest ML score of another would produce a
    # verdict that no single package deserves.
    worst: Optional[EvaluationBundle] = None
    triggers: List[str] = []
    drift = False
    actions: Dict[str, str] = {}
    for name, version in dependencies.items():
        feat = extract_manifest_features({name: version}, context=context)
        bundle = _bundle_for_vector(
            feat["vector_dict"],
            feat["vector"],
            layer="manifest",
            defense_mode=defense_mode,
            policy=policy,
            provider=provider,
            enforcement=enforcement,
            dependencies={name: version},
            mandatory=_mandatory_from_dc(feat["dc_findings"]),
        )
        triggers.extend(t for t in bundle.triggers if t not in triggers)
        drift = drift or bundle.baseline_drift
        actions[name] = bundle.verdict.action.value
        if worst is None or _severity_key(bundle.verdict) > _severity_key(worst.verdict):
            worst = bundle
    return EvaluationBundle(
        verdict=worst.verdict,
        evidence=worst.evidence,
        reasons=worst.reasons,
        baseline_drift=drift,
        triggers=triggers,
        package_actions=actions,
    )


_LEVEL_RANK = {"allow": 0, "warn": 1, "hold": 2, "block": 3}


def _severity_key(verdict: Verdict) -> Tuple[int, float]:
    """Order verdicts like the composite scan: block > hold > warn > allow, then by score."""
    return _LEVEL_RANK.get(verdict.verdict.value, 0), verdict.score if verdict.score is not None else -1.0


def _lab_provider(provider: Optional[ModelProvider]) -> Optional[ModelProvider]:
    """Lab mode reads the laboratory fixture packages from disk instead of the registry."""
    chosen = provider or _model_provider
    if isinstance(chosen, PackageContentModelProvider):
        from app.services.package_fetcher import lab_first_fetcher

        return PackageContentModelProvider(fetcher=lab_first_fetcher, ensemble=chosen._ensemble)
    return provider


def evaluate_workflow_bundle(
    workflow: Dict[str, Any],
    defense_mode: DefenseMode = DefenseMode.HYBRID,
    *,
    policy: Optional[Policy] = None,
    provider: Optional[ModelProvider] = None,
    enforcement: Optional[str] = None,
) -> EvaluationBundle:
    """Workflow layer: rules decide alone (``POLICY_WORKFLOW_RULES``); critical findings are mandatory.

    No learned model is applied: the package model was trained on package content and has never
    seen a workflow, so mixing its probability in would only dilute rule evidence.
    """
    feat = extract_workflow_features(workflow)
    return _bundle_for_vector(
        feat["vector_dict"],
        feat["vector"],
        layer="workflow",
        defense_mode=defense_mode,
        policy=policy or POLICY_WORKFLOW_RULES,
        provider=provider,
        enforcement=enforcement,
        mandatory=_mandatory_from_workflow(feat["ci_result"]),
        use_ml=False,
    )


def _reasons_from_features(v: Dict[str, float], ml_contrib: Optional[float]) -> List[Reason]:
    reasons: List[Reason] = []
    if v.get("typosquat_high"):
        reasons.append(
            Reason(
                feature="typosquat_high",
                contribution=0.40,
                description="Package name closely matches trusted package (typosquat pattern)",
            )
        )
    if v.get("baseline_drift"):
        reasons.append(
            Reason(
                feature="baseline_drift",
                contribution=0.35,
                description="Dependency drifts from lockfile-derived trust graph",
            )
        )
    if v.get("public_high_version"):
        reasons.append(
            Reason(
                feature="public_high_version",
                contribution=0.33,
                description="Internal-style package with suspicious high public version",
            )
        )
    if v.get("workflow_injection_signal", 0) > 0:
        reasons.append(
            Reason(
                feature="workflow_injection_signal",
                contribution=0.38,
                description="CI workflow contains injection or unpinned-action patterns",
            )
        )
    if ml_contrib is not None:
        reasons.append(
            Reason(
                feature="ml_malicious_probability",
                contribution=round(min(ml_contrib, 1.0), 2),
                description=f"ML classifier malicious probability: {ml_contrib:.2f}",
            )
        )
    return sorted(reasons, key=lambda r: r.contribution, reverse=True)[:5]


def _score_from_feature_dict(
    v: Dict[str, float],
    vector: List[float],
    defense_mode: DefenseMode,
) -> Tuple[float, Decision, List[Reason], bool, List[str]]:
    # Legacy-compatible tuple adapter. This is an explicit original-replay / named-call
    # path (kept for the frozen evaluate_all.py, socket mode and the old tests); it uses
    # POLICY_LEGACY_RUNTIME, never the accidental new default.
    bundle = _bundle_for_vector(
        v,
        vector,
        layer="runtime",
        defense_mode=defense_mode,
        policy=POLICY_LEGACY_RUNTIME,
        provider=None,
    )
    verdict = bundle.verdict
    rule_score = bundle.evidence.rule_score
    final = verdict.score if verdict.score is not None else rule_score
    return round(final, 3), _decision_from_action(verdict.action), bundle.reasons, bundle.baseline_drift, bundle.triggers


def decision_detail_from_features(
    v: Dict[str, float],
    vector: List[float],
    defense_mode: DefenseMode = DefenseMode.HYBRID,
) -> Verdict:
    """Expose the full contract verdict for a feature row (API/test seam)."""
    use_ml = defense_mode != DefenseMode.BASELINE
    evidence = _evidence_for_vector(v, vector, None, "runtime", use_ml=use_ml)
    enforcement = "unblocked" if defense_mode == DefenseMode.UNBLOCKED else "enforce"
    return decide(evidence, POLICY_LEGACY_RUNTIME, enforcement=enforcement)


def manifest_decision_detail(
    dependencies: Dict[str, str],
    defense_mode: DefenseMode = DefenseMode.HYBRID,
) -> Verdict:
    """Contract verdict for a manifest scan (used to expose decision detail on the API)."""
    feat = extract_manifest_features(dependencies)
    return decision_detail_from_features(feat["vector_dict"], feat["vector"], defense_mode)


def workflow_decision_detail(
    workflow: Dict[str, Any],
    defense_mode: DefenseMode = DefenseMode.HYBRID,
) -> Verdict:
    feat = extract_workflow_features(workflow)
    return decision_detail_from_features(feat["vector_dict"], feat["vector"], defense_mode)


def score_manifest_hybrid(
    dependencies: Dict[str, str],
    defense_mode: DefenseMode,
) -> Tuple[float, Decision, List[Reason], bool, List[str]]:
    feat = extract_manifest_features(dependencies)
    return _score_from_feature_dict(feat["vector_dict"], feat["vector"], defense_mode)


def score_workflow_hybrid(
    workflow: Dict[str, Any],
    defense_mode: DefenseMode,
) -> Tuple[float, Decision, List[Reason], bool, List[str]]:
    feat = extract_workflow_features(workflow)
    return _score_from_feature_dict(feat["vector_dict"], feat["vector"], defense_mode)
