"""Server-side install protection, decided by the pure decision contract.

* The decision is owned by ``app.policy.decision_contract``.
* Demo package names are not special-cased: ``training-leder`` and
  ``corp-internal-ledger-api`` are decided by their findings and the contract like any
  other name. ``LAB_ATTACK_PACKAGES`` is only a label for the demo narrative.
* A required ML score that cannot be computed yields HOLD (fail-closed), never ALLOW.
* Disabling protection maps to an explicit monitoring override (action=monitor);
  it changes the enforced action, never the detector result.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.policy.decision_contract import DEFAULT_RUNTIME_POLICY, Action, Policy, Verdict, decide
from app.schemas.scan_report import Decision, DefenseMode, Finding, Reason
from app.services.hybrid_scorer import (
    ModelProvider,
    evaluate_manifest_bundle,
    evidence_from_manifest,
    model_version,
)
from app.services.scan_service import _findings_from_manifest

# Inert demo-narrative labels only: NOT used to force a decision any more.
LAB_ATTACK_PACKAGES = frozenset(
    {
        "training-leder",
        "corp-internal-ledger-api",
    }
)

# Synced from dashboard Settings toggle (default: protect).
_protection_enabled: bool = True


def is_protection_enabled() -> bool:
    return _protection_enabled


def set_protection_enabled(enabled: bool) -> None:
    global _protection_enabled
    _protection_enabled = bool(enabled)


def get_protection_state() -> Dict[str, Any]:
    return {"enabled": _protection_enabled}


def _reasons_to_dict(reasons: List[Reason]) -> List[Dict[str, Any]]:
    return [
        {
            "feature": r.feature,
            "contribution": r.contribution,
            "description": r.description,
        }
        for r in reasons
    ]


def _findings_to_dict(findings: List[Finding]) -> List[Dict[str, Any]]:
    return [
        {
            "finding_id": f.finding_id,
            "attack_type": f.attack_type,
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
            "package": f.package,
            "version": f.version,
            "canonical": f.canonical,
            "message": f.message,
            "evidence": f.evidence,
        }
        for f in findings
    ]


def _primary_attack_type(findings: List[Finding], package: str) -> Optional[str]:
    if not findings:
        # Label fallback only (demo narrative); does not affect the decision.
        return "lab_attack" if package in LAB_ATTACK_PACKAGES else None
    return findings[0].attack_type


def _impacts_from_findings(findings: List[Finding]) -> List[str]:
    impacts: List[str] = []
    for f in findings:
        if f.message:
            impacts.append(f.message)
        effect = f.evidence.get("simulated_effect") if f.evidence else None
        if effect and effect not in impacts:
            impacts.append(f"If allowed: {effect}")
        preview = f.evidence.get("attacker_access_preview") if f.evidence else None
        if preview and preview not in impacts:
            impacts.append(str(preview))
    return impacts[:8]


def decision_for_install(
    package: str,
    version: str = "*",
    *,
    provider: Optional[ModelProvider] = None,
    policy: Policy = DEFAULT_RUNTIME_POLICY,
    enforcement: Optional[str] = None,
) -> Verdict:
    """Install-hook consumer adapter: normalized evidence -> contract verdict."""
    name = (package or "").strip()
    deps = {name: (version or "*")} if name else {}
    evidence = evidence_from_manifest(deps, provider=provider, source="install")
    enf = enforcement or ("enforce" if _protection_enabled else "monitor")
    return decide(evidence, policy, enforcement=enf)


def evaluate_package(package: str, version: str = "*", source: str = "live-install") -> Dict[str, Any]:
    """
    Hybrid ML + rule engine evaluation for a single package install.
    Used by postinstall hooks and the notification detail API.
    """
    name = (package or "").strip()
    ver = version or "*"

    if not name:
        # Fail-closed on invalid/empty/whitespace package name: never report "not
        # blocked" for input we cannot evaluate. This path is also hit by postinstall
        # hooks and block_details, not only the HTTP route that adds min_length.
        return {
            "blocked": True,
            "reason": "Cannot evaluate: empty or whitespace-only package name (fail-closed).",
            "attack_type": None,
            "protection_enabled": _protection_enabled,
            "canonical": None,
            "engine": None,
        }

    deps = {name: ver}
    # The install hooks are laboratory endpoints: scored in lab mode, which reads the lab
    # fixture packages from disk and any other package from the public registry, so the
    # package-content model sees each package's real content.
    from app.policy.project_context import lab_context

    context = lab_context()
    findings, _, rule_reasons, fixes = _findings_from_manifest(deps, source, context)

    # ONE feature extraction + ONE inference for this install layer; both the legacy
    # top_reasons and the decision_detail derive from the same bundle (no second infer).
    # Disabled protection is an explicit monitoring override (action=monitor), which
    # changes the enforced action, never the detector truth.
    enforcement = "monitor" if not _protection_enabled else None
    bundle = evaluate_manifest_bundle(deps, DefenseMode.HYBRID, enforcement=enforcement, context=context)
    verdict: Verdict = bundle.verdict
    dd = verdict.to_dict()

    top_reasons = bundle.reasons or rule_reasons
    primary_reason = _install_reason(verdict, top_reasons, name)
    attack_type = _primary_attack_type(findings, name)

    engine: Dict[str, Any] = {
        "defense_mode": DefenseMode.HYBRID.value,
        "policy_version": verdict.policy_version,
        "model_version": model_version(),
        "model_status": verdict.model_status.value,
        # Honest HOLD: when the fused score is unknown (required ML unavailable), expose
        # None, never a benign-looking rule-score fallback (hidden certainty).
        "risk_score": verdict.score,
        "decision": verdict.verdict.value,
        "action": verdict.action.value,
        "rule_triggers": bundle.triggers,
        "baseline_drift": bundle.baseline_drift,
        "top_reasons": _reasons_to_dict(top_reasons[:6]),
        "recommended_fixes": fixes[:8],
        "findings": _findings_to_dict(findings),
        "impacts": _impacts_from_findings(findings),
        "decision_detail": dd,
    }

    canonical = next((f.canonical for f in findings if f.canonical), None)

    # Fail-closed: BLOCK or HOLD means "do not proceed"; MONITOR/ALLOW do not.
    blocked = verdict.action in (Action.BLOCK, Action.HOLD)

    return {
        "blocked": blocked,
        "reason": primary_reason,
        "attack_type": attack_type,
        "protection_enabled": _protection_enabled,
        "canonical": canonical,
        "engine": engine,
    }


def _install_reason(verdict: Verdict, rule_reasons: List[Reason], name: str) -> str:
    if verdict.action is Action.HOLD and verdict.verdict.value == "hold":
        return (
            f"Cannot evaluate: the content of '{name}' could not be read for ML scoring "
            f"under policy {verdict.policy_version} (held, fail-closed)."
        )
    if verdict.mandatory_violations:
        mv = verdict.mandatory_violations[0]
        return f"Mandatory policy violation ({mv.code}). Blocked."
    if rule_reasons:
        return rule_reasons[0].description
    return "No significant risk signals"
