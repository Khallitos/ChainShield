"""
Attack simulation + scanning routes for all three ATKs.
Phase 2: ATK1 (typosquatting) endpoints.
Phase 3: ATK2/ATK3 stubs added later.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from app.attacks.typosquatting import (
    analyze_name_risk,
    scan_manifest,
    simulate_install,
    to_siem_event,
)
from app.attacks import dependency_confusion as dc
from app.attacks import ci_cd_injection as ci

router = APIRouter(tags=["Attacks"])

# ── request / response schemas ────────────────────────────────────────────────

class AnalyseRequest(BaseModel):
    requested: str
    canonical: str


class SimulateRequest(BaseModel):
    package_name: str


class ScanManifestRequest(BaseModel):
    dependencies: dict[str, str]
    source: str = "demo-site"


class DepConfPolicyRequest(BaseModel):
    prefer_internal: bool = True
    allow_public_fallback_for_internal_names: bool = False
    enforce_internal_namespace_block: bool = True


class DepConfScanRequest(BaseModel):
    dependencies: dict[str, str]
    source: str = "demo-site"
    policy: Optional[DepConfPolicyRequest] = None


class DepConfSimulateRequest(BaseModel):
    package_name: str
    requested_version: str = "*"
    source: str = "demo-site"
    policy: Optional[DepConfPolicyRequest] = None


# ── ATK1 endpoints ────────────────────────────────────────────────────────────

@router.post("/scan/typosquatting")
def scan_typosquatting(body: ScanManifestRequest):
    """
    Scan a {name: version} dependency manifest for typosquatting risks.
    Returns SIEM-ready events for every finding.
    """
    result = scan_manifest(body.dependencies)
    events = [to_siem_event(f, source=body.source) for f in result.findings]
    return {
        "scanned": result.scanned,
        "findings_count": len(result.findings),
        "risk_summary": result.risk_summary,
        "siem_events": events,
    }


@router.post("/simulate/typosquatting")
def simulate_typosquatting(body: SimulateRequest):
    """
    Simulate installing a package by name and return the install outcome + SIEM event.
    """
    result = simulate_install(body.package_name)
    record_data = None
    if result.record:
        record_data = {
            "display_name": result.record.display_name,
            "trusted": result.record.trusted,
            "publisher": result.record.publisher,
            "simulated_effect": result.record.simulated_effect,
            "masquerades_as": result.record.masquerades_as,
            "attacker_capabilities": list(result.record.attacker_capabilities),
        }
    event = None
    if result.attacker_success and result.record:
        canon = result.record.masquerades_as or result.resolved_key or ""
        event = to_siem_event({
            "package": result.requested,
            "canonical": canon,
            "distance": 1,
            "risk_tier": "high",
            "confidence": 0.90,
            "note": "Typosquat installed successfully in simulation.",
            "attacker_success": True,
            "simulated_effect": result.record.simulated_effect,
            "attacker_access_preview": result.attacker_access_preview,
        })
    return {
        "requested": result.requested,
        "outcome": result.outcome,
        "attacker_success": result.attacker_success,
        "record": record_data,
        "presentation_lines": result.presentation_lines,
        "attacker_access_preview": result.attacker_access_preview,
        "siem_event": event,
    }


@router.post("/analyse/typosquatting")
def analyse_name(body: AnalyseRequest):
    """Compare a requested name against a canonical and return risk tier."""
    a = analyze_name_risk(body.requested, body.canonical)
    return {
        "requested": a.requested,
        "canonical": a.canonical,
        "distance": a.distance,
        "risk_tier": a.risk_tier,
        "confidence": a.confidence,
        "note": a.note,
    }


# ── ATK2 endpoints ────────────────────────────────────────────────────────────


@router.post("/scan/dependency-confusion")
def scan_dependency_confusion(body: DepConfScanRequest):
    policy = dc.ResolverPolicy(**body.policy.model_dump()) if body.policy else dc.ResolverPolicy()
    result = dc.scan_manifest_for_dependency_confusion(body.dependencies, policy=policy)
    events = [dc.to_siem_event(f, source=body.source) for f in result["findings"]]
    return {
        **result,
        "siem_events": events,
        "policy": policy.__dict__,
    }


@router.post("/simulate/dependency-confusion")
def simulate_dependency_confusion(body: DepConfSimulateRequest):
    policy = dc.ResolverPolicy(**body.policy.model_dump()) if body.policy else dc.ResolverPolicy()
    result = dc.simulate_resolution(body.package_name, body.requested_version, policy=policy)
    finding = {
        "package": body.package_name,
        "requested_version": body.requested_version,
        "outcome": result.outcome,
        "attacker_success": result.attacker_success,
        "severity": "high" if result.outcome == "confused_public" else "medium",
        "reason": result.reason,
        "resolved_source": result.resolved.source if result.resolved else None,
        "resolved_version": result.resolved.version if result.resolved else None,
        "simulated_effect": result.resolved.simulated_effect if result.resolved else None,
    }
    return {
        "result": finding,
        "policy": policy.__dict__,
        "siem_event": dc.to_siem_event(finding, source=body.source),
    }


# ── ATK3 schemas ──────────────────────────────────────────────────────────────


class CICDPolicyRequest(BaseModel):
    block_script_injection: bool = True
    block_pull_request_target_checkout: bool = True
    block_unpinned_actions: bool = True
    require_explicit_permissions: bool = True
    block_dangerous_run_patterns: bool = True


class CICDScanRequest(BaseModel):
    workflow: dict
    source: str = "demo-site"
    policy: Optional[CICDPolicyRequest] = None


class CICDSimulateRequest(BaseModel):
    attack_vector: str = "script_injection"
    workflow_name: str = "CI"
    injected_into_step: str = "Run tests"
    source: str = "demo-site"
    policy: Optional[CICDPolicyRequest] = None


# ── ATK3 endpoints ─────────────────────────────────────────────────────────────


@router.post("/scan/ci-cd-injection")
def scan_ci_cd_injection(body: CICDScanRequest):
    """
    Scan a workflow dict for CI/CD injection vulnerabilities.
    Pass a parsed YAML workflow as JSON. Returns all findings as SIEM events.
    """
    policy = ci.CICDPolicy(**body.policy.model_dump()) if body.policy else ci.CICDPolicy()
    result = ci.scan_workflow(body.workflow, policy=policy)
    events = [ci.finding_to_siem_event(f, source=body.source) for f in result.findings]
    return {
        "workflow_name": result.workflow_name,
        "triggers": result.triggers,
        "jobs_scanned": result.jobs_scanned,
        "steps_scanned": result.steps_scanned,
        "findings_count": len(result.findings),
        "overall_severity": result.overall_severity,
        "risk_summary": result.risk_summary,
        "siem_events": events,
    }


@router.post("/simulate/ci-cd-injection")
def simulate_ci_cd_injection(body: CICDSimulateRequest):
    """
    Simulate an ATK3 attack scenario.
    attack_vector: 'script_injection' | 'prt_checkout' | 'unpinned_action'
    Returns a full narrative, attacker gain list, baseline vs improved outcome, and SIEM event.
    """
    policy = ci.CICDPolicy(**body.policy.model_dump()) if body.policy else ci.CICDPolicy()
    result = ci.simulate_attack(
        attack_vector=body.attack_vector,
        workflow_name=body.workflow_name,
        injected_into_step=body.injected_into_step,
        policy=policy,
    )
    return {
        "workflow_name": result.workflow_name,
        "attack_vector": result.attack_vector,
        "attacker_payload": result.attacker_payload,
        "injected_into_step": result.injected_into_step,
        "what_attacker_gains": result.what_attacker_gains,
        "baseline_outcome": result.baseline_outcome,
        "improved_outcome": result.improved_outcome,
        "siem_severity": result.siem_severity,
        "narrative": result.narrative,
        "siem_event": ci.simulation_to_siem_event(result, source=body.source),
    }
