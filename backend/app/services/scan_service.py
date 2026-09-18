"""Unified scan orchestration: manifest, workflow, SBOM → ScanReport."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.attacks import ci_cd_injection as ci
from app.attacks import dependency_confusion as dc
from app.attacks.typosquatting import scan_manifest, to_siem_event
from app.schemas.scan_report import (
    Decision,
    DefenseMode,
    Finding,
    Reason,
    ScanReport,
    ScanSummary,
    ScanType,
    SbomSummary,
    RiskyPath,
    ScoreResponse,
    Severity,
)
from app.services.hybrid_scorer import (
    _decision_from_action,
    evaluate_manifest_bundle,
    evaluate_workflow_bundle,
    model_version,
    score_manifest_hybrid,
    score_workflow_hybrid,
)
from app.services.socket_scanner import scan_manifest_socket
from app.services.sbom_scanner import parse_sbom

# In-memory report cache (lab); replace with DB in Phase 5.
_REPORT_STORE: Dict[str, ScanReport] = {}


def get_report(scan_id: str) -> Optional[ScanReport]:
    return _REPORT_STORE.get(scan_id)


def _severity_from_tier(tier: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "none": Severity.NONE,
    }
    return mapping.get(tier, Severity.MEDIUM)


def _risk_score_from_findings(findings: List[Finding]) -> float:
    if not findings:
        return 0.05
    weights = {
        Severity.CRITICAL: 0.98,
        Severity.HIGH: 0.88,
        Severity.MEDIUM: 0.65,
        Severity.LOW: 0.35,
        Severity.NONE: 0.1,
    }
    return max(weights.get(f.severity, 0.5) for f in findings)


def _decision_from_score(score: float, mode: DefenseMode, has_findings: bool) -> Decision:
    if mode == DefenseMode.UNBLOCKED:
        return Decision.ALLOW
    if not has_findings:
        return Decision.ALLOW
    if mode == DefenseMode.BASELINE:
        if score >= 0.75:
            return Decision.BLOCK
        if score >= 0.45:
            return Decision.WARN
        return Decision.ALLOW
    # hybrid
    if score >= 0.85:
        return Decision.BLOCK
    if score >= 0.60:
        return Decision.WARN
    return Decision.ALLOW


def _overall_severity(findings: List[Finding]) -> Severity:
    if not findings:
        return Severity.NONE
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.NONE]
    for sev in order:
        if any(f.severity == sev for f in findings):
            return sev
    return Severity.NONE


def _findings_from_manifest(
    dependencies: Dict[str, str], source: str, context: Optional[Any] = None
) -> tuple[List[Finding], List[Dict[str, Any]], List[Reason], List[str]]:
    findings: List[Finding] = []
    siem_events: List[Dict[str, Any]] = []
    reasons: List[Reason] = []
    fixes: List[str] = []

    typo = (
        scan_manifest(dependencies, baseline=context.baseline, use_policy_denylist=context.mode == "lab")
        if context is not None
        else scan_manifest(dependencies)
    )
    for i, f in enumerate(typo.findings):
        fid = f"fnd_typo_{i+1}"
        sev = _severity_from_tier(f.get("risk_tier", "medium"))
        findings.append(
            Finding(
                finding_id=fid,
                attack_type="typosquatting",
                severity=sev,
                package=f.get("package"),
                version=dependencies.get(f.get("package", ""), "*"),
                canonical=f.get("canonical"),
                message=f.get("note", "Typosquat risk detected"),
                evidence={
                    "edit_distance": f.get("distance"),
                    "confidence": f.get("confidence"),
                    "attacker_success": f.get("attacker_success"),
                },
                dependency_path=[source, f.get("package", "")],
            )
        )
        siem_events.append(to_siem_event(f, source=source))
        if f.get("distance") == 1:
            reasons.append(
                Reason(
                    feature="edit_distance_to_trusted",
                    contribution=0.41,
                    description=f"Package {f.get('package')} is 1 edit from {f.get('canonical')}",
                )
            )
            fixes.append(f"Use trusted package {f.get('canonical')} instead of {f.get('package')}")

    if context is not None and context.mode == "project":
        dc_result = dc.scan_manifest_for_dependency_confusion_project(dependencies, context)
    else:
        dc_result = dc.scan_manifest_for_dependency_confusion(dependencies)
    for i, f in enumerate(dc_result.get("findings", [])):
        if f.get("outcome") == "safe_internal" and not f.get("version_signal"):
            continue  # resolved to the trusted internal source as requested: nothing to report
        fid = f"fnd_dc_{i+1}"
        sev = _severity_from_tier(f.get("severity", "high"))
        pkg = f.get("package", "")
        findings.append(
            Finding(
                finding_id=fid,
                attack_type="dependency_confusion",
                severity=sev,
                package=pkg,
                version=f.get("requested_version") or dependencies.get(pkg, "*"),
                message=f.get("reason", "Dependency confusion risk"),
                evidence={
                    "resolved_source": f.get("resolved_source"),
                    "resolved_version": f.get("resolved_version"),
                    "outcome": f.get("outcome"),
                },
                dependency_path=[source, pkg],
            )
        )
        siem_events.append(dc.to_siem_event(f, source=source))
        reasons.append(
            Reason(
                feature="version_anomaly_public_registry",
                contribution=0.33,
                description=f"Public version may override internal for {pkg}",
            )
        )
        fixes.append("Pin internal registry in .npmrc and lock trusted versions")

    return findings, siem_events, reasons[:5], fixes


def _decision_rank(decision: Decision) -> int:
    return {Decision.ALLOW: 0, Decision.WARN: 1, Decision.HOLD: 2, Decision.BLOCK: 3}.get(
        decision, 0
    )


def _strictest_decision(a: Decision, b: Decision) -> Decision:
    return a if _decision_rank(a) >= _decision_rank(b) else b


def _qualify_name_signals(findings: List[Finding], package_actions: Dict[str, str]) -> List[Finding]:
    """A name-similarity finding on a package whose own verdict is ALLOW is only a signal.

    The rule layer flags any name close to a popular package (``rss``, ``@types/rss``); the
    package's decision fuses that signal with the model's reading of its content. When the
    package was allowed, the finding is reported as LOW so the list matches the decision.
    Decisions are unchanged.
    """
    out: List[Finding] = []
    for f in findings:
        if f.attack_type == "typosquatting" and package_actions.get(f.package or "") == "allow":
            f = f.model_copy(update={
                "severity": Severity.LOW,
                "message": f"Name similarity only; package content scored benign, so it is allowed. {f.message}",
                "evidence": {**f.evidence, "package_decision": "allow"},
            })
        out.append(f)
    return out


def scan_manifest_unified(
    dependencies: Dict[str, str],
    source: str,
    defense_mode: DefenseMode,
    context: Optional[Any] = None,
) -> ScanReport:
    findings, siem_events, rule_reasons, fixes = _findings_from_manifest(dependencies, source, context)

    if defense_mode == DefenseMode.SOCKET:
        socket_findings, socket_reasons, score, decision, socket_meta = scan_manifest_socket(
            dependencies, source
        )
        local_score, local_decision, local_reasons, _, _ = score_manifest_hybrid(
            dependencies, DefenseMode.BASELINE
        )
        score = max(score, local_score)
        decision = _strictest_decision(decision, local_decision)
        merged = socket_findings + findings
        # Deduplicate by package+attack_type
        seen = set()
        deduped: List[Finding] = []
        for f in merged:
            key = (f.package, f.attack_type)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        reasons = (socket_reasons + local_reasons)[:5] if socket_reasons else rule_reasons
        metadata = {
            **socket_meta,
            "local_findings_count": len(findings),
            "socket_findings_count": len(socket_findings),
            "local_score_merged": local_score,
        }
        decision_detail = evaluate_manifest_bundle(dependencies, defense_mode, context=context).verdict.to_dict()
    else:
        bundle = evaluate_manifest_bundle(dependencies, defense_mode, context=context)
        verdict = bundle.verdict
        score = None if verdict.score is None else round(verdict.score, 6)
        decision = _decision_from_action(verdict.action)
        reasons = bundle.reasons or rule_reasons
        deduped = _qualify_name_signals(findings, bundle.package_actions)
        metadata = {
            "model_version": model_version(),
            "baseline_drift": bundle.baseline_drift,
            "rule_triggers": bundle.triggers,
            "baseline_mode": context.mode if context is not None else "lab",
            "baseline_id": context.baseline.baseline_id if context is not None else "lab-default",
        }
        decision_detail = verdict.to_dict()

    report = ScanReport(
        scan_type=ScanType.MANIFEST,
        source=source,
        defense_mode=defense_mode,
        summary=ScanSummary(
            components_scanned=len(dependencies),
            findings_count=len(deduped),
            risk_score=score,
            decision=decision,
            severity=_overall_severity(deduped),
        ),
        findings=deduped,
        top_reasons=reasons,
        recommended_fixes=list(dict.fromkeys(fixes)),
        siem_events=siem_events,
        metadata=metadata,
        decision_detail=decision_detail,
    )
    _REPORT_STORE[report.scan_id] = report
    return report


def scan_workflow_unified(
    workflow: Dict[str, Any],
    source: str,
    defense_mode: DefenseMode,
) -> ScanReport:
    result = ci.scan_workflow(workflow)
    findings: List[Finding] = []
    siem_events: List[Dict[str, Any]] = []
    reasons: List[Reason] = []
    fixes: List[str] = []

    for i, f in enumerate(result.findings):
        sev = _severity_from_tier(f.severity)
        findings.append(
            Finding(
                finding_id=f"fnd_ci_{i+1}",
                attack_type="ci_cd_injection",
                severity=sev,
                message=f.why_dangerous,
                evidence={
                    "rule_id": f.rule_id,
                    "step": f.step_name,
                    "workflow": f.workflow_name,
                    "evidence_snippet": f.evidence,
                },
                dependency_path=[source, f.workflow_name, f.step_name or "step"],
            )
        )
        siem_events.append(ci.finding_to_siem_event(f, source=source))
        reasons.append(
            Reason(
                feature=f.rule_id.lower().replace("-", "_"),
                contribution=0.35,
                description=f.why_dangerous[:120],
            )
        )
        fixes.append(f.mitigation or "Harden workflow per GitHub Actions security guidance")

    bundle = evaluate_workflow_bundle(workflow, defense_mode)
    verdict = bundle.verdict
    score = None if verdict.score is None else round(verdict.score, 6)
    decision = _decision_from_action(verdict.action)
    hybrid_reasons = bundle.reasons
    reasons = hybrid_reasons or reasons

    report = ScanReport(
        scan_type=ScanType.WORKFLOW,
        source=source,
        defense_mode=defense_mode,
        summary=ScanSummary(
            components_scanned=result.steps_scanned,
            findings_count=len(findings),
            risk_score=score,
            decision=decision,
            severity=_overall_severity(findings),
        ),
        findings=findings,
        top_reasons=reasons[:5],
        recommended_fixes=list(dict.fromkeys(fixes))[:8],
        siem_events=siem_events,
        metadata={
            "workflow_name": result.workflow_name,
            "jobs_scanned": result.jobs_scanned,
            "model_version": model_version(),
            "baseline_drift": bundle.baseline_drift,
            "rule_triggers": bundle.triggers,
        },
        decision_detail=verdict.to_dict(),
    )
    _REPORT_STORE[report.scan_id] = report
    return report


def scan_sbom_unified(
    format_name: str,
    sbom: Dict[str, Any],
    source: str,
    defense_mode: DefenseMode,
    context: Optional[Any] = None,
) -> ScanReport:
    dependencies, raw_components = parse_sbom(format_name, sbom)
    base = scan_manifest_unified(dependencies, source, defense_mode, context)

    risky_paths: List[RiskyPath] = [
        RiskyPath(root=source, path=f.dependency_path, reason=f.attack_type)
        for f in base.findings
        if f.dependency_path
    ]
    high_risk = sum(1 for f in base.findings if f.severity in (Severity.HIGH, Severity.CRITICAL))

    sbom_summary = SbomSummary(
        format=format_name.lower(),
        total_components=len(raw_components),
        high_risk_components=high_risk,
        unsigned_components=len(raw_components),  # Phase 3: provenance check
        untrusted_registry_components=sum(
            1 for f in base.findings if f.attack_type == "dependency_confusion"
        ),
        risky_paths=risky_paths,
    )

    report = ScanReport(
        scan_id=base.scan_id,
        scan_type=ScanType.SBOM,
        timestamp=base.timestamp,
        source=source,
        defense_mode=defense_mode,
        summary=base.summary,
        findings=base.findings,
        top_reasons=base.top_reasons,
        recommended_fixes=base.recommended_fixes,
        sbom=sbom_summary,
        siem_events=base.siem_events,
        metadata={"sbom_format": format_name.lower(), "components_parsed": len(raw_components)},
        decision_detail=base.decision_detail,
    )
    _REPORT_STORE[report.scan_id] = report
    return report


def score_unified(
    input_type: str,
    payload: Dict[str, Any],
    defense_mode: DefenseMode,
    context: Optional[Any] = None,
) -> ScoreResponse:
    it = input_type.lower()
    if it == "manifest":
        deps = payload.get("dependencies") or {}
        report = scan_manifest_unified(deps, payload.get("source", "api"), defense_mode, context)
    elif it == "workflow":
        report = scan_workflow_unified(
            payload.get("workflow") or {}, payload.get("source", "api"), defense_mode
        )
    elif it == "sbom":
        report = scan_sbom_unified(
            payload.get("format", "cyclonedx"),
            payload.get("sbom") or {},
            payload.get("source", "api"),
            defense_mode,
            context,
        )
    else:
        report = scan_manifest_unified(
            payload.get("dependencies") or {}, "api", defense_mode, context
        )

    return ScoreResponse(
        risk_score=report.summary.risk_score,
        decision=report.summary.decision,
        model_version=model_version(),
        top_reasons=report.top_reasons,
        rule_triggers=report.metadata.get("rule_triggers", [f.attack_type for f in report.findings]),
        baseline_drift=bool(report.metadata.get("baseline_drift")),
        decision_detail=report.decision_detail,
    )


_COMPARE_MODES = (DefenseMode.UNBLOCKED, DefenseMode.SOCKET, DefenseMode.HYBRID)

_COMPOSITE_STORE: Dict[str, "CompositeScanResponse"] = {}


def _pipeline_status(report: ScanReport) -> str:
    if report.summary.decision == Decision.BLOCK:
        return "block"
    if report.summary.decision == Decision.HOLD:
        return "incomplete"
    if report.summary.findings_count > 0:
        return "warn"
    return "pass"


def _composite_decision(reports: List[ScanReport]) -> Decision:
    decisions = [r.summary.decision for r in reports]
    if Decision.BLOCK in decisions:
        return Decision.BLOCK  # a known blocker always wins
    if Decision.HOLD in decisions:
        return Decision.HOLD  # propagate unknown/incomplete
    if Decision.WARN in decisions:
        return Decision.WARN
    return Decision.ALLOW


def get_composite_scan(scan_id: str) -> Optional["CompositeScanResponse"]:
    return _COMPOSITE_STORE.get(scan_id)


def run_composite_scan(
    *,
    source: str,
    defense_mode: DefenseMode,
    dependencies: Dict[str, str],
    sbom: Dict[str, Any],
    workflow: Dict[str, Any],
    sbom_format: str = "cyclonedx",
    compare_defense_modes: bool = True,
    manifest_path: Optional[str] = None,
    workflow_path: Optional[str] = None,
    from_github: bool = False,
    demo_fallback: bool = False,
    context: Optional[Any] = None,
    extra_workflows: Optional[List[Dict[str, Any]]] = None,
) -> "CompositeScanResponse":
    from app.schemas.scan_report import (
        CompositeScanResponse,
        CompositeSummary,
        DefenseComparison,
        PipelineStage,
        TaggedFinding,
    )

    manifest = scan_manifest_unified(dependencies, source, defense_mode, context)
    sbom_report = scan_sbom_unified(sbom_format, sbom, source, defense_mode, context)
    workflow_report = scan_workflow_unified(workflow, source, defense_mode)
    # A repository has several workflow files; the workflow layer reports the strictest one.
    for extra in extra_workflows or []:
        candidate = scan_workflow_unified(extra, source, defense_mode)
        if _decision_rank(candidate.summary.decision) > _decision_rank(workflow_report.summary.decision):
            workflow_report = candidate

    layer_reports = {
        "manifest": manifest,
        "sbom": sbom_report,
        "workflow": workflow_report,
    }

    pipeline = [
        PipelineStage(
            layer=layer,
            status=_pipeline_status(report),
            decision=report.summary.decision,
            findings_count=report.summary.findings_count,
            risk_score=report.summary.risk_score,
            scan_id=report.scan_id,
        )
        for layer, report in layer_reports.items()
    ]

    tagged: List[TaggedFinding] = []
    for layer, report in layer_reports.items():
        for finding in report.findings:
            tagged.append(TaggedFinding(**finding.model_dump(), scan_layer=layer))

    reports = list(layer_reports.values())
    composite_decision = _composite_decision(reports)
    layer_scores = [r.summary.risk_score for r in reports]
    # Propagate unknown: if any layer's fused score is None (HOLD/incomplete), the
    # composite fused score is unknown too: never fabricate a max over partial data.
    composite_risk = None if any(s is None for s in layer_scores) else max(layer_scores)
    findings_count = sum(r.summary.findings_count for r in reports)

    defense_comparison: List[DefenseComparison] = []
    if compare_defense_modes:
        for mode in _COMPARE_MODES:
            manifest_cmp = scan_manifest_unified(dependencies, source, mode, context)
            defense_comparison.append(
                DefenseComparison(
                    mode=mode,
                    decision=manifest_cmp.summary.decision,
                    risk_score=manifest_cmp.summary.risk_score,
                    findings_count=manifest_cmp.summary.findings_count,
                )
            )

    reasons: List[Reason] = []
    fixes: List[str] = []
    for report in (manifest, workflow_report):
        reasons.extend(report.top_reasons)
        fixes.extend(report.recommended_fixes)

    deduped_reasons: List[Reason] = []
    seen_reasons: set[str] = set()
    for reason in reasons:
        key = reason.feature or reason.description
        if key in seen_reasons:
            continue
        seen_reasons.add(key)
        deduped_reasons.append(reason)

    response = CompositeScanResponse(
        source=source,
        defense_mode=defense_mode,
        summary=CompositeSummary(
            decision=composite_decision,
            risk_score=composite_risk,
            findings_count=findings_count,
            components_scanned=manifest.summary.components_scanned,
            severity=_overall_severity(tagged),
        ),
        pipeline=pipeline,
        manifest=manifest,
        sbom=sbom_report,
        workflow=workflow_report,
        findings=tagged,
        defense_comparison=defense_comparison,
        top_reasons=deduped_reasons[:6],
        recommended_fixes=list(dict.fromkeys(fixes))[:8],
        metadata={
            "manifest_path": manifest_path,
            "workflow_path": workflow_path,
            "from_github": from_github,
            "demo_fallback": demo_fallback,
            "dependency_count": len(dependencies),
        },
    )
    _COMPOSITE_STORE[response.scan_id] = response
    return response
