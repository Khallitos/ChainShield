"""Unified scan report and scoring schemas: see docs/api/API_SPEC.md."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class ScanType(str, Enum):
    MANIFEST = "manifest"
    WORKFLOW = "workflow"
    SBOM = "sbom"
    COMPOSITE = "composite"


class Decision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    HOLD = "hold"  # cannot evaluate safely (revised policy: model unavailable/error)
    BLOCK = "block"


class DefenseMode(str, Enum):
    UNBLOCKED = "unblocked"
    BASELINE = "baseline"  # internal rule simulation (evaluation)
    SOCKET = "socket"  # real Socket.dev API
    HYBRID = "hybrid"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


def _new_scan_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"scn_{ts}_{uuid4().hex[:8]}"


class Reason(BaseModel):
    feature: str
    contribution: float = Field(ge=0.0, le=1.0)
    description: str


class Finding(BaseModel):
    finding_id: str
    attack_type: str
    severity: Severity
    package: Optional[str] = None
    version: Optional[str] = None
    canonical: Optional[str] = None
    message: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    dependency_path: List[str] = Field(default_factory=list)


class RiskyPath(BaseModel):
    root: str
    path: List[str]
    reason: str


class SbomSummary(BaseModel):
    format: str
    total_components: int
    high_risk_components: int
    unsigned_components: int = 0
    untrusted_registry_components: int = 0
    risky_paths: List[RiskyPath] = Field(default_factory=list)


class ScanSummary(BaseModel):
    components_scanned: int
    findings_count: int
    # risk_score is None when the fused detector value is unknown (revised HOLD), so a
    # hold/cannot-evaluate state is never misread as a benign numeric certainty.
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    decision: Decision
    severity: Severity = Severity.NONE


class ScanReport(BaseModel):
    scan_id: str = Field(default_factory=_new_scan_id)
    scan_type: ScanType
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source: str = "unknown"
    defense_mode: DefenseMode = DefenseMode.HYBRID
    summary: ScanSummary
    findings: List[Finding] = Field(default_factory=list)
    top_reasons: List[Reason] = Field(default_factory=list)
    recommended_fixes: List[str] = Field(default_factory=list)
    sbom: Optional[SbomSummary] = None
    siem_events: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # Additive, consumer-independent decision detail from the pure contract.
    decision_detail: Optional[Dict[str, Any]] = None


# ── Request bodies ────────────────────────────────────────────────────────────


class ManifestScanRequest(BaseModel):
    dependencies: Dict[str, str]
    source: str = "unknown"
    defense_mode: DefenseMode = DefenseMode.HYBRID
    trusted_baseline_id: str = "default"
    lockfile: Optional[Dict[str, Any]] = None
    baseline_mode: str = Field(default="project", description="project (the scanned project's lockfile and declared internal names) or lab (demo baseline)")
    internal_namespaces: List[str] = Field(default_factory=list, description="Organisation-declared internal package prefixes, e.g. '@acme/'")


class WorkflowScanRequest(BaseModel):
    workflow: Dict[str, Any]
    source: str = "unknown"
    defense_mode: DefenseMode = DefenseMode.HYBRID


class SbomScanRequest(BaseModel):
    format: str = Field(description="cyclonedx or spdx")
    sbom: Dict[str, Any]
    source: str = "unknown"
    defense_mode: DefenseMode = DefenseMode.HYBRID
    lockfile: Optional[Dict[str, Any]] = None
    baseline_mode: str = Field(default="project", description="project (the scanned project's lockfile and declared internal names) or lab (demo baseline)")
    internal_namespaces: List[str] = Field(default_factory=list, description="Organisation-declared internal package prefixes, e.g. '@acme/'")


class ScoreRequest(BaseModel):
    input_type: str = Field(description="manifest | workflow | sbom | features")
    payload: Dict[str, Any]
    defense_mode: DefenseMode = DefenseMode.HYBRID


class ScoreResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    risk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    decision: Decision
    model_version: str = "scr_rules_v0"
    top_reasons: List[Reason] = Field(default_factory=list)
    rule_triggers: List[str] = Field(default_factory=list)
    baseline_drift: bool = False
    # Additive decision detail (policy_version, raw rule/ml score, model status,
    # mandatory violations, verdict vs action) exposed from the pure contract.
    decision_detail: Optional[Dict[str, Any]] = None


# ── Composite (full pipeline) scan ───────────────────────────────────────────


def _new_composite_scan_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"scn_cmp_{ts}_{uuid4().hex[:8]}"


class CompositeScanRequest(BaseModel):
    """Run manifest + SBOM + workflow scans in one request."""

    source: str = "demo-site"
    defense_mode: DefenseMode = DefenseMode.HYBRID
    dependencies: Dict[str, str]
    sbom: Dict[str, Any]
    workflow: Dict[str, Any]
    sbom_format: str = "cyclonedx"
    compare_defense_modes: bool = True
    manifest_path: Optional[str] = None
    workflow_path: Optional[str] = None
    from_github: bool = False
    demo_fallback: bool = False
    lockfile: Optional[Dict[str, Any]] = None
    baseline_mode: str = Field(default="project", description="project (the scanned project's lockfile and declared internal names) or lab (demo baseline)")
    internal_namespaces: List[str] = Field(default_factory=list, description="Organisation-declared internal package prefixes, e.g. '@acme/'")


class PipelineStage(BaseModel):
    layer: str
    status: str
    decision: Decision
    findings_count: int
    risk_score: Optional[float] = None
    scan_id: str


class DefenseComparison(BaseModel):
    mode: DefenseMode
    decision: Decision
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    findings_count: int


class CompositeSummary(BaseModel):
    decision: Decision
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    findings_count: int
    components_scanned: int
    severity: Severity = Severity.NONE


class TaggedFinding(Finding):
    scan_layer: str


class CompositeScanResponse(BaseModel):
    scan_id: str = Field(default_factory=_new_composite_scan_id)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source: str
    defense_mode: DefenseMode
    summary: CompositeSummary
    pipeline: List[PipelineStage] = Field(default_factory=list)
    manifest: ScanReport
    sbom: ScanReport
    workflow: ScanReport
    findings: List[TaggedFinding] = Field(default_factory=list)
    defense_comparison: List[DefenseComparison] = Field(default_factory=list)
    top_reasons: List[Reason] = Field(default_factory=list)
    recommended_fixes: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

