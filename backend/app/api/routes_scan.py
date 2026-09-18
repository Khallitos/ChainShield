"""Unified scan API: manifest, workflow, SBOM, score."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.schemas.scan_report import (
    CompositeScanRequest,
    CompositeScanResponse,
    ManifestScanRequest,
    ScanReport,
    ScoreRequest,
    ScoreResponse,
    SbomScanRequest,
    WorkflowScanRequest,
)
from app.services.scan_service import (
    get_composite_scan,
    get_report,
    run_composite_scan,
    scan_manifest_unified,
    scan_sbom_unified,
    scan_workflow_unified,
    score_unified,
)

from app.policy.project_context import resolve_context

router = APIRouter(tags=["Scan"])


def _context(body):
    """Scan context from the request: the project's lockfile and declared internal names."""
    try:
        return resolve_context(body.baseline_mode, body.lockfile, body.internal_namespaces)
    except Exception as exc:  # invalid namespace pattern
        raise HTTPException(status_code=400, detail=f"invalid scan context: {exc}") from exc


@router.post("/scan/run", response_model=CompositeScanResponse)
def scan_run(body: CompositeScanRequest) -> CompositeScanResponse:
    """
    Run the full scan pipeline (manifest + SBOM + workflow) in one call.
    Optionally compares manifest results across defense modes.
    """
    return run_composite_scan(
        source=body.source,
        defense_mode=body.defense_mode,
        dependencies=body.dependencies,
        sbom=body.sbom,
        workflow=body.workflow,
        sbom_format=body.sbom_format,
        compare_defense_modes=body.compare_defense_modes,
        manifest_path=body.manifest_path,
        workflow_path=body.workflow_path,
        from_github=body.from_github,
        demo_fallback=body.demo_fallback,
        context=_context(body),
    )


@router.get("/scan/composite/{scan_id}", response_model=CompositeScanResponse)
def fetch_composite_scan(scan_id: str) -> CompositeScanResponse:
    """Retrieve a cached composite scan by scan_id."""
    report = get_composite_scan(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Composite scan {scan_id!r} not found")
    return report


@router.post("/scan/manifest", response_model=ScanReport)
def scan_manifest(body: ManifestScanRequest) -> ScanReport:
    """
    Scan a dependency manifest for typosquatting (ATK1) and dependency confusion (ATK2).
    Returns unified ScanReport: see docs/api/API_SPEC.md.
    """
    return scan_manifest_unified(
        body.dependencies,
        source=body.source,
        defense_mode=body.defense_mode,
        context=_context(body),
    )


@router.post("/scan/workflow", response_model=ScanReport)
def scan_workflow(body: WorkflowScanRequest) -> ScanReport:
    """Scan a CI/CD workflow (JSON) for injection vulnerabilities (ATK3)."""
    return scan_workflow_unified(
        body.workflow,
        source=body.source,
        defense_mode=body.defense_mode,
    )


@router.post("/scan/sbom", response_model=ScanReport)
def scan_sbom(body: SbomScanRequest) -> ScanReport:
    """Scan CycloneDX or SPDX SBOM for supply-chain risks."""
    try:
        return scan_sbom_unified(
            body.format,
            body.sbom,
            source=body.source,
            defense_mode=body.defense_mode,
            context=_context(body),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/score", response_model=ScoreResponse)
def score(body: ScoreRequest) -> ScoreResponse:
    """Hybrid risk score for manifest, workflow, or SBOM input."""
    try:
        payload = body.payload or {}
        context = resolve_context(
            payload.get("baseline_mode"), payload.get("lockfile"), payload.get("internal_namespaces")
        )
        return score_unified(body.input_type, payload, body.defense_mode, context)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/report/{scan_id}", response_model=ScanReport)
def fetch_report(scan_id: str) -> ScanReport:
    """Retrieve a cached scan report by scan_id."""
    report = get_report(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    return report
