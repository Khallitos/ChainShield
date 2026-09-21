import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, DEMO_ATTACK_DEPS, DEMO_SBOM, DEMO_WORKFLOW } from "../UTILS/api.js";
import { isUnknown } from "../utils/riskDisplay.js";

function applyCompositeResult(data, setters) {
  const {
    setManifestReport,
    setSbomReport,
    setWorkflowReport,
    setComparisons,
    setCompositeScanId,
    setScanMetadata,
  } = setters;

  setManifestReport(data.manifest);
  setSbomReport(data.sbom);
  setWorkflowReport(data.workflow);
  setComparisons([]);
  setCompositeScanId(data.scan_id);
  setScanMetadata({
    summary: data.summary,
    pipeline: data.pipeline,
    top_reasons: data.top_reasons,
    recommended_fixes: data.recommended_fixes,
    metadata: {
      ...(data.metadata || {}),
      model_version: data.manifest?.metadata?.model_version,
      rule_triggers: data.manifest?.metadata?.rule_triggers,
    },
    timestamp: data.timestamp,
  });
}

export function useScanRunner({
  defenseApi,
  selectedRepo,
  artifacts,
  loadingArtifacts,
  labDemoActive = false,
  onGitHubDisconnected,
}) {
  const [manifestReport, setManifestReport] = useState(null);
  const [sbomReport, setSbomReport] = useState(null);
  const [workflowReport, setWorkflowReport] = useState(null);
  const [comparisons, setComparisons] = useState([]);
  const [compositeScanId, setCompositeScanId] = useState(null);
  const [scanMetadata, setScanMetadata] = useState(null);
  const [socketStatus, setSocketStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastRunAt, setLastRunAt] = useState(null);
  // Which target the reports on screen belong to, so a new target never shows the old findings.
  const [resultSource, setResultSource] = useState(null);
  const resultSourceRef = useRef(null);

  const scanSource = selectedRepo?.full_name || "demo-site";

  const requestPayload = useMemo(() => {
    if (selectedRepo && !artifacts) {
      // The backend reads the repository's own files; nothing here is demo data.
      return {
        dependencies: {},
        sbom: null,
        workflow: null,
        fromGitHub: true,
        manifestPath: null,
        workflowPath: null,
        demoFallback: false,
      };
    }
    if (selectedRepo && artifacts) {
      return {
        dependencies:
          artifacts.dependency_count > 0 ? artifacts.dependencies : DEMO_ATTACK_DEPS,
        sbom: artifacts.sbom || DEMO_SBOM,
        workflow: artifacts.workflow || DEMO_WORKFLOW,
        fromGitHub: Boolean(artifacts.dependency_count || artifacts.workflow),
        manifestPath: artifacts.manifest_path,
        workflowPath: artifacts.workflow_path,
        demoFallback: !(artifacts.dependency_count || artifacts.workflow),
      };
    }
    if (labDemoActive) {
      return {
        dependencies: DEMO_ATTACK_DEPS,
        sbom: DEMO_SBOM,
        workflow: DEMO_WORKFLOW,
        fromGitHub: false,
        manifestPath: null,
        workflowPath: null,
        demoFallback: true,
      };
    }
    return null;
  }, [selectedRepo, artifacts, labDemoActive]);

  // Once the backend has answered for this target, its metadata says what was really scanned.
  const scanPayload = useMemo(() => {
    if (!requestPayload) {
      return { fromGitHub: false, demoFallback: false };
    }
    const meta = scanMetadata?.metadata;
    if (!meta || resultSource !== scanSource) return requestPayload;
    return {
      ...requestPayload,
      fromGitHub: Boolean(meta.from_github) && !meta.demo_fallback,
      demoFallback: Boolean(meta.demo_fallback),
      manifestPath: meta.manifest_path ?? requestPayload.manifestPath,
      workflowPath: meta.workflow_path ?? requestPayload.workflowPath,
    };
  }, [requestPayload, scanMetadata, resultSource, scanSource]);

  const clearResults = useCallback(() => {
    setManifestReport(null);
    setSbomReport(null);
    setWorkflowReport(null);
    setComparisons([]);
    setCompositeScanId(null);
    setScanMetadata(null);
    setResultSource(null);
    resultSourceRef.current = null;
  }, []);

  const setters = useMemo(
    () => ({
      setManifestReport,
      setSbomReport,
      setWorkflowReport,
      setComparisons,
      setCompositeScanId,
      setScanMetadata,
    }),
    []
  );

  const runScan = useCallback(async () => {
    if (!selectedRepo?.owner && !selectedRepo?.name && !labDemoActive) {
      clearResults();
      setLoading(false);
      setError(null);
      return;
    }
    if (!requestPayload) {
      clearResults();
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);
    if (resultSourceRef.current !== scanSource) clearResults();
    try {
      await api.health();

      let data;
      if (selectedRepo?.owner && selectedRepo?.name) {
        data = await api.scanGitHubRepo(
          selectedRepo.owner,
          selectedRepo.name,
          defenseApi,
          false
        );
      } else {
        data = await api.scanRun({
          source: scanSource,
          defense_mode: defenseApi,
          dependencies: requestPayload.dependencies,
          sbom: requestPayload.sbom,
          workflow: requestPayload.workflow,
          sbom_format: "cyclonedx",
          compare_defense_modes: false,
          manifest_path: requestPayload.manifestPath,
          workflow_path: requestPayload.workflowPath,
          from_github: requestPayload.fromGitHub,
          demo_fallback: requestPayload.demoFallback,
          baseline_mode: requestPayload.demoFallback || !requestPayload.fromGitHub ? "lab" : "project",
        });
      }

      applyCompositeResult(data, setters);
      setResultSource(scanSource);
      resultSourceRef.current = scanSource;
      setLastRunAt(new Date());

      try {
        const sock = await api.socketStatus();
        setSocketStatus(sock);
      } catch {
        /* optional */
      }
    } catch (err) {
      const message = err.message || "Scan failed. Is the backend running?";
      if (selectedRepo && /GitHub not connected/i.test(message)) {
        // The backend lost the GitHub session (e.g. it was restarted): re-check the status so
        // the dashboard shows "Connect GitHub" again instead of a stuck repository.
        setError(
          "Your GitHub session has ended. Open Repositories, connect your token again, then scan."
        );
        onGitHubDisconnected?.();
      } else {
        setError(message);
      }
      clearResults();
    } finally {
      setLoading(false);
    }
  }, [
    defenseApi,
    requestPayload,
    scanSource,
    selectedRepo,
    labDemoActive,
    setters,
    clearResults,
    onGitHubDisconnected,
  ]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      await runScan();
      if (cancelled) return;
    })();
    return () => {
      cancelled = true;
    };
  }, [defenseApi, selectedRepo?.owner, selectedRepo?.name, labDemoActive]); // eslint-disable-line react-hooks/exhaustive-deps

  const allFindings = useMemo(() => {
    if (manifestReport || sbomReport || workflowReport) {
      return [
        ...(manifestReport?.findings || []).map((f) => ({ ...f, scan_layer: "manifest" })),
        ...(workflowReport?.findings || []).map((f) => ({ ...f, scan_layer: "workflow" })),
        ...(sbomReport?.findings || []).map((f) => ({ ...f, scan_layer: "sbom" })),
      ];
    }
    return [];
  }, [manifestReport, workflowReport, sbomReport]);

  const composite = useMemo(() => {
    if (scanMetadata?.summary) {
      return {
        ...scanMetadata.summary,
        scan_id: compositeScanId,
        timestamp: scanMetadata.timestamp,
        pipeline: scanMetadata.pipeline,
      };
    }

    const reports = [manifestReport, sbomReport, workflowReport].filter(Boolean);
    if (!reports.length) return null;

    // Fail closed: an unknown layer score must NOT be merged as a fake 0, and a
    // HOLD/unknown layer must not collapse into a benign "allow" composite.
    const anyUnknown = reports.some((r) => r?.summary != null && isUnknown(r.summary.risk_score));
    const knownRisks = reports
      .map((r) => r?.summary?.risk_score)
      .filter((v) => !isUnknown(v));
    const risk = anyUnknown ? null : Math.max(...knownRisks);
    const findingsCount = reports.reduce((n, r) => n + (r.summary?.findings_count ?? 0), 0);
    const components = manifestReport?.summary?.components_scanned ?? 0;
    const decisions = reports.map((r) => r.summary?.decision).filter(Boolean);
    const decision = decisions.includes("block")
      ? "block"
      : decisions.includes("hold") || anyUnknown
        ? "hold"
        : decisions.includes("warn")
          ? "warn"
          : "allow";
    const severities = ["critical", "high", "medium", "low"];
    const worstSeverity =
      severities.find((s) => allFindings.some((f) => f.severity === s)) ||
      manifestReport?.summary?.severity ||
      "none";

    return {
      decision,
      risk_score: risk,
      findings_count: findingsCount,
      components_scanned: components,
      severity: worstSeverity,
      scan_id: compositeScanId || manifestReport?.scan_id,
      timestamp: manifestReport?.timestamp,
    };
  }, [scanMetadata, compositeScanId, manifestReport, sbomReport, workflowReport, allFindings]);

  return {
    loading,
    error,
    lastRunAt,
    scanSource,
    scanPayload,
    manifestReport,
    sbomReport,
    workflowReport,
    comparisons,
    socketStatus,
    allFindings,
    composite,
    compositeScanId,
    scanMetadata,
    runScan,
  };
}
