import { useDefenseMode } from "../context/DefenseModeContext.jsx";
import { useGitHub } from "../context/GitHubContext.jsx";
import { useScanRunner } from "../hooks/useScanRunner.js";
import { useScanNotifications } from "../hooks/useScanNotifications.js";
import { useOverviewDashboard } from "../hooks/useOverviewDashboard.js";
import SocketOverviewLayout from "../Components/dashboard/SocketOverviewLayout.jsx";

export default function SiemDashboard({ onNavigate, showFindings, onShowFindings }) {
  const { blockingEnabled, config } = useDefenseMode();
  const { selectedRepo, artifacts, loadingArtifacts } = useGitHub();

  const scan = useScanRunner({
    defenseApi: config.api,
    selectedRepo,
    artifacts,
    loadingArtifacts,
  });

  useScanNotifications(scan);

  const overview = useOverviewDashboard({
    defenseApi: config.api,
    selectedRepo,
    refreshKey: scan.lastRunAt?.getTime?.() || 0,
  });

  const {
    loading,
    scanPayload,
    manifestReport,
    sbomReport,
    workflowReport,
    socketStatus,
    allFindings,
    composite,
    lastRunAt,
  } = scan;

  return (
    <>
      {selectedRepo && (
        <p className="repo-scan-banner">
          Scanning <strong>{selectedRepo.full_name}</strong>
          {artifacts?.manifest_path && <> · manifest: {artifacts.manifest_path}</>}
          {artifacts?.workflow_path && <> · workflow: {artifacts.workflow_path}</>}
          {scanPayload.fromGitHub ? "" : " · using lab demo payloads where repo files are missing"}
        </p>
      )}

      <SocketOverviewLayout
        blockingEnabled={blockingEnabled}
        protectionLabel={config.label}
        loading={loading}
        overviewData={overview.data}
        overviewLoading={overview.loading}
        manifestReport={manifestReport}
        workflowReport={workflowReport}
        sbomReport={sbomReport}
        composite={composite}
        socketStatus={socketStatus}
        allFindings={allFindings}
        lastRunAt={lastRunAt}
        demo={scanPayload.demoFallback}
        onNavigate={onNavigate}
        onReviewAlerts={() => onShowFindings?.(true)}
      />

      {overview.error && (
        <p className="overview-error-banner">{overview.error}</p>
      )}

      {showFindings && (allFindings.length > 0 || overview.data?.alerts?.findings?.length > 0) && (
        <section className="socket-card findings-drawer">
          <div className="socket-card-head">
            <h3>Alert details</h3>
            <button type="button" className="socket-card-action" onClick={() => onShowFindings?.(false)}>
              Close
            </button>
          </div>
          <ul className="campaign-list">
            {(allFindings.length ? allFindings : overview.data?.alerts?.findings || []).map((f) => (
              <li key={f.finding_id} className="campaign-item">
                <span
                  className="campaign-icon"
                  style={{
                    borderColor:
                      f.severity === "critical" || f.severity === "high"
                        ? "var(--color-critical)"
                        : "var(--color-medium)",
                    borderStyle: "solid",
                  }}
                />
                <div>
                  <div>{f.package || "workflow"}: {f.attack_type}</div>
                  <div className="campaign-meta">{f.message}</div>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  );
}
