import { useDefenseMode } from "../context/DefenseModeContext.jsx";
import { useGitHub } from "../context/GitHubContext.jsx";
import { useScanRunner } from "../hooks/useScanRunner.js";
import { useScanNotifications } from "../hooks/useScanNotifications.js";
import ScanTargetBar from "../Components/scan/ScanTargetBar.jsx";
import ScanPipeline from "../Components/scan/ScanPipeline.jsx";
import ScanVerdictHero from "../Components/scan/ScanVerdictHero.jsx";
import ScanLayerCards from "../Components/scan/ScanLayerCards.jsx";
import ScanFindingsPanel from "../Components/scan/ScanFindingsPanel.jsx";
import ScanRecommendations from "../Components/scan/ScanRecommendations.jsx";
import MlModelPanel from "../Components/ml/MlModelPanel.jsx";
import { useMlModel } from "../hooks/useMlModel.js";

export default function ScanPage({ onNavigate }) {
  const { config } = useDefenseMode();
  const { selectedRepo, artifacts, loadingArtifacts, refreshStatus, showLabDemo } = useGitHub();

  const scan = useScanRunner({
    defenseApi: config.api,
    selectedRepo,
    artifacts,
    loadingArtifacts,
    labDemoActive: showLabDemo,
    onGitHubDisconnected: refreshStatus,
  });

  useScanNotifications(scan);
  const { info: mlInfo } = useMlModel();

  const {
    loading,
    error,
    lastRunAt,
    scanSource,
    scanPayload,
    manifestReport,
    sbomReport,
    workflowReport,
    socketStatus,
    allFindings,
    composite,
    scanMetadata,
    runScan,
  } = scan;

  return (
    <div className="scan-page page-shell">
      <ScanTargetBar
        scanSource={scanSource}
        scanPayload={scanPayload}
        selectedRepo={selectedRepo}
        loading={loading}
        lastRunAt={lastRunAt}
        onRescan={runScan}
        onSelectRepo={() => onNavigate?.("repos")}
      />

      {loading && (
        <div className="loading-bar"><span /></div>
      )}
      {loading && selectedRepo && (
        <p className="scan-progress-note">
          Scanning {selectedRepo.full_name}: each dependency is downloaded from npm and read once.
          A first scan can take up to a minute; later scans reuse the results and finish in about a
          second.
        </p>
      )}

      {error && <p className="gh-connect-error">{error}</p>}

      <ScanPipeline
        pipeline={composite?.pipeline}
        manifestReport={manifestReport}
        sbomReport={sbomReport}
        workflowReport={workflowReport}
        loading={loading}
      />

      <ScanVerdictHero
        composite={composite}
        defenseLabel={config.label}
        socketStatus={socketStatus}
        mlInfo={mlInfo}
        scanMetadata={scanMetadata}
      />

      <div className="scan-main-grid">
        <ScanFindingsPanel findings={allFindings} />
        <ScanLayerCards
          manifestReport={manifestReport}
          sbomReport={sbomReport}
          workflowReport={workflowReport}
        />
      </div>

      <ScanRecommendations
        manifestReport={manifestReport}
        workflowReport={workflowReport}
        scanMetadata={scanMetadata}
      />

      <MlModelPanel compact />
    </div>
  );
}
