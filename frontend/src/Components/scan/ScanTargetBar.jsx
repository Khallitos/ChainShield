function formatTime(date) {
  if (!date) return "n/a";
  return date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export default function ScanTargetBar({
  scanSource,
  scanPayload,
  selectedRepo,
  loading,
  lastRunAt,
  onRescan,
  onSelectRepo,
}) {
  return (
    <header className="scan-target-bar">
      <div className="scan-target-main">
        <div>
          <p className="scan-target-label">Scan target</p>
          <h1 className="scan-page-title">{scanSource}</h1>
          <div className="scan-target-meta">
            {scanPayload.manifestPath && (
              <span className="scan-meta-chip">manifest · {scanPayload.manifestPath}</span>
            )}
            {scanPayload.workflowPath && (
              <span className="scan-meta-chip">workflow · {scanPayload.workflowPath}</span>
            )}
            {!scanPayload.fromGitHub && (
              <span className="scan-meta-chip scan-meta-demo">lab demo payloads</span>
            )}
            {lastRunAt && (
              <span className="scan-meta-chip">last run · {formatTime(lastRunAt)}</span>
            )}
          </div>
        </div>
        <div className="scan-target-actions">
          {!selectedRepo && (
            <button type="button" className="socket-card-action" onClick={onSelectRepo}>
              Select repository
            </button>
          )}
          <button
            type="button"
            className="socket-card-action primary"
            onClick={onRescan}
            disabled={loading}
          >
            {loading ? "Scanning…" : "Rescan"}
          </button>
        </div>
      </div>
    </header>
  );
}
