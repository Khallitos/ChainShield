import { riskPct, decisionTone, unavailableText } from "../../utils/riskDisplay.js";

export default function AiDecisionCard({ report, modelInfo, socketStatus }) {
  if (!report?.summary) {
    return (
      <section className="panel ai-decision-card">
        <h3>AI Decision</h3>
        <p className="muted">Run scan to see hybrid risk score…</p>
      </section>
    );
  }

  const { summary, top_reasons = [], metadata = {} } = report;
  const pct = riskPct(summary.risk_score); // null => unknown, never 0
  const tone = decisionTone(summary.decision);
  const decision =
    summary.decision === "hold"
      ? "HOLD"
      : summary.decision?.toUpperCase() ?? (pct === null ? "UNAVAILABLE" : "n/a");

  const decisionClass = `dec-${tone}`;
  const modelStatus = metadata?.model_status;

  return (
    <section className="panel ai-decision-card">
      <div className="module-head">
        <h3>AI Decision Card</h3>
        <span className="model-tag">{metadata.model_version || modelInfo?.model_version || "scr_rules_v0"}</span>
      </div>

      <div className="ai-score-row">
        <div className={`ai-gauge ${decisionClass}`}>
          <svg viewBox="0 0 36 36">
            <path
              className="ai-gauge-bg"
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
            <path
              className="ai-gauge-fill"
              strokeDasharray={`${pct ?? 0}, 100`}
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
          </svg>
          <span className="ai-gauge-val">{pct === null ? "n/a" : pct}</span>
        </div>
        <div className="ai-decision-meta">
          <p className="ai-decision-label">Decision</p>
          <p className={`ai-decision-value ${decisionClass}`}>{decision}</p>
          <p className="ai-decision-sub">
            {metadata.engine === "socket_dev_api"
              ? `Socket.dev · ${metadata.socket_packages_scanned || 0} pkg · quota ${socketStatus?.quota?.quota ?? "n/a"}/${socketStatus?.quota?.maxQuota ?? "n/a"}`
              : metadata.engine === "socket_fallback_baseline"
                ? (metadata.socket_configured ? "Socket API error, using local rules" : "Socket token not set, using local rules")
                : metadata.baseline_drift
                  ? "Baseline drift detected"
                  : "Matches trust graph"}
          </p>
        </div>
      </div>

      <div className="ai-reasons">
        {tone === "hold" && pct === null && (
          <p className="ai-hold-note">{unavailableText(modelStatus)}</p>
        )}
        <p className="ai-reasons-title">Top reasons</p>
        {(top_reasons.length ? top_reasons : [{ description: "No significant risk signals" }]).slice(0, 3).map((r, i) => (
          <div key={i} className="ai-reason-row">
            {r.contribution != null && (
              <span className="ai-reason-pct">{Math.round(r.contribution * 100)}%</span>
            )}
            <span>{r.description || r.feature}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
