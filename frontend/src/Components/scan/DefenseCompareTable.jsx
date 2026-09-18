import { formatRisk, isUnknown } from "../../utils/riskDisplay.js";

export default function DefenseCompareTable({ comparisons, activeMode }) {
  if (!comparisons?.length) return null;

  return (
    <section className="scan-defense-compare socket-card">
      <div className="scan-findings-head">
        <div>
          <h3>Defense comparison</h3>
          <p className="scan-findings-sub">Same manifest scanned under each defense mode</p>
        </div>
      </div>
      <div className="scan-defense-grid">
        {comparisons.map((row) => (
          <article
            key={row.mode}
            className={`scan-defense-col ${activeMode === row.mode ? "active" : ""}`}
            style={{ "--mode-color": row.color }}
          >
            <p className="scan-defense-label">{row.label}</p>
            <span className={`scan-defense-decision dec-${row.decision}`}>
              {row.decision?.toUpperCase()}
            </span>
            <div className="scan-defense-metrics">
              <div>
                <strong>{isUnknown(row.risk_score) ? "n/a" : formatRisk(row.risk_score)}</strong>
                <span>risk</span>
              </div>
              <div>
                <strong>{row.findings_count}</strong>
                <span>findings</span>
              </div>
            </div>
            {activeMode === row.mode && <span className="scan-defense-active-tag">Active</span>}
          </article>
        ))}
      </div>
    </section>
  );
}
