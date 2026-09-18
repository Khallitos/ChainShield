import { decisionTone, formatRisk, isUnknown } from "../../utils/riskDisplay.js";

export default function DefenseComparisonPanel({ comparisons, socketStatus }) {
  if (!comparisons?.length) return null;

  return (
    <section className="panel defense-compare">
      <h3>Defense comparison</h3>
      <div className="compare-grid">
        {comparisons.map((c) => (
          <div key={c.mode} className="compare-col">
            <p className="compare-mode" style={{ color: c.color }}>
              {c.label}
            </p>
            {c.mode === "socketai" && socketStatus?.configured && (
              <p className="compare-engine">socket.dev · {socketStatus.quota?.quota ?? "n/a"} quota left</p>
            )}
            {c.mode === "socketai" && c.engine && (
              <p className="compare-engine">{c.engine === "socket_dev_api" ? "Live API" : "Local fallback"}</p>
            )}
            {c.mode === "oursolution" && c.model_version && (
              <p className="compare-engine">{c.model_version}</p>
            )}
            <p className={`compare-dec dec-${decisionTone(c.decision)}`}>
              {c.decision === "hold" ? "HOLD" : c.decision?.toUpperCase() ?? "n/a"}
            </p>
            <p className="compare-score">
              {isUnknown(c.risk_score) ? "Risk unavailable" : `${formatRisk(c.risk_score)} risk`}
            </p>
            <p className="compare-findings">{c.findings_count} finding(s)</p>
          </div>
        ))}
      </div>
    </section>
  );
}
