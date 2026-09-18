import { formatRisk, isUnknown } from "../../utils/riskDisplay.js";

export default function SbomInsightsPanel({ sbomReport }) {
  const sbom = sbomReport?.sbom;

  if (!sbom) {
    return (
      <section className="panel sbom-panel">
        <h3>SBOM Insights</h3>
        <p className="muted">SBOM scan pending…</p>
      </section>
    );
  }

  const stats = [
    ["Total components", sbom.total_components],
    ["High risk", sbom.high_risk_components],
    ["Unsigned", sbom.unsigned_components],
    ["Untrusted registry", sbom.untrusted_registry_components],
  ];

  return (
    <section className="panel sbom-panel">
      <div className="module-head">
        <h3>SBOM Insights</h3>
        <span>{sbom.format?.toUpperCase()}</span>
      </div>

      <div className="sbom-stats">
        {stats.map(([label, val]) => (
          <div key={label} className="sbom-stat">
            <strong>{val}</strong>
            <span>{label}</span>
          </div>
        ))}
      </div>

      {sbom.risky_paths?.length > 0 && (
        <>
          <p className="sbom-paths-title">Risky dependency paths</p>
          <div className="sbom-paths">
            {sbom.risky_paths.slice(0, 4).map((p, i) => (
              <div key={i} className="sbom-path-row">
                <code>{p.path?.join(" → ")}</code>
                <span className="sbom-path-reason">{p.reason}</span>
              </div>
            ))}
          </div>
        </>
      )}

      {sbomReport.summary && (
        <p className="sbom-decision">
          SBOM scan decision:{" "}
          <strong className={`dec-${sbomReport.summary.decision}`}>
            {sbomReport.summary.decision?.toUpperCase()}
          </strong>
          {" "}({isUnknown(sbomReport.summary.risk_score) ? "risk n/a" : `${formatRisk(sbomReport.summary.risk_score)} risk`})
        </p>
      )}
    </section>
  );
}
