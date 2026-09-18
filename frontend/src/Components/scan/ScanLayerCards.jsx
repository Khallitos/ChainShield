import { formatRisk, isUnknown } from "../../utils/riskDisplay.js";

function LayerCard({ title, report, extra }) {
  if (!report?.summary) {
    return (
      <article className="scan-layer-card">
        <h4>{title}</h4>
        <p className="scan-layer-pending">Pending…</p>
      </article>
    );
  }

  const { summary, top_reasons = [], recommended_fixes = [], metadata = {} } = report;

  return (
    <article className="scan-layer-card">
      <div className="scan-layer-head">
        <h4>{title}</h4>
        <span className={`scan-layer-decision dec-${summary.decision}`}>
          {summary.decision?.toUpperCase()}
        </span>
      </div>
      <div className="scan-layer-metrics">
        <div>
          <strong>{summary.findings_count}</strong>
          <span>findings</span>
        </div>
        <div>
          <strong>{isUnknown(summary.risk_score) ? "n/a" : formatRisk(summary.risk_score)}</strong>
          <span>risk</span>
        </div>
        {summary.components_scanned != null && (
          <div>
            <strong>{summary.components_scanned}</strong>
            <span>components</span>
          </div>
        )}
      </div>
      {extra}
      {metadata.engine && (
        <p className="scan-layer-engine">Engine · {metadata.engine.replace(/_/g, " ")}</p>
      )}
      {top_reasons[0] && (
        <p className="scan-layer-reason">{top_reasons[0].description || top_reasons[0].feature}</p>
      )}
      {recommended_fixes[0] && (
        <p className="scan-layer-fix">{recommended_fixes[0]}</p>
      )}
    </article>
  );
}

export default function ScanLayerCards({ manifestReport, sbomReport, workflowReport }) {
  const sbom = sbomReport?.sbom;

  return (
    <section className="scan-layers">
      <h3 className="scan-section-title">Scan layers</h3>
      <div className="scan-layer-grid">
        <LayerCard title="Manifest" report={manifestReport} />
        <LayerCard
          title="SBOM"
          report={sbomReport}
          extra={
            sbom && (
              <div className="scan-sbom-mini">
                <span>{sbom.total_components} total</span>
                <span>{sbom.high_risk_components} high risk</span>
                {sbom.risky_paths?.length > 0 && (
                  <span>{sbom.risky_paths.length} risky paths</span>
                )}
              </div>
            )
          }
        />
        <LayerCard title="Workflow" report={workflowReport} />
      </div>
    </section>
  );
}
