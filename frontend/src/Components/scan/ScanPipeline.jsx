import { decisionTone, formatRisk, isUnknown } from "../../utils/riskDisplay.js";

const STAGE_LABELS = {
  manifest: { label: "Manifest", desc: "package.json / requirements" },
  sbom: { label: "SBOM", desc: "CycloneDX components" },
  workflow: { label: "Workflow", desc: "CI/CD YAML" },
};

function stageStatus(report, loading) {
  if (loading) return "running";
  if (!report?.summary) return "idle";
  if (report.summary.decision === "block") return "block";
  if (report.summary.findings_count > 0) return "warn";
  return "pass";
}

export default function ScanPipeline({ pipeline, manifestReport, sbomReport, workflowReport, loading }) {
  const reports = { manifest: manifestReport, sbom: sbomReport, workflow: workflowReport };

  if (pipeline?.length) {
    return (
      <div className="scan-pipeline">
        {pipeline.map((stage, i) => {
          const meta = STAGE_LABELS[stage.layer] || { label: stage.layer, desc: "" };
          return (
            <div key={stage.layer} className="scan-pipeline-stage-wrap">
              {i > 0 && <div className={`scan-pipeline-connector ${stage.status !== "idle" ? "active" : ""}`} />}
              <div className={`scan-pipeline-stage scan-stage-${stage.status}`}>
                <div className="scan-stage-head">
                  <span className="scan-stage-dot" />
                  <span className="scan-stage-name">{meta.label}</span>
                  <span className={`scan-stage-decision dec-${stage.decision}`}>
                    {stage.decision}
                  </span>
                </div>
                <p className="scan-stage-desc">{meta.desc}</p>
                <div className="scan-stage-stats">
                  <span>{stage.findings_count} finding{stage.findings_count === 1 ? "" : "s"}</span>
                  <span>{isUnknown(stage.risk_score) ? "risk n/a" : `${formatRisk(stage.risk_score)} risk`}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    );
  }

  const STAGES = [
    { key: "manifest", label: "Manifest", desc: "package.json / requirements" },
    { key: "sbom", label: "SBOM", desc: "CycloneDX components" },
    { key: "workflow", label: "Workflow", desc: "CI/CD YAML" },
  ];

  return (
    <div className="scan-pipeline">
      {STAGES.map((stage, i) => {
        const report = reports[stage.key];
        const status = stageStatus(report, loading && !report);
        const findings = report?.summary?.findings_count ?? 0;
        const risk = report?.summary?.risk_score;

        return (
          <div key={stage.key} className="scan-pipeline-stage-wrap">
            {i > 0 && <div className={`scan-pipeline-connector ${status !== "idle" ? "active" : ""}`} />}
            <div className={`scan-pipeline-stage scan-stage-${status}`}>
              <div className="scan-stage-head">
                <span className="scan-stage-dot" />
                <span className="scan-stage-name">{stage.label}</span>
                {report?.summary?.decision && (
                  <span className={`scan-stage-decision dec-${report.summary.decision}`}>
                    {report.summary.decision}
                  </span>
                )}
              </div>
              <p className="scan-stage-desc">{stage.desc}</p>
              {report?.summary && (
                <div className="scan-stage-stats">
                  <span>{findings} finding{findings === 1 ? "" : "s"}</span>
                  {!isUnknown(risk) && <span>{formatRisk(risk)} risk</span>}
                  {report?.summary && isUnknown(risk) && <span>risk n/a</span>}
                </div>
              )}
              {loading && !report && <span className="scan-stage-loading">Running…</span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}
