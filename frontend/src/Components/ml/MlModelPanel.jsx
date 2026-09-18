import { useMlModel } from "../../hooks/useMlModel.js";

function MetricCell({ label, value }) {
  const display = value == null ? "n/a" : typeof value === "number" ? value.toFixed(3) : value;
  return (
    <div className="ml-metric-cell">
      <span className="ml-metric-label">{label}</span>
      <strong className="ml-metric-value">{display}</strong>
    </div>
  );
}

function ArmMetrics({ title, arm }) {
  if (!arm) return null;
  return (
    <div className="ml-split-block">
      <h4>{title}</h4>
      <div className="ml-metrics-row">
        <MetricCell label="Precision" value={arm.precision} />
        <MetricCell label="Recall" value={arm.recall} />
        <MetricCell label="F1" value={arm.f1} />
        <MetricCell label="Accuracy" value={arm.accuracy} />
      </div>
    </div>
  );
}

const pct = (w) => (typeof w === "number" ? `${Math.round(w * 100)}%` : "n/a");

// Published inputs of the evaluation (research/README.md); shown as provenance, not fetched live.
const SOURCES = {
  "benchmark data": "https://doi.org/10.6084/m9.figshare.31869370",
  "content features (SAP)": "https://doi.org/10.1145/3627106.3627138",
  "popular-name reference": "https://github.com/DataDog/guarddog",
};

export default function MlModelPanel({ compact = false }) {
  const { info, metrics, loading, error, reload } = useMlModel();

  if (loading && !info) {
    return (
      <section className={`socket-card ml-model-panel ${compact ? "compact" : ""}`}>
        <p className="ml-loading">Loading ML model info…</p>
      </section>
    );
  }

  if (error && !info) {
    return (
      <section className={`socket-card ml-model-panel ${compact ? "compact" : ""}`}>
        <p className="gh-connect-error">{error}</p>
        <button type="button" className="socket-card-action" onClick={reload}>Retry</button>
      </section>
    );
  }

  const arms = metrics?.test_arms || info?.metrics_summary || {};
  const dataset = metrics?.dataset || info?.dataset_summary;
  const blend = info?.hybrid_blend;
  const cuts = info?.thresholds;

  return (
    <section className={`socket-card ml-model-panel ${compact ? "compact" : ""}`}>
      <header className="ml-model-head">
        <div>
          <h2>{compact ? "ML engine" : "Hybrid ML model"}</h2>
          {!compact && (
            <p className="ml-model-sub">
              {info?.algorithm || "Random forest"} over package-content features, trained on the
              training split of a public npm benchmark (malicious and benign packages from the npm
              registry). Stored as plain arrays: loading it cannot run code.
            </p>
          )}
        </div>
        <span className={`ml-model-badge ${info?.model_loaded ? "loaded" : "missing"}`}>
          {info?.model_version || "no model"}
        </span>
      </header>

      <div className="ml-model-status">
        <span className={`ml-status-dot ${info?.model_loaded ? "on" : "off"}`} />
        <span>
          {info?.model_loaded
            ? "Model loaded and active in hybrid scans"
            : info?.inference_note || "Model not active, so package decisions are held instead of allowed"}
        </span>
      </div>

      {!compact && (
        <div className="ml-blend-row">
          <strong>Hybrid blend:</strong> {pct(blend?.rules_weight)} rules + {pct(blend?.ml_weight)} ML
          {cuts && (
            <>
              <span className="ml-blend-sep">·</span>
              warn ≥ {cuts.warn} · block ≥ {cuts.block}
            </>
          )}
          <span className="ml-blend-sep">·</span>
          <strong>{info?.content_features_count ?? "n/a"}</strong> content features
          <span className="ml-blend-sep">·</span>
          <strong>{info?.policy_version || "n/a"}</strong>
        </div>
      )}

      <div className="ml-splits-grid">
        <ArmMetrics title="Hybrid · warn or block (test set)" arm={arms.hybrid_warn_or_block} />
        {!compact && <ArmMetrics title="Hybrid · block only" arm={arms.hybrid_block} />}
        {!compact && <ArmMetrics title="ML only" arm={arms.ml_only} />}
        {!compact && <ArmMetrics title="Rules only" arm={arms.rules_only_warn_or_block} />}
      </div>

      {!compact && (
        <div className="ml-sources">
          <h4>Evaluation inputs</h4>
          <ul>
            {Object.entries(SOURCES).map(([key, url]) => (
              <li key={key}>
                <span className="ml-source-key">{key}</span>
                <a href={url} target="_blank" rel="noreferrer">{url.replace(/^https?:\/\//, "")}</a>
              </li>
            ))}
          </ul>
        </div>
      )}

      {!compact && dataset && (
        <p className="ml-dataset-counts">
          Dataset: {dataset.train} train · {dataset.test} test · {dataset.malicious} malicious +{" "}
          {dataset.benign} benign package versions
        </p>
      )}

      <footer className="ml-model-foot">
        <button type="button" className="socket-card-action" onClick={reload}>Refresh</button>
        {!compact && info?.evaluation_command && (
          <code className="ml-train-cmd">{info.evaluation_command}</code>
        )}
      </footer>
    </section>
  );
}
