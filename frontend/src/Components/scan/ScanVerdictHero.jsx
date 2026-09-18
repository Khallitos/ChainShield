import { riskPct, decisionTone } from "../../utils/riskDisplay.js";

function RiskRing({ pct, decision }) {
  const r = 42;
  const c = 2 * Math.PI * r;
  const tone = decisionTone(decision);
  // Unknown/HOLD must never render as the success (green) ring.
  const color =
    tone === "block"
      ? "var(--color-critical)"
      : tone === "warn"
        ? "var(--color-medium)"
        : tone === "allow"
          ? "var(--color-success)"
          : "var(--color-muted)";
  const displayPct = pct === null ? 0 : pct;
  const offset = c - (displayPct / 100) * c;

  return (
    <div className="scan-verdict-ring">
      <svg width="104" height="104" viewBox="0 0 104 104">
        <circle cx="52" cy="52" r={r} fill="none" stroke="var(--bg-elevated)" strokeWidth="6" />
        <circle
          cx="52" cy="52" r={r} fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={c} strokeDashoffset={offset}
          strokeLinecap="round" transform="rotate(-90 52 52)"
        />
      </svg>
      <span className="scan-verdict-pct">{pct === null ? "n/a" : pct}</span>
    </div>
  );
}

export default function ScanVerdictHero({ composite, defenseLabel, socketStatus, mlInfo, scanMetadata }) {
  if (!composite) {
    return (
      <section className="scan-verdict-hero socket-card scan-verdict-empty">
        <p>Run a scan to see composite verdict.</p>
      </section>
    );
  }

  const pct = riskPct(composite.risk_score); // null => unknown, never 0
  const decision = composite.decision === "hold"
    ? "HOLD"
    : composite.decision?.toUpperCase() ?? (pct === null ? "UNAVAILABLE" : "n/a");
  const modelVersion =
    scanMetadata?.metadata?.model_version || mlInfo?.model_version || "no model";
  const testF1 = mlInfo?.metrics_summary?.hybrid_warn_or_block?.f1;
  const blend = mlInfo?.hybrid_blend;
  const blendLabel = blend
    ? `${Math.round(blend.rules_weight * 100)}% rules · ${Math.round(blend.ml_weight * 100)}% ML`
    : null;

  return (
    <section className={`scan-verdict-hero socket-card scan-verdict-${composite.decision}`}>
      <div className="scan-verdict-main">
        <div className="scan-verdict-badge-wrap">
          <span className={`scan-verdict-badge dec-${composite.decision}`}>{decision}</span>
          <p className="scan-verdict-sub">Composite verdict · {defenseLabel}</p>
          <p className="scan-verdict-ml">
            <span className="model-tag">{modelVersion}</span>
            {testF1 != null && (
              <span className="scan-verdict-ml-f1">Test F1 {Number(testF1).toFixed(2)}</span>
            )}
            {blendLabel && <span className="scan-verdict-ml-blend">{blendLabel}</span>}
          </p>
        </div>
        <RiskRing pct={pct} decision={composite.decision} />
        <div className="scan-verdict-stats">
          <div className="scan-verdict-stat">
            <strong>{composite.findings_count}</strong>
            <span>Findings</span>
          </div>
          <div className="scan-verdict-stat">
            <strong>{composite.components_scanned}</strong>
            <span>Components</span>
          </div>
          <div className="scan-verdict-stat">
            <strong className={`sev-${composite.severity}`}>{composite.severity}</strong>
            <span>Severity</span>
          </div>
        </div>
      </div>
      <div className="scan-verdict-foot">
        {composite.scan_id && <span>ID · {composite.scan_id}</span>}
        {socketStatus?.configured && socketStatus?.quota && (
          <span>
            Socket quota · {socketStatus.quota.quota}/{socketStatus.quota.maxQuota}
          </span>
        )}
      </div>
    </section>
  );
}
