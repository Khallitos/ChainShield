import { useMemo, useState } from "react";
import { isUnknown, formatRisk } from "../../utils/riskDisplay.js";

// NOTE: the previous hardcoded "campaigns" (e.g. "GemStuffor",
// "Red Hat Cloud Services Package Compromise") were fabricated, no CVE/advisory
// or evidence source backs them. There is no attack-campaign data source in this
// app, so the card renders an explicit "no confirmed data" state instead of an
// invented attribution. Never reintroduce fabricated campaign names here.

const SCORE_CATEGORIES = [
  { key: "overall", label: "Overall" },
  { key: "supply_chain_risk", label: "Supply chain risk" },
  { key: "vulnerability", label: "Vulnerability" },
  { key: "quality", label: "Quality" },
  { key: "maintenance", label: "Maintenance" },
  { key: "license", label: "License" },
];

const ALERT_LEVELS = [
  { label: "Low", key: "low", color: "#52525b" },
  { label: "Medium", key: "medium", color: "#eab308" },
  { label: "High", key: "high", color: "#f97316" },
  { label: "Critical", key: "critical", color: "#ef4444" },
];

const ALERT_FILTERS = [
  { key: "security", label: "Security" },
  { key: "operational", label: "Operational" },
  { key: "legal", label: "Legal" },
];

function VulnFunnelChart({ stages }) {
  const w = 520;
  const h = 130;
  const cols = stages.length;
  const colW = w / cols;

  return (
    <div className="vuln-funnel">
      <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" aria-hidden>
        <defs>
          <linearGradient id="vulnRed" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#ef4444" stopOpacity="1" />
            <stop offset="100%" stopColor="#ef4444" stopOpacity="0.55" />
          </linearGradient>
        </defs>
        {stages.map((stage, i) => {
          const t = stages[0].value || 1;
          const topPct = Math.max(0.12, stage.value / t);
          const next = stages[i + 1];
          const botPct = next ? Math.max(0.06, next.value / t) : Math.max(0.04, stage.value / t * 0.15);
          const x0 = i * colW;
          const x1 = (i + 1) * colW;
          const yTop = 18;
          const yBot = h - 14;
          const topH = (yBot - yTop) * topPct;
          const botH = (yBot - yTop) * botPct;
          const fill = i === 0 ? "url(#vulnRed)" : i === 1 ? "#f97316" : i === 2 ? "#eab308" : "#3f3f46";
          return (
            <polygon
              key={stage.label}
              points={`${x0},${yTop + (yBot - yTop - topH) / 2} ${x1},${yTop + (yBot - yTop - botH) / 2} ${x1},${yTop + (yBot - yTop + botH) / 2} ${x0},${yTop + (yBot - yTop + topH) / 2}`}
              fill={fill}
              opacity={i === 0 ? 1 : 0.85 - i * 0.08}
            />
          );
        })}
        {stages.map((_, i) => (
          <line
            key={`grid-${i}`}
            x1={(i + 1) * colW}
            y1={0}
            x2={(i + 1) * colW}
            y2={h}
            stroke="#27272a"
            strokeWidth="1"
          />
        ))}
      </svg>
    </div>
  );
}

function formatDepCount(n) {
  return Number(n || 0).toLocaleString("en-US").replace(/,/g, " ");
}

function PackageScoresChart({ chartData, loading }) {
  const yMax = chartData?.y_max ?? chartData?.total ?? 1;
  const yMid = chartData?.y_mid ?? Math.round(yMax / 2);
  const bars = chartData?.bars || [];
  const chartHeight = 160;

  if (loading) {
    return <p className="overview-chart-loading">Loading scores…</p>;
  }

  if (!bars.length) {
    return <p className="overview-chart-empty">No dependency score data.</p>;
  }

  return (
    <div className="score-chart-panel">
      <div className="score-bars-wrap">
        <div className="score-bars" style={{ height: chartHeight }}>
          {bars.map((bar) => {
            const h = yMax > 0 ? Math.max(bar.count > 0 ? 8 : 2, (bar.count / yMax) * chartHeight) : 2;
            return (
              <div
                key={bar.id}
                className="score-bar-col"
                title={`${bar.label}: ${bar.count.toLocaleString()} packages`}
              >
                <div
                  className="score-bar"
                  style={{ height: h, backgroundColor: bar.color }}
                />
              </div>
            );
          })}
        </div>
        <div className="score-y-axis" style={{ height: chartHeight }}>
          <span>{formatDepCount(yMax)}</span>
          <span>{formatDepCount(yMid)}</span>
          <span>0</span>
        </div>
      </div>
    </div>
  );
}

function EcosystemChart({ ecosystems, loading }) {
  const maxCount = Math.max(...(ecosystems || []).map((e) => e.count), 1);

  if (loading) {
    return <p className="overview-chart-loading">Loading ecosystems…</p>;
  }

  if (!ecosystems?.length) {
    return <p className="overview-chart-empty">No ecosystem data.</p>;
  }

  return (
    <div className="eco-chart">
      <div className="eco-axis">
        <span>0</span>
        <span>{Math.round(maxCount / 2).toLocaleString()}</span>
        <span>{maxCount.toLocaleString()}</span>
      </div>
      {ecosystems.map((eco) => {
        const pct = maxCount > 0 ? Math.max(4, (eco.count / maxCount) * 100) : 0;
        return (
          <div key={eco.id} className="h-bar-row h-bar-row--eco">
            <span className="h-bar-label">{eco.label}</span>
            <div className="h-bar-track h-bar-track--eco">
              <div className="h-bar-fill h-bar-fill--eco" style={{ width: `${pct}%` }} />
            </div>
            <span className="h-bar-val">{eco.count.toLocaleString()}</span>
          </div>
        );
      })}
    </div>
  );
}

function AlertsGauge({ alerts, loading, onReview }) {
  const [filters, setFilters] = useState({ security: true, operational: true, legal: true });

  const bySeverity = alerts?.by_severity || { low: 0, medium: 0, high: 0, critical: 0 };
  const byCategory = alerts?.by_category || { security: 0, operational: 0, legal: 0 };

  const filteredTotal = useMemo(() => {
    return ALERT_FILTERS.reduce((sum, f) => {
      if (!filters[f.key]) return sum;
      return sum + (byCategory[f.key] || 0);
    }, 0);
  }, [byCategory, filters]);

  const displayTotal = filteredTotal || alerts?.total || 0;

  const counts = ALERT_LEVELS.map((l) => ({
    ...l,
    count: bySeverity[l.key] || 0,
  }));

  const r = 100;
  const cx = 140;
  const cy = 120;

  let segments;
  if (displayTotal === 0) {
    segments = ALERT_LEVELS.map((l) => ({ color: l.color, pct: 0.25 }));
  } else {
    const raw = counts.map((c) => ({
      color: c.color,
      pct: c.count > 0 ? Math.max(c.count / displayTotal, 0.06) : 0,
    }));
    const sum = raw.reduce((s, x) => s + x.pct, 0) || 1;
    segments = raw.map((c) => ({ color: c.color, pct: c.pct / sum }));
  }

  let angle = 180;
  const arcs = segments.map((seg, i) => {
    const sweep = seg.pct * 180;
    const start = angle;
    angle -= sweep;
    const startRad = (start * Math.PI) / 180;
    const endRad = ((start - sweep) * Math.PI) / 180;
    const x1 = cx + r * Math.cos(startRad);
    const y1 = cy + r * Math.sin(startRad);
    const x2 = cx + r * Math.cos(endRad);
    const y2 = cy + r * Math.sin(endRad);
    const large = sweep > 90 ? 1 : 0;
    return (
      <path
        key={i}
        d={`M ${x1} ${y1} A ${r} ${r} 0 ${large} 0 ${x2} ${y2}`}
        fill="none"
        stroke={seg.color}
        strokeWidth="14"
        strokeLinecap="butt"
      />
    );
  });

  if (loading) {
    return <p className="overview-chart-loading">Loading alerts…</p>;
  }

  return (
    <div className="alerts-gauge-wrap">
      <div className="severity-legend">
        {counts.map((s) => (
          <div key={s.label} className="severity-legend-item">
            <span className="sev-swatch" style={{ background: s.color }} />
            {s.label} ({s.count})
          </div>
        ))}
      </div>

      <div className="alerts-gauge">
        <svg viewBox="0 0 280 160">{arcs}</svg>
        <div className="alerts-gauge-center">
          <strong>{displayTotal}</strong>
          <button type="button" onClick={onReview}>
            Review alerts
          </button>
        </div>
      </div>

      <div className="alert-filters">
        {ALERT_FILTERS.map((f) => (
          <label key={f.key} className="alert-filter-item">
            <input
              type="checkbox"
              checked={Boolean(filters[f.key])}
              onChange={(e) => setFilters((prev) => ({ ...prev, [f.key]: e.target.checked }))}
            />
            {f.label} ({byCategory[f.key] || 0})
          </label>
        ))}
      </div>
    </div>
  );
}

export default function SocketOverviewLayout({
  blockingEnabled,
  protectionLabel,
  loading,
  overviewData,
  overviewLoading,
  manifestReport,
  workflowReport,
  sbomReport,
  composite,
  socketStatus,
  allFindings = [],
  lastRunAt,
  onNavigate,
  onReviewAlerts,
  demo = false,
}) {
  const [scoreCategory, setScoreCategory] = useState("maintenance");

  const findings = allFindings.length
    ? allFindings
    : [
        ...(manifestReport?.findings || []),
        ...(workflowReport?.findings || []),
        ...(sbomReport?.findings || []),
      ];

  const totalFindings = findings.length || composite?.findings_count || 0;
  const depTotal = overviewData?.dependencies?.total ?? manifestReport?.summary?.components_scanned ?? 0;
  const decision = composite?.decision || manifestReport?.summary?.decision;
  const liveRisk = composite?.risk_score ?? manifestReport?.summary?.risk_score ?? null;

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const manifestCount = findings.filter((f) => (f.scan_layer || "manifest") === "manifest").length;
  const reachableCount = findings.filter((f) => f.severity === "high" || f.severity === "critical").length;
  const fixableCount = decision === "block" ? criticalCount + highCount : highCount;

  const funnelStages = useMemo(
    () => [
      { label: "Total", value: Math.max(totalFindings, 1) },
      { label: "Reachable", value: reachableCount },
      { label: "Production", value: manifestCount },
      { label: "Critical", value: criticalCount },
      { label: "Fixable", value: fixableCount },
    ],
    [totalFindings, reachableCount, manifestCount, criticalCount, fixableCount]
  );

  const scoreChart = overviewData?.dependencies?.score_histograms?.[scoreCategory] || null;
  const ecosystems = overviewData?.dependencies?.ecosystems || [];
  const alerts = overviewData?.alerts;

  return (
    <div className="socket-overview page-shell">
      {(loading || overviewLoading) && (
        <div className="loading-bar">
          <span />
        </div>
      )}

      {blockingEnabled !== undefined && (
        <p className={`mode-banner protection-banner ${blockingEnabled ? "on" : "off"} socket-overview-banner`}>
          {protectionLabel}
          {manifestReport && (
            <>
              {" "}
              · Decision: <strong>{decision?.toUpperCase() || "n/a"}</strong> · Risk {isUnknown(liveRisk) ? "n/a" : formatRisk(liveRisk)}
            </>
          )}
          {lastRunAt && (
            <>
              {" "}
              · Last scan{" "}
              {lastRunAt.toLocaleString(undefined, {
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit",
              })}
            </>
          )}
          {overviewData?.dependencies?.cached && <> · Inventory cached</>}
          {demo && (
            <> · <span className="demo-badge">DEMO DATA: illustrative, not a verified scan</span></>
          )}
          {socketStatus?.configured && (
            <>
              {" "}
              · Socket API · {socketStatus.quota?.quota}/{socketStatus.quota?.maxQuota}
            </>
          )}
        </p>
      )}

      <div className="socket-grid-2">
        <div className="socket-card socket-card--vuln">
          <div className="socket-card-title-row">
            <h3>
              <span className="socket-card-icon" aria-hidden>
                ◎
              </span>
              Vulnerabilities
            </h3>
          </div>
          <div className="metric-pills metric-pills--vuln">
            <div className="metric-pill">
              <span className="metric-pill-value">{totalFindings}</span>
              <span className="metric-pill-label">Findings</span>
            </div>
            <div className="metric-pill">
              <span className="metric-pill-value">{reachableCount}</span>
              <span className="metric-pill-label">Possibly reachable</span>
            </div>
            <div className="metric-pill">
              <span className="metric-pill-value">{manifestCount}</span>
              <span className="metric-pill-label">Production</span>
            </div>
            <div className="metric-pill">
              <span className="metric-pill-value">{criticalCount}</span>
              <span className="metric-pill-label">Critical</span>
            </div>
            <div className="metric-pill">
              <span className="metric-pill-value">{fixableCount}</span>
              <span className="metric-pill-label">Fixable</span>
            </div>
          </div>
          <VulnFunnelChart stages={funnelStages} />
          <div className="socket-card-foot">
            <button type="button" className="socket-card-link" onClick={() => onNavigate?.("scan")}>
              Explore findings
            </button>
          </div>
        </div>

        <div className="socket-card socket-card--campaigns">
          <div className="socket-card-title-row">
            <h3>
              <span className="socket-card-icon" aria-hidden>
                ⛨
              </span>
              Attack campaigns
            </h3>
          </div>
          <ul className="campaign-list campaign-list--simple">
            <li className="campaign-empty">
              No confirmed attack-campaign data. Attribution requires an advisory or evidence source.
            </li>
          </ul>
        </div>
      </div>

      <section className="deps-block">
        <div className="deps-section-head">
          <span className="deps-icon" aria-hidden>
            ◈
          </span>
          <h2>{formatDepCount(depTotal)} dependencies</h2>
        </div>
        <div className="socket-card socket-card--deps">
          <div className="deps-inner-grid">
            <div className="deps-panel deps-panel--scores">
              <h4 className="deps-panel-title deps-panel-title--center">By package scores</h4>
              <div className="package-scores-layout">
                <fieldset className="score-legend" aria-label="Score category">
                  {SCORE_CATEGORIES.map((cat) => (
                    <label
                      key={cat.key}
                      className={`score-legend-item ${scoreCategory === cat.key ? "active" : ""}`}
                    >
                      <input
                        type="radio"
                        name="score-category"
                        value={cat.key}
                        checked={scoreCategory === cat.key}
                        onChange={() => setScoreCategory(cat.key)}
                      />
                      <span className="score-radio-ui" aria-hidden />
                      {cat.label}
                    </label>
                  ))}
                </fieldset>
                <PackageScoresChart chartData={scoreChart} loading={overviewLoading} />
              </div>
            </div>

            <div className="deps-panel deps-panel--eco">
              <h4 className="deps-panel-title">By ecosystem</h4>
              <EcosystemChart ecosystems={ecosystems} loading={overviewLoading} />
            </div>
          </div>
          <div className="socket-card-foot">
            <button type="button" className="socket-card-link" onClick={() => onNavigate?.("dependencies")}>
              Explore dependencies
            </button>
          </div>
        </div>
      </section>

      <section className="socket-card alerts-card">
        <div className="socket-card-title-row">
          <h3>
            <span className="socket-card-icon" aria-hidden>
              ⚠
            </span>
            Alerts
          </h3>
        </div>
        <AlertsGauge
          alerts={alerts}
          loading={overviewLoading}
          onReview={onReviewAlerts}
        />
      </section>
    </div>
  );
}
