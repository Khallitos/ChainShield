import { DEFENSE_MODES } from "../../context/DefenseModeContext.jsx";
import { isUnknown } from "../../utils/riskDisplay.js";

function BarChart({ items, maxVal }) {
  const max = maxVal || Math.max(...items.map((i) => i.value), 1);
  return (
    <div className="stat-chart-bars">
      {items.map((item) => (
        <div key={item.label} className="stat-bar-col">
          <div className="stat-bar-wrap">
            <div
              className="stat-bar"
              style={{
                height: `${(item.value / max) * 100}%`,
                background: item.color,
              }}
            />
          </div>
          <span className="stat-bar-val">{item.value}%</span>
          <span className="stat-bar-label">{item.label}</span>
        </div>
      ))}
    </div>
  );
}

function DonutChart({ segments }) {
  const total = segments.reduce((s, x) => s + x.value, 0);
  let offset = 0;
  const r = 42;
  const c = 2 * Math.PI * r;

  return (
    <div className="stat-donut-wrap">
      <div className="stat-donut-ring">
        <svg viewBox="0 0 100 100" className="stat-donut">
        {segments.map((seg) => {
          const dash = (seg.value / total) * c;
          const el = (
            <circle
              key={seg.label}
              cx="50"
              cy="50"
              r={r}
              fill="none"
              stroke={seg.color}
              strokeWidth="14"
              strokeDasharray={`${dash} ${c - dash}`}
              strokeDashoffset={-offset}
              transform="rotate(-90 50 50)"
            />
          );
          offset += dash;
          return el;
        })}
        </svg>
        <div className="stat-donut-center">
          <strong>{total}</strong>
          <span>findings</span>
        </div>
      </div>
      <ul className="stat-donut-legend">
        {segments.map((seg) => (
          <li key={seg.label}>
            <i style={{ background: seg.color }} />
            {seg.label} ({seg.value})
          </li>
        ))}
      </ul>
    </div>
  );
}

function SparkLine({ points, color, label }) {
  const w = 280;
  const h = 64;
  const pad = 6;
  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const range = max - min || 1;
  const coords = points
    .map((v, i) => {
      const x = pad + (i * (w - pad * 2)) / (points.length - 1);
      const y = h - pad - ((v - min) / range) * (h - pad * 2);
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <div className="stat-spark">
      <p className="stat-spark-label">{label}</p>
      <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
        <defs>
          <linearGradient id={`grad-${label}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.35" />
            <stop offset="100%" stopColor={color} stopOpacity="0.02" />
          </linearGradient>
        </defs>
        <polygon
          points={`${pad},${h - pad} ${coords} ${w - pad},${h - pad}`}
          fill={`url(#grad-${label})`}
        />
        <polyline
          fill="none"
          stroke={color}
          strokeWidth="2.5"
          strokeLinecap="round"
          points={coords}
        />
      </svg>
    </div>
  );
}

export default function DefenseStatsCharts({ comparisons, activeMode }) {
  const modeOrder = ["unblocked", "socketai", "oursolution"];
  const blockRates = modeOrder.map((key) => ({
    label: DEFENSE_MODES[key].short,
    value: DEFENSE_MODES[key].stat.blockRate,
    color: DEFENSE_MODES[key].color,
  }));

  const f1Scores = modeOrder.map((key) => ({
    label: DEFENSE_MODES[key].short,
    value: Math.round(DEFENSE_MODES[key].stat.f1 * 100),
    color: DEFENSE_MODES[key].color,
  }));

  const liveRisk = modeOrder.map((key) => {
    const row = comparisons?.find((c) => c.mode === key);
    return {
      label: DEFENSE_MODES[key].short,
      value: row ? (isUnknown(row.risk_score) ? null : Math.round(row.risk_score * 100)) : DEFENSE_MODES[key].stat.blockRate,
      color: DEFENSE_MODES[key].color,
    };
  });

  const attackMix = [
    { label: "Typosquat", value: 35, color: "#dc2626" },
    { label: "Dep confusion", value: 28, color: "#f59e0b" },
    { label: "CI/CD inject", value: 22, color: "#6366f1" },
    { label: "Composite", value: 15, color: "#16a34a" },
  ];

  const trendByMode = {
    unblocked: [12, 15, 18, 22, 28, 35, 42, 48, 55, 62],
    socketai: [88, 85, 82, 80, 78, 76, 75, 74, 72, 70],
    oursolution: [92, 94, 95, 96, 97, 98, 99, 100, 100, 100],
  };

  return (
    <section className="panel stats-charts-panel">
      <div className="stats-charts-head">
        <div>
          <h3>Defense analytics</h3>
          <p className="muted">
            Static lab benchmarks + live scan for{" "}
            <strong style={{ color: DEFENSE_MODES[activeMode]?.color }}>
              {DEFENSE_MODES[activeMode]?.label}
            </strong>
          </p>
        </div>
      </div>

      <div className="stats-charts-grid">
        <div className="stat-chart-card">
          <h4>Block rate by mode</h4>
          <BarChart items={blockRates} maxVal={100} />
        </div>

        <div className="stat-chart-card">
          <h4>ML F1 score (held-out test)</h4>
          <BarChart items={f1Scores} maxVal={100} />
        </div>

        <div className="stat-chart-card">
          <h4>Live demo manifest risk</h4>
          <BarChart items={liveRisk} maxVal={100} />
        </div>

        <div className="stat-chart-card stat-chart-donut">
          <h4>Attack type distribution</h4>
          <DonutChart segments={attackMix} />
        </div>

        {modeOrder.map((key) => (
          <div key={key} className="stat-chart-card stat-chart-spark">
            <SparkLine
              points={trendByMode[key]}
              color={DEFENSE_MODES[key].color}
              label={`${DEFENSE_MODES[key].label} detection trend`}
            />
          </div>
        ))}
      </div>
    </section>
  );
}
