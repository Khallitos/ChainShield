// Not routed: kept for reference only.
// This is a legacy, unreachable demo dashboard. It is NOT routed anywhere in the
// active app: DashboardShell renders SiemDashboard ("overview"), ScanPage,
// SettingsPage, RepositoriesPage, DependenciesPage, PackageDetailPage and
// BlockDetailPage, never DashboardPage/SsiemDashboard. It contains large blocks
// of hardcoded ILLUSTRATIVE/"dummy" security numbers (block rates, severity
// series, triage items) that are NOT backed by any scan or evidence and MUST NOT
// be treated as real. It is kept only as dead reference; do not wire it into a
// route, and do not present any of its "dummy" numbers as verified facts.
import Sidebar from "../Components/layout/Sidebar.jsx";
import { BarChart } from "@mui/x-charts/BarChart";
import { LineChart } from "@mui/x-charts/LineChart";
import { PieChart } from "@mui/x-charts/PieChart";
import { ScatterChart } from "@mui/x-charts/ScatterChart";
import { useEffect, useMemo, useState } from "react";
import { decodeNote, encodeNote } from "../UTILS/shareLink.js";

const chartColors = {
  typosquat: "#cf5f34",
  depConf: "#d7a638",
  ciInject: "#2f3db0",
  clean: "#67b281",
  neutral: "#8b93b3"
};

const dummy = {
  eventsByAttack: [
    { label: "Typosquat", value: 18, color: chartColors.typosquat },
    { label: "Dep. Conf.", value: 11, color: chartColors.depConf },
    { label: "CI Inject.", value: 5, color: chartColors.ciInject },
    { label: "Clean", value: 22, color: chartColors.clean }
  ],
  histogramBins: [
    { label: "0-1", value: 2, color: "#dfe2eb" },
    { label: "2-3", value: 3, color: "#d7a638" },
    { label: "4-5", value: 5, color: "#cf5f34" },
    { label: "6-7", value: 9, color: "#2f3db0" },
    { label: "8-9", value: 6, color: "#67b281" },
    { label: "10+", value: 4, color: "#8b93b3" }
  ],
  severitySeries: [
    { label: "Critical", color: "#e2545b", values: [2, 3, 4, 2, 3, 5, 4, 4, 3, 2] },
    { label: "Warn", color: "#e5b53d", values: [4, 5, 6, 5, 7, 6, 7, 8, 6, 5] },
    { label: "Safe", color: "#5fb67b", values: [8, 7, 6, 7, 5, 6, 4, 5, 7, 8] }
  ],
  defenceBlockRate: [
    { label: "DEF1", value: 96, color: chartColors.clean },
    { label: "DEF2", value: 80, color: chartColors.depConf },
    { label: "DEF3", value: 95, color: chartColors.ciInject }
  ]
};

function maxOf(arr) {
  return arr.reduce((m, x) => (x > m ? x : m), 0);
}

function Legend({ items }) {
  return (
    <div className="chart-legend">
      {items.map((it) => (
        <span key={it.label} className="legend-item">
          <i style={{ background: it.color }} />
          {it.label}
        </span>
      ))}
    </div>
  );
}

function SvgLineChart({ series }) {
  const width = 620;
  const height = 180;
  const padX = 24;
  const padY = 18;
  const maxY = maxOf(series.flatMap((s) => s.values));
  const points = (values) =>
    values
      .map((v, i) => {
        const x = padX + (i * (width - padX * 2)) / (values.length - 1);
        const y = height - padY - (v * (height - padY * 2)) / (maxY || 1);
        return [x, y];
      })
      .map((p) => p.join(","))
      .join(" ");

  return (
    <svg className="chart-svg" viewBox={`0 0 ${width} ${height}`} role="img">
      <defs>
        <linearGradient id="gridFade" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0" stopColor="rgba(47,61,176,0.08)" />
          <stop offset="1" stopColor="rgba(207,95,52,0.04)" />
        </linearGradient>
      </defs>
      <rect x="0" y="0" width={width} height={height} fill="url(#gridFade)" rx="12" />
      {[0.25, 0.5, 0.75].map((t) => (
        <line
          key={t}
          x1={padX}
          x2={width - padX}
          y1={padY + t * (height - padY * 2)}
          y2={padY + t * (height - padY * 2)}
          stroke="rgba(43,47,68,0.08)"
          strokeWidth="1"
        />
      ))}
      {series.map((s) => (
        <g key={s.label}>
          <polyline
            fill="none"
            stroke={s.color}
            strokeWidth="3"
            strokeLinecap="round"
            strokeLinejoin="round"
            points={points(s.values)}
          />
          {s.values.map((v, i) => {
            const x = padX + (i * (width - padX * 2)) / (s.values.length - 1);
            const y = height - padY - (v * (height - padY * 2)) / (maxY || 1);
            return <circle key={i} cx={x} cy={y} r="3.5" fill={s.color} stroke="#fff" strokeWidth="2" />;
          })}
        </g>
      ))}
    </svg>
  );
}

function SvgDottedChart({ series }) {
  const width = 620;
  const height = 180;
  const padX = 24;
  const padY = 18;
  const maxY = maxOf(series.flatMap((s) => s.values));
  return (
    <svg className="chart-svg" viewBox={`0 0 ${width} ${height}`} role="img">
      <rect x="0" y="0" width={width} height={height} fill="rgba(250,251,254,1)" rx="12" />
      {[0.25, 0.5, 0.75].map((t) => (
        <line
          key={t}
          x1={padX}
          x2={width - padX}
          y1={padY + t * (height - padY * 2)}
          y2={padY + t * (height - padY * 2)}
          stroke="rgba(43,47,68,0.08)"
          strokeWidth="1"
        />
      ))}
      {series.map((s, si) => (
        <g key={s.label}>
          {s.values.map((v, i) => {
            const x = padX + (i * (width - padX * 2)) / (s.values.length - 1);
            const y = height - padY - (v * (height - padY * 2)) / (maxY || 1);
            return (
              <circle
                key={`${si}-${i}`}
                cx={x}
                cy={y}
                r="4"
                fill={s.color}
                opacity="0.9"
                stroke="#fff"
                strokeWidth="2"
              />
            );
          })}
        </g>
      ))}
    </svg>
  );
}

function GraphViz({ selectedGraph, chartType, graphTitle }) {
  const categorySource = useMemo(() => {
    if (selectedGraph === "eventsByAttack") return dummy.eventsByAttack;
    if (selectedGraph === "blockRateByDefence") return dummy.defenceBlockRate;
    return [
      {
        label: "Critical",
        value: dummy.severitySeries[0].values.reduce((a, b) => a + b, 0),
        color: dummy.severitySeries[0].color
      },
      {
        label: "Warn",
        value: dummy.severitySeries[1].values.reduce((a, b) => a + b, 0),
        color: dummy.severitySeries[1].color
      },
      {
        label: "Safe",
        value: dummy.severitySeries[2].values.reduce((a, b) => a + b, 0),
        color: dummy.severitySeries[2].color
      }
    ];
  }, [selectedGraph]);

  const labels = categorySource.map((d) => d.label);
  const values = categorySource.map((d) => d.value);
  const maxValue = Math.max(...values, 1);

  const histogram = useMemo(() => {
    const bins = [
      { min: 0, max: 20, label: "0-20", count: 0 },
      { min: 20, max: 40, label: "20-40", count: 0 },
      { min: 40, max: 60, label: "40-60", count: 0 },
      { min: 60, max: 80, label: "60-80", count: 0 },
      { min: 80, max: 100, label: "80-100", count: 0 }
    ];
    values.forEach((v) => {
      const idx = v >= 100 ? bins.length - 1 : Math.floor(v / 20);
      bins[Math.max(0, Math.min(idx, bins.length - 1))].count += 1;
    });
    return bins;
  }, [values]);

  return (
    <div className="graph-frame" role="img" aria-label={graphTitle}>
      <div className="graph-title">{graphTitle}</div>
      <div className="graph-placeholder graph-mui">
        {chartType === "bar" ? (
          <div className="chart-block">
            <Legend items={categorySource.map((d) => ({ label: d.label, color: d.color }))} />
            <BarChart
              height={320}
              borderRadius={10}
              skipAnimation
              series={[{ data: values, label: "Value" }]}
              xAxis={[
                {
                  scaleType: "band",
                  data: labels,
                  categoryGapRatio: 0.25,
                  barGapRatio: 0.1
                }
              ]}
              yAxis={[
                {
                  min: 0,
                  max: Math.max(100, maxValue),
                  colorMap: {
                    type: "piecewise",
                    thresholds: [maxValue * 0.35, maxValue * 0.65, maxValue * 0.85],
                    colors: ["#cf5f34", "#d7a638", "#2f3db0", "#67b281"]
                  }
                }
              ]}
            />
          </div>
        ) : null}

        {chartType === "histogram" ? (
          <div className="chart-block">
            <Legend items={histogram.map((b, idx) => ({ label: b.label, color: ["#dfe2eb", "#d7a638", "#cf5f34", "#2f3db0", "#67b281"][idx] }))} />
            <BarChart
              height={320}
              borderRadius={10}
              skipAnimation
              series={[{ data: histogram.map((b) => b.count), label: "Frequency" }]}
              xAxis={[
                {
                  scaleType: "band",
                  data: histogram.map((b) => b.label)
                }
              ]}
              yAxis={[
                {
                  min: 0,
                  max: Math.max(3, ...histogram.map((b) => b.count)),
                  colorMap: {
                    type: "piecewise",
                    thresholds: [1, 2, 3],
                    colors: ["#dfe2eb", "#d7a638", "#cf5f34", "#2f3db0"]
                  }
                }
              ]}
            />
          </div>
        ) : null}

        {chartType === "line" ? (
          <div className="chart-block">
            <Legend items={selectedGraph === "severityOverTime" ? dummy.severitySeries.map((s) => ({ label: s.label, color: s.color })) : categorySource.map((d) => ({ label: d.label, color: d.color }))} />
            <LineChart
              height={320}
              skipAnimation
              series={
                selectedGraph === "severityOverTime"
                  ? dummy.severitySeries.map((s) => ({ data: s.values, label: s.label, color: s.color }))
                  : [{ data: values, label: graphTitle, color: "#2f3db0" }]
              }
              xAxis={[
                {
                  data:
                    selectedGraph === "severityOverTime"
                      ? dummy.severitySeries[0].values.map((_, i) => i)
                      : labels,
                  scaleType: selectedGraph === "severityOverTime" ? "point" : "point"
                }
              ]}
              yAxis={[{ min: 0, max: Math.max(100, maxValue) }]}
            />
          </div>
        ) : null}

        {chartType === "dottedLine" ? (
          <div className="chart-block">
            <Legend items={selectedGraph === "severityOverTime" ? dummy.severitySeries.map((s) => ({ label: s.label, color: s.color })) : categorySource.map((d) => ({ label: d.label, color: d.color }))} />
            <LineChart
              height={320}
              skipAnimation
              series={
                selectedGraph === "severityOverTime"
                  ? dummy.severitySeries.map((s) => ({ data: s.values, label: s.label, color: s.color }))
                  : [{ data: values, label: graphTitle, color: "#2f3db0" }]
              }
              xAxis={[
                {
                  data:
                    selectedGraph === "severityOverTime"
                      ? dummy.severitySeries[0].values.map((_, i) => i)
                      : labels,
                  scaleType: "point"
                }
              ]}
              yAxis={[{ min: 0, max: Math.max(100, maxValue) }]}
              sx={{ "& .MuiLineElement-root": { strokeDasharray: "6 6", strokeWidth: 3 } }}
            />
          </div>
        ) : null}

        {chartType === "pie" ? (
          <div className="chart-block">
            <Legend items={categorySource.map((d) => ({ label: d.label, color: d.color }))} />
            <PieChart
              height={340}
              series={[
                {
                  data: categorySource.map((d, i) => ({
                    id: i,
                    value: d.value,
                    label: d.label,
                    color: d.color
                  })),
                  innerRadius: 40,
                  outerRadius: 80,
                  arcLabel: (item) => `${item.value}`,
                  arcLabelMinAngle: 20
                }
              ]}
              slotProps={{ legend: { hidden: true } }}
            />
          </div>
        ) : null}

        {chartType === "scatter" ? (
          <div className="chart-block">
            <Legend items={categorySource.map((d) => ({ label: d.label, color: d.color }))} />
            <ScatterChart
              height={340}
              series={[
                {
                  data: categorySource.map((d, i) => ({
                    x: i + 1,
                    y: d.value,
                    id: i
                  }))
                }
              ]}
              xAxis={[{ min: 0, max: categorySource.length + 1 }]}
              yAxis={[{ min: 0, max: Math.max(100, maxValue) }]}
            />
          </div>
        ) : null}
      </div>
    </div>
  );
}

function SharedGraphOnlyView() {
  const params = new URLSearchParams(window.location.search);
  const selectedGraph = params.get("graph") || "eventsByAttack";
  const chartType = params.get("chart") || "bar";
  const notes = decodeNote(params.get("note"));

  const graphTitle = useMemo(() => {
    switch (selectedGraph) {
      case "eventsByAttack":
        return "Events by attack type";
      case "blockRateByDefence":
        return "Block rate by defence tool";
      case "severityOverTime":
        return "Severity over time";
      default:
        return "Graph";
    }
  }, [selectedGraph]);

  return (
    <main className="share-only">
      <div className="share-only-inner">
        <GraphViz selectedGraph={selectedGraph} chartType={chartType} graphTitle={graphTitle} />

        <section className="notes-card">
          <div className="notes-head">
            <h3>Notes</h3>
            <p>Shared notes</p>
          </div>
          <div className="notes-readonly">{notes || "No notes provided."}</div>
        </section>
      </div>
    </main>
  );
}

const kpiTemplates = [
  { key: "total", title: "TOTAL EVENTS", value: 253, sub: "+4 / min" },
  { key: "blocked", title: "ATTACKS BLOCKED", value: 36, sub: "91.2% block rate", positive: true },
  { key: "missed", title: "MISSED (SLIPPED THROUGH)", value: 4, sub: "ATK2 ×2, ATK3 ×1", danger: true },
  { key: "triage", title: "PENDING TRIAGE", value: 7, sub: "2 critical unreviewed" }
];

const eventFeed = [
  {
    id: "EV-1001",
    severity: "critical",
    title: "internal-utils==9.9.9",
    tag: "dep confusion",
    detail: "Resolved from public registry · DEF2 blocked · 12:04:51",
    source: "PyPI mirror",
    module: "SafePip",
    confidence: "High (0.94)",
    recommendation: "Pin private index URL and enforce signed package policy."
  },
  {
    id: "EV-1002",
    severity: "warn",
    title: "requests==2.31.0",
    tag: "typosquat",
    detail: "Levenshtein=1 vs 'requests' · DEF1 blocked · 12:04:49",
    source: "Dependency resolver",
    module: "Name Checker",
    confidence: "Medium (0.81)",
    recommendation: "Enable allowlist mode for top 100 internal packages."
  },
  {
    id: "EV-1003",
    severity: "critical",
    title: ".github/workflows/build.yml",
    tag: "ci injection",
    detail: "Unpinned action ref · uses@main · DEF3 flagged · 12:04:44",
    source: "CI pipeline scanner",
    module: "Provenance Verifier",
    confidence: "High (0.97)",
    recommendation: "Pin action to commit SHA and enforce branch protection."
  },
  {
    id: "EV-1004",
    severity: "safe",
    title: "numpy==1.26.4",
    tag: "clean install",
    detail: "Hash verified · provenance logged · 12:04:40",
    source: "Package verification",
    module: "Provenance Verifier",
    confidence: "Verified",
    recommendation: "No action required. Keep monitoring."
  }
];

const triageItems = [
  { title: "internal-utils dep confusion", id: "ALT-0041 · Critical" },
  { title: "build.yml uses@main", id: "ALT-0040 · High" },
  { title: "crypt0 homoglyph", id: "ALT-0039 · High" }
];

function SsiemDashboard() {
  const [eventPanelView, setEventPanelView] = useState("feed"); // "feed" | "graphs"
  const [selectedGraph, setSelectedGraph] = useState("eventsByAttack");
  const [chartType, setChartType] = useState("bar"); // bar | histogram | dottedLine | line
  const [notes, setNotes] = useState("");
  const [copied, setCopied] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [secondsSinceUpdate, setSecondsSinceUpdate] = useState(0);
  const [kpiState, setKpiState] = useState(
    kpiTemplates.map((k) => ({
      ...k,
      delta: 0
    }))
  );

  const graphTitle = useMemo(() => {
    switch (selectedGraph) {
      case "eventsByAttack":
        return "Events by attack type";
      case "blockRateByDefence":
        return "Block rate by defence tool";
      case "severityOverTime":
        return "Severity over time";
      default:
        return "Graph";
    }
  }, [selectedGraph]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const view = params.get("evView");
    const graph = params.get("graph");
    const type = params.get("chart");
    const note = params.get("note");

    if (view === "graphs" || view === "feed") setEventPanelView(view);
    if (graph) setSelectedGraph(graph);
    if (type) setChartType(type);
    if (note) setNotes(decodeNote(note));
  }, []);

  useEffect(() => {
    const secTimer = window.setInterval(() => {
      setSecondsSinceUpdate((s) => Math.min(999, s + 1));
    }, 1000);

    const dataTimer = window.setInterval(() => {
      setKpiState((prev) =>
        prev.map((item) => {
          const rangeByKey = {
            total: [-1, 5],
            blocked: [-1, 2],
            missed: [-1, 1],
            triage: [-1, 2]
          };
          const [min, max] = rangeByKey[item.key] || [0, 0];
          const delta = Math.floor(Math.random() * (max - min + 1)) + min;
          return {
            ...item,
            value: Math.max(0, item.value + delta),
            delta
          };
        })
      );
      setSecondsSinceUpdate(0);
    }, 7000);

    return () => {
      window.clearInterval(secTimer);
      window.clearInterval(dataTimer);
    };
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    params.set("evView", eventPanelView);
    params.set("graph", selectedGraph);
    params.set("chart", chartType);
    const encoded = encodeNote(notes.trim());
    if (encoded) params.set("note", encoded);
    else params.delete("note");
    const next = `${window.location.pathname}?${params.toString()}`;
    window.history.replaceState({}, "", next);
  }, [eventPanelView, selectedGraph, chartType, notes]);

  async function copyShareLink() {
    try {
      const url = new URL(window.location.href);
      url.searchParams.set("share", "1");
      url.searchParams.set("evView", "graphs");
      await navigator.clipboard.writeText(url.toString());
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // no-op (clipboard may be blocked)
    }
  }

  return (
    <section className="siem">
      <article className="card threat-story-card">
        <div>
          <h2>Threat Story</h2>
          <p>
            Last 5 minutes: dependency confusion attempts are leading risk. DEF2 blocks most attempts,
            but CI injection remains the highest severity vector.
          </p>
        </div>
        <div className="live-status">
          <span className="pulse-dot" aria-hidden="true" />
          <span>Last updated {secondsSinceUpdate}s ago</span>
        </div>
      </article>

      <div className="kpi-grid">
        {kpiState.map((kpi) => (
          <article key={kpi.title} className="card kpi-card">
            <p>{kpi.title}</p>
            <h3 className={kpi.danger ? "danger" : ""}>{kpi.value}</h3>
            <div className="kpi-meta">
              <small className={kpi.positive ? "positive" : ""}>{kpi.sub}</small>
              <span className={`kpi-delta ${kpi.delta >= 0 ? "up" : "down"}`}>
                {kpi.delta >= 0 ? "+" : ""}
                {kpi.delta}
              </span>
            </div>
          </article>
        ))}
      </div>

      <div className="siem-mid">
        <article className="card event-card">
          <header>
            <div className="event-header-left">
              <h2>Live event feed</h2>
              <span className="chip live">
                <span className="live-dot" aria-hidden="true" />
                live
              </span>
            </div>

            <div className="event-header-right">
              <div className="segmented" role="tablist" aria-label="Event panel view">
                <button
                  type="button"
                  className={eventPanelView === "feed" ? "active" : ""}
                  onClick={() => setEventPanelView("feed")}
                  role="tab"
                  aria-selected={eventPanelView === "feed"}
                >
                  Feed
                </button>
                <button
                  type="button"
                  className={eventPanelView === "graphs" ? "active" : ""}
                  onClick={() => setEventPanelView("graphs")}
                  role="tab"
                  aria-selected={eventPanelView === "graphs"}
                >
                  Graphs
                </button>
              </div>
            </div>
          </header>

          {eventPanelView === "feed" ? (
            eventFeed.map((item) => (
              <div
                key={item.id}
                className="event-row clickable"
                onClick={() => setSelectedIncident(item)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") setSelectedIncident(item);
                }}
              >
                <span className={`dot ${item.severity}`} />
                <div>
                  <h4>
                    {item.title} <span>{item.tag}</span>
                  </h4>
                  <p>{item.detail}</p>
                </div>
              </div>
            ))
          ) : (
            <div className="event-graphs">
              <div className="graph-controls">
                <label>
                  Graph
                  <select
                    value={selectedGraph}
                    onChange={(e) => setSelectedGraph(e.target.value)}
                  >
                    <option value="eventsByAttack">Events by attack type</option>
                    <option value="blockRateByDefence">Block rate by defence tool</option>
                    <option value="severityOverTime">Severity over time</option>
                  </select>
                </label>

                <label>
                  Chart type
                  <select value={chartType} onChange={(e) => setChartType(e.target.value)}>
                    <option value="bar">Bar chart</option>
                    <option value="histogram">Histogram</option>
                    <option value="dottedLine">Dotted line</option>
                    <option value="line">Line graph</option>
                    <option value="pie">Pie chart</option>
                    <option value="scatter">Scatter chart</option>
                  </select>
                </label>

                <button type="button" className="share-btn" onClick={copyShareLink}>
                  {copied ? "Copied" : "Share link"}
                </button>
              </div>

              <GraphViz selectedGraph={selectedGraph} chartType={chartType} graphTitle={graphTitle} />

              <div className="notes-card">
                <div className="notes-head">
                  <h3>Notes</h3>
                  <p>These notes are included in the share link.</p>
                </div>
                <textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Add notes for the senior department (context, why it matters, what to do next)..."
                />
              </div>
            </div>
          )}
        </article>

        <div className="right-stack">
          <article className="card">
            <header>
              <h2>Module health</h2>
              <span className="chip success">3 / 3 up</span>
            </header>
            <div className="module-row">
              <p>DEF1 name checker</p>
              <small>online · 0ms lag</small>
            </div>
            <div className="module-row">
              <p>DEF2 SafePip</p>
              <small>online · 12ms lag</small>
            </div>
            <div className="module-row">
              <p>DEF3 provenance</p>
              <small>warn · 340ms lag</small>
            </div>
          </article>

          <article className="card">
            <h2>Defence block rates</h2>
            <div className="gauge-row">
              <div className="gauge">
                <div className="ring">96%</div>
                <small>DEF1</small>
              </div>
              <div className="gauge warn">
                <div className="ring">80%</div>
                <small>DEF2</small>
              </div>
              <div className="gauge">
                <div className="ring">95%</div>
                <small>DEF3</small>
              </div>
            </div>
          </article>
        </div>
      </div>

      <div className="siem-bottom">
        <article className="card">
          <h2>Attack volume by type last 24 hrs</h2>
          <div className="bar-item">
            <span>Typosquat</span>
            <div className="bar"><i style={{ width: "78%" }} /></div>
            <strong>18</strong>
          </div>
          <div className="bar-item">
            <span>Dep. conf.</span>
            <div className="bar"><i style={{ width: "52%" }} /></div>
            <strong>11</strong>
          </div>
          <div className="bar-item">
            <span>CI inject.</span>
            <div className="bar"><i style={{ width: "28%" }} /></div>
            <strong>5</strong>
          </div>
          <p className="heatmap-title">Activity heatmap (typosquat)</p>
          <div className="heatmap">
            {Array.from({ length: 24 }).map((_, idx) => (
              <span key={idx} style={{ opacity: Math.max(0.15, idx / 24) }} />
            ))}
          </div>
        </article>

        <article className="card">
          <header>
            <h2>Triage queue</h2>
            <span className="chip">7 open</span>
          </header>
          {triageItems.map((item) => (
            <div key={item.id} className="triage-row">
              <div>
                <h4>{item.title}</h4>
                <p>{item.id}</p>
              </div>
              <div className="triage-actions">
                <button type="button">Threat</button>
                <button type="button">False +</button>
              </div>
            </div>
          ))}
        </article>
      </div>

      {selectedIncident ? (
        <aside className="incident-drawer" role="dialog" aria-label="Incident details">
          <div className="incident-drawer-head">
            <h3>Incident Detail</h3>
            <button type="button" onClick={() => setSelectedIncident(null)}>
              Close
            </button>
          </div>
          <div className="incident-section">
            <p className="incident-id">{selectedIncident.id}</p>
            <h4>{selectedIncident.title}</h4>
            <p>{selectedIncident.detail}</p>
          </div>
          <div className="incident-grid">
            <div>
              <span>Severity</span>
              <strong>{selectedIncident.severity}</strong>
            </div>
            <div>
              <span>Tag</span>
              <strong>{selectedIncident.tag}</strong>
            </div>
            <div>
              <span>Source</span>
              <strong>{selectedIncident.source}</strong>
            </div>
            <div>
              <span>Module</span>
              <strong>{selectedIncident.module}</strong>
            </div>
            <div>
              <span>Confidence</span>
              <strong>{selectedIncident.confidence}</strong>
            </div>
          </div>
          <div className="incident-section">
            <span>Recommended action</span>
            <p>{selectedIncident.recommendation}</p>
          </div>
        </aside>
      ) : null}
    </section>
  );
}

export default function DashboardPage({ title, activePage, onSelectPage }) {
  const isShareOnly = new URLSearchParams(window.location.search).get("share") === "1";
  if (isShareOnly) return <SharedGraphOnlyView />;

  return (
    <div className="dashboard-shell">
      <Sidebar activePage={activePage} onSelectPage={onSelectPage} />
      <main className="dashboard-content">
        <div className="page-header">
          <h1>{title}</h1>
          <div className="page-header-actions">
            <button type="button" className="user-chip" aria-label="Profile">
              <span className="avatar" aria-hidden="true">
                SC
              </span>
            </button>
            <button type="button" className="logout-btn">
              Logout
            </button>
          </div>
        </div>

        {activePage === "siem-dashboard" ? (
          <SsiemDashboard />
        ) : (
          <div className="empty-page-card">
            <p>Empty page</p>
          </div>
        )}
      </main>
    </div>
  );
}
