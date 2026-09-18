/** High-contrast chart palette for dark dashboard backgrounds */
export const CHART = {
  severity: {
    critical: "#ff5c7a",
    high: "#ff9f43",
    medium: "#ffd54f",
    low: "#b4c6e7",
  },
  layer: {
    manifest: "#8b9cff",
    workflow: "#ff9f43",
    sbom: "#3dffb8",
  },
  trend: {
    line: "#b794ff",
    fill: "rgba(183, 148, 255, 0.28)",
  },
  risk: {
    safe: "#3dffb8",
    low: "#6ee7a8",
    medium: "#ffd54f",
    high: "#ff9f43",
    critical: "#ff5c7a",
  },
  ecosystem: {
    npm: "#38bdf8",
    ci: "#e879f9",
    sbom: "#34d399",
  },
  alert: {
    low: "#94a3b8",
    medium: "#facc15",
    high: "#ff9f43",
    critical: "#ff5c7a",
  },
};

export const RISK_BUCKET_COLORS = {
  "0-20": CHART.risk.safe,
  "20-40": CHART.risk.low,
  "40-60": CHART.risk.medium,
  "60-80": CHART.risk.high,
  "80+": CHART.risk.critical,
};

export const MUI_CHART_SX = {
  "& .MuiChartsAxis-tickLabel": { fill: "#d4d4d8", fontSize: 11 },
  "& .MuiChartsAxis-line": { stroke: "#52525b" },
  "& .MuiChartsGrid-line": { stroke: "rgba(82, 82, 91, 0.55)" },
  "& .MuiChartsLegend-label": { fill: "#e4e4e7" },
  "& .MuiLineElement-root": { strokeWidth: 3 },
  "& .MuiMarkElement-root": { stroke: "#fafafa", strokeWidth: 2, r: 5 },
  "& .MuiAreaElement-root": { fillOpacity: 0.35 },
  "& .MuiBarElement-root": { rx: 4 },
};
