// Real component render harness (bundled by esbuild, executed by run-tests.mjs).
// Every scenario returns the actual HTML produced by react-dom/server for the
// real component(s) under test, no source-string greps.
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import ScanPipeline from "../src/Components/scan/ScanPipeline.jsx";
import ScanVerdictHero from "../src/Components/scan/ScanVerdictHero.jsx";
import ScanLayerCards from "../src/Components/scan/ScanLayerCards.jsx";
import DefenseCompareTable from "../src/Components/scan/DefenseCompareTable.jsx";
import SbomInsightsPanel from "../src/Components/dashboard/SbomInsightsPanel.jsx";
import SocketInsightsPanel from "../src/Components/dashboard/SocketInsightsPanel.jsx";
import AiDecisionCard from "../src/Components/dashboard/AiDecisionCard.jsx";
import DefenseComparisonPanel from "../src/Components/dashboard/DefenseComparisonPanel.jsx";
import { GaugeScore } from "../src/pages/PackageDetailPage.jsx";

const render = (el) => {
  try {
    return renderToStaticMarkup(el);
  } catch (e) {
    return `__RENDER_ERROR__ ${e && e.message}`;
  }
};

// summary-shaped payload (this is what useScanRunner passes to ScanVerdictHero)
const summary = (decision, risk_score, extra = {}) => ({
  decision,
  risk_score,
  findings_count: 0,
  components_scanned: 3,
  severity: "none",
  ...extra,
});
// report-shaped payload (what scan endpoints return; .summary carries the fields)
const report = (decision, risk_score, extra = {}) => ({
  summary: summary(decision, risk_score),
  top_reasons: [],
  metadata: extra.metadata || {},
});
const sbomPayload = (decision, risk_score) => ({
  sbom: { format: "cyclonedx", total_components: 3, high_risk_components: 0, unsigned_components: 0, untrusted_registry_components: 0 },
  summary: summary(decision, risk_score),
});

export const scenarios = {
  // ---- unknown / HOLD (must NOT look like a safe 0%) ----
  "null+hold: ScanPipeline": () =>
    render(<ScanPipeline pipeline={[{ layer: "manifest", status: "warn", decision: "hold", findings_count: 0, risk_score: null }]} />),
  "null+hold: ScanVerdictHero": () => render(<ScanVerdictHero composite={summary("hold", null)} />),
  "null+hold: ScanLayerCards": () => render(<ScanLayerCards manifestReport={report("hold", null)} sbomReport={null} workflowReport={null} />),
  "null+hold: DefenseCompareTable": () =>
    render(<DefenseCompareTable comparisons={[{ mode: "m", label: "M", color: "#000", decision: "hold", risk_score: null, findings_count: 0 }]} />),
  "null+hold: SbomInsightsPanel": () => render(<SbomInsightsPanel sbomReport={sbomPayload("hold", null)} />),
  "null+hold: SocketInsightsPanel": () => render(<SocketInsightsPanel report={report("hold", null)} active socketStatus={null} />),
  "null+hold: AiDecisionCard": () => render(<AiDecisionCard report={report("hold", null)} modelInfo={null} socketStatus={null} />),
  "null+hold: DefenseComparisonPanel": () => render(<DefenseComparisonPanel comparisons={[{ mode: "m", label: "M", color: "#000", decision: "hold", risk_score: null, findings_count: 0 }]} />),
  "null+hold: GaugeScore": () => render(<GaugeScore label="risk" score={null} />),

  // ---- NaN / undefined ----
  "NaN: ScanPipeline": () =>
    render(<ScanPipeline pipeline={[{ layer: "sbom", status: "warn", decision: "hold", findings_count: 0, risk_score: NaN }]} />),
  "null+hold: ScanPipeline (layers)": () =>
    render(<ScanPipeline manifestReport={report("hold", null)} sbomReport={null} workflowReport={null} />),
  "NaN: ScanPipeline (layers)": () =>
    render(<ScanPipeline manifestReport={report("hold", NaN)} sbomReport={null} workflowReport={null} />),
  "NaN: ScanVerdictHero": () => render(<ScanVerdictHero composite={summary("hold", NaN)} />),
  "undefined: GaugeScore": () => render(<GaugeScore label="risk" score={undefined} />),
  "NaN: AiDecisionCard": () => render(<AiDecisionCard report={report("hold", NaN)} modelInfo={null} socketStatus={null} />),
  "undefined: SbomInsightsPanel": () => render(<SbomInsightsPanel sbomReport={sbomPayload("hold", undefined)} />),

  // ---- genuine numeric 0 must still read as the number 0 ----
  "zero: ScanVerdictHero": () => render(<ScanVerdictHero composite={summary("allow", 0)} />),
  "zero: ScanPipeline": () =>
    render(<ScanPipeline pipeline={[{ layer: "manifest", status: "pass", decision: "allow", findings_count: 0, risk_score: 0 }]} />),
  "zero: GaugeScore": () => render(<GaugeScore label="risk" score={0} />),
  "zero: AiDecisionCard": () => render(<AiDecisionCard report={report("allow", 0)} modelInfo={null} socketStatus={null} />),
  "zero: DefenseCompareTable": () =>
    render(<DefenseCompareTable comparisons={[{ mode: "m", label: "M", color: "#000", decision: "allow", risk_score: 0, findings_count: 0 }]} />),
  "zero: SbomInsightsPanel": () => render(<SbomInsightsPanel sbomReport={sbomPayload("allow", 0)} />),

  // ---- known BLOCK with null score must stay BLOCK, not be downgraded ----
  "block+null: ScanVerdictHero": () => render(<ScanVerdictHero composite={summary("block", null)} />),
  "block+null: ScanPipeline": () =>
    render(<ScanPipeline pipeline={[{ layer: "manifest", status: "block", decision: "block", findings_count: 2, risk_score: null }]} />),
  "block+null: AiDecisionCard": () => render(<AiDecisionCard report={report("block", null)} modelInfo={null} socketStatus={null} />),
  "block+null: DefenseCompareTable": () =>
    render(<DefenseCompareTable comparisons={[{ mode: "m", label: "M", color: "#000", decision: "block", risk_score: null, findings_count: 2 }]} />),

  // ---- normal numeric unchanged ----
  "normal: ScanVerdictHero": () => render(<ScanVerdictHero composite={summary("warn", 0.62)} />),
  "normal: ScanPipeline": () =>
    render(<ScanPipeline pipeline={[{ layer: "workflow", status: "warn", decision: "warn", findings_count: 1, risk_score: 0.62 }]} />),
  "normal: GaugeScore": () => render(<GaugeScore label="risk" score={62} />),
  "normal: DefenseCompareTable": () =>
    render(<DefenseCompareTable comparisons={[{ mode: "m", label: "M", color: "#000", decision: "warn", risk_score: 0.62, findings_count: 1 }]} />),
};
