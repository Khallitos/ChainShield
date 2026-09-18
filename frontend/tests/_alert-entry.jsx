// Alert-text guard render harness (bundled by esbuild, executed by
// run-alert-tests.mjs). Same pattern as tests/_render-entry.jsx but for the
// alert-guard behaviours: no source-string greps, asserts on real HTML.
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import SocketOverviewLayout from "../src/Components/dashboard/SocketOverviewLayout.jsx";
import { sanitizeAlerts } from "../src/UTILS/alertGuard.js";
import { packageDetailRiskParam } from "../src/UTILS/api.js";
import { engineFromScanContext } from "../src/UTILS/notificationDetails.js";

const render = (el) => {
  try {
    return renderToStaticMarkup(el);
  } catch (e) {
    return `__RENDER_ERROR__ ${e && e.message}`;
  }
};

// Render a batch of alerts through the SAME rendering shape PackageDetailPage uses
// (title + message per alert) AFTER the alert guard has run.
function AlertListProbe({ alerts }) {
  const sane = sanitizeAlerts(alerts);
  return (
    <div>
      {sane.map((a, i) => (
        <div key={i} className="probe-alert">
          <strong>{a.title}</strong>
          <p>{a.message}</p>
        </div>
      ))}
    </div>
  );
}

// Surface what risk-score value the API layer would send for a given input.
function RiskParamProbe({ cases }) {
  return (
    <div>
      {cases.map((c, i) => {
        const p = packageDetailRiskParam(c);
        return <div key={i} data-risk>{p === null ? "UNKNOWN" : `v:${p}`}</div>;
      })}
    </div>
  );
}

// Surface what riskScore the notification engine details carry (end-to-end unknown).
function EngineRiskProbe({ finding, scanMeta }) {
  const r = engineFromScanContext(finding, scanMeta, []).riskScore;
  return <div data-engine>{r === null || r === undefined ? "UNKNOWN" : `v:${r}`}</div>;
}

const FINDING = { attack_type: "typosquatting", package: "training-leder", message: "near-miss", severity: "high" };

export const scenarios = {
  // 1) An unbacked CVE claim must NOT render; it must be relabelled "unverified".
  "cve: unbacked CVE alert relabelled": () =>
    render(
      <AlertListProbe
        alerts={[
          { severity: "critical", title: "Critical CVE vulnerability", message: "CVE-2024-1234 detected in dependency" },
        ]}
      />
    ),

  // 2) A source-backed CVE alert is preserved and its ID still renders.
  "cve: sourced CVE alert preserved": () =>
    render(
      <AlertListProbe
        alerts={[
          { severity: "high", title: "Known advisory", message: "CVE-2023-0001", source: "advisory.example", advisory_url: "https://advisory.example/cve" },
        ]}
      />
    ),

  // 3) Unknown risk score is NOT defaulted to 0.15; known scores pass through.
  "risk: unknown not defaulted to 0.15": () =>
    render(<RiskParamProbe cases={[null, undefined, NaN]} />),
  "risk: known scores preserved": () =>
    render(<RiskParamProbe cases={[0.62, 0.15, 0]} />),

  // 4) Engine details always preserve an unknown risk_score (never 0).
  "engine: unknown risk_score preserved": () =>
    render(
      <EngineRiskProbe
        finding={FINDING}
        scanMeta={{ summary: { risk_score: null, decision: "warn" }, metadata: {} }}
      />
    ),
  "engine: known risk_score preserved": () =>
    render(
      <EngineRiskProbe
        finding={FINDING}
        scanMeta={{ summary: { risk_score: 0.7, decision: "warn" }, metadata: {} }}
      />
    ),

  // 5) Fabricated campaign names must never render, verified scan body only.
  "campaigns: no fabricated names (no demo)": () =>
    render(
      <SocketOverviewLayout
        blockingEnabled={true}
        protectionLabel="Hybrid protection"
        overviewData={{}}
        composite={null}
        manifestReport={null}
        onNavigate={() => {}}
        onReviewAlerts={() => {}}
      />
    ),

  // 6) Demo mode is clearly labelled.
  "demo: data labelled as demo/illustrative": () =>
    render(
      <SocketOverviewLayout
        blockingEnabled={true}
        protectionLabel="Hybrid protection"
        overviewData={{}}
        composite={null}
        manifestReport={null}
        demo={true}
        onNavigate={() => {}}
        onReviewAlerts={() => {}}
      />
    ),
};