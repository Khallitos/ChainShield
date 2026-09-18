// Guard for security alert text.
//
// A security finding that claims a CVE (or an otherwise-confidence-high
// vulnerability) must carry an advisory/evidence source before it is rendered
// as a confirmed fact. If it does not, the claim is relabelled as an unverified
// heuristic and the raw CVE text is dropped, never shown as a confirmed CVE.
//
// Pure and side-effect-free, so it is safe to unit-test directly and to render
// through the existing react-dom/server harness.

// True when the alert carries a concrete advisory/evidence source that can
// actually back a CVE claim. A bare heuristic-kind `source` label (e.g.
// "hybrid-ml-rules-heuristic") is provenance, NOT evidence for a specific CVE,
// so it is deliberately excluded here.
export function hasAdvisorySource(alert) {
  return Boolean(alert && (alert.advisory_url || alert.cve_url || alert.cve_source));
}

// Sanitize one alert for rendering. Alerts that mention a CVE without a source
// are relabelled; the raw CVE wording/id is removed.
export function sanitizeAlertForRender(alert) {
  if (!alert) return alert;
  const text = `${alert.title || ""} ${alert.message || ""}`;
  const mentionsCve = /\bCVE\b/i.test(text);
  if (!mentionsCve) return alert;
  if (hasAdvisorySource(alert)) return alert; // source-backed → render as-is
  return {
    ...alert,
    severity: alert.severity || "low",
    title: "Unverified heuristic signal",
    message:
      "Flagged without a vulnerability advisory or evidence source; not confirmed. Inspect the registry record directly.",
  };
}

// Sanitize a batch of alerts (keeps order).
export function sanitizeAlerts(alerts = []) {
  return (alerts || []).map(sanitizeAlertForRender);
}