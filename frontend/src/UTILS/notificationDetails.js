/** Labels and helpers for hybrid-engine notification details (no static block copy). */

const ATTACK_LABELS = {
  typosquatting: "Typosquatting",
  dependency_confusion: "Dependency confusion",
  ci_cd_injection: "CI/CD injection",
  lab_attack: "Lab attack package",
  supply_chain: "Supply chain risk",
};

export function attackTypeLabel(attackType) {
  return ATTACK_LABELS[attackType] || attackType?.replace(/_/g, " ") || "Supply chain";
}

/** Pick hybrid reasons most relevant to a scan finding. */
export function reasonsForFinding(finding, topReasons = []) {
  if (!topReasons.length) return [];
  const pkg = (finding.package || "").toLowerCase();
  const canonical = (finding.canonical || "").toLowerCase();
  const matched = topReasons.filter((r) => {
    const desc = (r.description || "").toLowerCase();
    const feat = (r.feature || "").toLowerCase();
    if (pkg && desc.includes(pkg)) return true;
    if (canonical && desc.includes(canonical)) return true;
    if (finding.attack_type === "typosquatting" && feat.includes("typosquat")) return true;
    if (finding.attack_type === "typosquatting" && feat.includes("edit_distance")) return true;
    if (finding.attack_type === "dependency_confusion" && feat.includes("version")) return true;
    if (finding.attack_type === "ci_cd_injection" && feat.includes("workflow")) return true;
    if (feat.includes("ml_malicious")) return true;
    return false;
  });
  return matched.length ? matched : topReasons.slice(0, 4);
}

export function buildEngineDetails({
  topReasons = [],
  recommendedFixes = [],
  impacts = [],
  findings = [],
  riskScore,
  decision,
  modelVersion,
  defenseMode = "hybrid",
  ruleTriggers = [],
  canonical,
  hostname,
  cwd,
  primaryReason,
}) {
  const findingImpacts = findings
    .map((f) => f.message)
    .filter(Boolean);
  const mergedImpacts = [...new Set([...impacts, ...findingImpacts])].slice(0, 8);

  return {
    whyBlocked: primaryReason || topReasons[0]?.description || "Blocked by hybrid ML + rule engine",
    topReasons,
    recommendedFixes,
    impacts: mergedImpacts,
    riskScore,
    decision,
    modelVersion,
    defenseMode,
    ruleTriggers,
    canonical: canonical || findings.find((f) => f.canonical)?.canonical || null,
    hostname: hostname || null,
    cwd: cwd || null,
    findings,
  };
}

export function engineFromProtectionResponse(data) {
  const eng = data?.engine || {};
  return buildEngineDetails({
    topReasons: eng.top_reasons || [],
    recommendedFixes: eng.recommended_fixes || [],
    impacts: eng.impacts || [],
    findings: eng.findings || [],
    riskScore: eng.risk_score,
    decision: eng.decision,
    modelVersion: eng.model_version,
    defenseMode: eng.defense_mode || "hybrid",
    ruleTriggers: eng.rule_triggers || [],
    canonical: data.canonical,
    primaryReason: data.reason || data.block_reason,
  });
}

export function engineFromScanContext(finding, scanMeta, topReasonsAll) {
  const topReasons = reasonsForFinding(finding, topReasonsAll);
  const summary = scanMeta?.summary || {};
  return buildEngineDetails({
    topReasons,
    recommendedFixes: scanMeta?.recommended_fixes || [],
    impacts: finding.message ? [finding.message] : [],
    findings: [finding],
    riskScore: summary.risk_score,
    decision: summary.decision,
    modelVersion: scanMeta?.metadata?.model_version,
    defenseMode: "hybrid",
    ruleTriggers: scanMeta?.metadata?.rule_triggers || [],
    canonical: finding.canonical,
    primaryReason: topReasons[0]?.description || finding.message,
  });
}
