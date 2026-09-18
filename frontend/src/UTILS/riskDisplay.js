// Shared pure display normalization for risk scores that may be unknown.
// Backend contract: risk_score is `null` when the fused detector value is
// unknown (revised HOLD), and a real numeric 0 is a genuine 0. Unknown must
// NEVER render as a benign 0%/green state, so all rendering goes through here.
//
// These functions are pure and side-effect-free, safe to unit-test directly.

// Returns the integer percentage (0-100) for a KNOWN numeric score, or `null`
// for unknown (null/undefined/non-finite). Real numeric 0 -> 0.
export function riskPct(score) {
  if (score === null || score === undefined) return null;
  const n = Number(score);
  if (!Number.isFinite(n)) return null; // NaN, Infinity, "abc" -> unknown
  return Math.round(n * 100);
}

// True when the score cannot be rendered as a number.
export function isUnknown(score) {
  return riskPct(score) === null;
}

// Returns "0%" for a real numeric 0, "62%" for 0.62, or `null` for unknown.
export function formatRisk(score) {
  const pct = riskPct(score);
  return pct === null ? null : `${pct}%`;
}

// Decision tone from the backend-authoritative `decision` field. Maps to a CSS
// class suffix. Unknown/missing decision -> "unknown" (never defaults to allow).
// HOLD stays its own tone (never allow/green).
export function decisionTone(decision) {
  const d = String(decision || "").toLowerCase();
  if (d === "block" || d === "warn" || d === "allow" || d === "hold") return d;
  return "unknown";
}

// Human text for an unknown/unscorable state. Only claims "model unavailable"
// when the backend status actually proves the ML model is absent/error/disabled;
// otherwise it is a generic "cannot evaluate" (missing evidence, not proven ML).
export function unavailableText(modelStatus) {
  const s = String(modelStatus || "").toLowerCase();
  if (s === "absent" || s === "error" || s === "disabled") {
    return "Cannot evaluate: model unavailable";
  }
  return "Cannot evaluate";
}
