import { useState } from "react";
import { api } from "../UTILS/api.js";

const SEVERITY_COLOR = { high: "#ef4444", medium: "#f59e0b", low: "#3b82f6", none: "#94a3b8" };

export default function Atk1Page() {
  const [pkgInput, setPkgInput] = useState("training-leder");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function runSimulate() {
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await api.simulateTyposquatting(pkgInput.trim());
      setResult(data);
    } catch (e) {
      setError("Backend offline or request failed. Start uvicorn on port 8000.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="atk-page">
      <div className="atk-intro">
        <h2>What is Typosquatting?</h2>
        <p>
          An attacker publishes a package whose name is one edit away from a popular trusted
          package. When a developer or CI pipeline installs the mistyped name, the attacker's
          code runs, often at install time, without any warning.
        </p>
        <p>
          The lab attack package <code>training-leder</code> (typo of <code>training-ledger</code>) lives under{" "}
          <code>demo-site/packages/training-leder</code> and is installed only via{" "}
          <code>demo-site/lab-victim-typo-only/</code>, not as a dependency of the main trainer app.
          Try simulating an install below.
        </p>
      </div>

      <div className="sim-box">
        <h3>Simulate install</h3>
        <div className="sim-row">
          <input
            value={pkgInput}
            onChange={(e) => setPkgInput(e.target.value)}
            placeholder="package-name"
            className="pkg-input"
          />
          <button type="button" className="btn" onClick={runSimulate} disabled={loading}>
            {loading ? "Running…" : "Run simulation"}
          </button>
        </div>
        <p className="hint">Try: <code>training-leder</code> (typosquat) vs <code>training-ledger</code> (correct)</p>
        {error && <p className="err-msg">{error}</p>}
      </div>

      {result && (
        <div className={`sim-result ${result.attacker_success ? "attack" : "safe"}`}>
          <div className="res-header">
            <span className={`res-badge ${result.attacker_success ? "danger" : "ok"}`}>
              {result.attacker_success ? "⚠ Typosquat: Attacker Succeeded" : "✓ Safe Install"}
            </span>
            <span className="res-outcome">{result.outcome}</span>
          </div>

          <div className="terminal">
            {result.presentation_lines.map((l, i) => (
              <p key={i} className={l.includes("***") ? "line-warn" : ""}>{l}</p>
            ))}
          </div>

          {result.siem_event && (
            <div className="siem-event-card">
              <p className="siem-label">SIEM Event Generated</p>
              <div className="incident-grid">
                {[
                  ["Event ID", result.siem_event.event_id],
                  ["Severity", result.siem_event.severity],
                  ["Confidence", `${Math.round(result.siem_event.confidence * 100)}%`],
                  ["Distance", result.siem_event.distance],
                ].map(([k, v]) => (
                  <div key={k} className="ig-cell">
                    <span>{k}</span>
                    <strong style={{ color: k === "Severity" ? SEVERITY_COLOR[v] : undefined }}>{v}</strong>
                  </div>
                ))}
              </div>
              <div className="incident-rec warn">
                <p className="rec-label">Simulated effect</p>
                <p>{result.siem_event.simulated_effect}</p>
              </div>
              <div className="incident-rec">
                <p className="rec-label">Recommendation</p>
                <p>{result.siem_event.recommendation}</p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
