import { useEffect, useState } from "react";
import { api } from "../UTILS/api.js";
import { attackTypeLabel, engineFromProtectionResponse } from "../UTILS/notificationDetails.js";
import { useNotifications } from "../context/NotificationContext.jsx";

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleString(undefined, {
      weekday: "short",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

function pct(n) {
  if (n == null || Number.isNaN(n)) return null;
  return `${Math.round(Number(n) * 100)}%`;
}

function ReasonRow({ reason }) {
  const share = pct(reason.contribution);
  return (
    <li className="block-reason-item">
      <div className="block-reason-head">
        <code>{reason.feature}</code>
        {share && <span className="block-reason-signal">{share} signal</span>}
      </div>
      <p>{reason.description}</p>
      {reason.contribution != null && (
        <div className="block-reason-bar">
          <div className="block-reason-bar-fill" style={{ width: share || "0%" }} />
        </div>
      )}
    </li>
  );
}

function buildEnginePayload(details) {
  if (!details) return null;
  return {
    defense_mode: details.defenseMode,
    model_version: details.modelVersion,
    risk_score: details.riskScore,
    decision: details.decision,
    rule_triggers: details.ruleTriggers,
    baseline_drift: details.baselineDrift,
    top_reasons: details.topReasons,
    recommended_fixes: details.recommendedFixes,
    findings: details.findings,
    impacts: details.impacts,
  };
}

export default function BlockDetailPage({ notificationId, onBack }) {
  const { notifications, updateNotificationDetails } = useNotifications();
  const notification = notifications.find((n) => n.id === notificationId);
  const [loading, setLoading] = useState(false);
  const [fetchError, setFetchError] = useState(null);
  const [geminiReport, setGeminiReport] = useState(null);
  const [geminiLoading, setGeminiLoading] = useState(false);
  const [geminiError, setGeminiError] = useState(null);

  const d = notification?.details || {};
  const hasEngineReasons = (d.topReasons?.length ?? 0) > 0;
  const engineReady = hasEngineReasons || d.riskScore != null || d.whyBlocked;

  useEffect(() => {
    if (!notification?.package || hasEngineReasons) return undefined;

    let cancelled = false;
    (async () => {
      setLoading(true);
      setFetchError(null);
      try {
        const data = await api.getBlockDetails(notification.package, notification.version || "*");
        if (cancelled) return;
        const engineDetails = engineFromProtectionResponse(data);
        engineDetails.hostname = engineDetails.hostname || d.hostname;
        engineDetails.cwd = engineDetails.cwd || d.cwd;
        updateNotificationDetails(notification.id, engineDetails);
      } catch (err) {
        if (!cancelled) setFetchError(err.message || "Could not load engine details");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [
    notification?.id,
    notification?.package,
    notification?.version,
    hasEngineReasons,
    updateNotificationDetails,
    d.hostname,
    d.cwd,
  ]);

  useEffect(() => {
    if (!notification?.package || loading || !engineReady) return undefined;

    let cancelled = false;
    (async () => {
      setGeminiLoading(true);
      setGeminiError(null);
      try {
        const report = await api.blockExplain({
          package: notification.package,
          version: notification.version || "*",
          attack_type: notification.attackType,
          source: notification.source,
          primary_reason: d.whyBlocked || notification.reason,
          canonical: d.canonical,
          hostname: d.hostname,
          cwd: d.cwd,
          audience: "developer",
          engine: buildEnginePayload(d),
        });
        if (!cancelled) setGeminiReport(report);
      } catch (err) {
        if (!cancelled) setGeminiError(err.message || "Gemini report unavailable");
      } finally {
        if (!cancelled) setGeminiLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [
    notification?.id,
    notification?.package,
    notification?.version,
    notification?.attackType,
    notification?.source,
    notification?.reason,
    loading,
    engineReady,
    d.whyBlocked,
    d.canonical,
    d.hostname,
    d.cwd,
    d.riskScore,
    d.topReasons,
  ]);

  if (!notification) {
    return (
      <div className="block-detail-page page-shell">
        <button type="button" className="block-back-btn" onClick={onBack}>
          ← Back
        </button>
        <div className="socket-card block-empty">
          <p>Block report not found. It may have been cleared from the notification list.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="block-detail-page page-shell">
      <button type="button" className="block-back-btn" onClick={onBack}>
        ← Back to dashboard
      </button>

      <header className="block-detail-header">
        <div>
          <span className={`block-detail-badge block-sev-${notification.severity || "high"}`}>
            {notification.title}
          </span>
          <h1 className="page-title">{notification.package}</h1>
          <p className="block-detail-sub">
            {notification.attackLabel || attackTypeLabel(notification.attackType)} · {notification.source} ·{" "}
            {formatTime(notification.timestamp)}
          </p>
        </div>
      </header>

      {loading && (
        <div className="socket-card block-loading">
          <p>Loading hybrid ML + rule engine analysis…</p>
        </div>
      )}
      {fetchError && (
        <div className="socket-card block-error">
          <p>{fetchError}</p>
        </div>
      )}

      {(geminiLoading || geminiReport) && (
        <section className="socket-card block-card block-card-wide block-gemini-card">
          <div className="block-gemini-head">
            <h2>Gemini intelligence report</h2>
            <span className="block-gemini-badge">
              {geminiReport?.source === "gemini" ? "Powered by Gemini" : "Fallback summary"}
            </span>
          </div>
          <p className="block-gemini-disclaimer">
            Narrative only. The block decision stays with the hybrid ML and rule engine above.
          </p>
          {geminiLoading && <p className="block-gemini-loading">Generating grounded report…</p>}
          {geminiError && <p className="block-gemini-error">{geminiError}</p>}
          {geminiReport && !geminiLoading && (
            <div className="block-gemini-body">
              <div className="block-gemini-section">
                <h3>Summary</h3>
                <p>{geminiReport.summary}</p>
              </div>
              {geminiReport.training_platform_note && (
                <div className="block-gemini-section block-gemini-highlight">
                  <h3>Training platform context</h3>
                  <p>{geminiReport.training_platform_note}</p>
                </div>
              )}
              {geminiReport.business_impact && (
                <div className="block-gemini-section">
                  <h3>Business impact</h3>
                  <p>{geminiReport.business_impact}</p>
                </div>
              )}
              {(geminiReport.technical_impact?.length ?? 0) > 0 && (
                <div className="block-gemini-section">
                  <h3>Technical impact</h3>
                  <ul className="block-list">
                    {geminiReport.technical_impact.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}
              {(geminiReport.recommended_actions?.length ?? 0) > 0 && (
                <div className="block-gemini-section">
                  <h3>Recommended actions</h3>
                  <ul className="block-list block-list-rec">
                    {geminiReport.recommended_actions.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}
              {geminiReport.gemini_error && (
                <p className="block-note">Gemini unavailable, showing the engine-based summary instead.</p>
              )}
            </div>
          )}
        </section>
      )}

      <div className="block-detail-grid">
        {(d.riskScore != null || d.decision) && (
          <section className="socket-card block-card block-card-wide">
            <h2>Hybrid ML + rule engine</h2>
            <div className="block-metrics">
              {d.riskScore != null && Number.isFinite(Number(d.riskScore)) && (
                <div className="block-metric">
                  <span>Risk score</span>
                  <strong>{Number(d.riskScore).toFixed(2)}</strong>
                </div>
              )}
              {d.decision && (
                <div className="block-metric">
                  <span>Decision</span>
                  <strong className={`block-decision-${d.decision}`}>{d.decision}</strong>
                </div>
              )}
              {d.modelVersion && (
                <div className="block-metric">
                  <span>Model</span>
                  <strong>{d.modelVersion}</strong>
                </div>
              )}
              {d.defenseMode && (
                <div className="block-metric">
                  <span>Mode</span>
                  <strong>{d.defenseMode}</strong>
                </div>
              )}
            </div>
            {d.ruleTriggers?.length > 0 && (
              <p className="block-note">Rule triggers: {d.ruleTriggers.join(", ")}</p>
            )}
          </section>
        )}

        <section className="socket-card block-card">
          <h2>Why it was blocked</h2>
          <p className="block-lead">{d.whyBlocked || notification.reason}</p>
          {d.canonical && (
            <p className="block-note">
              Trusted package: <code>{d.canonical}</code>
            </p>
          )}
          {(d.topReasons?.length ?? 0) > 0 && (
            <ul className="block-reasons">
              {d.topReasons.map((r) => (
                <ReasonRow key={`${r.feature}-${r.description}`} reason={r} />
              ))}
            </ul>
          )}
        </section>

        {(d.impacts?.length ?? 0) > 0 && (
          <section className="socket-card block-card">
            <h2>What could have happened</h2>
            <ul className="block-list">
              {d.impacts.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>
        )}

        {(d.recommendedFixes?.length ?? 0) > 0 && (
          <section className="socket-card block-card">
            <h2>Recommended actions</h2>
            <ul className="block-list block-list-rec">
              {d.recommendedFixes.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>
        )}

        {(d.hostname || d.cwd) && (
          <section className="socket-card block-card">
            <h2>Live install context</h2>
            {d.hostname && (
              <p className="block-context-row">
                <span>Host</span> {d.hostname}
              </p>
            )}
            {d.cwd && (
              <p className="block-context-row">
                <span>Directory</span> <code>{d.cwd}</code>
              </p>
            )}
          </section>
        )}
      </div>
    </div>
  );
}
