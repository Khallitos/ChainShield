/** Live Socket.dev connection + scan results for SIEM dashboard. */
import { formatRisk, isUnknown } from "../../utils/riskDisplay.js";

export default function SocketInsightsPanel({ socketStatus, report, active }) {
  if (!active) return null;

  const quota = socketStatus?.quota;
  const configured = socketStatus?.configured;
  const meta = report?.metadata || {};
  const socketFindings = (report?.findings || []).filter(
    (f) => f.finding_id?.startsWith("socket_") || f.evidence?.socket_type
  );
  const localCount = meta.local_findings_count ?? 0;
  const socketCount = meta.socket_findings_count ?? socketFindings.length;

  const quotaPct =
    quota?.maxQuota > 0
      ? Math.round((quota.quota / quota.maxQuota) * 100)
      : null;

  const refreshLabel = quota?.nextWindowRefresh
    ? new Date(quota.nextWindowRefresh).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      })
    : null;

  return (
    <section className="panel socket-insights">
      <div className="module-head">
        <h3>Socket.dev</h3>
        <span className={`socket-badge ${configured ? "ok" : "warn"}`}>
          {configured ? "LIVE" : "NO TOKEN"}
        </span>
      </div>

      <div className="socket-status-row">
        <span className={`dot-live ${configured ? "green" : "red"}`} />
        <div>
          <p className="socket-status-title">
            {configured ? "API connected" : "Token not configured"}
          </p>
          <p className="socket-status-sub">
            {configured
              ? meta.engine === "socket_dev_api"
                ? "Real-time package analysis active"
                : "Using local rules fallback"
              : "Add SOCKET_SECURITY_API_TOKEN to backend/.env"}
          </p>
        </div>
      </div>

      {configured && quota && (
        <div className="socket-quota">
          <div className="socket-quota-head">
            <span>API quota</span>
            <strong>
              {quota.quota} / {quota.maxQuota}
            </strong>
          </div>
          <div className="socket-quota-bar">
            <div
              className="socket-quota-fill"
              style={{ width: `${quotaPct ?? 0}%` }}
            />
          </div>
          {refreshLabel && (
            <p className="socket-quota-refresh">Resets ~{refreshLabel}</p>
          )}
        </div>
      )}

      {report?.summary && (
        <div className="socket-scan-summary">
          <div className="socket-stat">
            <span>Decision</span>
            <strong className={`dec-${report.summary.decision}`}>
              {report.summary.decision?.toUpperCase()}
            </strong>
          </div>
          <div className="socket-stat">
            <span>Risk</span>
            <strong>{isUnknown(report.summary.risk_score) ? "n/a" : formatRisk(report.summary.risk_score)}</strong>
          </div>
          <div className="socket-stat">
            <span>Socket alerts</span>
            <strong>{socketCount}</strong>
          </div>
          <div className="socket-stat">
            <span>Local rules</span>
            <strong>{localCount}</strong>
          </div>
        </div>
      )}

      {socketFindings.length > 0 ? (
        <div className="socket-findings">
          <p className="socket-findings-title">Socket alerts</p>
          {socketFindings.slice(0, 5).map((f) => (
            <div key={f.finding_id} className="socket-finding-row">
              <span className={`sev-dot ${f.severity === "critical" || f.severity === "high" ? "red" : "amber"}`} />
              <div>
                <strong>{f.package || "package"}</strong>
                <span className="socket-type-tag">
                  {f.evidence?.socket_type || f.attack_type}
                </span>
                <p>{f.message}</p>
              </div>
            </div>
          ))}
        </div>
      ) : (
        configured &&
        report && (
          <p className="muted socket-empty">
            No Socket registry alerts. Lab packages may show local typosquat findings only.
          </p>
        )
      )}
    </section>
  );
}
