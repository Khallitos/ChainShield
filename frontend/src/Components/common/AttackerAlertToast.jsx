import { useEffect, useState } from "react";

/**
 * Renders a red "attacker got a hit" toast when `alert` changes.
 * Automatically dismisses after 8 seconds.
 */
export default function AttackerAlertToast({ alert, onDismiss }) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (!alert) return;
    setVisible(true);
    const t = setTimeout(() => {
      setVisible(false);
      onDismiss?.();
    }, 8000);
    return () => clearTimeout(t);
  }, [alert]);

  if (!visible || !alert) return null;

  return (
    <div className="atk-toast" role="alert" aria-live="assertive">
      <div className="atk-toast-header">
        <span className="atk-toast-icon">💀</span>
        <strong>ATTACKER ALERT: Package Installed!</strong>
        <button
          className="atk-toast-close"
          onClick={() => { setVisible(false); onDismiss?.(); }}
          aria-label="Dismiss"
        >
          ×
        </button>
      </div>
      <div className="atk-toast-body">
        <div className="atk-toast-row">
          <span className="atk-toast-label">Package</span>
          <code>{alert.package}</code>
          {alert.version && <code>v{alert.version}</code>}
        </div>
        {alert.hostname && (
          <div className="atk-toast-row">
            <span className="atk-toast-label">Victim host</span>
            <span>{alert.hostname}</span>
          </div>
        )}
        {alert.username && (
          <div className="atk-toast-row">
            <span className="atk-toast-label">User</span>
            <span>{alert.username}</span>
          </div>
        )}
        {alert.platform && (
          <div className="atk-toast-row">
            <span className="atk-toast-label">OS</span>
            <span>{alert.platform}</span>
          </div>
        )}
        {alert.cwd && (
          <div className="atk-toast-row">
            <span className="atk-toast-label">Install path</span>
            <code className="atk-toast-path">{alert.cwd}</code>
          </div>
        )}
        <div className="atk-toast-time">
          {new Date(alert.timestamp).toLocaleTimeString()}
        </div>
      </div>
    </div>
  );
}
