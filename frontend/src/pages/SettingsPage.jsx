import { useDefenseMode } from "../context/DefenseModeContext.jsx";
import ScheduledScanSettings from "../Components/settings/ScheduledScanSettings.jsx";
import MlModelPanel from "../Components/ml/MlModelPanel.jsx";
import ThemeToggle from "../Components/layout/ThemeToggle.jsx";
import { useTheme } from "../context/ThemeContext.jsx";

export default function SettingsPage() {
  const { blockingEnabled, setBlockingEnabled, config } = useDefenseMode();
  const { theme } = useTheme();

  return (
    <div className="settings-page page-shell">
      <header className="settings-head">
        <h1 className="page-title">Settings</h1>
        <p className="settings-sub">
          Protection, scheduled scans, appearance, and notification preferences for your training platform.
        </p>
      </header>

      <section className="socket-card settings-card">
        <div className="theme-appearance-row">
          <div className="settings-row-text">
            <h2>Appearance</h2>
            <p>
              Default is dark (black). Switch to light (white) for brighter environments.
              Your choice is saved in this browser.
            </p>
          </div>
          <ThemeToggle />
        </div>
        <p className="settings-hint" style={{ marginTop: 12 }}>
          Current theme: <strong>{theme === "dark" ? "Dark" : "Light"}</strong>
        </p>
      </section>

      <section className="socket-card settings-card">
        <div className="settings-row">
          <div className="settings-row-text">
            <h2>Attack blocking</h2>
            <p>
              When enabled, the system blocks or flags malicious packages and CI/CD patterns before
              they can enter your pipeline. When disabled, scans still run but attacks are allowed through.
            </p>
          </div>
          <label className="settings-toggle">
            <input
              type="checkbox"
              checked={blockingEnabled}
              onChange={(e) => setBlockingEnabled(e.target.checked)}
            />
            <span className="settings-toggle-track" aria-hidden />
            <span className="settings-toggle-label">{blockingEnabled ? "On" : "Off"}</span>
          </label>
        </div>

        <div className={`settings-status ${blockingEnabled ? "on" : "off"}`}>
          <span className="settings-status-dot" />
          <div>
            <strong>{config.label}</strong>
            <p>
              {blockingEnabled
                ? "Hybrid ML + rule engine will block typosquats, dependency confusion, and CI injection."
                : "Monitoring only. Detected attacks will not be blocked."}
            </p>
          </div>
        </div>
      </section>

      <MlModelPanel />

      <ScheduledScanSettings />

      <section className="socket-card settings-card settings-info">
        <h3>Notifications</h3>
        <p>
          Use the bell icon in the top bar for blocked attacks and scheduled scan issues. Open a
          notification for the full hybrid engine and Gemini report.
        </p>
      </section>
    </div>
  );
}
