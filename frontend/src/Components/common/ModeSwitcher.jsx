import { DEFENSE_MODES, useDefenseMode } from "../../context/DefenseModeContext.jsx";

export default function ModeSwitcher() {
  const { mode, setMode } = useDefenseMode();

  return (
    <div className="mode-switcher" role="group" aria-label="Defense mode">
      {Object.entries(DEFENSE_MODES).map(([key, cfg]) => (
        <button
          key={key}
          type="button"
          className={`mode-btn ${mode === key ? "active" : ""}`}
          style={{ "--mode-color": cfg.color }}
          onClick={() => setMode(key)}
        >
          {cfg.label}
        </button>
      ))}
    </div>
  );
}
