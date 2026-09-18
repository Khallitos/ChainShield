import { useTheme } from "../../context/ThemeContext.jsx";

export default function ThemeToggle({ compact = false, className = "" }) {
  const { theme, setTheme, isDark } = useTheme();

  if (compact) {
    return (
      <button
        type="button"
        className={`theme-toggle-btn compact ${className}`.trim()}
        onClick={() => setTheme(isDark ? "light" : "dark")}
        title={isDark ? "Switch to light theme" : "Switch to dark theme"}
        aria-label={isDark ? "Switch to light theme" : "Switch to dark theme"}
      >
        {isDark ? (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
          </svg>
        ) : (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
          </svg>
        )}
      </button>
    );
  }

  return (
    <div className={`theme-toggle ${className}`.trim()} role="group" aria-label="Color theme">
      <button
        type="button"
        className={`theme-toggle-option ${theme === "dark" ? "active" : ""}`}
        onClick={() => setTheme("dark")}
        aria-pressed={theme === "dark"}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
        Dark
      </button>
      <button
        type="button"
        className={`theme-toggle-option ${theme === "light" ? "active" : ""}`}
        onClick={() => setTheme("light")}
        aria-pressed={theme === "light"}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
        </svg>
        Light
      </button>
    </div>
  );
}
