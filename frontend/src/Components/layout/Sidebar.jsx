import { BRAND } from "../../UTILS/brand.js";
import ThemeToggle from "./ThemeToggle.jsx";

const NAV = [
  { key: "siem", label: "Overview", icon: "overview" },
  { key: "scan", label: "Scan", icon: "scan" },
  { key: "tryit", label: "Try It", icon: "tryit" },
  { key: "repos", label: "Repositories", icon: "repos" },
  { key: "dependencies", label: "Dependencies", icon: "dependencies" },
  { key: "settings", label: "Settings", icon: "settings" },
];

function NavIcon({ name, active }) {
  const stroke = active ? "var(--socket-purple)" : "currentColor";
  if (name === "overview") {
    return (
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden>
        <rect x="2" y="2" width="6" height="6" rx="1.5" stroke={stroke} strokeWidth="1.5" />
        <rect x="10" y="2" width="6" height="6" rx="1.5" stroke={stroke} strokeWidth="1.5" />
        <rect x="2" y="10" width="6" height="6" rx="1.5" stroke={stroke} strokeWidth="1.5" />
        <rect x="10" y="10" width="6" height="6" rx="1.5" stroke={stroke} strokeWidth="1.5" />
      </svg>
    );
  }
  if (name === "scan") {
    return (
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden>
        <circle cx="8" cy="8" r="5" stroke={stroke} strokeWidth="1.5" />
        <path d="M12 12l4 4" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    );
  }
  if (name === "tryit") {
    return (
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden>
        <rect x="2" y="2" width="14" height="14" rx="2" stroke={stroke} strokeWidth="1.5" />
        <path d="M6 9l2 2 4-4.5" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  if (name === "settings") {
    return (
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden>
        <circle cx="9" cy="9" r="2.5" stroke={stroke} strokeWidth="1.5" />
        <path
          d="M9 1.5v2M9 14.5v2M1.5 9h2M14.5 9h2M3.4 3.4l1.4 1.4M13.2 13.2l1.4 1.4M3.4 14.6l1.4-1.4M13.2 4.8l1.4-1.4"
          stroke={stroke}
          strokeWidth="1.5"
          strokeLinecap="round"
        />
      </svg>
    );
  }
  if (name === "repos") {
    return (
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden>
        <path d="M3 4h12v10H3V4z" stroke={stroke} strokeWidth="1.5" />
        <path d="M6 7h6M6 10h4" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    );
  }
  if (name === "dependencies") {
    return (
      <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden>
        <circle cx="9" cy="9" r="6.5" stroke={stroke} strokeWidth="1.5" />
        <path d="M9 5v4l2.5 1.5" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    );
  }
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden>
      <circle cx="9" cy="9" r="6.5" stroke={stroke} strokeWidth="1.5" />
    </svg>
  );
}

function BrandLogo() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path
        d="M12 2.5l7 3.5v5.5c0 4.5-3 7.5-7 9.5-4-2-7-5-7-9.5V6l7-3.5z"
        fill="var(--socket-purple)"
        fillOpacity="0.2"
        stroke="var(--socket-purple)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M9.5 12.5l2 2 4-4.5"
        stroke="var(--socket-purple)"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function Sidebar({ activePage, onNavigate }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <BrandLogo />
        <span className="sidebar-brand-name">{BRAND.name}</span>
      </div>

      <nav className="sidebar-nav">
        {NAV.map((item) => (
          <button
            key={item.key}
            type="button"
            className={`sidebar-item ${activePage === item.key ? "active" : ""}`}
            onClick={() => onNavigate(item.key)}
          >
            <NavIcon name={item.icon} active={activePage === item.key} />
            {item.label}
            {activePage === item.key && <span className="nav-active-dot" />}
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <ThemeToggle compact />
        <button type="button" className="sidebar-footer-btn" title="Help">?</button>
      </div>
    </aside>
  );
}
