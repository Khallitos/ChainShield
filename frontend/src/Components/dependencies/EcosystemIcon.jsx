/** npm / pypi ecosystem icons */
export function EcosystemIcon({ ecosystem, size = 20 }) {
  if (ecosystem === "pypi" || ecosystem === "pip") {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden className="eco-icon eco-pypi">
        <path
          fill="currentColor"
          d="M12 2L2 7v10l10 5 10-5V7L12 2zm0 2.2l7.5 3.75v7.5L12 19.8l-7.5-3.75v-7.5L12 4.2z"
        />
        <path fill="currentColor" d="M11 8h2v8h-2V8z" opacity="0.9" />
      </svg>
    );
  }
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden className="eco-icon eco-npm">
      <rect x="2" y="2" width="20" height="20" rx="2" fill="currentColor" opacity="0.15" />
      <path fill="currentColor" d="M4 4h16v16H4V4zm2 2v12h12V6H6zm2 2h8v2H8V8zm0 4h8v2H8v-2z" />
    </svg>
  );
}

export function GitHubIcon({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}

export function LinkIcon({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
      <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71" />
    </svg>
  );
}

export function ShieldIcon({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <path d="M12 2l8 3v6c0 5.25-3.5 9.74-8 11-4.5-1.26-8-5.75-8-11V5l8-3zm0 2.2L6 6.3v4.7c0 4.1 2.7 7.68 6 8.85 3.3-1.17 6-4.75 6-8.85V6.3l-6-2.1z" />
    </svg>
  );
}

export function AlertIcon({ severity }) {
  const color = severity === "critical" ? "var(--color-critical)" : "var(--color-high)";
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" aria-hidden>
      <path d="M12 9v4M12 17h.01" strokeLinecap="round" />
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
    </svg>
  );
}
