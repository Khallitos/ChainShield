import { useEffect, useState } from "react";
import { api } from "../UTILS/api.js";
import { isUnknown } from "../utils/riskDisplay.js";
import { sanitizeAlerts } from "../UTILS/alertGuard.js";
import { AlertIcon, LinkIcon } from "../Components/dependencies/EcosystemIcon.jsx";
import ReadmeContent from "../Components/dependencies/ReadmeContent.jsx";

export function GaugeScore({ label, score }) {
  // Unknown/incomplete evidence must show as unavailable, never as a benign 0.
  const known = !isUnknown(score);
  const pct = known ? Math.max(0, Math.min(100, Number(score))) : null;
  const color =
    pct === null
      ? "var(--color-muted)"
      : pct >= 70
        ? "var(--color-success)"
        : pct >= 40
          ? "var(--color-medium)"
          : "var(--color-critical)";
  const r = 22;
  const c = 2 * Math.PI * r;
  const offset = pct === null ? c : c - (pct / 100) * c;

  return (
    <div className="pkg-gauge">
      <svg width="56" height="56" viewBox="0 0 56 56">
        <circle cx="28" cy="28" r={r} fill="none" stroke="var(--bg-elevated)" strokeWidth="4" />
        <circle
          cx="28" cy="28" r={r} fill="none" stroke={color} strokeWidth="4"
          strokeDasharray={c} strokeDashoffset={offset}
          strokeLinecap="round" transform="rotate(-90 28 28)"
        />
      </svg>
      <span className="pkg-gauge-val">{pct === null ? "n/a" : pct}</span>
      <span className="pkg-gauge-label">{label}</span>
    </div>
  );
}

function formatDate(iso) {
  if (!iso) return "n/a";
  try {
    return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
  } catch {
    return iso;
  }
}

function StatCard({ label, value }) {
  return (
    <div className="pkg-stat-card">
      <span className="pkg-stat-label">{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export default function PackageDetailPage({ packageRef, onBack }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("readme");
  const [copied, setCopied] = useState(false);

  const packageKey = packageRef
    ? `${packageRef.ecosystem}:${packageRef.package}:${packageRef.version ?? ""}`
    : "";

  useEffect(() => {
    if (!packageRef) return undefined;

    let cancelled = false;
    setLoading(true);
    setError(null);
    setDetail(null);
    setTab("readme");
    setCopied(false);

    api
      .githubPackageDetail(
        packageRef.ecosystem,
        packageRef.package,
        packageRef.version,
        packageRef.risk_score // may be null/unknown → never defaulted to a number
      )
      .then((data) => {
        if (cancelled) return;
        setDetail(data);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err.message);
        setDetail(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [packageKey, packageRef?.risk_score]);

  if (!packageRef) {
    return (
      <div className="pkg-detail-page page-shell">
        <button type="button" className="pkg-back-btn" onClick={onBack}>← Back to Dependencies</button>
        <p className="repo-dropdown-empty">No package selected.</p>
      </div>
    );
  }

  async function copyPurl() {
    if (!detail?.purl) return;
    try {
      await navigator.clipboard.writeText(detail.purl);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch { /* ignore */ }
  }

  const scores = detail?.scores || {};
  const eco = detail?.ecosystem || packageRef.ecosystem;
  const detailMatches =
    detail &&
    detail.package === packageRef.package &&
    (detail.ecosystem || eco) === packageRef.ecosystem;

  return (
    <div className="pkg-detail-page page-shell">
      <button type="button" className="pkg-back-btn" onClick={onBack}>
        ← Back to Dependencies
      </button>

      {loading && (
        <div className="pkg-detail-hero socket-card pkg-detail-loading">
          <span className="beacon-processing-spinner" />
          <span>Loading {packageRef.package}…</span>
        </div>
      )}

      {error && <p className="gh-connect-error">{error}</p>}

      {detailMatches && !loading && (
        <>
          <nav className="pkg-breadcrumb">
            <span>{eco}</span>
            <span className="pkg-crumb-sep">›</span>
            <span>{detail.package}</span>
          </nav>

          <header className="pkg-detail-hero socket-card">
            <div className="pkg-hero-header-row">
              <h1 className="pkg-detail-title">{detail.package}</h1>
              <div className="pkg-gauge-row">
                <GaugeScore label="Supply chain" score={scores.supply_chain} />
                <GaugeScore label="Vulnerability" score={scores.vulnerability} />
                <GaugeScore label="Quality" score={scores.quality} />
                <GaugeScore label="Maintenance" score={scores.maintenance} />
                <GaugeScore label="License" score={scores.license} />
              </div>
            </div>
            <p className="pkg-detail-desc">{detail.description || "No description available."}</p>
            <div className="pkg-action-pills">
              {detail.repository && (
                <a href={detail.repository} target="_blank" rel="noreferrer" className="pkg-pill">
                  Source
                </a>
              )}
              <a href={detail.registry_url} target="_blank" rel="noreferrer" className="pkg-pill">
                {eco}
              </a>
              <button type="button" className="pkg-pill" onClick={copyPurl}>
                {copied ? "Copied!" : "Copy purl"}
              </button>
              <span className="pkg-socket-badge">Socket {scores.overall ?? "n/a"}</span>
            </div>
          </header>

          {(sanitizeAlerts(detail.alerts) || []).map((alert) => (
            <div key={alert.title} className={`pkg-alert pkg-alert-${alert.severity}`}>
              <AlertIcon severity={alert.severity} />
              <div>
                <strong>{alert.title}</strong>
                <p>{alert.message}</p>
              </div>
            </div>
          ))}

          <div className="pkg-stats-grid">
            <StatCard label="Version" value={detail.version} />
            <StatCard label="Published" value={formatDate(detail.published_at)} />
            <StatCard label="Maintainers" value={detail.maintainers ?? "n/a"} />
            <StatCard label="License" value={detail.license || "n/a"} />
          </div>

          {packageRef.repositories?.length > 0 && (
            <div className="pkg-repos-banner socket-card">
              <span className="pkg-stat-label">Used in your repositories</span>
              <div className="pkg-repo-chips">
                {packageRef.repositories.map((r) => (
                  <span key={r} className="pkg-repo-chip">{r}</span>
                ))}
              </div>
            </div>
          )}

          <section className="pkg-readme-section socket-card">
            <div className="pkg-tabs">
              <button type="button" className={`pkg-tab ${tab === "readme" ? "active" : ""}`} onClick={() => setTab("readme")}>
                README
              </button>
              <button type="button" className={`pkg-tab ${tab === "similar" ? "active" : ""}`} onClick={() => setTab("similar")}>
                Similar packages
              </button>
              <a href={detail.registry_url} target="_blank" rel="noreferrer" className="pkg-tab-source">
                <LinkIcon size={12} /> Registry
              </a>
            </div>
            {tab === "readme" && (
              <div className="pkg-readme-body">
                {detail.readme ? (
                  <ReadmeContent
                    key={`${detail.ecosystem}:${detail.package}:${detail.version}`}
                    text={detail.readme}
                    packageName={detail.package}
                  />
                ) : (
                  <p className="pkg-readme-empty">
                    No README on the registry. Visit{" "}
                    <a href={detail.registry_url} target="_blank" rel="noreferrer">{detail.registry_url}</a>.
                  </p>
                )}
              </div>
            )}
            {tab === "similar" && (
              <p className="pkg-readme-empty">Similar package recommendations available with Socket upgrade.</p>
            )}
          </section>
        </>
      )}
    </div>
  );
}
