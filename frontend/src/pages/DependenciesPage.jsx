import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../UTILS/api.js";
import { useDefenseMode } from "../context/DefenseModeContext.jsx";
import { useGitHub } from "../context/GitHubContext.jsx";
import GitHubConnectPanel from "../Components/github/GitHubConnectPanel.jsx";
import { EcosystemIcon } from "../Components/dependencies/EcosystemIcon.jsx";
import DepsSkeleton, { DepsLoadingBanner } from "../Components/dependencies/DepsSkeleton.jsx";

const CACHE_KEY = "scr-deps-inventory";

function readCache(mode) {
  try {
    const raw = sessionStorage.getItem(`${CACHE_KEY}:${mode}`);
    if (!raw) return null;
    const { ts, data } = JSON.parse(raw);
    if (Date.now() - ts > 10 * 60 * 1000) return null;
    return data;
  } catch {
    return null;
  }
}

function writeCache(mode, data) {
  try {
    sessionStorage.setItem(`${CACHE_KEY}:${mode}`, JSON.stringify({ ts: Date.now(), data }));
  } catch {
    /* ignore */
  }
}

function ScoreRing({ score }) {
  const pct = Math.max(0, Math.min(100, score));
  const color =
    pct >= 70 ? "var(--color-success)" : pct >= 40 ? "var(--color-medium)" : "var(--color-critical)";
  const circumference = 2 * Math.PI * 14;
  const offset = circumference - (pct / 100) * circumference;

  return (
    <div className="dep-score-ring" title={`Overall score ${pct}`}>
      <svg width="36" height="36" viewBox="0 0 36 36">
        <circle cx="18" cy="18" r="14" fill="none" stroke="var(--bg-elevated)" strokeWidth="3" />
        <circle
          cx="18" cy="18" r="14" fill="none" stroke={color} strokeWidth="3"
          strokeDasharray={circumference} strokeDashoffset={offset}
          strokeLinecap="round" transform="rotate(-90 18 18)"
        />
      </svg>
      <span className="dep-score-val">{pct}</span>
    </div>
  );
}

function formatCount(n) {
  return n.toLocaleString("en-US").replace(/,/g, " ");
}

export default function DependenciesPage({ onNavigate, onOpenPackage }) {
  const { config } = useDefenseMode();
  const { isConnected, showLabDemo } = useGitHub();
  const [data, setData] = useState(() => readCache(config.api));
  const [loading, setLoading] = useState(!readCache(config.api));
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [query, setQuery] = useState("");
  const [ecosystem, setEcosystem] = useState("all");
  const [scopeFilter, setScopeFilter] = useState("all");
  const [loadPhase, setLoadPhase] = useState("scan");
  const [progress, setProgress] = useState(15);

  const load = useCallback(async (refresh = false) => {
    const hasCache = Boolean(data?.dependencies?.length) && !refresh;
    if (hasCache) {
      setRefreshing(true);
    } else {
      setLoading(true);
      setProgress(20);
    }
    setError(null);
    setLoadPhase(hasCache ? "cache" : "scan");

    const tick = window.setInterval(() => {
      setProgress((p) => Math.min(92, p + 4));
    }, 400);

    try {
      const res = await api.githubDependencies(config.api, showLabDemo && !isConnected, refresh);
      setProgress(100);
      setData(res);
      writeCache(config.api, res);
    } catch (err) {
      setError(err.message);
      if (!hasCache) setData(null);
    } finally {
      window.clearInterval(tick);
      setLoading(false);
      setRefreshing(false);
      setLoadPhase("done");
    }
  }, [config.api, isConnected, showLabDemo, data?.dependencies?.length]);

  useEffect(() => {
    if (!isConnected && !showLabDemo) {
      setData(null);
      setLoading(false);
      setError(null);
      return;
    }
    const cached = readCache(config.api);
    if (cached && (isConnected || showLabDemo)) {
      setData(cached);
      setLoading(false);
    }
    load(false);
  }, [config.api, isConnected, showLabDemo]); // eslint-disable-line react-hooks/exhaustive-deps

  const filtered = useMemo(() => {
    if (!data?.dependencies) return [];
    let list = data.dependencies;
    if (ecosystem !== "all") list = list.filter((d) => d.ecosystem === ecosystem);
    if (scopeFilter !== "all") list = list.filter((d) => d.scope === scopeFilter);
    if (query.trim()) {
      const q = query.toLowerCase();
      list = list.filter(
        (d) =>
          d.package.toLowerCase().includes(q) ||
          d.version.toLowerCase().includes(q) ||
          d.repositories.some((r) => r.toLowerCase().includes(q))
      );
    }
    return list;
  }, [data, query, ecosystem, scopeFilter]);

  const ecosystems = useMemo(() => {
    const set = new Set((data?.dependencies || []).map((d) => d.ecosystem));
    return ["all", ...Array.from(set).sort()];
  }, [data]);

  const stats = data?.stats || {};
  const showSkeleton = loading && !data?.dependencies?.length;
  const showTable = data?.dependencies?.length > 0;

  function openDetail(dep, e) {
    e?.stopPropagation();
    onOpenPackage?.({
      ecosystem: dep.ecosystem,
      package: dep.package,
      version: dep.version,
      risk_score: dep.risk_score,
      repositories: dep.repositories,
      overall_score: dep.overall_score,
    });
  }

  if (!isConnected && !showLabDemo && !loading && !data?.dependencies?.length) {
    return (
      <div className="deps-page page-shell">
        <h1 className="page-title">Dependencies</h1>
        <p className="deps-page-sub">
          Connect GitHub to inventory npm and pip dependencies across your repositories, or choose{" "}
          <strong>Lab demo data</strong> from the repo menu in the top bar.
        </p>
        <GitHubConnectPanel />
      </div>
    );
  }

  return (
    <div className="deps-page page-shell">
      <header className="deps-page-header">
        <div>
          <h1 className="page-title">Dependencies</h1>
          <p className="deps-page-sub">
            {data?.demo
              ? "Lab demo inventory (npm + pypi)"
              : showTable
                ? `${formatCount(stats.total || 0)} packages · ${stats.npm || 0} npm · ${stats.pypi || 0} pip`
                : "Building inventory…"}
            {data?.cached && !refreshing && " · cached"}
            {refreshing && " · updating…"}
          </p>
        </div>
        <div className="deps-header-actions">
          <button type="button" className="socket-card-action" onClick={() => load(true)} disabled={loading || refreshing}>
            {refreshing ? "Refreshing…" : "Refresh"}
          </button>
        </div>
      </header>

      {(showSkeleton || refreshing) && (
        <DepsLoadingBanner phase={loadPhase} progress={progress} />
      )}

      <div className="deps-layout">
        <section className="deps-main socket-card">
          <div className="deps-toolbar">
            <input
              type="search"
              className="deps-search"
              placeholder="Search dependencies (e.g. react, django)"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              disabled={showSkeleton}
            />
            <select className="deps-select" value={ecosystem} onChange={(e) => setEcosystem(e.target.value)} disabled={showSkeleton}>
              {ecosystems.map((e) => (
                <option key={e} value={e}>{e === "all" ? "All ecosystems" : e}</option>
              ))}
            </select>
            <select className="deps-select" value={scopeFilter} onChange={(e) => setScopeFilter(e.target.value)} disabled={showSkeleton}>
              <option value="all">All scopes</option>
              <option value="production">Production</option>
              <option value="development">Development</option>
            </select>
          </div>

          {error && <p className="gh-connect-error">{error}</p>}

          {showSkeleton ? (
            <DepsSkeleton rows={14} />
          ) : showTable ? (
            <div className={`deps-table-scroll ${refreshing ? "deps-table-dimmed" : ""}`}>
              <table className="deps-table">
                <thead>
                  <tr>
                    <th>Ecosystem</th>
                    <th>Package</th>
                    <th>Overall score</th>
                    <th>Type</th>
                    <th>Repository</th>
                    <th aria-label="Details" />
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((dep) => (
                    <tr key={dep.id} className="deps-row-clickable" onClick={(e) => openDetail(dep, e)}>
                      <td>
                        <span className={`dep-eco-badge dep-eco-${dep.ecosystem}`}>
                          <EcosystemIcon ecosystem={dep.ecosystem} size={16} />
                          {dep.ecosystem}
                        </span>
                      </td>
                      <td className="dep-pkg-cell">
                        <strong>
                          {dep.package}
                          <span className="dep-ver">@{dep.version}</span>
                        </strong>
                      </td>
                      <td><ScoreRing score={dep.overall_score} /></td>
                      <td>
                        <div className="dep-badges">
                          <span className="dep-badge dep-badge-type">{dep.dep_type}</span>
                          <span className="dep-badge dep-badge-scope">{dep.scope}</span>
                        </div>
                      </td>
                      <td className="dep-repos-cell">
                        {dep.repositories.slice(0, 2).map((r) => (
                          <span key={r} className="dep-repo-tag">{r}</span>
                        ))}
                        {dep.repositories.length > 2 && (
                          <span className="dep-repo-more">+{dep.repositories.length - 2}</span>
                        )}
                      </td>
                      <td className="dep-arrow-cell">
                        <button type="button" className="dep-detail-arrow" title="View package details" onClick={(e) => openDetail(dep, e)} aria-label={`View ${dep.package}`}>
                          →
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!filtered.length && !loading && (
                <p className="repo-dropdown-empty">No dependencies match your filters.</p>
              )}
            </div>
          ) : null}
        </section>

        <aside className="deps-sidebar">
          <div className="deps-stat-card socket-card">
            <div className="deps-stat-total">{formatCount(stats.total || 0)}</div>
            <div className="deps-stat-split">
              <span><strong>{formatCount(stats.direct || 0)}</strong> direct</span>
              <span><strong>{formatCount(stats.transitive || 0)}</strong> transitive</span>
            </div>
            <div className="deps-stat-meta">
              <span>{formatCount(stats.production || 0)} production</span>
              <span>{formatCount(stats.development || 0)} dev</span>
            </div>
            <div className="deps-eco-split">
              <span className="dep-eco-badge dep-eco-npm"><EcosystemIcon ecosystem="npm" size={14} /> {stats.npm || 0}</span>
              <span className="dep-eco-badge dep-eco-pypi"><EcosystemIcon ecosystem="pypi" size={14} /> {stats.pypi || 0}</span>
            </div>
            {!data?.demo && stats.repos_scanned && (
              <p className="deps-stat-foot">
                Scanned {stats.repos_scanned} of {stats.repos_total} repos · {config.label}
              </p>
            )}
          </div>
          <div className="deps-hint-card socket-card">
            <p>Click a row or <strong>→</strong> for scores, alerts, and README.</p>
          </div>
        </aside>
      </div>
    </div>
  );
}
