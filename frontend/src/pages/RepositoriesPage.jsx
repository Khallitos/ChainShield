import { useMemo, useState } from "react";
import GitHubConnectPanel from "../Components/github/GitHubConnectPanel.jsx";
import { useGitHub } from "../context/GitHubContext.jsx";

function formatDate(iso) {
  if (!iso) return "n/a";
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  } catch {
    return iso;
  }
}

export default function RepositoriesPage({ onNavigate }) {
  const {
    isConnected,
    repos,
    selectedRepo,
    loadingRepos,
    error,
    loadRepos,
    selectRepo,
  } = useGitHub();

  const [query, setQuery] = useState("");
  const [visibility, setVisibility] = useState("all");

  const filtered = useMemo(() => {
    let list = repos;
    if (visibility === "public") list = list.filter((r) => !r.private);
    if (visibility === "private") list = list.filter((r) => r.private);
    if (query.trim()) {
      const q = query.toLowerCase();
      list = list.filter(
        (r) =>
          r.full_name.toLowerCase().includes(q) ||
          (r.description || "").toLowerCase().includes(q) ||
          (r.language || "").toLowerCase().includes(q)
      );
    }
    return list;
  }, [repos, query, visibility]);

  async function scanRepo(repo) {
    await selectRepo(repo);
    onNavigate?.("scan");
  }

  return (
    <div className="repos-page page-shell">
      <header className="repos-page-head">
        <div>
          <h1 className="page-title">Repositories</h1>
          <p className="repos-page-sub">
            {isConnected
              ? `${repos.length} repositories from your GitHub account`
              : "Connect GitHub to import your repositories"}
          </p>
        </div>
        {isConnected && (
          <button type="button" className="socket-card-action" onClick={loadRepos} disabled={loadingRepos}>
            {loadingRepos ? "Loading…" : "Refresh"}
          </button>
        )}
      </header>

      {!isConnected ? (
        <GitHubConnectPanel />
      ) : (
        <>
          <div className="repos-toolbar socket-card">
            <input
              type="search"
              className="repo-search repos-search-wide"
              placeholder="Search by name, language, or description…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <div className="repos-filters">
              {["all", "public", "private"].map((v) => (
                <button
                  key={v}
                  type="button"
                  className={`repos-filter-btn ${visibility === v ? "active" : ""}`}
                  onClick={() => setVisibility(v)}
                >
                  {v.charAt(0).toUpperCase() + v.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {error && <p className="gh-connect-error">{error}</p>}

          {loadingRepos && !repos.length ? (
            <div className="repos-loading">
              <span className="beacon-processing-spinner" />
              Loading repositories from GitHub…
            </div>
          ) : (
            <div className="repos-table-wrap socket-card">
              <table className="repos-table">
                <thead>
                  <tr>
                    <th>Repository</th>
                    <th>Visibility</th>
                    <th>Language</th>
                    <th>Updated</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((repo) => (
                    <tr
                      key={repo.id}
                      className={selectedRepo?.id === repo.id ? "selected" : ""}
                    >
                      <td className="repos-name-cell">
                        <strong>{repo.full_name}</strong>
                        {repo.description && (
                          <span className="repos-desc">{repo.description}</span>
                        )}
                      </td>
                      <td>
                        <span className={`repos-vis ${repo.private ? "private" : "public"}`}>
                          {repo.private ? "Private" : "Public"}
                        </span>
                      </td>
                      <td>{repo.language || "n/a"}</td>
                      <td className="repos-date">{formatDate(repo.updated_at)}</td>
                      <td className="repos-actions">
                        <a
                          href={repo.html_url}
                          target="_blank"
                          rel="noreferrer"
                          className="repos-link-btn"
                        >
                          GitHub
                        </a>
                        <button type="button" className="repos-scan-btn" onClick={() => scanRepo(repo)}>
                          Scan
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!filtered.length && (
                <p className="repo-dropdown-empty">No repositories match your filters.</p>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
