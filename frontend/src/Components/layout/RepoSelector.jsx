import { useEffect, useRef, useState } from "react";
import { useGitHub } from "../../context/GitHubContext.jsx";

export default function RepoSelector({ onNavigate }) {
  const {
    status,
    repos,
    selectedRepo,
    loadingRepos,
    loadingStatus,
    isConnected,
    user,
    selectRepo,
    loadRepos,
  } = useGitHub();

  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const rootRef = useRef(null);

  useEffect(() => {
    function onDocClick(e) {
      if (rootRef.current && !rootRef.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, []);

  const filtered = repos.filter((r) =>
    r.full_name.toLowerCase().includes(query.toLowerCase())
  );

  const label = selectedRepo?.full_name
    || (isConnected ? `All repositories (${repos.length})` : "Connect GitHub");

  function openConnect() {
    setOpen(false);
    onNavigate?.("repos");
  }

  return (
    <div className="repo-selector" ref={rootRef}>
      <button
        type="button"
        className="topbar-btn topbar-select repo-selector-trigger"
        onClick={() => {
          if (!isConnected) {
            openConnect();
            return;
          }
          setOpen((v) => !v);
          if (!repos.length) loadRepos();
        }}
        disabled={loadingStatus}
      >
        {user?.login && <span className="repo-user-badge">@{user.login}</span>}
        <span className="repo-selector-label">{label}</span>
        <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor"><path d="M3 4.5L6 7.5L9 4.5" /></svg>
      </button>

      {open && isConnected && (
        <div className="repo-dropdown">
          <div className="repo-dropdown-head">
            <input
              type="search"
              placeholder="Search repositories…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="repo-search"
            />
            <span className="repo-dropdown-hint">{repos.length} repos loaded</span>
          </div>

          <div className="repo-dropdown-list">
            <button
              type="button"
              className={`repo-option ${!selectedRepo ? "active" : ""}`}
              onClick={() => {
                selectRepo(null);
                setOpen(false);
              }}
            >
              <strong>Lab demo data</strong>
              <span>Use built-in attack scenarios</span>
            </button>

            {loadingRepos && <p className="repo-dropdown-empty">Loading repositories…</p>}

            {!loadingRepos && filtered.slice(0, 50).map((repo) => (
              <button
                key={repo.id}
                type="button"
                className={`repo-option ${selectedRepo?.id === repo.id ? "active" : ""}`}
                onClick={() => {
                  selectRepo(repo);
                  setOpen(false);
                }}
              >
                <strong>{repo.full_name}</strong>
                <span>
                  {repo.private ? "Private" : "Public"}
                  {repo.language ? ` · ${repo.language}` : ""}
                </span>
              </button>
            ))}

            {!loadingRepos && filtered.length > 50 && (
              <button type="button" className="repo-option" onClick={openConnect}>
                <strong>View all {repos.length} repositories →</strong>
              </button>
            )}

            {!loadingRepos && !filtered.length && (
              <p className="repo-dropdown-empty">No repositories match your search.</p>
            )}
          </div>

          <div className="repo-dropdown-foot">
            <button type="button" className="repo-foot-btn" onClick={loadRepos}>
              Refresh
            </button>
            <button type="button" className="repo-foot-btn" onClick={openConnect}>
              Manage
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
