import { useState } from "react";
import { useGitHub } from "../../context/GitHubContext.jsx";

export default function GitHubConnectPanel({ compact = false }) {
  const {
    isConnected,
    user,
    oauthEnabled,
    loadingStatus,
    error,
    connectGitHub,
    connectWithToken,
    disconnectGitHub,
  } = useGitHub();

  const [token, setToken] = useState("");
  const [connecting, setConnecting] = useState(false);
  const [localError, setLocalError] = useState(null);

  async function submitToken(e) {
    e.preventDefault();
    if (!token.trim()) return;
    setConnecting(true);
    setLocalError(null);
    try {
      await connectWithToken(token.trim());
      setToken("");
    } catch (err) {
      setLocalError(err.message);
    } finally {
      setConnecting(false);
    }
  }

  if (isConnected && user) {
    return (
      <div className={`gh-connect-panel ${compact ? "compact" : ""}`}>
        <div className="gh-connected-user">
          {user.avatar_url ? (
            <img src={user.avatar_url} alt="" className="gh-avatar-lg" />
          ) : (
            <span className="gh-avatar-lg placeholder">{user.login?.[0]?.toUpperCase()}</span>
          )}
          <div>
            <strong>@{user.login}</strong>
            <span className="gh-connected-meta">
              {user.public_repos != null && `${user.public_repos} public repos`}
              {user.total_private_repos != null && ` · ${user.total_private_repos} private`}
            </span>
          </div>
          <button type="button" className="repo-foot-btn danger" onClick={disconnectGitHub}>
            Disconnect
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={`gh-connect-panel ${compact ? "compact" : ""}`}>
      <h3>Connect GitHub</h3>
      <p className="gh-connect-desc">
        Link your account to list all repositories and scan real <code>package.json</code> files.
      </p>

      {oauthEnabled && (
        <button
          type="button"
          className="gh-oauth-btn"
          onClick={connectGitHub}
          disabled={loadingStatus}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
          </svg>
          Connect with GitHub
        </button>
      )}

      <div className="gh-connect-divider">
        <span>{oauthEnabled ? "or use a personal access token" : "Personal access token"}</span>
      </div>

      <form onSubmit={submitToken} className="gh-token-form">
        <label htmlFor="gh-pat">GitHub token</label>
        <input
          id="gh-pat"
          type="password"
          autoComplete="off"
          placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          disabled={connecting}
        />
        <p className="gh-token-hint">
          Create at{" "}
          <a href="https://github.com/settings/tokens" target="_blank" rel="noreferrer">
            github.com/settings/tokens
          </a>
          {" "}with <strong>repo</strong> and <strong>read:user</strong> scopes.
          Stored in your browser session only, never saved to disk.
        </p>
        <button type="submit" className="gh-connect-submit" disabled={connecting || !token.trim()}>
          {connecting ? "Connecting…" : "Connect token"}
        </button>
      </form>

      {(localError || error) && (
        <p className="gh-connect-error">{localError || error}</p>
      )}
    </div>
  );
}
