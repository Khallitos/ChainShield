import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api } from "../UTILS/api.js";

const STORAGE_KEY = "scr-selected-repo";

const GitHubContext = createContext(null);

function readStoredRepo() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function GitHubProvider({ children }) {
  const [status, setStatus] = useState(null);
  const [repos, setRepos] = useState([]);
  const [selectedRepo, setSelectedRepoState] = useState(readStoredRepo);
  const [artifacts, setArtifacts] = useState(null);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [loadingArtifacts, setLoadingArtifacts] = useState(false);
  const [error, setError] = useState(null);

  const refreshStatus = useCallback(async () => {
    setLoadingStatus(true);
    setError(null);
    try {
      const data = await api.githubStatus();
      setStatus(data);
      if (!data.connected) {
        setRepos([]);
        setArtifacts(null);
      }
    } catch (err) {
      setError(err.message);
      setStatus({ connected: false });
    } finally {
      setLoadingStatus(false);
    }
  }, []);

  const loadRepos = useCallback(async () => {
    setLoadingRepos(true);
    setError(null);
    try {
      const data = await api.githubRepos();
      setRepos(data.repos || []);
      return data.repos || [];
    } catch (err) {
      setError(err.message);
      setRepos([]);
      return [];
    } finally {
      setLoadingRepos(false);
    }
  }, []);

  const selectRepo = useCallback(async (repo) => {
    if (!repo) {
      setSelectedRepoState(null);
      setArtifacts(null);
      localStorage.removeItem(STORAGE_KEY);
      return;
    }
    setSelectedRepoState(repo);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(repo));
    setLoadingArtifacts(true);
    setError(null);
    try {
      const data = await api.githubRepoArtifacts(repo.owner, repo.name);
      setArtifacts(data);
    } catch (err) {
      setError(err.message);
      setArtifacts(null);
    } finally {
      setLoadingArtifacts(false);
    }
  }, []);

  const connectGitHub = useCallback(() => {
    window.location.href = api.githubLoginUrl();
  }, []);

  const connectWithToken = useCallback(async (token) => {
    setError(null);
    const data = await api.githubConnect(token);
    setStatus({
      connected: true,
      user: data.user,
      oauth_enabled: false,
      session_connected: true,
    });
    const list = await loadRepos();
    return list;
  }, [loadRepos]);

  const disconnectGitHub = useCallback(async () => {
    try {
      await api.githubLogout();
    } catch {
      /* ignore */
    }
    setSelectedRepoState(null);
    setArtifacts(null);
    setRepos([]);
    localStorage.removeItem(STORAGE_KEY);
    await refreshStatus();
  }, [refreshStatus]);

  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);

  useEffect(() => {
    if (!status?.connected) return;
    loadRepos().then((list) => {
      const stored = readStoredRepo();
      if (!stored) return;
      const match = list.find((r) => r.full_name === stored.full_name);
      if (match) selectRepo(match);
    });
  }, [status?.connected, loadRepos, selectRepo]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("github") === "connected") {
      refreshStatus();
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, [refreshStatus]);

  // A repository chosen earlier is remembered in the browser, but it can only be scanned while
  // the backend holds a GitHub session. Without one (never connected, logged out, or the session
  // expired) the pages fall back to the lab demo instead of repeatedly failing with 401.
  const isConnected = Boolean(status?.connected);
  const activeRepo = isConnected ? selectedRepo : null;

  const value = useMemo(
    () => ({
      status,
      repos,
      selectedRepo: activeRepo,
      rememberedRepo: selectedRepo,
      artifacts,
      loadingStatus,
      loadingRepos,
      loadingArtifacts,
      error,
      refreshStatus,
      loadRepos,
      selectRepo,
      connectGitHub,
      connectWithToken,
      disconnectGitHub,
      isConnected,
      user: status?.user,
      oauthEnabled: Boolean(status?.oauth_enabled),
    }),
    [
      status,
      repos,
      activeRepo,
      selectedRepo,
      isConnected,
      artifacts,
      loadingStatus,
      loadingRepos,
      loadingArtifacts,
      error,
      refreshStatus,
      loadRepos,
      selectRepo,
      connectGitHub,
      connectWithToken,
      disconnectGitHub,
    ]
  );

  return <GitHubContext.Provider value={value}>{children}</GitHubContext.Provider>;
}

export function useGitHub() {
  const ctx = useContext(GitHubContext);
  if (!ctx) throw new Error("useGitHub must be used within GitHubProvider");
  return ctx;
}
