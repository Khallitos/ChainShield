import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api } from "../UTILS/api.js";

const STORAGE_KEY = "scr-selected-repo";
const LAB_DEMO_KEY = "scr-lab-demo-active";

function readLabDemoActive() {
  try {
    return localStorage.getItem(LAB_DEMO_KEY) === "true";
  } catch {
    return false;
  }
}

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
  const [labDemoActive, setLabDemoActive] = useState(readLabDemoActive);
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

  const clearLabDemo = useCallback(() => {
    setLabDemoActive(false);
    try {
      localStorage.removeItem(LAB_DEMO_KEY);
    } catch {
      /* ignore */
    }
  }, []);

  const enableLabDemo = useCallback(() => {
    setLabDemoActive(true);
    try {
      localStorage.setItem(LAB_DEMO_KEY, "true");
    } catch {
      /* ignore */
    }
    setSelectedRepoState(null);
    setArtifacts(null);
    localStorage.removeItem(STORAGE_KEY);
  }, []);

  const selectRepo = useCallback(async (repo) => {
    if (!repo) {
      clearLabDemo();
      setSelectedRepoState(null);
      setArtifacts(null);
      localStorage.removeItem(STORAGE_KEY);
      return;
    }
    clearLabDemo();
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
  }, [clearLabDemo]);

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
    clearLabDemo();
    setSelectedRepoState(null);
    setArtifacts(null);
    setRepos([]);
    localStorage.removeItem(STORAGE_KEY);
    await refreshStatus();
  }, [refreshStatus, clearLabDemo]);

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
  // expired) scans stay empty until GitHub is connected again or lab demo is enabled explicitly.
  const isConnected = Boolean(status?.connected);
  const activeRepo = isConnected ? selectedRepo : null;
  const showLabDemo = labDemoActive && (!isConnected || !selectedRepo);

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
      enableLabDemo,
      clearLabDemo,
      labDemoActive,
      showLabDemo,
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
      labDemoActive,
      showLabDemo,
      artifacts,
      loadingStatus,
      loadingRepos,
      loadingArtifacts,
      error,
      refreshStatus,
      loadRepos,
      selectRepo,
      enableLabDemo,
      clearLabDemo,
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
