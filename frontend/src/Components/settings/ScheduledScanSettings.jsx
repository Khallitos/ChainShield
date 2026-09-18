import { useEffect, useMemo, useState } from "react";
import { useGitHub } from "../../context/GitHubContext.jsx";
import { api } from "../../UTILS/api.js";
import { isUnknown, formatRisk } from "../../utils/riskDisplay.js";

const CRON_PRESETS = [
  { id: "hourly", label: "Every hour", cron: "0 * * * *" },
  { id: "daily_9", label: "Daily at 9:00 AM", cron: "0 9 * * *" },
  { id: "daily_6", label: "Daily at 6:00 AM", cron: "0 6 * * *" },
  { id: "weekly_mon", label: "Weekly on Monday, 9:00 AM", cron: "0 9 * * 1" },
  { id: "custom", label: "Custom cron expression", cron: "" },
];

function formatWhen(iso) {
  if (!iso) return "n/a";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function matchPreset(cron) {
  return CRON_PRESETS.find((p) => p.cron && p.cron === cron)?.id || "custom";
}

function repoOwner(repo) {
  return repo.owner?.login || repo.full_name?.split("/")[0] || "";
}

function mergeRepoTargets(repos, savedTargets) {
  const savedMap = new Map((savedTargets || []).map((t) => [t.full_name, t]));
  const merged = (repos || []).map((repo, i) => {
    const saved = savedMap.get(repo.full_name);
    return {
      full_name: repo.full_name,
      owner: repoOwner(repo),
      name: repo.name,
      enabled: Boolean(saved?.enabled),
      priority: saved?.priority ?? i + 100,
      private: repo.private,
      updated_at: repo.updated_at,
    };
  });

  for (const t of savedTargets || []) {
    if (!merged.some((m) => m.full_name === t.full_name)) {
      merged.push({
        full_name: t.full_name,
        owner: t.owner || t.full_name.split("/")[0],
        name: t.name || t.full_name.split("/")[1],
        enabled: Boolean(t.enabled),
        priority: t.priority ?? 999,
        missing: true,
      });
    }
  }

  return merged.sort((a, b) => {
    if (a.enabled !== b.enabled) return a.enabled ? -1 : 1;
    return a.priority - b.priority || a.full_name.localeCompare(b.full_name);
  });
}

function serializeTargets(targets) {
  return targets.map(({ full_name, owner, name, priority, enabled }) => ({
    full_name,
    owner,
    name,
    priority,
    enabled,
  }));
}

export default function ScheduledScanSettings() {
  const {
    isConnected,
    loadingRepos,
    loadingStatus,
    repos,
    loadRepos,
    connectGitHub,
  } = useGitHub();

  const [config, setConfig] = useState(null);
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);
  const [saved, setSaved] = useState(false);

  const [enabled, setEnabled] = useState(false);
  const [preset, setPreset] = useState("daily_9");
  const [customCron, setCustomCron] = useState("0 9 * * *");
  const [source, setSource] = useState("training-platform");
  const [repoTargets, setRepoTargets] = useState([]);
  const [repoFilter, setRepoFilter] = useState("");

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [cfg, history] = await Promise.all([
        api.getScheduledScan(),
        api.getScheduledScanRuns(10),
      ]);
      setConfig(cfg);
      setRuns(history.runs || []);
      setEnabled(Boolean(cfg.enabled));
      setSource(cfg.source || "training-platform");
      const id = matchPreset(cfg.cron_expression);
      setPreset(id);
      if (id === "custom") setCustomCron(cfg.cron_expression || "0 9 * * *");
      setRepoTargets((prev) => {
        const merged = mergeRepoTargets(repos, cfg.repo_targets);
        if (merged.length) return merged;
        return prev.length ? prev : merged;
      });
    } catch (err) {
      setError(err.message || "Could not load schedule");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    if (!isConnected || loadingStatus) return;
    loadRepos();
  }, [isConnected, loadingStatus, loadRepos]);

  useEffect(() => {
    if (!repos.length && !config?.repo_targets?.length) return;
    setRepoTargets(mergeRepoTargets(repos, config?.repo_targets));
  }, [repos, config?.repo_targets]);

  const filteredTargets = useMemo(() => {
    const q = repoFilter.trim().toLowerCase();
    if (!q) return repoTargets;
    return repoTargets.filter((r) => r.full_name.toLowerCase().includes(q));
  }, [repoTargets, repoFilter]);

  const enabledCount = repoTargets.filter((r) => r.enabled).length;

  const enabledSorted = useMemo(
    () =>
      repoTargets
        .filter((r) => r.enabled)
        .slice()
        .sort((a, b) => a.priority - b.priority),
    [repoTargets]
  );

  function resolvedCron() {
    if (preset === "custom") return customCron.trim();
    return CRON_PRESETS.find((p) => p.id === preset)?.cron || "0 9 * * *";
  }

  function toggleRepo(fullName, nextEnabled) {
    setRepoTargets((prev) => {
      let next = prev.map((r) =>
        r.full_name === fullName ? { ...r, enabled: nextEnabled } : r
      );
      const enabledList = next
        .filter((r) => r.enabled)
        .sort((a, b) => a.priority - b.priority);

      if (nextEnabled) {
        const maxP = enabledList.reduce((m, r) => Math.max(m, r.priority), 0);
        next = next.map((r) =>
          r.full_name === fullName ? { ...r, enabled: true, priority: maxP + 1 } : r
        );
      } else {
        const renumbered = enabledList.filter((r) => r.full_name !== fullName);
        const pmap = new Map(renumbered.map((r, i) => [r.full_name, i + 1]));
        next = next.map((r) =>
          pmap.has(r.full_name)
            ? { ...r, priority: pmap.get(r.full_name) }
            : { ...r, enabled: false }
        );
      }
      return next;
    });
  }

  function moveRepo(fullName, direction) {
    setRepoTargets((prev) => {
      const enabled = prev
        .filter((r) => r.enabled)
        .slice()
        .sort((a, b) => a.priority - b.priority);
      const idx = enabled.findIndex((r) => r.full_name === fullName);
      if (idx < 0) return prev;
      const swapIdx = direction === "up" ? idx - 1 : idx + 1;
      if (swapIdx < 0 || swapIdx >= enabled.length) return prev;
      [enabled[idx], enabled[swapIdx]] = [enabled[swapIdx], enabled[idx]];
      const pmap = new Map(enabled.map((r, i) => [r.full_name, i + 1]));
      return prev.map((r) =>
        pmap.has(r.full_name) ? { ...r, priority: pmap.get(r.full_name) } : r
      );
    });
  }

  async function save() {
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      const cfg = await api.updateScheduledScan({
        enabled,
        cron_expression: resolvedCron(),
        source: source.trim() || "training-platform",
        repo_targets: serializeTargets(repoTargets),
      });
      setConfig(cfg);
      setRepoTargets(mergeRepoTargets(repos, cfg.repo_targets));
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2500);
    } catch (err) {
      setError(err.message || "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function runNow() {
    setRunning(true);
    setError(null);
    try {
      await api.runScheduledScanNow();
      await load();
    } catch (err) {
      setError(err.message || "Scan failed");
    } finally {
      setRunning(false);
    }
  }

  const cronExpr = resolvedCron();
  const scanUsesRepos = enabledCount > 0;

  return (
    <section className="socket-card settings-card settings-card-wide">
      <div className="settings-row">
        <div className="settings-row-text">
          <h2>Scheduled system scan</h2>
          <p>
            Choose which GitHub repositories to scan and set their priority. Higher-priority repos
            (lower number) are scanned first on each cron run. Results appear below and in the
            notification bell when issues are found.
          </p>
        </div>
        <label className="settings-toggle">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <span className="settings-toggle-track" aria-hidden />
          <span className="settings-toggle-label">{enabled ? "On" : "Off"}</span>
        </label>
      </div>

      {loading ? (
        <p className="settings-muted">Loading schedule…</p>
      ) : (
        <>
          <div className="settings-repos-section">
            <div className="settings-repos-head">
              <div>
                <h3>Repository scan targets</h3>
                <p className="settings-hint settings-repos-sub">
                  {enabledCount > 0
                    ? `${enabledCount} repo${enabledCount === 1 ? "" : "s"} selected · scanned in priority order`
                    : "No repos selected. The demo scan runs with the label below."}
                </p>
              </div>
              {isConnected && (
                <input
                  type="search"
                  className="settings-repos-search"
                  placeholder="Filter repositories…"
                  value={repoFilter}
                  onChange={(e) => setRepoFilter(e.target.value)}
                />
              )}
            </div>

            {!isConnected ? (
              <div className="settings-repos-empty">
                <p>Connect GitHub to see all your repositories and choose scan priorities.</p>
                <button type="button" className="settings-btn primary" onClick={connectGitHub}>
                  Connect GitHub
                </button>
              </div>
            ) : loadingRepos ? (
              <p className="settings-muted">Loading repositories…</p>
            ) : repoTargets.length === 0 ? (
              <p className="settings-muted">No repositories found on your GitHub account.</p>
            ) : (
              <div className="settings-repos-table-wrap">
                <table className="settings-repos-table">
                  <thead>
                    <tr>
                      <th>Scan</th>
                      <th>Priority</th>
                      <th>Repository</th>
                      <th aria-label="Reorder" />
                    </tr>
                  </thead>
                  <tbody>
                    {filteredTargets.map((repo) => {
                      const rank = enabledSorted.findIndex((r) => r.full_name === repo.full_name);
                      return (
                        <tr
                          key={repo.full_name}
                          className={repo.enabled ? "settings-repo-enabled" : ""}
                        >
                          <td>
                            <input
                              type="checkbox"
                              checked={repo.enabled}
                              onChange={(e) => toggleRepo(repo.full_name, e.target.checked)}
                              aria-label={`Include ${repo.full_name} in scheduled scan`}
                            />
                          </td>
                          <td>
                            {repo.enabled ? (
                              <span className="settings-priority-badge">{rank + 1}</span>
                            ) : (
                              <span className="settings-muted">n/a</span>
                            )}
                          </td>
                          <td>
                            <strong>{repo.full_name}</strong>
                            {repo.private && <span className="settings-repo-tag">private</span>}
                            {repo.missing && (
                              <span className="settings-repo-tag settings-repo-missing">
                                not in list
                              </span>
                            )}
                          </td>
                          <td className="settings-repo-actions">
                            {repo.enabled && (
                              <>
                                <button
                                  type="button"
                                  className="settings-icon-btn"
                                  disabled={rank <= 0}
                                  onClick={() => moveRepo(repo.full_name, "up")}
                                  title="Higher priority"
                                  aria-label="Move up"
                                >
                                  ↑
                                </button>
                                <button
                                  type="button"
                                  className="settings-icon-btn"
                                  disabled={rank < 0 || rank >= enabledSorted.length - 1}
                                  onClick={() => moveRepo(repo.full_name, "down")}
                                  title="Lower priority"
                                  aria-label="Move down"
                                >
                                  ↓
                                </button>
                              </>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {scanUsesRepos && config && !config.github_token_configured && (
              <p className="settings-warn">
                Server <code>GITHUB_TOKEN</code> is not set in <code>backend/.env</code>. Scheduled
                repo scans need a token on the server (OAuth session tokens are not available in
                the background).
              </p>
            )}
          </div>

          {!scanUsesRepos && (
            <div className="settings-field">
              <label htmlFor="scan-source">Demo scan label</label>
              <input
                id="scan-source"
                type="text"
                value={source}
                onChange={(e) => setSource(e.target.value)}
                placeholder="training-platform"
              />
              <span className="settings-hint">
                Used when no repositories are selected (demo payload scan).
              </span>
            </div>
          )}

          <div className="settings-field">
            <label htmlFor="scan-preset">Schedule</label>
            <select
              id="scan-preset"
              value={preset}
              onChange={(e) => setPreset(e.target.value)}
            >
              {CRON_PRESETS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>

          {preset === "custom" && (
            <div className="settings-field">
              <label htmlFor="scan-cron">Cron expression</label>
              <input
                id="scan-cron"
                type="text"
                value={customCron}
                onChange={(e) => setCustomCron(e.target.value)}
                placeholder="0 9 * * *"
              />
              <span className="settings-hint">Standard cron: minute hour day month weekday</span>
            </div>
          )}

          <div className="settings-schedule-meta">
            <span>
              <strong>Cron:</strong> <code>{cronExpr}</code>
            </span>
            {config?.next_run_at && enabled && (
              <span>
                <strong>Next run:</strong> {formatWhen(config.next_run_at)}
              </span>
            )}
            {scanUsesRepos && (
              <span>
                <strong>Mode:</strong> GitHub repos ({enabledCount})
              </span>
            )}
          </div>

          <div className="settings-actions">
            <button type="button" className="settings-btn primary" onClick={save} disabled={saving}>
              {saving ? "Saving…" : saved ? "Saved" : "Save schedule"}
            </button>
            <button type="button" className="settings-btn" onClick={runNow} disabled={running}>
              {running ? "Scanning…" : "Run scan now"}
            </button>
          </div>

          {error && <p className="settings-error">{error}</p>}

          {runs.length > 0 && (
            <div className="settings-runs">
              <h3>Recent scan results</h3>
              <ul className="settings-runs-list">
                {runs.map((run) => (
                  <li key={run.run_id} className={`settings-run settings-run-${run.status}`}>
                    <div className="settings-run-head">
                      <strong>
                        {run.scan_mode === "repos"
                          ? `${run.repos_scanned || 0} repo${run.repos_scanned === 1 ? "" : "s"}`
                          : run.source}
                      </strong>
                      <span>{formatWhen(run.finished_at || run.started_at)}</span>
                    </div>
                    <p className="settings-run-summary">
                      {run.status === "failed" && <>Failed: {run.error}</>}
                      {run.status === "completed" && (
                        <>
                          {run.has_issues ? (
                            <>
                              <span className="settings-run-bad">
                                {run.findings_count} issue{run.findings_count === 1 ? "" : "s"}
                                {run.repos_with_issues != null &&
                                  ` across ${run.repos_with_issues} repo${run.repos_with_issues === 1 ? "" : "s"}`}
                              </span>
                              {" · "}
                              decision <strong>{run.decision}</strong>
                              {" · "}
                              risk {isUnknown(run.risk_score) ? "n/a" : formatRisk(run.risk_score)}
                            </>
                          ) : (
                            <span className="settings-run-ok">No issues detected</span>
                          )}
                        </>
                      )}
                      {run.status === "running" && "Scan in progress…"}
                    </p>
                    {run.repo_results?.length > 0 && (
                      <ul className="settings-run-repos">
                        {run.repo_results.map((rr) => (
                          <li
                            key={rr.source}
                            className={rr.has_issues ? "settings-run-repo-bad" : ""}
                          >
                            <span>{rr.source}</span>
                            {rr.status === "failed" && <>, failed: {rr.error}</>}
                            {rr.status !== "failed" && (
                              <>
                                {" "}
                                : {rr.has_issues ? `${rr.findings_count} issues` : "clean"} (
                                {rr.decision})
                              </>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                    {!run.repo_results?.length && run.findings_preview?.length > 0 && (
                      <ul className="settings-run-findings">
                        {run.findings_preview.map((f, i) => (
                          <li key={`${f.repo || ""}-${f.package}-${f.attack_type}-${i}`}>
                            {f.repo ? `${f.repo}: ` : ""}
                            {f.package}: {f.message}
                          </li>
                        ))}
                      </ul>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </section>
  );
}
