import { useCallback, useEffect, useState } from "react";
import { api } from "../UTILS/api.js";

export function useOverviewDashboard({ defenseApi, selectedRepo, refreshKey = 0 }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const owner =
        typeof selectedRepo?.owner === "string"
          ? selectedRepo.owner
          : selectedRepo?.owner?.login;
      const payload = await api.overviewDashboard({
        defenseMode: defenseApi,
        owner,
        repo: selectedRepo?.name,
      });
      setData(payload);
    } catch (err) {
      setError(err.message || "Could not load overview");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [defenseApi, selectedRepo?.owner, selectedRepo?.name]);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  return { data, loading, error, reload: load };
}
