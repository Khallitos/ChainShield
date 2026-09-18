import { useCallback, useEffect, useState } from "react";
import { api } from "../UTILS/api.js";

export function useMlModel() {
  const [info, setInfo] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const modelInfo = await api.mlModelInfo();
      setInfo(modelInfo);
      try {
        const m = await api.mlMetrics();
        setMetrics(m);
      } catch {
        setMetrics(modelInfo.metrics_summary ? { ...modelInfo.metrics_summary, model_version: modelInfo.model_version } : null);
      }
    } catch (err) {
      setError(err.message);
      setInfo(null);
      setMetrics(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  return { info, metrics, loading, error, reload };
}
