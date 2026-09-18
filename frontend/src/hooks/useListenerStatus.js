/** Poll whether a real attacker listener (terminal script) is connected. */
import { useCallback, useEffect, useState } from "react";
import { api } from "../UTILS/api.js";

export function useListenerStatus(pollMs = 2500) {
  const [status, setStatus] = useState(null);
  const [backendOk, setBackendOk] = useState(null);

  const refresh = useCallback(async () => {
    try {
      await api.health();
      setBackendOk(true);
      const data = await api.labListenerStatus();
      setStatus(data);
    } catch {
      setBackendOk(false);
      setStatus(null);
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, pollMs);
    return () => window.clearInterval(id);
  }, [refresh, pollMs]);

  return {
    backendOk,
    listenerCount: status?.listener_count ?? 0,
    alertsTotal: status?.alerts_total ?? 0,
    listenerConnected: (status?.listener_count ?? 0) > 0,
    refresh,
  };
}
