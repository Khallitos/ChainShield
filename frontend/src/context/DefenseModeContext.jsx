import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api } from "../UTILS/api.js";

const STORAGE_KEY = "scr-blocking-enabled";

function readBlocking() {
  try {
    return localStorage.getItem(STORAGE_KEY) !== "false";
  } catch {
    return true;
  }
}

const DefenseModeContext = createContext(null);

export function DefenseModeProvider({ children }) {
  const [blockingEnabled, setBlockingEnabledState] = useState(readBlocking);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await api.getProtection();
        if (!cancelled && typeof data.enabled === "boolean") {
          setBlockingEnabledState(data.enabled);
          try {
            localStorage.setItem(STORAGE_KEY, data.enabled ? "true" : "false");
          } catch {
            /* ignore */
          }
        }
      } catch {
        /* backend unavailable, keep local preference */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const setBlockingEnabled = useCallback((enabled) => {
    setBlockingEnabledState(enabled);
    try {
      localStorage.setItem(STORAGE_KEY, enabled ? "true" : "false");
    } catch {
      /* ignore */
    }
    api.setProtection(enabled).catch(() => {
      /* sync best-effort */
    });
  }, []);

  const config = useMemo(
    () => ({
      api: blockingEnabled ? "hybrid" : "unblocked",
      label: blockingEnabled ? "Protection on" : "Protection off",
      blockingEnabled,
    }),
    [blockingEnabled]
  );

  return (
    <DefenseModeContext.Provider value={{ blockingEnabled, setBlockingEnabled, config }}>
      {children}
    </DefenseModeContext.Provider>
  );
}

export function useDefenseMode() {
  const ctx = useContext(DefenseModeContext);
  if (!ctx) throw new Error("useDefenseMode must be used within DefenseModeProvider");
  return ctx;
}
