import { useEffect, useRef, useState } from "react";

const WS_URL =
  (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/v1")
    .replace(/^http/, "ws")
    .replace(/\/v1$/, "") + "/v1/lab/ws/install-alerts";

/**
 * Connects to the backend WebSocket and returns:
 *  - alerts: array of all received install-alert objects (newest first)
 *  - newAlert: the most recent alert (used to trigger toast)
 *  - connected: boolean
 */
export function useInstallAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [newAlert, setNewAlert] = useState(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const reconnectTimer = useRef(null);

  function connect() {
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.type === "history") {
          setAlerts(msg.data || []);
        } else if (msg.type === "install_alert") {
          setAlerts((prev) => [msg.data, ...prev]);
          setNewAlert(msg.data);
        }
        // ignore ping
      } catch {
        /* malformed frame */
      }
    };

    ws.onclose = () => {
      setConnected(false);
      // Reconnect after 5 s
      reconnectTimer.current = setTimeout(connect, 5000);
    };

    ws.onerror = () => ws.close();
  }

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { alerts, newAlert, connected };
}
