/**
 * UniDetect Centralized API & WebSocket Client
 */

import type {
  AlertEvent,
  AlertsListResponse,
  ConnectionState,
  HealthResponse,
  MetricsResponse,
  ModelInfoResponse,
  StatusResponse,
} from "./types";

const API_BASE = (import.meta as any).env?.VITE_API_URL || "http://127.0.0.1:8000";
const WS_BASE = (import.meta as any).env?.VITE_WS_URL || "ws://127.0.0.1:8000/ws/alerts";

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error(`Health check failed: HTTP ${res.status}`);
  return res.json();
}

export async function fetchStatus(): Promise<StatusResponse> {
  const res = await fetch(`${API_BASE}/api/v1/status`);
  if (!res.ok) throw new Error(`Status fetch failed: HTTP ${res.status}`);
  return res.json();
}

export async function fetchAlerts(params?: {
  limit?: number;
  offset?: number;
  threat_class?: string;
  decision?: string;
}): Promise<AlertsListResponse> {
  const query = new URLSearchParams();
  if (params?.limit !== undefined) query.set("limit", params.limit.toString());
  if (params?.offset !== undefined) query.set("offset", params.offset.toString());
  if (params?.threat_class) query.set("threat_class", params.threat_class);
  if (params?.decision) query.set("decision", params.decision);

  const url = `${API_BASE}/api/v1/alerts${query.toString() ? `?${query.toString()}` : ""}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Alerts fetch failed: HTTP ${res.status}`);
  return res.json();
}

export async function fetchAlertById(alertId: string): Promise<AlertEvent> {
  const res = await fetch(`${API_BASE}/api/v1/alerts/${encodeURIComponent(alertId)}`);
  if (!res.ok) throw new Error(`Alert fetch failed: HTTP ${res.status}`);
  return res.json();
}

export async function fetchMetrics(): Promise<MetricsResponse> {
  const res = await fetch(`${API_BASE}/api/v1/metrics`);
  if (!res.ok) throw new Error(`Metrics fetch failed: HTTP ${res.status}`);
  return res.json();
}

export async function fetchModelInfo(): Promise<ModelInfoResponse> {
  const res = await fetch(`${API_BASE}/api/v1/model`);
  if (!res.ok) throw new Error(`Model info fetch failed: HTTP ${res.status}`);
  return res.json();
}

export async function ingestDemoAlert(alert: Partial<AlertEvent>): Promise<AlertEvent> {
  const res = await fetch(`${API_BASE}/api/v1/demo/alerts`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(alert),
  });
  if (!res.ok) throw new Error(`Demo alert ingestion failed: HTTP ${res.status}`);
  return res.json();
}

export async function clearBackendAlerts(): Promise<void> {
  const res = await fetch(`${API_BASE}/api/v1/alerts/clear`, {
    method: "POST",
  });
  if (!res.ok) throw new Error(`Clear alerts failed: HTTP ${res.status}`);
}

export async function updateAlertDecision(
  alertId: string,
  decision: "ANALYST_REVIEW" | "AUTOMATED_DETECTION" | "FALSE_POSITIVE"
): Promise<AlertEvent> {
  const res = await fetch(`${API_BASE}/api/v1/alerts/${encodeURIComponent(alertId)}/decision`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ decision }),
  });
  if (!res.ok) throw new Error(`Failed to update decision: HTTP ${res.status}`);
  return res.json();
}

export interface WebSocketSubscription {
  close: () => void;
}

/**
 * Creates a robust WebSocket connection with automatic exponential backoff reconnection.
 */
export function createAlertsWebSocket(
  onAlert: (alert: AlertEvent) => void,
  onStateChange: (state: ConnectionState) => void
): WebSocketSubscription {
  let ws: WebSocket | null = null;
  let isClosedManually = false;
  let reconnectAttempts = 0;
  let reconnectTimeout: any = null;

  const connect = () => {
    if (isClosedManually) return;

    onStateChange(reconnectAttempts > 0 ? "RECONNECTING" : "CONNECTING");

    try {
      ws = new WebSocket(WS_BASE);

      ws.onopen = () => {
        reconnectAttempts = 0;
        onStateChange("CONNECTED");
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data && data.alert_id) {
            onAlert(data as AlertEvent);
          }
        } catch (e) {
          console.error("Failed to parse WebSocket AlertEvent JSON:", e);
        }
      };

      ws.onerror = (err) => {
        console.warn("WebSocket connection encountered an error:", err);
      };

      ws.onclose = () => {
        if (isClosedManually) {
          onStateChange("DISCONNECTED");
          return;
        }

        onStateChange("DISCONNECTED");
        reconnectAttempts++;
        const delay = Math.min(1000 * Math.pow(1.5, reconnectAttempts), 10000);
        reconnectTimeout = setTimeout(() => {
          connect();
        }, delay);
      };
    } catch (e) {
      console.error("Failed to establish WebSocket connection:", e);
      onStateChange("DISCONNECTED");
      reconnectAttempts++;
      const delay = Math.min(1000 * Math.pow(1.5, reconnectAttempts), 10000);
      reconnectTimeout = setTimeout(connect, delay);
    }
  };

  connect();

  return {
    close: () => {
      isClosedManually = true;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (ws) ws.close();
      onStateChange("DISCONNECTED");
    },
  };
}
