import React, { useEffect, useState, useRef } from "react";
import {
  createAlertsWebSocket,
  fetchAlerts,
  fetchHealth,
  fetchMetrics,
  fetchModelInfo,
  fetchStatus,
} from "./api/client";
import type { WebSocketSubscription } from "./api/client";
import type {
  AlertEvent,
  ConnectionState,
  HealthResponse,
  MetricsResponse,
  ModelInfoResponse,
  StatusResponse,
} from "./api/types";
import { Header } from "./components/Header";
import { MetricCards } from "./components/MetricCards";
import { ThreatDistribution } from "./components/ThreatDistribution";
import { ActivityTimeline } from "./components/ActivityTimeline";
import { AlertTable } from "./components/AlertTable";
import { AlertDetailsModal } from "./components/AlertDetailsModal";
import { ModelStatusDrawer } from "./components/ModelStatusDrawer";

export const App: React.FC = () => {
  const [alerts, setAlerts] = useState<AlertEvent[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertEvent | null>(null);
  const [isModelDrawerOpen, setIsModelDrawerOpen] = useState(false);
  const [connectionState, setConnectionState] = useState<ConnectionState>("CONNECTING");
  const [isStreamPaused, setIsStreamPaused] = useState(false);
  const [newAlertIds, setNewAlertIds] = useState<Set<string>>(new Set());

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [modelInfo, setModelInfo] = useState<ModelInfoResponse | null>(null);

  const [sessionFlows, setSessionFlows] = useState(0);
  const [sessionThreats, setSessionThreats] = useState(0);
  const [sessionReviews, setSessionReviews] = useState(0);
  const [sessionClasses, setSessionClasses] = useState<Record<string, number>>({});

  const wsSubscription = useRef<WebSocketSubscription | null>(null);
  const isPausedRef = useRef(isStreamPaused);
  isPausedRef.current = isStreamPaused;

  // Poll Telemetry Endpoints Periodically
  const refreshTelemetry = async () => {
    try {
      const [h, s, m, info] = await Promise.allSettled([
        fetchHealth(),
        fetchStatus(),
        fetchMetrics(),
        fetchModelInfo(),
      ]);
      if (h.status === "fulfilled") setHealth(h.value);
      if (s.status === "fulfilled") setStatus(s.value);
      if (m.status === "fulfilled") setMetrics(m.value);
      if (info.status === "fulfilled") setModelInfo(info.value);
    } catch (e) {
      console.warn("Failed to poll telemetry endpoints:", e);
    }
  };

  useEffect(() => {
    // Initial fetch of stored alerts & telemetry
    refreshTelemetry();

    fetchAlerts({ limit: 50 })
      .then((res) => {
        if (res.items && res.items.length > 0) {
          setAlerts(res.items);
        }
      })
      .catch((err) => console.warn("Initial alerts fetch error:", err));

    const pollInterval = setInterval(refreshTelemetry, 3000);

    // Initialize WebSocket Streaming Connection
    wsSubscription.current = createAlertsWebSocket(
      (newAlert: AlertEvent) => {
        if (isPausedRef.current) return;

        setAlerts((prev) => {
          // Bounded client-side queue of 500 alerts
          const updated = [newAlert, ...prev.filter((a) => a.alert_id !== newAlert.alert_id)].slice(0, 500);
          return updated;
        });

        // Trigger brief flash highlight for new alert
        setNewAlertIds((prev) => {
          const next = new Set(prev);
          next.add(newAlert.alert_id);
          return next;
        });

        setTimeout(() => {
          setNewAlertIds((prev) => {
            const next = new Set(prev);
            next.delete(newAlert.alert_id);
            return next;
          });
        }, 1500);

        // Update session counters
        setSessionFlows((c) => c + 1);
        if (newAlert.abstained) {
          setSessionReviews((c) => c + 1);
        } else if (newAlert.predicted_label !== "BENIGN") {
          setSessionThreats((c) => c + 1);
        }

        setSessionClasses((prev) => ({
          ...prev,
          [newAlert.predicted_label]: (prev[newAlert.predicted_label] || 0) + 1,
        }));
      },
      (state: ConnectionState) => {
        setConnectionState(state);
      }
    );

    return () => {
      clearInterval(pollInterval);
      if (wsSubscription.current) {
        wsSubscription.current.close();
      }
    };
  }, []);

  const handleClearAlerts = () => {
    setAlerts([]);
    setSessionFlows(0);
    setSessionThreats(0);
    setSessionReviews(0);
    setSessionClasses({});
  };

  return (
    <div className="dashboard-container">
      <Header
        connectionState={connectionState}
        health={health}
        onOpenModelDrawer={() => setIsModelDrawerOpen(true)}
        onClearAlerts={handleClearAlerts}
        alertCount={alerts.length}
      />

      <main className="dashboard-main">
        {/* Metric Overview Cards */}
        <MetricCards
          metrics={metrics}
          status={status}
          sessionFlowCount={sessionFlows}
          sessionThreatCount={sessionThreats}
          sessionReviewCount={sessionReviews}
        />

        {/* Analytics & Modality Charts */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.3fr", gap: "1.25rem", minHeight: "220px" }}>
          <ThreatDistribution metrics={metrics} sessionClassCounts={sessionClasses} />
          <ActivityTimeline alerts={alerts} />
        </div>

        {/* Live Streaming Alert Table */}
        <AlertTable
          alerts={alerts}
          onSelectAlert={(a) => setSelectedAlert(a)}
          isStreamPaused={isStreamPaused}
          onTogglePause={() => setIsStreamPaused((p) => !p)}
          newAlertIds={newAlertIds}
        />
      </main>

      {/* Forensic Modal Inspector */}
      <AlertDetailsModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />

      {/* Frozen ML Model Spec Drawer */}
      <ModelStatusDrawer
        modelInfo={modelInfo}
        isOpen={isModelDrawerOpen}
        onClose={() => setIsModelDrawerOpen(false)}
      />
    </div>
  );
};

export default App;
