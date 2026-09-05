import React, { useEffect, useState, useRef } from "react";
import {
  createAlertsWebSocket,
  fetchAlerts,
  fetchHealth,
  fetchMetrics,
  fetchModelInfo,
  fetchStatus,
  clearBackendAlerts,
  updateAlertDecision,
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
import { Sidebar, type TabType } from "./components/Sidebar";
import { Header } from "./components/Header";
import { MetricCards } from "./components/MetricCards";
import { AlertTable, type TriageMode } from "./components/AlertTable";
import { AlertDetailsDrawer } from "./components/AlertDetailsDrawer";
import { ThreatPriorityBanner } from "./components/ThreatPriorityBanner";
import { ThreatDistribution } from "./components/ThreatDistribution";
import { ThreatAnalyticsView } from "./components/ThreatAnalyticsView";
import { ModelIntelligenceView } from "./components/ModelIntelligenceView";
import { SystemStatusView } from "./components/SystemStatusView";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>("live");
  const [alerts, setAlerts] = useState<AlertEvent[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertEvent | null>(null);
  const [connectionState, setConnectionState] = useState<ConnectionState>("CONNECTING");
  const [isStreamPaused, setIsStreamPaused] = useState(false);
  const [newAlertIds, setNewAlertIds] = useState<Set<string>>(new Set());
  const [triageMode, setTriageMode] = useState<TriageMode>("ALL");

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

  useEffect(() => {
    isPausedRef.current = isStreamPaused;
  }, [isStreamPaused]);

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
    let isMounted = true;

    const initTelemetry = async () => {
      try {
        const [h, s, m, info] = await Promise.allSettled([
          fetchHealth(),
          fetchStatus(),
          fetchMetrics(),
          fetchModelInfo(),
        ]);
        if (!isMounted) return;
        if (h.status === "fulfilled") setHealth(h.value);
        if (s.status === "fulfilled") setStatus(s.value);
        if (m.status === "fulfilled") setMetrics(m.value);
        if (info.status === "fulfilled") setModelInfo(info.value);
      } catch (e) {
        console.warn("Initial telemetry fetch error:", e);
      }
    };

    void initTelemetry();

    fetchAlerts({ limit: 50 })
      .then((res) => {
        if (!isMounted) return;
        if (res.items && res.items.length > 0) {
          setAlerts(res.items);
          setSelectedAlert(res.items[0]);
        }
      })
      .catch((err) => console.warn("Initial alerts fetch error:", err));

    const pollInterval = setInterval(() => {
      void refreshTelemetry();
    }, 3000);

    // Initialize WebSocket Streaming Connection
    wsSubscription.current = createAlertsWebSocket(
      (newAlert: AlertEvent) => {
        if (isPausedRef.current) return;

        setAlerts((prev) => {
          const updated = [newAlert, ...prev.filter((a) => a.alert_id !== newAlert.alert_id)].slice(0, 500);
          return updated;
        });

        // Trigger flash highlight for new alert
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
        if (newAlert.abstained || newAlert.decision === "ANALYST_REVIEW") {
          setSessionReviews((r) => r + 1);
        } else if (newAlert.predicted_label !== "BENIGN") {
          setSessionThreats((t) => t + 1);
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
      isMounted = false;
      clearInterval(pollInterval);
      if (wsSubscription.current) {
        wsSubscription.current.close();
      }
    };
  }, []);

  const handleClearAlerts = async () => {
    try {
      await clearBackendAlerts();
    } catch (e) {
      console.warn("Failed to clear backend alert store:", e);
    }
    setAlerts([]);
    setSelectedAlert(null);
    setSessionFlows(0);
    setSessionThreats(0);
    setSessionReviews(0);
    setSessionClasses({});
    await refreshTelemetry();
  };

  const handleInvestigateAlert = (alert: AlertEvent) => {
    setSelectedAlert(alert);
  };

  const handleToggleThreatsFilter = () => {
    setTriageMode((prev) => (prev === "THREATS_ONLY" ? "ALL" : "THREATS_ONLY"));
  };

  const handleUpdateDecision = async (
    newDecision: "ANALYST_REVIEW" | "AUTOMATED_DETECTION" | "FALSE_POSITIVE"
  ) => {
    if (!selectedAlert) return;
    const alertId = selectedAlert.alert_id;
    const isAbstained = newDecision === "ANALYST_REVIEW";

    // 1. Optimistic UI update
    const updatedAlert: AlertEvent = {
      ...selectedAlert,
      decision: newDecision,
      abstained: isAbstained,
    };
    setSelectedAlert(updatedAlert);
    setAlerts((prev) =>
      prev.map((a) => (a.alert_id === alertId ? updatedAlert : a))
    );

    // 2. Persist update to backend
    try {
      await updateAlertDecision(alertId, newDecision);
      void refreshTelemetry();
    } catch (e) {
      console.error("Failed to update alert decision:", e);
    }
  };

  const handleBatchUpdateDecision = async (
    alertIds: string[],
    newDecision: "ANALYST_REVIEW" | "AUTOMATED_DETECTION" | "FALSE_POSITIVE"
  ) => {
    if (alertIds.length === 0) return;
    const isAbstained = newDecision === "ANALYST_REVIEW";
    const idSet = new Set(alertIds);

    // Optimistic UI update
    setAlerts((prev) =>
      prev.map((a) =>
        idSet.has(a.alert_id)
          ? { ...a, decision: newDecision, abstained: isAbstained }
          : a
      )
    );
    if (selectedAlert && idSet.has(selectedAlert.alert_id)) {
      setSelectedAlert({
        ...selectedAlert,
        decision: newDecision,
        abstained: isAbstained,
      });
    }

    // Persist all updates to SQLite backend
    try {
      await Promise.allSettled(
        alertIds.map((id) => updateAlertDecision(id, newDecision))
      );
      void refreshTelemetry();
    } catch (e) {
      console.error("Failed batch decision update:", e);
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#0a0a0c] text-white antialiased font-sans select-none">
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={(tab) => setActiveTab(tab)}
        health={health}
        connectionState={connectionState}
      />

      {/* Main Workspace */}
      <main className="flex-1 flex flex-col h-screen overflow-hidden bg-[#0a0a0c]">
        {/* Top Header with Breadcrumbs & Global Actions */}
        <Header
          activeTab={activeTab}
          connectionState={connectionState}
          health={health}
          isStreamPaused={isStreamPaused}
          onTogglePause={() => setIsStreamPaused((p) => !p)}
          onClearAlerts={handleClearAlerts}
          alertCount={alerts.length}
        />

        {/* Multi-Page Views */}
        {activeTab === "status" && (
          <SystemStatusView
            health={health}
            status={status}
            metrics={metrics}
            connectionState={connectionState}
          />
        )}

        {activeTab === "analytics" && (
          <ThreatAnalyticsView
            alerts={alerts}
            metrics={metrics}
            sessionClasses={metrics?.per_class_counts ?? sessionClasses}
          />
        )}

        {activeTab === "model" && (
          <ModelIntelligenceView modelInfo={modelInfo} />
        )}

        {activeTab === "alerts" && (
          <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-4">
            <div className="flex justify-between items-center">
              <div>
                <h1 className="text-xl font-bold text-white font-mono">
                  Forensic Alert Archive
                </h1>
                <p className="text-xs text-gray-400">
                  Search, inspect, and export all historical flow records and threat classifications
                </p>
              </div>
            </div>

            <div className="flex-1 flex gap-5 min-h-[500px]">
              <div className="flex-1 flex flex-col min-w-0">
                <AlertTable
                  alerts={alerts}
                  selectedAlertId={selectedAlert?.alert_id ?? null}
                  onSelectAlert={(a) => setSelectedAlert(a)}
                  isStreamPaused={isStreamPaused}
                  newAlertIds={newAlertIds}
                  triageMode={triageMode}
                  onTriageModeChange={setTriageMode}
                  onBatchUpdateDecision={handleBatchUpdateDecision}
                />
              </div>

              {selectedAlert && (
                <div className="w-96 flex-shrink-0 flex flex-col">
                  <AlertDetailsDrawer
                    alert={selectedAlert}
                    onClose={() => setSelectedAlert(null)}
                    onUpdateDecision={handleUpdateDecision}
                  />
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "live" && (
          <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-4">
            {/* Top Compact Metric Summary Cards */}
            <MetricCards
              metrics={metrics}
              status={status}
              health={health}
              sessionFlowCount={sessionFlows}
              sessionThreatCount={sessionThreats}
              sessionReviewCount={sessionReviews}
            />

            {/* Active Threat Priority Incident Banner (Instantly highlights any detected attack) */}
            <ThreatPriorityBanner
              alerts={alerts}
              onInvestigate={handleInvestigateAlert}
              isFilteredToThreats={triageMode === "THREATS_ONLY"}
              onToggleThreatsFilter={handleToggleThreatsFilter}
            />

            {/* Main Work Area */}
            <div className="flex-1 flex flex-col lg:flex-row gap-4 min-h-[480px]">
              {/* Left Column: Live Traffic Stream with Triage Tabs */}
              <div className="flex-1 flex flex-col min-w-0">
                <AlertTable
                  alerts={alerts}
                  selectedAlertId={selectedAlert?.alert_id ?? null}
                  onSelectAlert={(a) => setSelectedAlert(a)}
                  isStreamPaused={isStreamPaused}
                  newAlertIds={newAlertIds}
                  triageMode={triageMode}
                  onTriageModeChange={setTriageMode}
                  onBatchUpdateDecision={handleBatchUpdateDecision}
                />
              </div>

              {/* Right Column: Forensic Details Drawer OR Quick Threat Modality Breakdown */}
              {selectedAlert ? (
                <div className="w-full lg:w-[420px] flex-shrink-0 flex flex-col">
                  <AlertDetailsDrawer
                    alert={selectedAlert}
                    onClose={() => setSelectedAlert(null)}
                    onUpdateDecision={handleUpdateDecision}
                  />
                </div>
              ) : (
                <div className="w-full lg:w-[320px] flex-shrink-0 flex flex-col gap-4">
                  <ThreatDistribution
                    metrics={metrics}
                    sessionClassCounts={metrics?.per_class_counts ?? sessionClasses}
                  />
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default App;
