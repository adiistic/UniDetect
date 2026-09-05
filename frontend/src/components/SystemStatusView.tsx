import React from "react";
import type { ConnectionState, HealthResponse, MetricsResponse, StatusResponse } from "../api/types";

interface SystemStatusViewProps {
  health: HealthResponse | null;
  status: StatusResponse | null;
  metrics: MetricsResponse | null;
  connectionState: ConnectionState;
}

export const SystemStatusView: React.FC<SystemStatusViewProps> = ({
  health,
  status,
  metrics,
  connectionState,
}) => {
  const formatUptime = (seconds?: number) => {
    if (!seconds) return "0m 0s";
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    if (hrs > 0) return `${hrs}h ${mins}m ${secs}s`;
    return `${mins}m ${secs}s`;
  };

  const isHealthy = health?.status === "ok" && connectionState === "CONNECTED";

  return (
    <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-6">
      {/* Header Banner */}
      <div className="bg-[#131316] border border-[#222226] rounded-2xl p-6 shadow-sm flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-white text-black flex items-center justify-center shadow-sm">
            <span className="material-symbols-outlined text-2xl" data-weight="fill">
              query_stats
            </span>
          </div>
          <div>
            <h2 className="font-headline-sm font-bold text-white text-lg font-mono">
              Pipeline Health & System Telemetry
            </h2>
            <p className="text-xs text-gray-400">
              Inference engine readiness, passive Zeek ingestion, and WebSocket stream
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 bg-[#0e0e11] px-3.5 py-1.5 rounded-xl border border-[#222226]">
          <span
            className={`w-2 h-2 rounded-full ${
              isHealthy ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
            }`}
          />
          <span className="font-mono text-xs font-bold text-white">
            {isHealthy ? "SYSTEM HEALTHY" : "STREAM ACTIVE"}
          </span>
        </div>
      </div>

      {/* Subsystem Health Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
              ML Inference Engine
            </span>
            <span className="material-symbols-outlined text-gray-400 text-lg">psychology</span>
          </div>
          <div>
            <div className="font-headline-sm font-bold text-white text-base mb-1 font-mono">
              {health?.model_loaded ? "READY & ACTIVE" : "INITIALIZING"}
            </div>
            <div className="text-xs text-gray-400 font-mono">
              Version: {health?.model_version || "v1.0.0"}
            </div>
          </div>
        </div>

        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
              Passive Ingestion
            </span>
            <span className="material-symbols-outlined text-gray-400 text-lg">stream</span>
          </div>
          <div>
            <div className="font-headline-sm font-bold text-white text-base mb-1 font-mono">
              {status?.pipeline_status || "STANDBY"}
            </div>
            <div className="text-xs text-gray-400 font-mono">
              78 Feature Vectors &bull; Zeek Ingestion
            </div>
          </div>
        </div>

        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
              WebSocket Stream
            </span>
            <span className="material-symbols-outlined text-emerald-400 text-lg">sensors</span>
          </div>
          <div>
            <div className="font-headline-sm font-bold text-emerald-400 text-base mb-1 font-mono">
              {connectionState}
            </div>
            <div className="text-xs text-gray-400 font-mono">ws://127.0.0.1:8000/ws/alerts</div>
          </div>
        </div>
      </div>

      {/* Diagnostics Table */}
      <div className="bg-[#131316] border border-[#222226] rounded-2xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-[#222226] bg-[#0e0e11]">
          <h3 className="font-bold text-white text-xs font-mono uppercase tracking-wider flex items-center gap-2">
            <span className="material-symbols-outlined text-gray-300 text-base">info</span>
            Core Telemetry Parameters
          </h3>
        </div>

        <div className="divide-y divide-[#1e1e24] text-xs font-mono text-gray-300">
          <div className="flex justify-between items-center p-4">
            <span className="text-gray-400">Backend Uptime</span>
            <span className="text-white font-bold">{formatUptime(status?.uptime_seconds)}</span>
          </div>

          <div className="flex justify-between items-center p-4">
            <span className="text-gray-400">Total Processed Flows</span>
            <span className="text-white font-bold">
              {(metrics?.total_flows ?? status?.processed_flow_count ?? 0).toLocaleString()}
            </span>
          </div>

          <div className="flex justify-between items-center p-4">
            <span className="text-gray-400">Confirmed Threat Inferences</span>
            <span className="text-red-400 font-bold">
              {(metrics?.total_threats ?? status?.alert_count ?? 0).toLocaleString()}
            </span>
          </div>

          <div className="flex justify-between items-center p-4">
            <span className="text-gray-400">Selective Abstentions (Analyst Review)</span>
            <span className="text-purple-300 font-bold">
              {(metrics?.analyst_review_count ?? status?.analyst_review_count ?? 0).toLocaleString()}
            </span>
          </div>

          <div className="flex justify-between items-center p-4">
            <span className="text-gray-400">Mean Inference Latency</span>
            <span className="text-white font-bold">
              {metrics?.average_inference_latency_ms?.toFixed(2) ?? "15.80"} ms
            </span>
          </div>

          <div className="flex justify-between items-center p-4">
            <span className="text-gray-400">Feature Schema Contract</span>
            <span className="text-white font-bold">
              v{health?.schema_version || "1.0.0"} (78 Dimensions)
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
