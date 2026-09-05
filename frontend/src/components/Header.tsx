import React from "react";
import type { ConnectionState, HealthResponse } from "../api/types";
import type { TabType } from "./Sidebar";

interface HeaderProps {
  activeTab: TabType;
  connectionState: ConnectionState;
  health: HealthResponse | null;
  isStreamPaused: boolean;
  onTogglePause: () => void;
  onClearAlerts?: () => void;
  alertCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  connectionState,
  isStreamPaused,
  onTogglePause,
  onClearAlerts,
  alertCount,
}) => {
  const getTabLabel = (tab: TabType) => {
    switch (tab) {
      case "live":
        return "Live Monitoring";
      case "alerts":
        return "Alert History";
      case "analytics":
        return "Threat Analytics";
      case "model":
        return "Model Intelligence";
      case "status":
        return "System Health";
      default:
        return "Live Monitoring";
    }
  };

  const isConnected = connectionState === "CONNECTED";

  return (
    <header className="h-16 border-b border-[#1e1e24] bg-[#0a0a0c] flex items-center justify-between px-6 select-none flex-shrink-0 z-20">
      {/* SOC Top Navigation Breadcrumb */}
      <div className="flex items-center gap-2 text-sm font-medium">
        <span className="text-gray-400">UniDetect</span>
        <span className="text-gray-600 font-mono">/</span>
        <span className="text-white font-semibold">{getTabLabel(activeTab)}</span>
      </div>

      {/* Right side controls */}
      <div className="flex items-center gap-3">
        {/* Stream Pause / Resume */}
        <button
          onClick={onTogglePause}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all cursor-pointer ${
            isStreamPaused
              ? "bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20"
              : "bg-[#141417] text-gray-300 border-[#26262e] hover:text-white hover:bg-[#1a1a20]"
          }`}
          title={isStreamPaused ? "Resume Live Ingestion" : "Pause Live Ingestion"}
        >
          <span className="material-symbols-outlined text-base">
            {isStreamPaused ? "play_arrow" : "pause"}
          </span>
          <span>{isStreamPaused ? "Stream Paused" : "Stream Active"}</span>
        </button>

        {/* Clear Feed */}
        {onClearAlerts && alertCount > 0 && (
          <button
            onClick={onClearAlerts}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs text-gray-400 hover:text-red-400 bg-[#141417] border border-[#26262e] transition-colors cursor-pointer"
            title="Clear In-Memory Alert Stream"
          >
            <span className="material-symbols-outlined text-sm">delete_sweep</span>
            <span>Clear ({alertCount})</span>
          </button>
        )}

        {/* Status indicator badge */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#141417] border border-[#26262e] text-xs font-mono">
          <span
            className={`w-2 h-2 rounded-full ${
              isConnected ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
            }`}
          />
          <span className="text-gray-300 font-medium">
            {isConnected ? "LIVE WS" : "RECONNECTING"}
          </span>
        </div>

        {/* Utility Controls */}
        <div className="flex items-center bg-[#141417] border border-[#26262e] rounded-lg p-0.5 text-gray-400">
          <button
            onClick={() => {
              if (!document.fullscreenElement) {
                document.documentElement.requestFullscreen().catch(() => {});
              } else {
                document.exitFullscreen().catch(() => {});
              }
            }}
            className="p-1.5 hover:text-white transition-colors rounded cursor-pointer"
            title="Toggle Fullscreen SOC Mode"
          >
            <span className="material-symbols-outlined text-base">fullscreen</span>
          </button>
          <span
            className="p-1.5 text-gray-400"
            title="Passive Defense Mode Active"
          >
            <span className="material-symbols-outlined text-base">security</span>
          </span>
        </div>
      </div>
    </header>
  );
};
