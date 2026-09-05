import React from "react";
import type { HealthResponse, ConnectionState } from "../api/types";

export type TabType = "live" | "alerts" | "analytics" | "model" | "status";

interface SidebarProps {
  activeTab: TabType;
  onTabChange: (tab: TabType) => void;
  health: HealthResponse | null;
  connectionState: ConnectionState;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  connectionState,
}) => {
  const isConnected = connectionState === "CONNECTED";

  return (
    <nav className="w-64 h-screen bg-[#0e0e11] border-r border-[#1e1e24] flex flex-col justify-between p-4 select-none flex-shrink-0 z-30">
      <div className="flex flex-col gap-6">
        {/* Brand Block */}
        <div className="flex items-center justify-between pt-1">
          <div className="flex items-center gap-2.5">
            {/* White squircle icon badge */}
            <div className="w-9 h-9 rounded-xl bg-white flex items-center justify-center text-black shadow-sm flex-shrink-0">
              <span className="material-symbols-outlined text-xl" data-weight="fill">
                shield
              </span>
            </div>
            <div className="flex flex-col">
              <span className="font-bold text-sm text-white tracking-wider font-mono">
                UNIDETECT
              </span>
              <span className="text-[10px] text-gray-400 -mt-0.5 tracking-tight font-mono">
                AI Threat SOC
              </span>
            </div>
          </div>

          {/* Portal pill badge */}
          <div className="bg-[#18181c] border border-[#2a2a32] text-gray-400 text-[10px] font-semibold tracking-wider px-2 py-0.5 rounded-full uppercase">
            SOC PORTAL
          </div>
        </div>

        {/* Navigation Categories */}
        <div className="flex flex-col gap-5">
          {/* Section: GENERAL */}
          <div className="flex flex-col gap-1">
            <span className="text-[11px] font-semibold tracking-wider text-gray-500 uppercase px-2.5 mb-1 font-mono">
              GENERAL
            </span>

            <button
              onClick={() => onTabChange("live")}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-left w-full cursor-pointer ${
                activeTab === "live"
                  ? "bg-[#1e1e24] text-white border border-[#2e2e38] shadow-sm"
                  : "text-gray-400 hover:text-white hover:bg-[#16161a]"
              }`}
            >
              <span
                className="material-symbols-outlined text-lg"
                data-weight={activeTab === "live" ? "fill" : undefined}
              >
                stream
              </span>
              <span>Live Monitoring</span>
            </button>

            <button
              onClick={() => onTabChange("alerts")}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-left w-full cursor-pointer ${
                activeTab === "alerts"
                  ? "bg-[#1e1e24] text-white border border-[#2e2e38] shadow-sm"
                  : "text-gray-400 hover:text-white hover:bg-[#16161a]"
              }`}
            >
              <span
                className="material-symbols-outlined text-lg"
                data-weight={activeTab === "alerts" ? "fill" : undefined}
              >
                notifications
              </span>
              <span>Alert History</span>
            </button>
          </div>

          {/* Section: INTELLIGENCE */}
          <div className="flex flex-col gap-1">
            <span className="text-[11px] font-semibold tracking-wider text-gray-500 uppercase px-2.5 mb-1 font-mono">
              INTELLIGENCE
            </span>

            <button
              onClick={() => onTabChange("analytics")}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-left w-full cursor-pointer ${
                activeTab === "analytics"
                  ? "bg-[#1e1e24] text-white border border-[#2e2e38] shadow-sm"
                  : "text-gray-400 hover:text-white hover:bg-[#16161a]"
              }`}
            >
              <span
                className="material-symbols-outlined text-lg"
                data-weight={activeTab === "analytics" ? "fill" : undefined}
              >
                analytics
              </span>
              <span>Threat Analytics</span>
            </button>

            <button
              onClick={() => onTabChange("model")}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-left w-full cursor-pointer ${
                activeTab === "model"
                  ? "bg-[#1e1e24] text-white border border-[#2e2e38] shadow-sm"
                  : "text-gray-400 hover:text-white hover:bg-[#16161a]"
              }`}
            >
              <span
                className="material-symbols-outlined text-lg"
                data-weight={activeTab === "model" ? "fill" : undefined}
              >
                psychology
              </span>
              <span>Model Intelligence</span>
            </button>
          </div>

          {/* Section: SYSTEM */}
          <div className="flex flex-col gap-1">
            <span className="text-[11px] font-semibold tracking-wider text-gray-500 uppercase px-2.5 mb-1 font-mono">
              SYSTEM
            </span>

            <button
              onClick={() => onTabChange("status")}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-left w-full cursor-pointer ${
                activeTab === "status"
                  ? "bg-[#1e1e24] text-white border border-[#2e2e38] shadow-sm"
                  : "text-gray-400 hover:text-white hover:bg-[#16161a]"
              }`}
            >
              <span
                className="material-symbols-outlined text-lg"
                data-weight={activeTab === "status" ? "fill" : undefined}
              >
                query_stats
              </span>
              <span>System Health</span>
            </button>
          </div>
        </div>
      </div>

      {/* Sidebar Footer CTA Button */}
      <div className="flex flex-col gap-2 pt-4 border-t border-[#1e1e24]">
        <div className="flex items-center justify-between px-2 text-xs text-gray-400 mb-1">
          <span className="flex items-center gap-1.5 font-mono">
            <span
              className={`w-2 h-2 rounded-full ${
                isConnected ? "bg-emerald-500 animate-pulse" : "bg-amber-500"
              }`}
            />
            {isConnected ? "Zeek Connected" : "Connecting..."}
          </span>
          <span className="text-[10px] text-gray-500 font-mono">v1.0.0</span>
        </div>

        <div className="w-full bg-[#141418] text-gray-400 font-medium text-xs py-2.5 px-4 rounded-xl border border-[#24242c] text-center font-mono flex items-center justify-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span>Passive Observer Mode</span>
        </div>
      </div>
    </nav>
  );
};
