import React from "react";
import type { AlertEvent } from "../api/types";

interface ThreatPriorityBannerProps {
  alerts: AlertEvent[];
  onInvestigate: (alert: AlertEvent) => void;
  isFilteredToThreats: boolean;
  onToggleThreatsFilter: () => void;
}

export const ThreatPriorityBanner: React.FC<ThreatPriorityBannerProps> = ({
  alerts,
  onInvestigate,
  isFilteredToThreats,
  onToggleThreatsFilter,
}) => {
  // Find all flagged events (confirmed threats or abstained analyst reviews)
  const flaggedAlerts = alerts.filter(
    (a) => a.predicted_label !== "BENIGN" || a.abstained || a.decision === "ANALYST_REVIEW"
  );
  const confirmedCount = flaggedAlerts.filter((a) => !a.abstained && a.decision !== "ANALYST_REVIEW").length;
  const reviewCount = flaggedAlerts.filter((a) => a.abstained || a.decision === "ANALYST_REVIEW").length;

  const latestFlagged = flaggedAlerts.length > 0 ? flaggedAlerts[0] : null;

  // Case 1: No threats or reviews detected
  if (!latestFlagged) {
    return (
      <div className="bg-[#101014] border border-[#1f1f26] rounded-2xl px-5 py-3.5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center flex-shrink-0">
            <span className="material-symbols-outlined text-lg">verified_user</span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                Normal Baseline Activity
              </span>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            </div>
            <p className="text-xs text-gray-400">
              Zero active threats detected across {alerts.length} monitored flows. Out-of-band passive telemetry healthy.
            </p>
          </div>
        </div>

        <div className="text-xs font-mono text-gray-500 bg-[#16161c] px-3 py-1.5 rounded-lg border border-[#24242e]">
          PASSIVE OBSERVER • ALL PROTOCOLS
        </div>
      </div>
    );
  }

  // Case 2: Threat or Review Flagged
  const isConfirmed = !latestFlagged.abstained && latestFlagged.decision !== "ANALYST_REVIEW";

  return (
    <div
      className={`rounded-2xl p-5 border shadow-lg transition-all ${
        isConfirmed
          ? "bg-gradient-to-r from-red-950/40 via-[#181114] to-[#121216] border-red-500/40 shadow-red-950/20"
          : "bg-gradient-to-r from-amber-950/40 via-[#181511] to-[#121216] border-amber-500/40 shadow-amber-950/20"
      }`}
    >
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        {/* Threat Alert Info */}
        <div className="flex items-start gap-3.5">
          <div
            className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 shadow-md ${
              isConfirmed
                ? "bg-red-500 text-white animate-pulse"
                : "bg-amber-400 text-black animate-pulse"
            }`}
          >
            <span className="material-symbols-outlined text-xl">
              {isConfirmed ? "crisis_alert" : "notification_important"}
            </span>
          </div>

          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span
                className={`text-xs font-black font-mono px-2.5 py-0.5 rounded-md uppercase tracking-wider ${
                  isConfirmed ? "bg-red-500/20 text-red-300 border border-red-500/40" : "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                }`}
              >
                {latestFlagged.predicted_label}
              </span>

              <span className="text-sm font-bold text-white font-mono">
                {latestFlagged.source_ip}:{latestFlagged.source_port} &rarr; {latestFlagged.destination_ip}:{latestFlagged.destination_port}
              </span>

              <span className="text-xs font-mono text-gray-400 uppercase bg-[#181820] px-2 py-0.5 rounded border border-[#282834]">
                {latestFlagged.protocol}
              </span>

              <span className="text-xs font-mono text-gray-300">
                Confidence: <strong className="text-white">{(latestFlagged.confidence * 100).toFixed(1)}%</strong>
              </span>

              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-semibold ${
                  isConfirmed ? "text-cyan-400 bg-cyan-950/40 border border-cyan-800/40" : "text-purple-300 bg-purple-950/40 border border-purple-800/40"
                }`}
              >
                {latestFlagged.decision}
              </span>
            </div>

            <div className="flex items-center gap-2 mt-0.5">
              <span className="text-[10px] font-mono text-gray-300 bg-black/40 px-2 py-0.5 rounded border border-white/10">
                {confirmedCount} Confirmed • {reviewCount} In Review
              </span>
              <p className="text-xs text-gray-300">
                {isConfirmed
                  ? `High-confidence threat detected. Automated defensive policy flagged this connection.`
                  : `Ambiguous connection profile. ML confidence is below 40% threshold (sent to Tier-2 Analyst Review).`}
              </p>
            </div>
          </div>
        </div>

        {/* Quick Triage Actions */}
        <div className="flex items-center gap-2.5 flex-shrink-0 w-full lg:w-auto justify-end">
          <button
            onClick={() => onInvestigate(latestFlagged)}
            className="flex-1 lg:flex-initial flex items-center justify-center gap-2 px-4 py-2 rounded-xl text-xs font-bold text-black bg-white hover:bg-gray-100 transition-all shadow-md cursor-pointer active:scale-95"
            title="Inspect 78 Feature Vectors & Probabilities"
          >
            <span className="material-symbols-outlined text-base">troubleshoot</span>
            <span>Investigate Incident</span>
          </button>

          <button
            onClick={onToggleThreatsFilter}
            className={`flex-1 lg:flex-initial flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold border transition-all cursor-pointer ${
              isFilteredToThreats
                ? "bg-white/10 text-white border-white/30"
                : "bg-[#16161c] text-gray-300 border-[#282834] hover:text-white hover:border-[#383848]"
            }`}
            title="Filter live table to flagged threats and reviews only"
          >
            <span className="material-symbols-outlined text-base">filter_list</span>
            <span>
              {isFilteredToThreats ? "Show All Traffic" : `Threats Only (${flaggedAlerts.length})`}
            </span>
          </button>
        </div>
      </div>
    </div>
  );
};
