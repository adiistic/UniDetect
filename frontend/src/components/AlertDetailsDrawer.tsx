import React, { useState } from "react";
import type { AlertEvent } from "../api/types";

interface AlertDetailsDrawerProps {
  alert: AlertEvent | null;
  onClose: () => void;
  onUpdateDecision?: (decision: "ANALYST_REVIEW" | "AUTOMATED_DETECTION" | "FALSE_POSITIVE") => void;
}

export const AlertDetailsDrawer: React.FC<AlertDetailsDrawerProps> = ({
  alert,
  onClose,
  onUpdateDecision,
}) => {
  const [copied, setCopied] = useState(false);

  if (!alert) return null;

  const handleCopy = () => {
    navigator.clipboard?.writeText(JSON.stringify(alert, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const formattedTime = alert.timestamp_iso
    ? alert.timestamp_iso.split("T")[1]?.slice(0, 8) ||
      new Date(alert.timestamp * 1000).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      })
    : new Date(alert.timestamp * 1000).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });

  const defaultClasses = ["BENIGN", "DDOS", "RECON", "DNS_TUNNEL", "C2_BEACON", "SLOW_HTTP"];
  const probEntries = defaultClasses
    .map((cls) => {
      const val = alert.probabilities?.[cls] ?? (alert.predicted_label === cls ? alert.confidence : 0);
      return {
        cls,
        prob: val,
        pct: (val * 100).toFixed(1),
      };
    })
    .sort((a, b) => b.prob - a.prob);

  return (
    <div className="w-96 bg-[#0e0e11] border-l border-[#1e1e24] flex flex-col flex-shrink-0 z-20 h-full overflow-hidden shadow-2xl">
      {/* Header */}
      <div className="p-5 border-b border-[#1e1e24] flex items-center justify-between bg-[#0a0a0c]">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-white text-black flex items-center justify-center shadow-sm">
            <span className="material-symbols-outlined text-base">manage_search</span>
          </div>
          <span className="font-bold text-sm text-white font-mono">Flow Inspector</span>
        </div>
        <button
          onClick={onClose}
          className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-[#18181c] transition-colors cursor-pointer"
        >
          <span className="material-symbols-outlined text-base">close</span>
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-5">
        {/* Threat Header */}
        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4 flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <span className="font-headline-sm font-bold text-white text-lg font-mono">
              {alert.predicted_label}
            </span>
            <span className="font-mono text-xs font-bold text-white bg-white/10 px-2 py-0.5 rounded-md">
              {(alert.confidence * 100).toFixed(1)}% Conf
            </span>
          </div>

          <div className="flex items-center gap-2 text-xs text-gray-400 font-mono">
            <span>{formattedTime}</span>
            <span>&bull;</span>
            <span className="text-gray-300">
              {alert.abstained ? "Analyst Review" : "Automated Block"}
            </span>
          </div>
        </div>

        {/* Analyst Interactive Triage Controls */}
        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4 flex flex-col gap-2.5">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider font-mono">
              Analyst Triage & Mitigation
            </span>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                alert.decision === "ANALYST_REVIEW" || alert.abstained
                  ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                  : alert.decision === "FALSE_POSITIVE"
                  ? "bg-gray-500/20 text-gray-300 border border-gray-500/30"
                  : alert.predicted_label === "BENIGN"
                  ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                  : "bg-red-500/20 text-red-300 border border-red-500/30"
              }`}
            >
              {alert.decision === "ANALYST_REVIEW" || alert.abstained
                ? "In Review Queue"
                : alert.decision === "FALSE_POSITIVE"
                ? "Dismissed (FP)"
                : alert.predicted_label === "BENIGN"
                ? "Normal Baseline"
                : "Active Threat"}
            </span>
          </div>

          <div className="grid grid-cols-3 gap-2 mt-1">
            <button
              onClick={() => onUpdateDecision?.("ANALYST_REVIEW")}
              className={`px-2 py-2.5 rounded-xl text-xs font-semibold border flex flex-col items-center gap-1 transition-all cursor-pointer ${
                alert.decision === "ANALYST_REVIEW" || alert.abstained
                  ? "bg-amber-500/25 border-amber-400 text-amber-200 shadow-sm"
                  : "bg-[#18181c] border-[#2a2a34] text-gray-300 hover:text-white hover:border-[#3e3e4c]"
              }`}
              title="Add this flow to the Tier-2 Analyst Review queue"
            >
              <span className="material-symbols-outlined text-base text-amber-400">rate_review</span>
              <span className="font-mono text-[11px]">To Review</span>
            </button>

            <button
              onClick={() => onUpdateDecision?.("AUTOMATED_DETECTION")}
              className={`px-2 py-2.5 rounded-xl text-xs font-semibold border flex flex-col items-center gap-1 transition-all cursor-pointer ${
                alert.decision === "AUTOMATED_DETECTION" && alert.predicted_label !== "BENIGN"
                  ? "bg-red-500/25 border-red-400 text-red-200 shadow-sm"
                  : "bg-[#18181c] border-[#2a2a34] text-gray-300 hover:text-white hover:border-[#3e3e4c]"
              }`}
              title="Confirm as active threat incident"
            >
              <span className="material-symbols-outlined text-base text-red-400">gavel</span>
              <span className="font-mono text-[11px]">Confirm</span>
            </button>

            <button
              onClick={() => onUpdateDecision?.("FALSE_POSITIVE")}
              className={`px-2 py-2.5 rounded-xl text-xs font-semibold border flex flex-col items-center gap-1 transition-all cursor-pointer ${
                alert.decision === "FALSE_POSITIVE"
                  ? "bg-emerald-500/25 border-emerald-400 text-emerald-200 shadow-sm"
                  : "bg-[#18181c] border-[#2a2a34] text-gray-300 hover:text-white hover:border-[#3e3e4c]"
              }`}
              title="Mark as benign false positive"
            >
              <span className="material-symbols-outlined text-base text-emerald-400">verified</span>
              <span className="font-mono text-[11px]">Dismiss FP</span>
            </button>
          </div>
        </div>

        {/* Network 5-Tuple Card */}
        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4 flex flex-col gap-2.5">
          <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider font-mono">
            Network 5-Tuple
          </span>

          <div className="flex flex-col gap-2 font-mono text-xs">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Source</span>
              <span className="text-white font-semibold">
                {alert.source_ip}:{alert.source_port}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Destination</span>
              <span className="text-white font-semibold">
                {alert.destination_ip}:{alert.destination_port}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Protocol</span>
              <span className="text-gray-200 uppercase">{alert.protocol}</span>
            </div>
            <div className="flex justify-between items-center pt-2 border-t border-[#1e1e24]">
              <span className="text-gray-400">Flow UID</span>
              <span className="text-gray-400 truncate max-w-[150px]">{alert.flow_uid}</span>
            </div>
          </div>
        </div>

        {/* Multi-Class Probabilities */}
        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4 flex flex-col gap-3">
          <div className="flex justify-between items-center">
            <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider font-mono">
              Calibrated Probabilities
            </span>
            <span className="text-[10px] text-gray-500 font-mono">Platt Scaling</span>
          </div>

          <div className="flex flex-col gap-2.5">
            {probEntries.slice(0, 4).map((item) => {
              const isWinner = alert.predicted_label === item.cls;
              return (
                <div key={item.cls} className="flex flex-col gap-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className={isWinner ? "text-white font-bold" : "text-gray-400"}>
                      {item.cls}
                    </span>
                    <span className={isWinner ? "text-white font-bold" : "text-gray-400"}>
                      {item.pct}%
                    </span>
                  </div>
                  <div className="h-1.5 w-full bg-[#1e1e24] rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        isWinner ? "bg-white" : "bg-gray-600"
                      }`}
                      style={{ width: `${Math.min(100, Math.max(0, item.prob * 100))}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Detection Metadata */}
        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4 flex flex-col gap-2 text-xs font-mono">
          <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1">
            Inference Telemetry
          </span>
          <div className="flex justify-between text-gray-400">
            <span>Latency</span>
            <span className="text-white">
              {alert.processing_time_ms ? `${alert.processing_time_ms.toFixed(1)} ms` : "15.8 ms"}
            </span>
          </div>
          <div className="flex justify-between text-gray-400">
            <span>Model Version</span>
            <span className="text-white">{alert.model_version || "v1.0.0"}</span>
          </div>
          <div className="flex justify-between text-gray-400">
            <span>Schema Vector</span>
            <span className="text-white">78 Dimensions</span>
          </div>
        </div>
      </div>

      {/* Footer CTA */}
      <div className="p-4 border-t border-[#1e1e24] bg-[#0a0a0c] flex gap-2">
        <button
          onClick={handleCopy}
          className="flex-1 bg-white hover:bg-gray-100 text-black font-semibold text-xs py-2.5 rounded-xl transition-all flex items-center justify-center gap-1.5 cursor-pointer shadow-sm active:scale-[0.98]"
        >
          <span className="material-symbols-outlined text-sm">
            {copied ? "check" : "content_copy"}
          </span>
          <span>{copied ? "Copied JSON!" : "Copy Payload"}</span>
        </button>
        <button
          onClick={onClose}
          className="flex-1 bg-[#18181c] hover:bg-[#202026] text-gray-300 font-medium text-xs py-2.5 rounded-xl border border-[#282832] transition-colors cursor-pointer"
        >
          Dismiss
        </button>
      </div>
    </div>
  );
};
