import React from "react";
import type { AlertEvent } from "../api/types";

interface AlertRowProps {
  alert: AlertEvent;
  isSelected: boolean;
  onSelect: (alert: AlertEvent) => void;
  isChecked?: boolean;
  onToggleCheck?: (alertId: string, checked: boolean) => void;
  isNew?: boolean;
}

export const AlertRow: React.FC<AlertRowProps> = ({
  alert,
  isSelected,
  onSelect,
  isChecked = false,
  onToggleCheck,
  isNew,
}) => {
  const getThreatBadge = (label: string) => {
    switch (label) {
      case "DDOS":
        return {
          dotClass: "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.7)]",
          textClass: "text-red-400 font-bold",
          barColor: "bg-red-500",
        };
      case "RECON":
        return {
          dotClass: "bg-purple-400 shadow-[0_0_8px_rgba(192,132,252,0.7)]",
          textClass: "text-purple-300 font-bold",
          barColor: "bg-purple-400",
        };
      case "DNS_TUNNEL":
        return {
          dotClass: "bg-orange-400 shadow-[0_0_8px_rgba(251,146,60,0.7)]",
          textClass: "text-orange-300 font-bold",
          barColor: "bg-orange-400",
        };
      case "C2_BEACON":
        return {
          dotClass: "bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.7)]",
          textClass: "text-cyan-300 font-bold",
          barColor: "bg-cyan-400",
        };
      case "SLOW_HTTP":
        return {
          dotClass: "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.7)]",
          textClass: "text-amber-300 font-bold",
          barColor: "bg-amber-400",
        };
      case "BENIGN":
      default:
        return {
          dotClass: "bg-emerald-500 opacity-70",
          textClass: "text-emerald-400 font-medium",
          barColor: "bg-emerald-500",
        };
    }
  };

  const badge = getThreatBadge(alert.predicted_label);

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

  const confidencePct = (alert.confidence * 100).toFixed(1);
  const latencyMs = alert.processing_time_ms ? `${alert.processing_time_ms.toFixed(1)} ms` : "< 1.0 ms";

  const isConfirmedThreat = alert.predicted_label !== "BENIGN" && !alert.abstained && alert.decision !== "ANALYST_REVIEW" && alert.decision !== "FALSE_POSITIVE";
  const isReview = alert.abstained || alert.decision === "ANALYST_REVIEW";
  const isFalsePositive = alert.decision === "FALSE_POSITIVE";

  const rowBackground = isSelected
    ? "bg-[#202028] border-l-4 border-l-white shadow-sm"
    : isNew
    ? "animate-row-flash bg-white/10"
    : isConfirmedThreat
    ? "bg-red-950/25 hover:bg-red-900/35 border-l-4 border-l-red-500"
    : isReview
    ? "bg-amber-950/20 hover:bg-amber-900/30 border-l-4 border-l-amber-400"
    : isFalsePositive
    ? "bg-gray-900/30 hover:bg-gray-800/40 border-l-4 border-l-gray-600 opacity-60"
    : "hover:bg-[#16161c] border-l-4 border-l-transparent";

  return (
    <tr
      onClick={() => onSelect(alert)}
      className={`transition-all group cursor-pointer select-none border-b border-[#1c1c22] ${rowBackground}`}
    >
      {/* Selector Checkbox for Batch Actions */}
      <td
        className="w-10 px-4 py-3 text-center"
        onClick={(e) => e.stopPropagation()}
      >
        <input
          type="checkbox"
          checked={isChecked}
          onChange={(e) => onToggleCheck?.(alert.alert_id, e.target.checked)}
          className="rounded border-[#33333e] bg-[#18181c] text-white focus:ring-0 cursor-pointer"
        />
      </td>

      {/* Timestamp */}
      <td className="px-4 py-3 font-mono text-xs text-gray-400 whitespace-nowrap">
        {formattedTime}
      </td>

      {/* Predicted Threat */}
      <td className="px-4 py-3 whitespace-nowrap">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full flex-shrink-0 ${badge.dotClass}`} />
          <span className={`font-mono text-xs ${badge.textClass}`}>
            {alert.predicted_label}
          </span>
        </div>
      </td>

      {/* Source */}
      <td className="px-4 py-3 font-mono text-xs text-gray-200 whitespace-nowrap">
        {alert.source_ip}:{alert.source_port}
      </td>

      {/* Destination */}
      <td className="px-4 py-3 font-mono text-xs text-gray-200 whitespace-nowrap">
        {alert.destination_ip}:{alert.destination_port}
      </td>

      {/* Protocol */}
      <td className="px-4 py-3 whitespace-nowrap">
        <span className="px-2 py-0.5 rounded-md text-[11px] font-mono bg-[#1c1c22] border border-[#282832] text-gray-300 uppercase">
          {alert.protocol}
        </span>
      </td>

      {/* Confidence */}
      <td className="px-4 py-3 whitespace-nowrap">
        <div className="flex items-center gap-2">
          <div className="w-16 h-1.5 bg-[#1e1e24] rounded-full overflow-hidden">
            <div
              className={`h-full ${badge.barColor}`}
              style={{ width: `${Math.min(100, Math.max(0, alert.confidence * 100))}%` }}
            />
          </div>
          <span className="font-mono text-xs text-gray-300 font-semibold">{confidencePct}%</span>
        </div>
      </td>

      {/* Decision */}
      <td className="px-4 py-3 whitespace-nowrap">
        {alert.decision === "FALSE_POSITIVE" ? (
          <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold bg-gray-500/20 text-gray-400 border border-gray-500/30">
            DISMISSED FP
          </span>
        ) : alert.abstained || alert.decision === "ANALYST_REVIEW" ? (
          <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40">
            IN REVIEW
          </span>
        ) : alert.predicted_label === "BENIGN" ? (
          <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
            NORMAL
          </span>
        ) : (
          <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold bg-red-500/10 text-red-300 border border-red-500/30">
            AUTOMATED
          </span>
        )}
      </td>

      {/* Latency */}
      <td className="px-4 py-3 font-mono text-xs text-gray-400 whitespace-nowrap">
        {latencyMs}
      </td>
    </tr>
  );
};
