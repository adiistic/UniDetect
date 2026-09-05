import React from "react";
import type { AlertEvent } from "../api/types";

interface ActivityTimelineProps {
  alerts: AlertEvent[];
}

export const ActivityTimeline: React.FC<ActivityTimelineProps> = ({ alerts }) => {
  const bucketCount = 14;
  const recentAlerts = alerts.slice(0, 140).reverse();

  const buckets: { threats: number; benign: number; reviews: number }[] = Array.from(
    { length: bucketCount },
    () => ({ threats: 0, benign: 0, reviews: 0 })
  );

  if (recentAlerts.length > 0) {
    const chunkSize = Math.max(1, Math.ceil(recentAlerts.length / bucketCount));
    recentAlerts.forEach((a, idx) => {
      const bIdx = Math.min(bucketCount - 1, Math.floor(idx / chunkSize));
      if (a.abstained || a.decision === "ANALYST_REVIEW") {
        buckets[bIdx].reviews++;
      } else if (a.predicted_label === "BENIGN") {
        buckets[bIdx].benign++;
      } else {
        buckets[bIdx].threats++;
      }
    });
  }

  const maxTotal = Math.max(1, ...buckets.map((b) => b.threats + b.benign + b.reviews));

  return (
    <div className="bg-[#131316] border border-[#222226] rounded-2xl p-6 flex flex-col justify-between shadow-sm">
      <div className="flex items-center justify-between pb-4 border-b border-[#222226] mb-4">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-xl bg-white text-black flex items-center justify-center shadow-sm">
            <span className="material-symbols-outlined text-base">bar_chart</span>
          </div>
          <span className="font-bold text-white text-base">Real-Time Ingestion Activity</span>
        </div>
        <div className="flex items-center gap-3 text-xs font-mono text-gray-400">
          <span className="flex items-center gap-1.5 text-red-400">
            <span className="w-2 h-2 bg-red-400 rounded-full" /> Threats
          </span>
          <span className="flex items-center gap-1.5 text-emerald-400">
            <span className="w-2 h-2 bg-emerald-400 rounded-full" /> Benign
          </span>
          <span className="flex items-center gap-1.5 text-purple-400">
            <span className="w-2 h-2 bg-purple-400 rounded-full" /> Review
          </span>
        </div>
      </div>

      {/* Chart Bars */}
      <div className="flex-1 flex items-end gap-2 py-2 min-h-[140px]">
        {buckets.map((b, i) => {
          const threatHeight = (b.threats / maxTotal) * 100;
          const benignHeight = (b.benign / maxTotal) * 100;
          const reviewHeight = (b.reviews / maxTotal) * 100;

          return (
            <div
              key={i}
              className="flex-1 h-full flex flex-col justify-end gap-1 group relative cursor-pointer"
              title={`Slot ${i + 1}: ${b.threats} Threats, ${b.benign} Benign, ${b.reviews} Reviews`}
            >
              {b.threats > 0 && (
                <div
                  className="bg-red-500 rounded-sm transition-all duration-300 group-hover:opacity-80"
                  style={{ height: `${threatHeight}%` }}
                />
              )}
              {b.reviews > 0 && (
                <div
                  className="bg-purple-400 rounded-sm transition-all duration-300 group-hover:opacity-80"
                  style={{ height: `${reviewHeight}%` }}
                />
              )}
              {b.benign > 0 && (
                <div
                  className="bg-emerald-500 rounded-sm transition-all duration-300 group-hover:opacity-80"
                  style={{ height: `${benignHeight}%` }}
                />
              )}
              {b.threats === 0 && b.benign === 0 && b.reviews === 0 && (
                <div className="h-1 bg-[#1c1c22] rounded-sm" />
              )}
            </div>
          );
        })}
      </div>

      {/* Timeline Footer */}
      <div className="flex justify-between text-xs text-gray-500 border-t border-[#222226] pt-3 mt-2 font-mono">
        <span>&larr; Earlier Stream</span>
        <span className="flex items-center gap-1 text-gray-400">
          <span className="material-symbols-outlined text-sm">schedule</span>
          Zeek Rolling Ingestion Tail
        </span>
        <span>Latest Flow &rarr;</span>
      </div>
    </div>
  );
};
