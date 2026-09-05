import React from "react";
import type { MetricsResponse } from "../api/types";

interface ThreatDistributionProps {
  metrics: MetricsResponse | null;
  sessionClassCounts: Record<string, number>;
}

export const ThreatDistribution: React.FC<ThreatDistributionProps> = ({
  metrics,
  sessionClassCounts,
}) => {
  const counts = metrics?.per_class_counts ?? sessionClassCounts;

  const threatConfig: Record<string, { label: string; icon: string }> = {
    DDOS: { label: "DDoS Volumetric", icon: "crisis_alert" },
    RECON: { label: "Port Scan / Recon", icon: "radar" },
    DNS_TUNNEL: { label: "DNS Exfiltration", icon: "dns" },
    C2_BEACON: { label: "C2 Beaconing", icon: "router" },
    SLOW_HTTP: { label: "Slow HTTP DoS", icon: "hourglass_bottom" },
    BENIGN: { label: "Benign Baseline", icon: "check_circle" },
  };

  const totalCount = Object.values(counts).reduce((acc, v) => acc + v, 0);

  return (
    <div className="bg-[#131316] border border-[#222226] rounded-2xl p-6 flex flex-col justify-between shadow-sm">
      <div className="flex items-center justify-between pb-4 border-b border-[#222226] mb-4">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-xl bg-white text-black flex items-center justify-center shadow-sm">
            <span className="material-symbols-outlined text-base">donut_small</span>
          </div>
          <span className="font-bold text-white text-base">Threat Modality Breakdown</span>
        </div>
        <span className="font-mono text-xs text-gray-400">
          {totalCount.toLocaleString()} Total Inferences
        </span>
      </div>

      <div className="flex flex-col gap-3.5 flex-1 justify-center">
        {Object.entries(threatConfig).map(([key, cfg]) => {
          const count = counts[key] || 0;
          const pct = totalCount > 0 ? (count / totalCount) * 100 : 0;

          return (
            <div key={key} className="flex flex-col gap-1.5">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-gray-300 flex items-center gap-2">
                  <span className="material-symbols-outlined text-sm text-gray-400">
                    {cfg.icon}
                  </span>
                  {cfg.label}
                </span>
                <span className="text-gray-400">
                  <strong className="text-white">{count.toLocaleString()}</strong> ({pct.toFixed(1)}%)
                </span>
              </div>
              <div className="h-1.5 bg-[#1c1c22] rounded-full overflow-hidden">
                <div
                  className="h-full bg-white rounded-full transition-all duration-500"
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
