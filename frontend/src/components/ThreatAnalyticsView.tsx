import React from "react";
import type { AlertEvent, MetricsResponse } from "../api/types";
import { ActivityTimeline } from "./ActivityTimeline";
import { ThreatDistribution } from "./ThreatDistribution";

interface ThreatAnalyticsViewProps {
  alerts: AlertEvent[];
  metrics: MetricsResponse | null;
  sessionClasses: Record<string, number>;
}

export const ThreatAnalyticsView: React.FC<ThreatAnalyticsViewProps> = ({
  alerts,
  metrics,
  sessionClasses,
}) => {
  const counts = metrics?.per_class_counts ?? sessionClasses;
  const totalInferences = metrics?.total_flows ?? alerts.length;
  const threatCount = metrics?.total_threats ?? alerts.filter((a) => a.predicted_label !== "BENIGN").length;
  const reviewCount = metrics?.analyst_review_count ?? alerts.filter((a) => a.abstained).length;
  const avgLatency = metrics?.average_inference_latency_ms ?? 0.0;
  const p95Latency = metrics?.p95_latency_ms ?? 0.0;

  // Compute protocol distribution from alerts
  const protoCounts: Record<string, number> = {};
  alerts.forEach((a) => {
    const p = (a.protocol || "OTHER").toUpperCase();
    protoCounts[p] = (protoCounts[p] || 0) + 1;
  });
  const totalSampleProtocols = Object.values(protoCounts).reduce((a, b) => a + b, 0);

  return (
    <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-6 select-none bg-[#0a0a0c]">
      {/* Header Banner */}
      <div className="bg-[#131316] border border-[#222226] rounded-2xl p-6 shadow-sm flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-white text-black flex items-center justify-center shadow-sm">
            <span className="material-symbols-outlined text-2xl" data-weight="fill">
              analytics
            </span>
          </div>
          <div>
            <h2 className="font-bold text-white text-lg font-mono">
              Threat Telemetry & Attack Analytics
            </h2>
            <p className="text-xs text-gray-400">
              Multi-modal distribution, historical ingestion activity, and real-time inference latency
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs text-gray-400">
          <span className="bg-[#16161c] px-3 py-1.5 rounded-xl border border-[#26262e]">
            {totalInferences.toLocaleString()} Inferences Evaluated
          </span>
          <span className="bg-[#16161c] px-3 py-1.5 rounded-xl border border-[#26262e] text-red-400">
            {threatCount.toLocaleString()} Confirmed Attacks
          </span>
        </div>
      </div>

      {/* Latency & Protocol KPIs */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
            Mean Inference Speed
          </span>
          <div className="text-xl font-bold text-white font-mono mt-1">
            {avgLatency > 0 ? `${avgLatency.toFixed(2)} ms` : "< 2.0 ms"}
          </div>
          <span className="text-xs text-gray-500 font-mono">Real-time Scikit-Learn evaluation</span>
        </div>

        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
            P95 Latency Bound
          </span>
          <div className="text-xl font-bold text-white font-mono mt-1">
            {p95Latency > 0 ? `${p95Latency.toFixed(2)} ms` : "< 20.0 ms"}
          </div>
          <span className="text-xs text-gray-500 font-mono">95% of flows processed faster</span>
        </div>

        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
            Selective Abstentions
          </span>
          <div className="text-xl font-bold text-purple-300 font-mono mt-1">
            {reviewCount.toLocaleString()} Flows
          </div>
          <span className="text-xs text-gray-500 font-mono">Confidence &lt; 40% (Tier-2 SOC)</span>
        </div>

        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
            Attack Surface Ratio
          </span>
          <div className="text-xl font-bold text-red-400 font-mono mt-1">
            {totalInferences > 0 ? ((threatCount / totalInferences) * 100).toFixed(1) : 0}%
          </div>
          <span className="text-xs text-gray-500 font-mono">Confirmed threat prevalence</span>
        </div>
      </div>

      {/* Visual Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[320px]">
        <ThreatDistribution metrics={metrics} sessionClassCounts={counts} />
        <ActivityTimeline alerts={alerts} />
      </div>

      {/* Protocol Telemetry Breakdown */}
      <div className="bg-[#131316] border border-[#222226] rounded-2xl p-6 shadow-sm">
        <div className="flex items-center gap-2 mb-4 pb-3 border-b border-[#222226]">
          <span className="material-symbols-outlined text-gray-400">network_check</span>
          <span className="font-bold text-white text-sm font-mono">Transport Protocol Distribution</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {["TCP", "UDP", "ICMP"].map((proto) => {
            const count = protoCounts[proto] || 0;
            const pct = totalSampleProtocols > 0 ? (count / totalSampleProtocols) * 100 : 0;
            return (
              <div key={proto} className="bg-[#0e0e11] border border-[#222226] rounded-xl p-4 flex flex-col gap-2">
                <div className="flex justify-between items-center text-xs font-mono">
                  <span className="text-gray-300 font-bold">{proto}</span>
                  <span className="text-gray-400">{count.toLocaleString()} flows ({pct.toFixed(1)}%)</span>
                </div>
                <div className="h-1.5 bg-[#1a1a22] rounded-full overflow-hidden">
                  <div className="h-full bg-white rounded-full transition-all" style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
