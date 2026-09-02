import React from "react";
import { PieChart } from "lucide-react";
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

  const threatConfig: Record<string, { label: string; color: string; bg: string }> = {
    DDOS: { label: "DDoS Attack", color: "var(--color-ddos)", bg: "var(--color-ddos-bg)" },
    RECON: { label: "Port Scan / Recon", color: "var(--color-recon)", bg: "var(--color-recon-bg)" },
    DNS_TUNNEL: { label: "DNS Exfiltration", color: "var(--color-dns)", bg: "var(--color-dns-bg)" },
    C2_BEACON: { label: "C2 Beaconing", color: "var(--color-c2)", bg: "var(--color-c2-bg)" },
    SLOW_HTTP: { label: "Slow HTTP DoS", color: "var(--color-slowhttp)", bg: "var(--color-slowhttp-bg)" },
    BENIGN: { label: "Benign Traffic", color: "var(--color-benign)", bg: "var(--color-benign-bg)" },
  };

  const totalCount = Object.values(counts).reduce((acc, v) => acc + v, 0);

  return (
    <div className="soc-card" style={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <div className="soc-card-header">
        <span className="soc-card-title">
          <PieChart size={18} color="#38bdf8" />
          Threat Modality Breakdown
        </span>
        <span style={{ fontSize: "0.74rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
          {totalCount} Total Vectors
        </span>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.85rem", flex: 1, justifyContent: "center" }}>
        {Object.entries(threatConfig).map(([key, cfg]) => {
          const count = counts[key] || 0;
          const pct = totalCount > 0 ? (count / totalCount) * 100 : 0;

          return (
            <div key={key} style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.78rem" }}>
                <span style={{ fontWeight: 600, color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: cfg.color }} />
                  {cfg.label} ({key})
                </span>
                <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                  <strong style={{ color: "#ffffff" }}>{count}</strong> ({pct.toFixed(1)}%)
                </span>
              </div>
              <div
                style={{
                  height: "7px",
                  background: "var(--bg-surface)",
                  borderRadius: "4px",
                  overflow: "hidden",
                }}
              >
                <div
                  style={{
                    height: "100%",
                    width: `${pct}%`,
                    background: cfg.color,
                    borderRadius: "4px",
                    transition: "width 0.4s ease",
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
