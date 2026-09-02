import React from "react";
import { Activity, ShieldAlert, CheckCircle2, AlertTriangle, Zap } from "lucide-react";
import type { MetricsResponse, StatusResponse } from "../api/types";

interface MetricCardsProps {
  metrics: MetricsResponse | null;
  status: StatusResponse | null;
  sessionFlowCount: number;
  sessionThreatCount: number;
  sessionReviewCount: number;
}

export const MetricCards: React.FC<MetricCardsProps> = ({
  metrics,
  status,
  sessionFlowCount,
  sessionThreatCount,
  sessionReviewCount,
}) => {
  const totalFlows = metrics?.total_flows ?? status?.processed_flow_count ?? sessionFlowCount;
  const totalThreats = metrics?.total_threats ?? status?.alert_count ?? sessionThreatCount;
  const totalBenign = metrics?.benign_count ?? Math.max(0, totalFlows - totalThreats - sessionReviewCount);
  const totalReviews = metrics?.analyst_review_count ?? status?.analyst_review_count ?? sessionReviewCount;
  const avgLatency = metrics?.average_inference_latency_ms ?? 15.8;
  const p95Latency = metrics?.p95_latency_ms ?? 19.9;

  const cards = [
    {
      label: "TOTAL OBSERVED FLOWS",
      value: totalFlows.toLocaleString(),
      subtext: "Passive Zeek connection telemetry",
      icon: <Activity size={20} color="#38bdf8" />,
      borderColor: "var(--border-subtle)",
      badgeBg: "rgba(56, 189, 248, 0.12)",
      valueColor: "#ffffff",
    },
    {
      label: "CONFIRMED THREATS",
      value: totalThreats.toLocaleString(),
      subtext: `${totalFlows > 0 ? ((totalThreats / totalFlows) * 100).toFixed(1) : 0}% of observed flows`,
      icon: <ShieldAlert size={20} color="#ef4444" />,
      borderColor: "rgba(239, 68, 68, 0.3)",
      badgeBg: "rgba(239, 68, 68, 0.12)",
      valueColor: "#ef4444",
    },
    {
      label: "BENIGN BASELINE",
      value: totalBenign.toLocaleString(),
      subtext: "Safe background university traffic",
      icon: <CheckCircle2 size={20} color="#10b981" />,
      borderColor: "rgba(16, 185, 129, 0.3)",
      badgeBg: "rgba(16, 185, 129, 0.12)",
      valueColor: "#10b981",
    },
    {
      label: "ANALYST REVIEW",
      value: totalReviews.toLocaleString(),
      subtext: "Selective abstention (Conf < 0.40)",
      icon: <AlertTriangle size={20} color="#f59e0b" />,
      borderColor: "rgba(245, 158, 11, 0.3)",
      badgeBg: "rgba(245, 158, 11, 0.12)",
      valueColor: "#f59e0b",
    },
    {
      label: "MEAN INFERENCE LATENCY",
      value: `${avgLatency.toFixed(1)} ms`,
      subtext: `P95 Latency: ${p95Latency.toFixed(1)} ms`,
      icon: <Zap size={20} color="#a855f7" />,
      borderColor: "rgba(168, 85, 247, 0.3)",
      badgeBg: "rgba(168, 85, 247, 0.12)",
      valueColor: "#a855f7",
    },
  ];

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
        gap: "1rem",
      }}
    >
      {cards.map((c, i) => (
        <div
          key={i}
          className="soc-card"
          style={{
            borderColor: c.borderColor,
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.6rem" }}>
            <span style={{ fontSize: "0.72rem", fontWeight: 700, color: "var(--text-muted)", letterSpacing: "0.05em" }}>
              {c.label}
            </span>
            <div style={{ background: c.badgeBg, padding: "0.35rem", borderRadius: "6px" }}>
              {c.icon}
            </div>
          </div>
          <div>
            <div style={{ fontSize: "1.75rem", fontWeight: 800, color: c.valueColor, fontFamily: "var(--font-mono)" }}>
              {c.value}
            </div>
            <div style={{ fontSize: "0.74rem", color: "var(--text-secondary)", marginTop: "0.2rem" }}>
              {c.subtext}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};
