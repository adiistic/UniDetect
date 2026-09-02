import React from "react";
import { BarChart3, Clock } from "lucide-react";
import type { AlertEvent } from "../api/types";

interface ActivityTimelineProps {
  alerts: AlertEvent[];
}

export const ActivityTimeline: React.FC<ActivityTimelineProps> = ({ alerts }) => {
  // Aggregate alerts into last 14 dynamic activity slots
  const bucketCount = 14;
  const recentAlerts = alerts.slice(0, 140).reverse();

  // Create equal buckets from recent alerts
  const buckets: { threats: number; benign: number; reviews: number }[] = Array.from(
    { length: bucketCount },
    () => ({ threats: 0, benign: 0, reviews: 0 })
  );

  if (recentAlerts.length > 0) {
    const chunkSize = Math.max(1, Math.ceil(recentAlerts.length / bucketCount));
    recentAlerts.forEach((a, idx) => {
      const bIdx = Math.min(bucketCount - 1, Math.floor(idx / chunkSize));
      if (a.abstained) {
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
    <div className="soc-card" style={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <div className="soc-card-header">
        <span className="soc-card-title">
          <BarChart3 size={18} color="#38bdf8" />
          Real-Time Detection Activity
        </span>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", fontSize: "0.72rem" }}>
          <span style={{ display: "flex", alignItems: "center", gap: "0.3rem", color: "var(--color-ddos)" }}>
            <span style={{ width: 8, height: 8, background: "var(--color-ddos)", borderRadius: 2 }} /> Threats
          </span>
          <span style={{ display: "flex", alignItems: "center", gap: "0.3rem", color: "var(--color-benign)" }}>
            <span style={{ width: 8, height: 8, background: "var(--color-benign)", borderRadius: 2 }} /> Benign
          </span>
          <span style={{ display: "flex", alignItems: "center", gap: "0.3rem", color: "var(--color-review)" }}>
            <span style={{ width: 8, height: 8, background: "var(--color-review)", borderRadius: 2 }} /> Review
          </span>
        </div>
      </div>

      <div style={{ flex: 1, display: "flex", alignItems: "flex-end", gap: "0.5rem", padding: "0.5rem 0 0.25rem 0" }}>
        {buckets.map((b, i) => {
          const threatHeight = (b.threats / maxTotal) * 100;
          const benignHeight = (b.benign / maxTotal) * 100;
          const reviewHeight = (b.reviews / maxTotal) * 100;

          return (
            <div
              key={i}
              style={{
                flex: 1,
                height: "100%",
                display: "flex",
                flexDirection: "column",
                justifyContent: "flex-end",
                gap: "2px",
                position: "relative",
              }}
              title={`Slot ${i + 1}: ${b.threats} Threats, ${b.benign} Benign, ${b.reviews} Review`}
            >
              {b.threats > 0 && (
                <div
                  style={{
                    height: `${threatHeight}%`,
                    background: "var(--color-ddos)",
                    borderRadius: "2px",
                    transition: "height 0.3s ease",
                  }}
                />
              )}
              {b.reviews > 0 && (
                <div
                  style={{
                    height: `${reviewHeight}%`,
                    background: "var(--color-review)",
                    borderRadius: "2px",
                    transition: "height 0.3s ease",
                  }}
                />
              )}
              {b.benign > 0 && (
                <div
                  style={{
                    height: `${benignHeight}%`,
                    background: "var(--color-benign)",
                    borderRadius: "2px",
                    transition: "height 0.3s ease",
                  }}
                />
              )}
              {b.threats === 0 && b.benign === 0 && b.reviews === 0 && (
                <div
                  style={{
                    height: "3px",
                    background: "var(--bg-surface)",
                    borderRadius: "2px",
                  }}
                />
              )}
            </div>
          );
        })}
      </div>

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          fontSize: "0.68rem",
          color: "var(--text-muted)",
          borderTop: "1px solid var(--border-subtle)",
          paddingTop: "0.4rem",
          marginTop: "0.4rem",
          fontFamily: "var(--font-mono)",
        }}
      >
        <span>← Earlier Events</span>
        <span style={{ display: "flex", alignItems: "center", gap: "0.25rem" }}>
          <Clock size={11} /> Live Ingestion Tail
        </span>
        <span>Latest Flow →</span>
      </div>
    </div>
  );
};
