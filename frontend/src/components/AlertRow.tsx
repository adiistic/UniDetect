import React from "react";
import { ExternalLink, ShieldAlert, AlertTriangle, CheckCircle2 } from "lucide-react";
import type { AlertEvent } from "../api/types";

interface AlertRowProps {
  alert: AlertEvent;
  onSelect: (alert: AlertEvent) => void;
  isNew?: boolean;
}

export const AlertRow: React.FC<AlertRowProps> = ({ alert, onSelect, isNew }) => {
  const getBadgeClass = (label: string, abstained: boolean) => {
    if (abstained) return "badge badge-ANALYST_REVIEW";
    switch (label) {
      case "DDOS": return "badge badge-DDOS";
      case "RECON": return "badge badge-RECON";
      case "DNS_TUNNEL": return "badge badge-DNS_TUNNEL";
      case "C2_BEACON": return "badge badge-C2_BEACON";
      case "SLOW_HTTP": return "badge badge-SLOW_HTTP";
      case "BENIGN": return "badge badge-BENIGN";
      default: return "badge badge-ANALYST_REVIEW";
    }
  };

  const getConfidenceColor = (conf: number, abstained: boolean) => {
    if (abstained) return "var(--color-review)";
    if (conf >= 0.85) return "var(--color-ddos)";
    if (conf >= 0.6) return "var(--color-recon)";
    return "var(--color-benign)";
  };

  const formattedTime = new Date(alert.timestamp * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  return (
    <tr
      className={isNew ? "flash-new-row" : ""}
      onClick={() => onSelect(alert)}
      style={{
        borderBottom: "1px solid var(--border-subtle)",
        cursor: "pointer",
        transition: "background 0.15s ease",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-card-hover)")}
      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
    >
      {/* Time */}
      <td style={{ padding: "0.65rem 1rem", fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "var(--text-secondary)" }}>
        {formattedTime}
      </td>

      {/* Predicted Class */}
      <td style={{ padding: "0.65rem 1rem" }}>
        <span className={getBadgeClass(alert.predicted_label, alert.abstained)}>
          {alert.abstained ? (
            <AlertTriangle size={12} />
          ) : alert.predicted_label === "BENIGN" ? (
            <CheckCircle2 size={12} />
          ) : (
            <ShieldAlert size={12} />
          )}
          {alert.predicted_label}
        </span>
      </td>

      {/* Decision */}
      <td style={{ padding: "0.65rem 1rem", fontSize: "0.76rem", fontFamily: "var(--font-mono)" }}>
        {alert.abstained ? (
          <span style={{ color: "var(--color-review)", fontWeight: 700 }}>
            ANALYST_REVIEW
          </span>
        ) : (
          <span style={{ color: "var(--color-cyan-glow)", fontWeight: 600 }}>
            AUTOMATED
          </span>
        )}
      </td>

      {/* 5-Tuple Network Coordinates */}
      <td style={{ padding: "0.65rem 1rem", fontFamily: "var(--font-mono)", fontSize: "0.78rem" }}>
        <span style={{ color: "var(--text-primary)" }}>{alert.source_ip}</span>
        <span style={{ color: "var(--text-muted)" }}>:{alert.source_port}</span>
        <span style={{ color: "var(--color-cyan-glow)", margin: "0 0.35rem" }}>→</span>
        <span style={{ color: "var(--text-primary)" }}>{alert.destination_ip}</span>
        <span style={{ color: "var(--text-muted)" }}>:{alert.destination_port}</span>
      </td>

      {/* Protocol */}
      <td style={{ padding: "0.65rem 1rem", fontFamily: "var(--font-mono)", fontSize: "0.76rem", color: "var(--text-secondary)" }}>
        {alert.protocol.toUpperCase()}
      </td>

      {/* Confidence */}
      <td style={{ padding: "0.65rem 1rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <div style={{ width: "60px", height: "6px", background: "var(--bg-surface)", borderRadius: "3px", overflow: "hidden" }}>
            <div
              style={{
                height: "100%",
                width: `${Math.round(alert.confidence * 100)}%`,
                background: getConfidenceColor(alert.confidence, alert.abstained),
                borderRadius: "3px",
              }}
            />
          </div>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", fontWeight: 700, color: getConfidenceColor(alert.confidence, alert.abstained) }}>
            {(alert.confidence * 100).toFixed(1)}%
          </span>
        </div>
      </td>

      {/* Inspect Action */}
      <td style={{ padding: "0.65rem 1rem", textAlign: "right" }}>
        <button
          style={{
            background: "transparent",
            border: "none",
            color: "var(--text-muted)",
            cursor: "pointer",
            padding: "0.2rem",
            display: "inline-flex",
            alignItems: "center",
          }}
          title="Inspect Alert Details"
        >
          <ExternalLink size={15} color="var(--color-cyan-glow)" />
        </button>
      </td>
    </tr>
  );
};
