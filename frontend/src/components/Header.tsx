import React from "react";
import { Shield, Radio, Cpu, Trash2 } from "lucide-react";
import type { ConnectionState, HealthResponse } from "../api/types";

interface HeaderProps {
  connectionState: ConnectionState;
  health: HealthResponse | null;
  onOpenModelDrawer: () => void;
  onClearAlerts: () => void;
  alertCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  connectionState,
  health,
  onOpenModelDrawer,
  onClearAlerts,
  alertCount,
}) => {
  const getStatusColor = () => {
    switch (connectionState) {
      case "CONNECTED":
        return { bg: "rgba(16, 185, 129, 0.15)", border: "#10b981", text: "#10b981", label: "LIVE STREAM ACTIVE" };
      case "CONNECTING":
      case "RECONNECTING":
        return { bg: "rgba(245, 158, 11, 0.15)", border: "#f59e0b", text: "#f59e0b", label: "RECONNECTING..." };
      case "DISCONNECTED":
      default:
        return { bg: "rgba(239, 68, 68, 0.15)", border: "#ef4444", text: "#ef4444", label: "STREAM OFFLINE" };
    }
  };

  const status = getStatusColor();

  return (
    <header
      style={{
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border-subtle)",
        padding: "1rem 2rem",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
        <div
          style={{
            background: "linear-gradient(135deg, #0ea5e9, #6366f1)",
            padding: "0.6rem",
            borderRadius: "8px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            boxShadow: "0 0 15px rgba(14, 165, 233, 0.4)",
          }}
        >
          <Shield size={26} color="#ffffff" />
        </div>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <h1
              style={{
                fontSize: "1.35rem",
                fontWeight: 800,
                letterSpacing: "0.08em",
                color: "#ffffff",
                fontFamily: "var(--font-mono)",
              }}
            >
              UNIDETECT <span style={{ color: "#38bdf8" }}>SOC</span>
            </h1>
            <span
              style={{
                fontSize: "0.65rem",
                background: "rgba(56, 189, 248, 0.12)",
                color: "#38bdf8",
                border: "1px solid rgba(56, 189, 248, 0.3)",
                padding: "0.15rem 0.5rem",
                borderRadius: "4px",
                fontFamily: "var(--font-mono)",
                fontWeight: 700,
              }}
            >
              REPLAY / LAB MODE
            </span>
          </div>
          <p style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>
            Passive Network Threat Intelligence & Calibrated ML Telemetry
          </p>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
        {/* Connection Status Pill */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
            background: status.bg,
            border: `1px solid ${status.border}`,
            padding: "0.4rem 0.85rem",
            borderRadius: "6px",
            fontSize: "0.75rem",
            fontWeight: 700,
            color: status.text,
            fontFamily: "var(--font-mono)",
          }}
        >
          <Radio size={14} className={connectionState === "CONNECTED" ? "animate-pulse-glow" : ""} />
          <span>{status.label}</span>
        </div>

        {/* Model Spec Button */}
        <button
          onClick={onOpenModelDrawer}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.4rem",
            background: "var(--bg-surface)",
            border: "1px solid var(--border-subtle)",
            color: "var(--text-primary)",
            padding: "0.45rem 0.85rem",
            borderRadius: "6px",
            fontSize: "0.78rem",
            fontWeight: 600,
            cursor: "pointer",
            transition: "all 0.2s",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--color-cyan-glow)")}
          onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border-subtle)")}
        >
          <Cpu size={14} color="#38bdf8" />
          <span>Model Specs ({health?.model_version ? "v1.0.0" : "Offline"})</span>
        </button>

        {/* Clear Alerts Button */}
        {alertCount > 0 && (
          <button
            onClick={onClearAlerts}
            title="Clear in-browser alert feed"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
              background: "rgba(239, 68, 68, 0.1)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              color: "#ef4444",
              padding: "0.45rem 0.75rem",
              borderRadius: "6px",
              fontSize: "0.78rem",
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            <Trash2 size={14} />
            <span>Clear ({alertCount})</span>
          </button>
        )}
      </div>
    </header>
  );
};
