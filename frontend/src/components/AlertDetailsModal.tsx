import React from "react";
import { X, ShieldAlert, AlertTriangle, Network, Cpu, Lock } from "lucide-react";
import type { AlertEvent } from "../api/types";

interface AlertDetailsModalProps {
  alert: AlertEvent | null;
  onClose: () => void;
}

export const AlertDetailsModal: React.FC<AlertDetailsModalProps> = ({ alert, onClose }) => {
  if (!alert) return null;

  const threatClasses = ["BENIGN", "DDOS", "RECON", "DNS_TUNNEL", "C2_BEACON", "SLOW_HTTP"];

  const classColors: Record<string, string> = {
    BENIGN: "var(--color-benign)",
    DDOS: "var(--color-ddos)",
    RECON: "var(--color-recon)",
    DNS_TUNNEL: "var(--color-dns)",
    C2_BEACON: "var(--color-c2)",
    SLOW_HTTP: "var(--color-slowhttp)",
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        {/* Modal Header */}
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "1rem" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
              <span style={{ fontSize: "1.1rem", fontWeight: 800, color: "#ffffff", fontFamily: "var(--font-mono)" }}>
                ALERT FORENSIC INSPECTOR
              </span>
              <span
                style={{
                  fontSize: "0.72rem",
                  fontFamily: "var(--font-mono)",
                  background: "var(--bg-surface)",
                  padding: "0.2rem 0.5rem",
                  borderRadius: "4px",
                  color: "var(--text-secondary)",
                }}
              >
                UID: {alert.flow_uid}
              </span>
            </div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem", fontFamily: "var(--font-mono)" }}>
              ID: {alert.alert_id}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border-subtle)",
              color: "var(--text-muted)",
              borderRadius: "6px",
              padding: "0.3rem",
              cursor: "pointer",
            }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Decision Verdict Banner */}
        <div
          style={{
            background: alert.abstained ? "var(--color-review-bg)" : "rgba(56, 189, 248, 0.1)",
            border: `1px solid ${alert.abstained ? "var(--color-review-border)" : "rgba(56, 189, 248, 0.3)"}`,
            borderRadius: "8px",
            padding: "0.85rem 1rem",
            display: "flex",
            alignItems: "center",
            gap: "0.75rem",
          }}
        >
          {alert.abstained ? (
            <AlertTriangle size={24} color="var(--color-review)" />
          ) : (
            <ShieldAlert size={24} color={classColors[alert.predicted_label] || "var(--color-cyan-glow)"} />
          )}
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <span style={{ fontWeight: 800, fontSize: "0.95rem", color: "#ffffff" }}>
                {alert.abstained ? "SELECTIVE CLASSIFICATION ABSTENTION" : `CONFIRMED: ${alert.predicted_label}`}
              </span>
              <span style={{ fontSize: "0.75rem", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                (Confidence: {(alert.confidence * 100).toFixed(1)}%)
              </span>
            </div>
            <p style={{ fontSize: "0.78rem", color: "var(--text-secondary)", marginTop: "0.2rem" }}>
              {alert.abstained
                ? "Calibrated prediction confidence fell below the θ = 0.40 threshold. Flow is flagged for analyst review rather than automated inline enforcement."
                : `Model classified flow as ${alert.predicted_label} based on 78-dimensional temporal causal patterns.`}
            </p>
          </div>
        </div>

        {/* Multi-Class Probability Distribution */}
        <div className="soc-card" style={{ padding: "1rem" }}>
          <div style={{ fontSize: "0.82rem", fontWeight: 700, color: "var(--text-primary)", letterSpacing: "0.04em", textTransform: "uppercase", marginBottom: "0.6rem" }}>
            Calibrated Multi-Class Probabilities (Sigmoid Platt Scaling)
          </div>
          <div className="prob-bar-container">
            {threatClasses.map((cls) => {
              const prob = (alert.probabilities && alert.probabilities[cls]) || 0;
              const pct = (prob * 100).toFixed(1);
              const isWinner = alert.predicted_label === cls;

              return (
                <div key={cls} className="prob-row">
                  <div className="prob-label" style={{ fontWeight: isWinner ? 700 : 400, color: isWinner ? "#ffffff" : "var(--text-secondary)" }}>
                    {cls}
                  </div>
                  <div className="prob-track">
                    <div
                      className="prob-fill"
                      style={{
                        width: `${pct}%`,
                        background: classColors[cls] || "var(--color-cyan-glow)",
                      }}
                    />
                  </div>
                  <div className="prob-pct" style={{ color: isWinner ? "#ffffff" : "var(--text-muted)" }}>
                    {pct}%
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Network & Ingestion Metadata Grid */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
          {/* Network Coordinates */}
          <div className="soc-card" style={{ padding: "0.85rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.78rem", fontWeight: 700, color: "var(--text-muted)", marginBottom: "0.5rem" }}>
              <Network size={14} color="#38bdf8" />
              NETWORK 5-TUPLE
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.35rem", fontSize: "0.78rem", fontFamily: "var(--font-mono)" }}>
              <div><span style={{ color: "var(--text-muted)" }}>Source: </span><span style={{ color: "#ffffff" }}>{alert.source_ip}:{alert.source_port}</span></div>
              <div><span style={{ color: "var(--text-muted)" }}>Destination: </span><span style={{ color: "#ffffff" }}>{alert.destination_ip}:{alert.destination_port}</span></div>
              <div><span style={{ color: "var(--text-muted)" }}>Protocol: </span><span style={{ color: "#38bdf8" }}>{alert.protocol.toUpperCase()}</span></div>
              <div><span style={{ color: "var(--text-muted)" }}>Conn State: </span><span style={{ color: "var(--color-recon)" }}>{alert.metadata?.conn_state || "SF"}</span></div>
            </div>
          </div>

          {/* Model & Processing Telemetry */}
          <div className="soc-card" style={{ padding: "0.85rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.78rem", fontWeight: 700, color: "var(--text-muted)", marginBottom: "0.5rem" }}>
              <Cpu size={14} color="#a855f7" />
              INFERENCE METADATA
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.35rem", fontSize: "0.78rem", fontFamily: "var(--font-mono)" }}>
              <div><span style={{ color: "var(--text-muted)" }}>Model: </span><span style={{ color: "#ffffff" }}>{alert.model_version}</span></div>
              <div><span style={{ color: "var(--text-muted)" }}>Feature Vector: </span><span style={{ color: "#ffffff" }}>78 Dimensions (v{alert.schema_version})</span></div>
              <div><span style={{ color: "var(--text-muted)" }}>Processing Latency: </span><span style={{ color: "var(--color-benign)" }}>{alert.processing_time_ms.toFixed(2)} ms</span></div>
              <div><span style={{ color: "var(--text-muted)" }}>Volume: </span><span style={{ color: "#ffffff" }}>{alert.metadata?.total_bytes || 0} bytes</span></div>
            </div>
          </div>
        </div>

        {/* Passive Security Guarantee Footer */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
            fontSize: "0.72rem",
            color: "var(--text-muted)",
            borderTop: "1px solid var(--border-subtle)",
            paddingTop: "0.75rem",
          }}
        >
          <Lock size={13} color="var(--color-benign)" />
          <span>
            <strong>Passive SOC Guarantee:</strong> Zero packet payloads intercepted or decrypted. Features derived solely from Zeek transport headers and causal sliding-window aggregations.
          </span>
        </div>
      </div>
    </div>
  );
};
