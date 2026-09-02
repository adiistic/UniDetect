import React from "react";
import { X, Cpu, Sliders, ShieldCheck } from "lucide-react";
import type { ModelInfoResponse } from "../api/types";

interface ModelStatusDrawerProps {
  modelInfo: ModelInfoResponse | null;
  isOpen: boolean;
  onClose: () => void;
}

export const ModelStatusDrawer: React.FC<ModelStatusDrawerProps> = ({
  modelInfo,
  isOpen,
  onClose,
}) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: "620px" }} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "0.85rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Cpu size={22} color="#38bdf8" />
            <h2 style={{ fontSize: "1.1rem", fontWeight: 800, color: "#ffffff", fontFamily: "var(--font-mono)" }}>
              FROZEN ML MODEL SPECIFICATION
            </h2>
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

        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {/* Architecture Badge */}
          <div
            style={{
              background: "rgba(56, 189, 248, 0.08)",
              border: "1px solid rgba(56, 189, 248, 0.25)",
              borderRadius: "8px",
              padding: "0.85rem 1rem",
            }}
          >
            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700 }}>
              ESTIMATOR ARCHITECTURE
            </div>
            <div style={{ fontSize: "0.92rem", fontWeight: 700, color: "#ffffff", marginTop: "0.2rem", fontFamily: "var(--font-mono)" }}>
              {modelInfo?.model_type || "HistGradientBoosting + CalibratedClassifierCV"}
            </div>
          </div>

          {/* Model Specification Grid */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
            <div className="soc-card" style={{ padding: "0.75rem" }}>
              <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", textTransform: "uppercase" }}>MODEL VERSION</span>
              <div style={{ fontSize: "0.9rem", fontWeight: 700, color: "#ffffff", fontFamily: "var(--font-mono)" }}>
                {modelInfo?.model_version || "unidetect-hgb-calibrated-v1.0.0"}
              </div>
            </div>

            <div className="soc-card" style={{ padding: "0.75rem" }}>
              <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", textTransform: "uppercase" }}>FEATURE SCHEMA</span>
              <div style={{ fontSize: "0.9rem", fontWeight: 700, color: "var(--color-cyan-glow)", fontFamily: "var(--font-mono)" }}>
                {modelInfo?.feature_count || 78} Dimensions (v{modelInfo?.schema_version || "1.0.0"})
              </div>
            </div>

            <div className="soc-card" style={{ padding: "0.75rem" }}>
              <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", textTransform: "uppercase" }}>PROBABILITY CALIBRATION</span>
              <div style={{ fontSize: "0.9rem", fontWeight: 700, color: "var(--color-benign)", fontFamily: "var(--font-mono)" }}>
                {modelInfo?.calibration_method || "Sigmoid / Platt Scaling (3-Fold CV)"}
              </div>
            </div>

            <div className="soc-card" style={{ padding: "0.75rem" }}>
              <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", textTransform: "uppercase" }}>TEMPORAL CAUSAL WINDOWS</span>
              <div style={{ fontSize: "0.9rem", fontWeight: 700, color: "#ffffff", fontFamily: "var(--font-mono)" }}>
                10s / 60s / 300s Backward Horizons
              </div>
            </div>
          </div>

          {/* Decision Policy Thresholds */}
          <div className="soc-card" style={{ padding: "1rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.8rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: "0.6rem" }}>
              <Sliders size={14} color="#f59e0b" />
              DECISION POLICY THRESHOLDS
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", fontSize: "0.78rem", fontFamily: "var(--font-mono)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "0.3rem" }}>
                <span style={{ color: "var(--text-secondary)" }}>Global Abstention Threshold (θ_abstain):</span>
                <strong style={{ color: "var(--color-review)" }}>
                  {modelInfo?.thresholds?.abstain_confidence_threshold ?? 0.40}
                </strong>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "0.3rem" }}>
                <span style={{ color: "var(--text-secondary)" }}>Recon Specific Threshold (θ_recon):</span>
                <strong style={{ color: "var(--color-recon)" }}>
                  {modelInfo?.thresholds?.recon_threshold ?? 0.35}
                </strong>
              </div>
            </div>
          </div>

          {/* Supported Threat Modalities */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.4rem" }}>
            {(modelInfo?.active_classes || ["BENIGN", "DDOS", "RECON", "DNS_TUNNEL", "C2_BEACON", "SLOW_HTTP"]).map((cls) => (
              <span key={cls} className={`badge badge-${cls}`}>
                <ShieldCheck size={11} /> {cls}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
