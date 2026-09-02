import React, { useState } from "react";
import { Shield, Filter, Search, Play, Pause, AlertOctagon } from "lucide-react";
import type { AlertEvent } from "../api/types";
import { AlertRow } from "./AlertRow";

interface AlertTableProps {
  alerts: AlertEvent[];
  onSelectAlert: (alert: AlertEvent) => void;
  isStreamPaused: boolean;
  onTogglePause: () => void;
  newAlertIds: Set<string>;
}

export const AlertTable: React.FC<AlertTableProps> = ({
  alerts,
  onSelectAlert,
  isStreamPaused,
  onTogglePause,
  newAlertIds,
}) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [classFilter, setClassFilter] = useState("ALL");
  const [decisionFilter, setDecisionFilter] = useState("ALL");

  const filteredAlerts = alerts.filter((a) => {
    // Class filter
    if (classFilter !== "ALL" && a.predicted_label !== classFilter) return false;

    // Decision filter
    if (decisionFilter === "ANALYST_REVIEW" && !a.abstained) return false;
    if (decisionFilter === "AUTOMATED" && a.abstained) return false;

    // Search query
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      const matchIp = a.source_ip.toLowerCase().includes(q) || a.destination_ip.toLowerCase().includes(q);
      const matchPort = a.source_port.toString().includes(q) || a.destination_port.toString().includes(q);
      const matchUid = a.flow_uid.toLowerCase().includes(q);
      const matchLabel = a.predicted_label.toLowerCase().includes(q);
      if (!matchIp && !matchPort && !matchUid && !matchLabel) return false;
    }

    return true;
  });

  return (
    <div className="soc-card" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      {/* Table Toolbar */}
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", justifyContent: "space-between", gap: "0.75rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <span className="soc-card-title">
            <Shield size={18} color="#38bdf8" />
            Live Threat Stream ({filteredAlerts.length} Events)
          </span>
          {isStreamPaused && (
            <span style={{ fontSize: "0.7rem", background: "rgba(239, 68, 68, 0.15)", color: "#ef4444", border: "1px solid rgba(239, 68, 68, 0.4)", padding: "0.15rem 0.5rem", borderRadius: "4px", fontWeight: 700 }}>
              STREAM PAUSED
            </span>
          )}
        </div>

        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "0.6rem" }}>
          {/* Search Box */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
              background: "var(--bg-surface)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "6px",
              padding: "0.35rem 0.65rem",
            }}
          >
            <Search size={14} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search IP, Port, UID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: "transparent",
                border: "none",
                outline: "none",
                color: "#ffffff",
                fontSize: "0.78rem",
                width: "140px",
              }}
            />
          </div>

          {/* Class Filter Dropdown */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
              background: "var(--bg-surface)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "6px",
              padding: "0.35rem 0.55rem",
            }}
          >
            <Filter size={13} color="var(--text-muted)" />
            <select
              value={classFilter}
              onChange={(e) => setClassFilter(e.target.value)}
              style={{
                background: "transparent",
                border: "none",
                outline: "none",
                color: "var(--text-primary)",
                fontSize: "0.76rem",
                fontFamily: "var(--font-mono)",
                cursor: "pointer",
              }}
            >
              <option value="ALL">All Threat Classes</option>
              <option value="DDOS">DDOS</option>
              <option value="RECON">RECON</option>
              <option value="DNS_TUNNEL">DNS_TUNNEL</option>
              <option value="C2_BEACON">C2_BEACON</option>
              <option value="SLOW_HTTP">SLOW_HTTP</option>
              <option value="BENIGN">BENIGN</option>
            </select>
          </div>

          {/* Decision Filter Dropdown */}
          <select
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
            style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "6px",
              padding: "0.35rem 0.55rem",
              color: "var(--text-primary)",
              fontSize: "0.76rem",
              fontFamily: "var(--font-mono)",
              outline: "none",
              cursor: "pointer",
            }}
          >
            <option value="ALL">All Decisions</option>
            <option value="AUTOMATED">Automated Detection</option>
            <option value="ANALYST_REVIEW">Analyst Review (Abstained)</option>
          </select>

          {/* Pause / Resume Button */}
          <button
            onClick={onTogglePause}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.35rem",
              background: isStreamPaused ? "rgba(16, 185, 129, 0.15)" : "rgba(245, 158, 11, 0.15)",
              border: `1px solid ${isStreamPaused ? "rgba(16, 185, 129, 0.4)" : "rgba(245, 158, 11, 0.4)"}`,
              color: isStreamPaused ? "#10b981" : "#f59e0b",
              padding: "0.35rem 0.65rem",
              borderRadius: "6px",
              fontSize: "0.76rem",
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            {isStreamPaused ? <Play size={13} /> : <Pause size={13} />}
            <span>{isStreamPaused ? "Resume Feed" : "Pause Feed"}</span>
          </button>
        </div>
      </div>

      {/* Alert Feed Table */}
      <div style={{ overflowX: "auto", maxHeight: "460px", overflowY: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
          <thead style={{ position: "sticky", top: 0, background: "var(--bg-surface)", zIndex: 10 }}>
            <tr style={{ borderBottom: "1px solid var(--border-glow)", fontSize: "0.72rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              <th style={{ padding: "0.6rem 1rem" }}>TIMESTAMP</th>
              <th style={{ padding: "0.6rem 1rem" }}>PREDICTED CLASS</th>
              <th style={{ padding: "0.6rem 1rem" }}>DECISION</th>
              <th style={{ padding: "0.6rem 1rem" }}>NETWORK 5-TUPLE</th>
              <th style={{ padding: "0.6rem 1rem" }}>PROTOCOL</th>
              <th style={{ padding: "0.6rem 1rem" }}>CONFIDENCE</th>
              <th style={{ padding: "0.6rem 1rem", textAlign: "right" }}>INSPECT</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.length > 0 ? (
              filteredAlerts.map((alert) => (
                <AlertRow
                  key={alert.alert_id}
                  alert={alert}
                  onSelect={onSelectAlert}
                  isNew={newAlertIds.has(alert.alert_id)}
                />
              ))
            ) : (
              <tr>
                <td colSpan={7} style={{ textAlign: "center", padding: "3rem 1rem", color: "var(--text-muted)" }}>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "0.5rem" }}>
                    <AlertOctagon size={32} color="var(--border-glow)" />
                    <span style={{ fontSize: "0.9rem", fontWeight: 600 }}>No threat events matching current filters</span>
                    <span style={{ fontSize: "0.75rem" }}>Adjust search terms or verify that the ingestion stream is running</span>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
