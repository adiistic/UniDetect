import React, { useState, useRef, useEffect } from "react";
import type { AlertEvent } from "../api/types";
import { AlertRow } from "./AlertRow";

export type TriageMode = "ALL" | "THREATS_ONLY" | "REVIEW_ONLY" | "BENIGN_ONLY";

interface AlertTableProps {
  alerts: AlertEvent[];
  selectedAlertId: string | null;
  onSelectAlert: (alert: AlertEvent) => void;
  isStreamPaused: boolean;
  onTogglePause?: () => void;
  newAlertIds: Set<string>;
  triageMode?: TriageMode;
  onTriageModeChange?: (mode: TriageMode) => void;
  onBatchUpdateDecision?: (
    alertIds: string[],
    decision: "ANALYST_REVIEW" | "AUTOMATED_DETECTION" | "FALSE_POSITIVE"
  ) => void;
}

function generateExportFilename(extension: "csv" | "json"): string {
  return `unidetect_telemetry_${Date.now()}.${extension}`;
}

export const AlertTable: React.FC<AlertTableProps> = ({
  alerts,
  selectedAlertId,
  onSelectAlert,
  isStreamPaused,
  newAlertIds,
  triageMode = "ALL",
  onTriageModeChange,
  onBatchUpdateDecision,
}) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [protocolFilter, setProtocolFilter] = useState<string>("ALL");
  const [classFilter, setClassFilter] = useState<string>("ALL");
  const [autoScroll, setAutoScroll] = useState(true);
  const [checkedIds, setCheckedIds] = useState<Set<string>>(new Set());

  const tableContainerRef = useRef<HTMLDivElement>(null);

  const activeTriageMode = triageMode;

  const handleModeChange = (mode: TriageMode) => {
    if (onTriageModeChange) onTriageModeChange(mode);
  };

  // Auto-scroll when new alerts arrive
  useEffect(() => {
    if (autoScroll && !isStreamPaused && tableContainerRef.current) {
      tableContainerRef.current.scrollTop = 0;
    }
  }, [alerts, autoScroll, isStreamPaused]);

  // Counts
  const reviewCount = alerts.filter(
    (a) => a.abstained || a.decision === "ANALYST_REVIEW"
  ).length;
  const threatCount = alerts.filter(
    (a) => a.predicted_label !== "BENIGN" && !a.abstained && a.decision !== "ANALYST_REVIEW" && a.decision !== "FALSE_POSITIVE"
  ).length;
  const benignCount = alerts.filter(
    (a) => (a.predicted_label === "BENIGN" || a.decision === "FALSE_POSITIVE") && !a.abstained && a.decision !== "ANALYST_REVIEW"
  ).length;

  const filteredAlerts = alerts.filter((a) => {
    const isReview = a.abstained || a.decision === "ANALYST_REVIEW";
    const isThreat = a.predicted_label !== "BENIGN" && !isReview && a.decision !== "FALSE_POSITIVE";

    // 1. Triage Mode
    if (activeTriageMode === "THREATS_ONLY" && !isThreat) return false;
    if (activeTriageMode === "REVIEW_ONLY" && !isReview) return false;
    if (activeTriageMode === "BENIGN_ONLY" && (isThreat || isReview)) return false;

    // 2. Class filter
    if (classFilter !== "ALL" && a.predicted_label.toUpperCase() !== classFilter.toUpperCase()) {
      return false;
    }

    // 3. Protocol filter
    if (protocolFilter !== "ALL" && a.protocol.toUpperCase() !== protocolFilter.toUpperCase()) {
      return false;
    }

    // 4. Search query
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      const matchIp = a.source_ip.toLowerCase().includes(q) || a.destination_ip.toLowerCase().includes(q);
      const matchPort = a.source_port.toString().includes(q) || a.destination_port.toString().includes(q);
      const matchUid = a.flow_uid?.toLowerCase().includes(q);
      const matchLabel = a.predicted_label.toLowerCase().includes(q);
      const matchProtocol = a.protocol.toLowerCase().includes(q);
      if (!matchIp && !matchPort && !matchUid && !matchLabel && !matchProtocol) return false;
    }

    return true;
  });

  const handleToggleCheckAll = (checked: boolean) => {
    if (checked) {
      setCheckedIds(new Set(filteredAlerts.map((a) => a.alert_id)));
    } else {
      setCheckedIds(new Set());
    }
  };

  const handleToggleCheckOne = (alertId: string, checked: boolean) => {
    setCheckedIds((prev) => {
      const next = new Set(prev);
      if (checked) next.add(alertId);
      else next.delete(alertId);
      return next;
    });
  };

  const handleExportJson = () => {
    const toExport = checkedIds.size > 0
      ? filteredAlerts.filter((a) => checkedIds.has(a.alert_id))
      : filteredAlerts;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(toExport, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", generateExportFilename("json"));
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleExportCsv = () => {
    const toExport = checkedIds.size > 0
      ? filteredAlerts.filter((a) => checkedIds.has(a.alert_id))
      : filteredAlerts;
    const headers = [
      "alert_id", "timestamp_iso", "flow_uid", "source_ip", "source_port",
      "destination_ip", "destination_port", "protocol", "predicted_label",
      "confidence", "decision", "abstained", "processing_time_ms"
    ];
    const rows = toExport.map((a) => [
      a.alert_id,
      a.timestamp_iso,
      a.flow_uid,
      a.source_ip,
      a.source_port,
      a.destination_ip,
      a.destination_port,
      a.protocol,
      a.predicted_label,
      a.confidence.toFixed(4),
      a.decision,
      a.abstained ? 1 : 0,
      a.processing_time_ms.toFixed(2),
    ]);
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", encodeURI(csvContent));
    downloadAnchor.setAttribute("download", generateExportFilename("csv"));
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const isAllChecked = filteredAlerts.length > 0 && filteredAlerts.every((a) => checkedIds.has(a.alert_id));

  return (
    <div className="bg-[#131316] border border-[#222226] rounded-2xl flex flex-col overflow-hidden shadow-sm flex-1 min-h-0">
      {/* Compact Triage Toolbar */}
      <div className="p-4 border-b border-[#222226] bg-[#0e0e11] flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        {/* Left: Triage Tabs */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center bg-[#18181c] border border-[#26262e] rounded-xl p-0.5 text-xs font-mono">
            <button
              onClick={() => handleModeChange("ALL")}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                activeTriageMode === "ALL"
                  ? "bg-[#282832] text-white font-bold"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              All Traffic ({alerts.length})
            </button>

            <button
              onClick={() => handleModeChange("THREATS_ONLY")}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTriageMode === "THREATS_ONLY"
                  ? "bg-red-950/60 text-red-300 font-bold border border-red-500/40"
                  : threatCount > 0
                  ? "text-red-400 hover:bg-red-950/30"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />
              <span>Threats ({threatCount})</span>
            </button>

            <button
              onClick={() => handleModeChange("REVIEW_ONLY")}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTriageMode === "REVIEW_ONLY"
                  ? "bg-amber-950/60 text-amber-300 font-bold border border-amber-500/40"
                  : reviewCount > 0
                  ? "text-amber-400 hover:bg-amber-950/30"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              <span>In Review ({reviewCount})</span>
            </button>

            <button
              onClick={() => handleModeChange("BENIGN_ONLY")}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                activeTriageMode === "BENIGN_ONLY"
                  ? "bg-[#282832] text-white font-bold"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              Normal Only ({benignCount})
            </button>
          </div>

          {/* Threat Class Dropdown Filter */}
          <select
            value={classFilter}
            onChange={(e) => setClassFilter(e.target.value)}
            className="bg-[#18181c] border border-[#26262e] rounded-xl px-2.5 py-1.5 text-xs text-gray-300 font-mono focus:outline-none focus:border-gray-400 cursor-pointer"
          >
            <option value="ALL">All Threat Vectors</option>
            <option value="DDOS">DDoS Volumetric</option>
            <option value="RECON">Recon & Port Scan</option>
            <option value="DNS_TUNNEL">DNS Exfiltration</option>
            <option value="C2_BEACON">C2 Beaconing</option>
            <option value="SLOW_HTTP">Slow HTTP DoS</option>
            <option value="BENIGN">Benign Baseline</option>
          </select>
        </div>

        {/* Right: Search, Protocol, & Actions */}
        <div className="flex items-center gap-2 flex-wrap justify-end">
          {/* Protocol Pills */}
          <div className="flex items-center bg-[#18181c] border border-[#26262e] rounded-xl p-0.5 text-xs font-mono">
            {["ALL", "TCP", "UDP"].map((proto) => (
              <button
                key={proto}
                onClick={() => setProtocolFilter(proto)}
                className={`px-2.5 py-1 rounded-lg transition-all cursor-pointer ${
                  protocolFilter === proto
                    ? "bg-[#282832] text-white font-bold"
                    : "text-gray-400 hover:text-white"
                }`}
              >
                {proto}
              </button>
            ))}
          </div>

          {/* Search Box */}
          <div className="relative w-44 sm:w-52">
            <span className="material-symbols-outlined absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400 text-sm">
              search
            </span>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search IP, Port, UID..."
              className="w-full bg-[#0a0a0c] border border-[#222226] rounded-xl py-1.5 pl-8 pr-3 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-gray-400 font-mono transition-colors"
            />
          </div>

          {/* Export CSV */}
          <button
            onClick={handleExportCsv}
            className="p-1.5 text-gray-400 hover:text-white bg-[#18181c] border border-[#26262e] rounded-xl transition-colors cursor-pointer"
            title="Export to CSV"
          >
            <span className="material-symbols-outlined text-base">table_view</span>
          </button>

          {/* Export JSON */}
          <button
            onClick={handleExportJson}
            className="p-1.5 text-gray-400 hover:text-white bg-[#18181c] border border-[#26262e] rounded-xl transition-colors cursor-pointer"
            title="Export to JSON"
          >
            <span className="material-symbols-outlined text-base">download</span>
          </button>

          {/* Auto-scroll Toggle */}
          <button
            onClick={() => setAutoScroll((v) => !v)}
            className={`px-2.5 py-1 rounded-xl border text-xs font-mono flex items-center gap-1 transition-all cursor-pointer ${
              autoScroll
                ? "bg-[#18181c] border-emerald-500/40 text-emerald-400"
                : "bg-[#0a0a0c] border-[#222226] text-gray-400"
            }`}
            title="Auto-scroll to latest flow"
          >
            <span className="material-symbols-outlined text-sm">
              {autoScroll ? "vertical_align_top" : "pause"}
            </span>
          </button>
        </div>
      </div>

      {/* Batch Selection Action Bar */}
      {checkedIds.size > 0 && (
        <div className="bg-[#1c1c24] border-b border-[#2e2e38] px-4 py-2 flex items-center justify-between text-xs font-mono animate-in fade-in duration-100">
          <div className="flex items-center gap-2">
            <span className="bg-white/10 text-white font-bold px-2 py-0.5 rounded">
              {checkedIds.size} Selected
            </span>
            <span className="text-gray-400">Batch Analyst Actions:</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                onBatchUpdateDecision?.(Array.from(checkedIds), "FALSE_POSITIVE");
                setCheckedIds(new Set());
              }}
              className="px-2.5 py-1 rounded-lg bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30 border border-emerald-500/40 cursor-pointer font-semibold flex items-center gap-1"
            >
              <span className="material-symbols-outlined text-sm">verified</span>
              <span>Dismiss as FP</span>
            </button>

            <button
              onClick={() => {
                onBatchUpdateDecision?.(Array.from(checkedIds), "ANALYST_REVIEW");
                setCheckedIds(new Set());
              }}
              className="px-2.5 py-1 rounded-lg bg-amber-500/20 text-amber-300 hover:bg-amber-500/30 border border-amber-500/40 cursor-pointer font-semibold flex items-center gap-1"
            >
              <span className="material-symbols-outlined text-sm">rate_review</span>
              <span>To Review</span>
            </button>

            <button
              onClick={handleExportCsv}
              className="px-2.5 py-1 rounded-lg bg-[#282834] text-gray-200 hover:text-white border border-[#383848] cursor-pointer flex items-center gap-1"
            >
              <span className="material-symbols-outlined text-sm">download</span>
              <span>Export Selected</span>
            </button>

            <button
              onClick={() => setCheckedIds(new Set())}
              className="px-2 py-1 rounded-lg text-gray-400 hover:text-white cursor-pointer"
            >
              Deselect All
            </button>
          </div>
        </div>
      )}

      {/* Table Container */}
      <div ref={tableContainerRef} className="flex-1 overflow-y-auto min-h-[300px]">
        <table className="w-full text-left border-collapse">
          <thead className="bg-[#0c0c0f] sticky top-0 z-10 border-b border-[#222226]">
            <tr>
              <th className="w-10 px-4 py-2.5 text-center">
                <input
                  type="checkbox"
                  checked={isAllChecked}
                  onChange={(e) => handleToggleCheckAll(e.target.checked)}
                  className="rounded border-[#33333e] bg-[#18181c] text-white focus:ring-0 cursor-pointer"
                  title={isAllChecked ? "Deselect all" : "Select all"}
                />
              </th>
              <th className="px-4 py-2.5 text-xs font-mono font-medium text-gray-400 uppercase">
                Timestamp
              </th>
              <th className="px-4 py-2.5 text-xs font-mono font-medium text-gray-400 uppercase">
                Threat Classification
              </th>
              <th className="px-4 py-2.5 text-xs font-mono font-medium text-gray-400 uppercase">
                Source IP:Port
              </th>
              <th className="px-4 py-2.5 text-xs font-mono font-medium text-gray-400 uppercase">
                Destination IP:Port
              </th>
              <th className="px-4 py-2.5 text-xs font-mono font-medium text-gray-400 uppercase">
                Protocol
              </th>
              <th className="px-4 py-2.5 text-xs font-mono font-medium text-gray-400 uppercase">
                Confidence
              </th>
              <th className="px-4 py-2.5 text-xs font-mono font-medium text-gray-400 uppercase">
                Policy Verdict
              </th>
              <th className="px-4 py-2.5 text-xs font-mono font-medium text-gray-400 uppercase">
                Latency
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#18181f]">
            {filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-4 py-16 text-center text-gray-500 font-mono text-sm">
                  {activeTriageMode === "THREATS_ONLY"
                    ? "Zero flagged threats in active buffer. Network traffic is completely benign."
                    : "No network flow telemetry matching current filters."}
                </td>
              </tr>
            ) : (
              filteredAlerts.map((alert) => (
                <AlertRow
                  key={alert.alert_id}
                  alert={alert}
                  isSelected={selectedAlertId === alert.alert_id}
                  onSelect={onSelectAlert}
                  isChecked={checkedIds.has(alert.alert_id)}
                  onToggleCheck={handleToggleCheckOne}
                  isNew={newAlertIds.has(alert.alert_id)}
                />
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Table Footer */}
      <div className="px-4 py-2.5 border-t border-[#222226] bg-[#0c0c0f] flex items-center justify-between text-xs text-gray-400 font-mono">
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-emerald-500" />
          Showing {filteredAlerts.length} of {alerts.length} Observed Flows
        </span>
        <span className="text-gray-500">
          Click any row to open forensic deep-dive drawer
        </span>
      </div>
    </div>
  );
};
