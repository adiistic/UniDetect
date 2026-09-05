import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { AlertTable } from "../AlertTable";
import type { AlertEvent } from "../../api/types";

const mockAlerts: AlertEvent[] = [
  {
    alert_id: "a-001",
    flow_uid: "uid-01",
    timestamp: 1700000000,
    timestamp_iso: "2026-09-02T12:00:00Z",
    source_ip: "192.168.1.10",
    destination_ip: "10.0.0.1",
    source_port: 45000,
    destination_port: 80,
    protocol: "TCP",
    predicted_class_id: 1,
    predicted_label: "DDOS",
    confidence: 0.98,
    probabilities: { BENIGN: 0.02, DDOS: 0.98 },
    abstained: false,
    decision: "AUTOMATED_DETECTION",
    model_version: "v1.0.0",
    schema_version: "1.0.0",
    processing_time_ms: 1.2,
  },
  {
    alert_id: "a-002",
    flow_uid: "uid-02",
    timestamp: 1700000001,
    timestamp_iso: "2026-09-02T12:00:01Z",
    source_ip: "192.168.1.20",
    destination_ip: "10.0.0.2",
    source_port: 45001,
    destination_port: 53,
    protocol: "UDP",
    predicted_class_id: 0,
    predicted_label: "BENIGN",
    confidence: 0.99,
    probabilities: { BENIGN: 0.99 },
    abstained: false,
    decision: "AUTOMATED_DETECTION",
    model_version: "v1.0.0",
    schema_version: "1.0.0",
    processing_time_ms: 0.8,
  },
];

describe("AlertTable Component", () => {
  it("renders alerts and handles selection", () => {
    const onSelectAlert = vi.fn();

    render(
      <AlertTable
        alerts={mockAlerts}
        selectedAlertId={null}
        onSelectAlert={onSelectAlert}
        isStreamPaused={false}
        newAlertIds={new Set()}
        triageMode="ALL"
      />
    );

    expect(screen.getByText("DDOS")).toBeDefined();
    expect(screen.getByText("BENIGN")).toBeDefined();
    expect(screen.getByText("192.168.1.10:45000")).toBeDefined();

    // Click on row
    fireEvent.click(screen.getByText("DDOS"));
    expect(onSelectAlert).toHaveBeenCalledWith(mockAlerts[0]);
  });

  it("filters threats only when triage mode is THREATS_ONLY", () => {
    render(
      <AlertTable
        alerts={mockAlerts}
        selectedAlertId={null}
        onSelectAlert={vi.fn()}
        isStreamPaused={false}
        newAlertIds={new Set()}
        triageMode="THREATS_ONLY"
      />
    );

    expect(screen.getByText("DDOS")).toBeDefined();
    expect(screen.queryByText("BENIGN")).toBeNull();
  });
});
