import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MetricCards } from "../MetricCards";
import type { MetricsResponse, StatusResponse, HealthResponse } from "../../api/types";

describe("MetricCards Component", () => {
  it("renders correctly with active metrics and health", () => {
    const mockMetrics: MetricsResponse = {
      total_flows: 1542,
      total_predictions: 1542,
      total_threats: 38,
      benign_count: 1480,
      analyst_review_count: 24,
      per_class_counts: { BENIGN: 1480, DDOS: 38 },
      average_inference_latency_ms: 1.5,
      p95_latency_ms: 3.1,
    };

    const mockStatus: StatusResponse = {
      model_status: "LOADED_AND_ACTIVE",
      inference_status: "READY",
      pipeline_status: "PASSIVE_INGESTION_READY",
      processed_flow_count: 1542,
      alert_count: 38,
      analyst_review_count: 24,
      uptime_seconds: 120,
    };

    const mockHealth: HealthResponse = {
      status: "ok",
      model_loaded: true,
      model_version: "v1.0.0",
      schema_version: "1.0.0",
    };

    render(
      <MetricCards
        metrics={mockMetrics}
        status={mockStatus}
        health={mockHealth}
        sessionFlowCount={1542}
        sessionThreatCount={38}
        sessionReviewCount={24}
      />
    );

    // Verify key counts appear
    expect(screen.getByText("1,542")).toBeDefined();
    expect(screen.getByText("38")).toBeDefined();
    expect(screen.getByText("24")).toBeDefined();
    expect(screen.getByText("1.5 ms")).toBeDefined();
    expect(screen.getByText("HEALTHY")).toBeDefined();
  });
});
