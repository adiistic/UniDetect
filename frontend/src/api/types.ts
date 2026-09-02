/**
 * UniDetect TypeScript API Type Definitions (Mirrors FastAPI & Phase 7 Schemas)
 */

export interface Probabilities {
  BENIGN?: number;
  DDOS?: number;
  RECON?: number;
  DNS_TUNNEL?: number;
  C2_BEACON?: number;
  SLOW_HTTP?: number;
  [key: string]: number | undefined;
}

export interface AlertEvent {
  alert_id: string;
  flow_uid: string;
  timestamp: number;
  timestamp_iso: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  predicted_class_id: number;
  predicted_label: string;
  confidence: number;
  probabilities: Probabilities;
  abstained: boolean;
  decision: "AUTOMATED_DETECTION" | "ANALYST_REVIEW" | "INFERENCE_ERROR" | string;
  model_version: string;
  schema_version: string;
  processing_time_ms: number;
  metadata?: {
    duration?: number;
    orig_bytes?: number;
    resp_bytes?: number;
    total_bytes?: number;
    conn_state?: string;
    [key: string]: any;
  };
}

export interface HealthResponse {
  status: "ok" | "degraded" | string;
  model_loaded: boolean;
  model_version: string;
  schema_version: string;
}

export interface StatusResponse {
  model_status: string;
  inference_status: string;
  pipeline_status: string;
  processed_flow_count: number;
  alert_count: number;
  analyst_review_count: number;
  uptime_seconds: number;
}

export interface AlertsListResponse {
  total: number;
  offset: number;
  limit: number;
  items: AlertEvent[];
}

export interface MetricsResponse {
  total_flows: number;
  total_predictions: number;
  total_threats: number;
  benign_count: number;
  analyst_review_count: number;
  per_class_counts: Record<string, number>;
  average_inference_latency_ms: number;
  p95_latency_ms: number;
}

export interface ModelInfoResponse {
  model_version: string;
  model_type: string;
  feature_count: number;
  schema_version: string;
  calibration_method: string;
  thresholds: {
    abstain_confidence_threshold: number;
    recon_threshold: number;
    [key: string]: number;
  };
  active_classes: string[];
}

export type ConnectionState = "CONNECTED" | "CONNECTING" | "DISCONNECTED" | "RECONNECTING";
