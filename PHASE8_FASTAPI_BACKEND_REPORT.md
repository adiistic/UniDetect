# UniDetect Phase 8: FastAPI Backend & Dashboard Integration Report

**Project**: UniDetect — Passive Network Threat Detection (SIH PS 145)  
**Phase**: Phase 8 (FastAPI REST API, Asynchronous WebSocket Stream, Thread-Safe In-Memory State & Replay Integration)  
**Execution Date**: 2026-09-02  
**API Version**: `1.0.0`  
**Frozen Model Target**: `models/phase6e/` (`unidetect-hgb-calibrated-v1.0.0`)  
**Backend Framework**: FastAPI + Starlette + Uvicorn  
**Automated Test Suite Status**: **112 / 112 Unit Tests Passing (100% Green across 12 test suites)**

---

## 1. 🎯 Executive Summary

Phase 8 successfully constructed the backend and API integration layer for UniDetect. The backend cleanly exposes the frozen Phase 6E ML model and Phase 7 streaming pipeline to analysts and external dashboards through high-performance REST endpoints and an asynchronous WebSocket event stream.

The architecture decouples web serving from ML inference, maintains a thread-safe bounded in-memory ring buffer for alert retention, and preserves 100% passive monitoring guarantees.

```
+---------------------------------------------------------------------------------------------------------+
| PHASE 8 BACKEND AT A GLANCE                                                                             |
+---------------------------------+-----------------------------------------------------------------------+
| REST API Endpoints              | /health, /api/v1/status, /api/v1/alerts, /api/v1/metrics, /api/v1/model|
| Real-Time Streaming Protocol    | Asynchronous WebSocket (/ws/alerts)                                   |
| Interactive Documentation       | OpenAPI / Swagger UI (/docs, /openapi.json)                          |
| State Management                | Bounded Thread-Safe Ring Buffer (AlertStore)                          |
| REST Query Latency              | ~5.28 ms (Single-endpoint retrieval under test)                       |
| Replay Demo Verification        | 424 Multi-Class Alerts Ingested & Streamed across 6 Threat Modalities |
| Automated Test Suite Health     | 112 / 112 Unit Tests Passing (100% Green across 12 test suites)       |
+---------------------------------+-----------------------------------------------------------------------+
```

---

## 2. 🏗️ Backend System Architecture & Data Flow

```
[ Network Traffic / Zeek Log Directory ]
                 │
                 ▼
[ RealtimeInferencePipeline (Phase 7) ]  (LogCorrelator -> WindowAggregator -> Assembler)
                 │
                 ▼
 [ Frozen ML Engine (Phase 6E) ]  (CalibratedClassifierCV -> DecisionPolicy)
                 │
                 ▼
           [ AlertEvent ]  (Standardized ISO 8601 Threat DTO)
                 │
                 ├─────────────────────────────────────────┐
                 ▼                                         ▼
   [ AlertStore (In-Memory Ring Buffer) ]      [ WebSocketManager (Broadcast) ]
                 │                                         │
                 ▼                                         ▼
  [ FastAPI REST Endpoints ]                   [ WebSocket Subscribers ]
  • GET /health                                (Live Dashboard / Analyst UI)
  • GET /api/v1/status
  • GET /api/v1/alerts
  • GET /api/v1/alerts/{id}
  • GET /api/v1/metrics
  • GET /api/v1/model
```

---

## 3. 🌐 REST API Endpoints Specification

### 1. `GET /health`
- **Purpose**: System liveness and model loading status.
- **Response Example**:
```json
{
  "status": "ok",
  "model_loaded": true,
  "model_version": "unidetect-hgb-calibrated-v1.0.0",
  "schema_version": "1.0.0"
}
```

### 2. `GET /api/v1/status`
- **Purpose**: High-level ingestion and processing telemetry.
- **Response Example**:
```json
{
  "model_status": "LOADED_AND_ACTIVE",
  "inference_status": "READY",
  "pipeline_status": "PASSIVE_INGESTION_READY",
  "processed_flow_count": 424,
  "alert_count": 348,
  "analyst_review_count": 2,
  "uptime_seconds": 120.45
}
```

### 3. `GET /api/v1/alerts`
- **Query Parameters**:
  - `limit`: Integer ($1 \le \text{limit} \le 500$, default: $50$).
  - `offset`: Integer ($\ge 0$, default: $0$).
  - `threat_class`: Optional string filter (`BENIGN`, `DDOS`, `RECON`, `DNS_TUNNEL`, `C2_BEACON`, `SLOW_HTTP`).
  - `decision`: Optional string filter (`AUTOMATED_DETECTION`, `ANALYST_REVIEW`, `INFERENCE_ERROR`).
- **Response Example**:
```json
{
  "total": 50,
  "offset": 0,
  "limit": 10,
  "items": [
    {
      "alert_id": "5bed94f4-6e11-4475-a832-7a8e578c7c90",
      "flow_uid": "CPscHQ3tM1IrMCYcvg",
      "timestamp": 1788291626.227356,
      "timestamp_iso": "2026-09-01T19:40:26.227356+00:00",
      "source_ip": "127.0.0.1",
      "destination_ip": "127.0.0.1",
      "source_port": 39010,
      "destination_port": 8443,
      "protocol": "tcp",
      "predicted_class_id": 5,
      "predicted_label": "C2_BEACON",
      "confidence": 0.5961,
      "probabilities": {
        "BENIGN": 0.1097,
        "DDOS": 0.2185,
        "RECON": 0.0209,
        "DNS_TUNNEL": 0.0306,
        "C2_BEACON": 0.5961,
        "SLOW_HTTP": 0.0243
      },
      "abstained": false,
      "decision": "AUTOMATED_DETECTION",
      "model_version": "unidetect-hgb-calibrated-v1.0.0",
      "schema_version": "1.0.0",
      "processing_time_ms": 15.8,
      "metadata": {
        "duration": 0.001175,
        "orig_bytes": 254,
        "resp_bytes": 201,
        "total_bytes": 455,
        "conn_state": "SF"
      }
    }
  ]
}
```

### 4. `GET /api/v1/alerts/{alert_id}`
- **Purpose**: Fetch detailed diagnostic alert by UUID. Returns `404 Not Found` if missing.

### 5. `GET /api/v1/metrics`
- **Purpose**: Threat breakdown, total processed flows, and latency percentiles ($P_{50}, P_{95}$).
- **Response Example**:
```json
{
  "total_flows": 424,
  "total_predictions": 424,
  "total_threats": 348,
  "benign_count": 74,
  "analyst_review_count": 2,
  "per_class_counts": {
    "BENIGN": 74,
    "DDOS": 150,
    "RECON": 54,
    "SLOW_HTTP": 50,
    "DNS_TUNNEL": 44,
    "C2_BEACON": 50
  },
  "average_inference_latency_ms": 21.646,
  "p95_latency_ms": 19.887
}
```

### 6. `GET /api/v1/model`
- **Purpose**: Technical specification of active model, frozen 78D contract, and decision thresholds.
- **Response Example**:
```json
{
  "model_version": "unidetect-hgb-calibrated-v1.0.0",
  "model_type": "CalibratedClassifierCV(HistGradientBoostingClassifier, method='sigmoid', cv=3)",
  "feature_count": 78,
  "schema_version": "1.0.0",
  "calibration_method": "sigmoid",
  "thresholds": {
    "abstain_confidence_threshold": 0.40,
    "recon_threshold": 0.35
  },
  "active_classes": ["BENIGN", "DDOS", "RECON", "DNS_TUNNEL", "C2_BEACON", "SLOW_HTTP"]
}
```

---

## 4. ⚡ Asynchronous WebSocket Alert Stream (`/ws/alerts`)

- **Protocol**: WebSocket over HTTP/1.1 or HTTP/2.
- **Endpoint**: `/ws/alerts`
- **Behavior**:
  - Automatically manages subscriber connections and disconnections.
  - Broadcasts structured `AlertEvent` JSON payloads concurrently to all active subscribers.
  - Non-blocking design: a slow or stalled client connection does not block the ML inference loop.
  - Clean error isolation: disconnected sockets are removed gracefully.

---

## 5. 💾 In-Memory State & Ring Buffer Design (`AlertStore`)

To avoid external database dependencies during development and offline evaluation, UniDetect utilizes a thread-safe in-memory ring buffer:
- **Bounded Capacity**: Configurable capacity (default: 2,000 alerts; tested up to 5,000) implemented via Python `collections.deque(maxlen=N)`.
- **Automatic FIFO Eviction**: When capacity is reached, the oldest alerts are automatically discarded, strictly bounding memory usage ($\approx 2.5\text{ MB}$ for 2,000 full alerts).
- **Thread Safety**: Protected with standard Python `threading.Lock()` primitives.

---

## 6. 🛡️ Passive Security Guarantees & Non-Intrusive Verification

1. **Zero Active Probing**: The backend is purely a downstream consumer of telemetry; it never transmits packets onto the monitored network interface.
2. **Zero Payload Logging**: Alert objects contain only IP addresses, port numbers, protocol names, timing metrics, and calibrated model probabilities. No decrypted application payloads (HTTP bodies, TLS records, raw DNS payloads) are serialized or exposed.
3. **Robust Input Validation**: All REST query parameters are validated via Pydantic; invalid class filters or negative pagination indices are cleanly rejected with HTTP 400 or 422 errors.

---

## 7. 📁 Implemented Backend Modules & Files

1. [`src/api/schemas.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/api/schemas.py): Pydantic response models.
2. [`src/api/state.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/api/state.py): `AlertStore` and `AppState` thread-safe state holders.
3. [`src/api/websocket.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/api/websocket.py): `WebSocketManager` asynchronous connection pool and broadcaster.
4. [`src/api/dependencies.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/api/dependencies.py): Dependency injection providers.
5. [`src/api/routes.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/api/routes.py): REST API route handlers.
6. [`src/api/app.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/api/app.py): Application factory `create_app()` with CORS middleware.
7. [`src/api/__init__.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/api/__init__.py): API package exports.
8. [`scripts/run_phase8_demo.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/scripts/run_phase8_demo.py): End-to-end replay, REST, and WebSocket integration demonstration script.
9. [`reports/phase8/demo_summary.json`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/reports/phase8/demo_summary.json): Exported demo benchmark metrics.
10. [`tests/test_phase8_backend.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/tests/test_phase8_backend.py): 18 comprehensive backend unit tests.

---

## 8. 🧪 Automated Test Suite Health

```bash
python -m unittest discover -s tests
```
- **Total Test Suites**: 12 suites
- **Total Passing Tests**: **112 unit tests** (68 baseline + 11 Phase 6E + 15 Phase 7 streaming + 18 Phase 8 backend tests)
- **Pass Rate**: **100% (112 / 112 passing)**

---

## 9. ⚠️ Documented Dataset Limitations & Future Persistence Considerations

1. **Laboratory Corpus Evaluation**: The system has been validated on the 12 controlled laboratory experiments. Production deployment in a live university campus network will encounter unforeseen protocols, unmodeled background services, and higher traffic density.
2. **In-Memory Store Scope**: `AlertStore` is an ephemeral development buffer. Long-term compliance, historical SIEM auditing, or multi-month forensic queries will benefit from persistent time-series or relational database adapters (e.g. SQLite / PostgreSQL) in downstream extensions.

---

## 10. 🚦 Phase 8 Conclusion & Next Steps

### **SUMMARY & STATUS**
- FastAPI backend and WebSocket streaming pipeline are **fully implemented, integrated, and verified**.
- 112 / 112 automated unit tests pass with zero regressions.
- No database, Docker, frontend, or active defense code was created.

*Phase 8 is complete. We are stopped and awaiting your direction.*
