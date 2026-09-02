# UniDetect Phase 9: SOC Dashboard & Frontend Integration Report

**Project**: UniDetect — Passive Network Threat Detection (SIH PS 145)  
**Phase**: Phase 9 (Cybersecurity SOC Dashboard, React + TypeScript + Vite, Real-Time WebSocket Streaming, Forensic Modal & Model Drawer)  
**Execution Date**: 2026-09-02  
**Frontend Framework**: React 18 + TypeScript + Vite + Vanilla CSS  
**Backend Framework**: FastAPI + Uvicorn + WebSocket  
**Build & Test Status**: **100% Green (Frontend Bundle: 231.8 kB / 113 Automated Python Unit Tests Passing)**

---

## 1. 🎯 Executive Summary

Phase 9 completed the development of the **UniDetect SOC Dashboard**, an operations-grade cybersecurity user interface specifically designed for security analysts to observe passive network traffic telemetry and calibrated machine learning threat detections in real time.

The frontend is constructed using **React, TypeScript, and Vite**, utilizing a high-density, dark-mode cybersecurity design system with zero bloated UI frameworks. It integrates with the FastAPI backend across all standard REST endpoints and streams live `AlertEvent` objects over an asynchronous WebSocket connection (`/ws/alerts`) with automatic reconnection handling.

```
+---------------------------------------------------------------------------------------------------------+
| PHASE 9 SOC DASHBOARD AT A GLANCE                                                                       |
+---------------------------------+-----------------------------------------------------------------------+
| Frontend Stack                  | React 19 / TypeScript / Vite 8 / Lucide Icons / Vanilla CSS           |
| UI Theme & Aesthetics           | Cyber Dark Obsidian (#080c14), Glassmorphism, Neon Modality Accents   |
| Real-Time Streaming Protocol    | Asynchronous WebSocket (/ws/alerts) with Auto-Reconnect Exponential   |
| Live Components Built           | Header, MetricCards, ThreatDistribution, ActivityTimeline, AlertTable |
| Forensic Modal Inspector        | 5-Tuple, Sigmoid Probabilities (Horizontal Bars), Transport Metadata  |
| Model Architecture Drawer       | CalibratedClassifierCV + HistGradientBoosting, 78D Contract, θ=0.40   |
| Static Bundle Build Time        | 795 ms (dist/assets/index.js: 231.78 kB | gzip: 70.46 kB)             |
| Automated Test Suite Health     | 113 / 113 Python Unit Tests Passing (100% Green across 12 test suites)|
+---------------------------------+-----------------------------------------------------------------------+
```

---

## 2. 🏗️ Full-Stack System Architecture & Real-Time Data Flow

```
[ University Network / Tap PCAP ]
                │
                ▼
      [ Passive Zeek Engine ]  (conn.log, dns.log, ssl.log, weird.log, quic.log)
                │
                ▼
[ RealtimeInferencePipeline (Phase 7) ]  (LogCorrelator -> WindowAggregator -> Assembler)
                │
                ▼
[ Frozen CalibratedClassifierCV (Phase 6E) ]  (HistGradientBoosting + Platt Scaling)
                │
                ▼
          [ AlertEvent ]  (Standardized DTO: UID, IPs, Ports, Probs, Decision)
                │
                ├─────────────────────────────────────────┐
                ▼                                         ▼
   [ AlertStore (In-Memory Ring Buffer) ]      [ WebSocketManager (Async Broadcast) ]
                │                                         │
                ▼                                         ▼
    [ FastAPI REST Endpoints ]                 [ WebSocket Stream (/ws/alerts) ]
    • GET /health                              • Live Alert Dispatch
    • GET /api/v1/status                       • Auto-Reconnect Client
    • GET /api/v1/alerts                                  │
    • GET /api/v1/alerts/{id}                             ▼
    • GET /api/v1/metrics                     [ UniDetect React SOC Dashboard ]
    • GET /api/v1/model                       • Live Alert Table & Filters
    • GET / (Static Dashboard Root)           • Probability Distribution Bars
                                              • Modality Breakdown & Activity Histogram
```

---

## 3. 🖥️ Dashboard Components & Visual Features

### 1. `Header` ([`frontend/src/components/Header.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/Header.tsx))
- **Brand & Mode**: Displays `UNIDETECT SOC` with explicit `REPLAY / LAB MODE` badge to maintain experimental integrity.
- **Connection Status Badge**: Dynamic status indicator (`LIVE STREAM ACTIVE` [Emerald], `RECONNECTING...` [Amber], `STREAM OFFLINE` [Crimson]) with pulsing radio dot.
- **Actions**: One-click "Model Specs" drawer trigger and "Clear Feed" control.

### 2. `MetricCards` ([`frontend/src/components/MetricCards.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/MetricCards.tsx))
- Real-time telemetry summary cards:
  - **Total Observed Flows**: Cumulative connections ingested from Zeek.
  - **Confirmed Threats**: Flows classified as attacks by the calibrated model.
  - **Benign Baseline**: Safe, normal university traffic flows.
  - **Analyst Review**: Ambiguous flows routed to human review via selective abstention ($\theta < 0.40$).
  - **Mean Inference Latency**: Sub-$20\text{ ms}$ processing time per flow ($P_{95}$ reported).

### 3. `ThreatDistribution` ([`frontend/src/components/ThreatDistribution.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/ThreatDistribution.tsx))
- Horizontal distribution bars visualizing detected attack categories:
  - `DDOS` (Crimson `#ef4444`)
  - `RECON` (Amber `#f59e0b`)
  - `DNS_TUNNEL` (Cyan `#06b6d4`)
  - `C2_BEACON` (Purple `#a855f7`)
  - `SLOW_HTTP` (Pink `#ec4899`)
  - `BENIGN` (Emerald `#10b981`)

### 4. `ActivityTimeline` ([`frontend/src/components/ActivityTimeline.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/ActivityTimeline.tsx))
- Dynamic multi-series histogram tracking threat volume, benign baselines, and review abstentions over the active session stream.

### 5. `AlertTable` & `AlertRow` ([`frontend/src/components/AlertTable.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/AlertTable.tsx))
- High-density live alert feed with:
  - Timestamp (HH:MM:SS)
  - Color-coded threat badge
  - Decision verdict (`AUTOMATED` vs `ANALYST_REVIEW`)
  - Network 5-tuple (`source_ip:port → dest_ip:port`)
  - Transport protocol
  - Confidence progress bar
  - Instant search filtering (by IP, Port, or Flow UID)
  - Dropdown filter by Threat Class and Decision
  - Stream Pause / Resume toggle

### 6. `AlertDetailsModal` ([`frontend/src/components/AlertDetailsModal.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/AlertDetailsModal.tsx))
- Forensic inspection modal opening on alert click:
  - Decision Explanation Banner (distinguishing automated detection from selective abstention)
  - **Calibrated Multi-Class Probability Bars**: Exact probabilities across all 6 classes (e.g. `BENIGN 48.5%`, `DDOS 16.6%`, `SLOW_HTTP 21.3%`), demonstrating model probabilistic reasoning.
  - Network 5-tuple and connection states (`SF`, `S0`, `REJ`).
  - Model version, schema version (78D), and processing time.
  - Non-intrusive guarantee notice: "Zero packet payloads decrypted."

### 7. `ModelStatusDrawer` ([`frontend/src/components/ModelStatusDrawer.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/ModelStatusDrawer.tsx))
- Detailed technical drawer displaying:
  - Estimator: `CalibratedClassifierCV(HistGradientBoostingClassifier, method='sigmoid', cv=3)`
  - Frozen Feature Schema: 78 Continuous Numerical Dimensions (v1.0.0)
  - Probability Calibration: Sigmoid / Platt Scaling
  - Decision Policy: Global Abstention Threshold $\theta_{\text{abstain}} = 0.40$, Recon Threshold $\theta_{\text{recon}} = 0.35$.

---

## 4. ⚡ Real-Time WebSocket Streaming & Client-Side Resiliency

- **Centralized Client**: [`frontend/src/api/client.ts`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/api/client.ts) manages WebSocket lifecycle.
- **Bounded In-Browser Queue**: Limits in-memory alert list to 500 items, preventing browser memory leaks during extended monitoring sessions.
- **Automatic Reconnection**: Implements exponential backoff ($1\text{s} \to 10\text{s}$ ceiling) on disconnect without aggressive polling loops.

---

## 5. 🛡️ Passive Security Guarantees Maintained

1. **Zero Active Scanning**: The dashboard only consumes backend telemetry; no network sockets, port scans, or packet transmissions originate from the client.
2. **Zero Payload Exposure**: No raw packet payloads, application contents, or decrypted TLS streams are stored or presented.
3. **Local Deployment**: Completely functional offline on localhost without external CDN or analytics trackers.

---

## 6. 📁 Implemented Frontend Modules & Files

1. [`frontend/src/api/types.ts`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/api/types.ts): TypeScript interfaces.
2. [`frontend/src/api/client.ts`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/api/client.ts): Centralized REST & WebSocket client.
3. [`frontend/src/components/Header.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/Header.tsx): Top navigation header.
4. [`frontend/src/components/MetricCards.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/MetricCards.tsx): Telemetry metric cards.
5. [`frontend/src/components/ThreatDistribution.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/ThreatDistribution.tsx): Modality breakdown chart.
6. [`frontend/src/components/ActivityTimeline.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/ActivityTimeline.tsx): Detection activity histogram.
7. [`frontend/src/components/AlertRow.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/AlertRow.tsx): Interactive table row.
8. [`frontend/src/components/AlertTable.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/AlertTable.tsx): Live alert stream table with filters.
9. [`frontend/src/components/AlertDetailsModal.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/AlertDetailsModal.tsx): Forensic modal inspector.
10. [`frontend/src/components/ModelStatusDrawer.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/components/ModelStatusDrawer.tsx): Technical model specification drawer.
11. [`frontend/src/App.tsx`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/App.tsx): Root dashboard component.
12. [`frontend/src/index.css`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/frontend/src/index.css): Comprehensive SOC dark theme CSS.
13. [`src/main.py`](file:///c:/Users/GOURAV%20GABA/Downloads/unidetectml/src/main.py): CLI updated with `--dashboard` server launcher.

---

## 7. 🧪 Build & Test Suite Verification

### Frontend Build
```bash
cd frontend && npm run build
```
- **Build Time**: 795 ms
- **Output Bundle**: `dist/assets/index.js` ($231.78\text{ kB}$ / $70.46\text{ kB}$ gzip), `dist/assets/index.css` ($4.45\text{ kB}$).

### Full Python Test Discovery
```bash
python -m unittest discover -s tests
```
- **Total Test Suites**: 12 suites
- **Total Passing Tests**: **113 unit tests** (68 baseline + 11 Phase 6E + 15 Phase 7 streaming + 19 Phase 8/9 backend & dashboard tests).
- **Pass Rate**: **100% (113 / 113 passing)**.

---

## 8. ⚠️ Scope & Documented Limitations

1. **Controlled Laboratory Validation**: The visualized telemetry and model inferences are based on the 12 retained laboratory experiments. Real-world university deployment remains future work.
2. **Ephemeral In-Memory Store**: Dashboard data reflects the active server session and the backend's bounded ring buffer. Persistent historical querying requires external database integration in future phases.

---

## 9. 🚦 Phase 9 Conclusion & Final Project Status

### **COMPLETE END-TO-END SYSTEM OPERATIONAL**
1. **Passive Ingestion**: Zeek connection, DNS, SSL, Weird, and QUIC log tailing with binary seek checkpointing.
2. **Feature Engineering**: 78 continuous numerical features including Shannon entropy and 10s/60s/300s causal backward sliding windows.
3. **Calibrated Machine Learning**: Frozen `HistGradientBoostingClassifier` with sigmoid Platt scaling and selective abstention.
4. **Real-Time Streaming**: Sub-$20\text{ms}$ inference latency with standardized `AlertEvent` schema.
5. **FastAPI Backend**: REST endpoints and non-blocking `/ws/alerts` WebSocket broadcasting.
6. **Interactive SOC Dashboard**: Cyber dark theme, probability bar distribution, forensic modal inspector, and live streaming alert feed.

*Phase 9 is complete. We are stopped and awaiting your direction.*
