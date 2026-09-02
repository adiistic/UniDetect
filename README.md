# UniDetect Backend - Network Threat Classification API

UniDetect is a high-performance network-threat classification REST API built with FastAPI, Pydantic, and Scikit-Learn. It serves inference over a frozen **78-dimensional network flow feature schema** across 6 canonical threat classes.

---

## Architecture Overview

```
Frontend / Client / Security Dashboard
                  │
                  ▼
          FastAPI REST API
                  │
                  ▼
       Input & Type Validation
                  │
                  ▼
   78-D Feature Schema Normalizer
                  │
                  ▼
          InferenceService
                  │
                  ▼
            ModelAdapter
        ┌─────────┼─────────┐
        ▼         ▼         ▼
    MockModel  LocalModel  ExternalAPI
                  │
                  ▼
   Class Prediction + Probabilities
                  │
                  ▼
       Standard JSON Response
```

---

## Canonical Experiment Classes

| Class ID | Threat Class | Subtypes / Scope |
| :---: | :--- | :--- |
| `0` | **BENIGN** | Normal network flow activity |
| `1` | **DDOS** | TCP SYN Flood, UDP Flood |
| `2` | **RECON** | Port scanning, host enumeration |
| `3` | **SLOW_HTTP** | Slowloris, Slow POST attacks |
| `4` | **DNS_TUNNEL** | DNS exfiltration / C2 over DNS |
| `5` | **C2_BEACON** | Command and Control periodic beaconing |

---

## Quick Start

### 1. Environment Setup & Dependencies
```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Default `.env` settings:
```env
MODEL_PROVIDER=mock
MODEL_PATH=models/unidetect_model.joblib
MODEL_VERSION=0.1.0-dev
SCHEMA_VERSION=78d-v1
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
```

### 3. Start the Backend Server
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Interactive API Documentation

Once the server is running, visit:
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **OpenAPI Schema**: [http://localhost:8000/openapi.json](http://localhost:8000/openapi.json)

---

## API Endpoints

### 1. Health Probe (`GET /api/v1/health`)
Liveness check indicating whether the backend process is running.
```bash
curl http://localhost:8000/api/v1/health
```
**Response (200 OK):**
```json
{
  "status": "ok",
  "service": "unidetect-backend",
  "model_loaded": true
}
```

---

### 2. Readiness Probe (`GET /api/v1/readiness`)
Checks if the model adapter is loaded and ready to serve inference.
```bash
curl http://localhost:8000/api/v1/readiness
```
**Response (200 OK):**
```json
{
  "ready": true,
  "status": "READY",
  "reason": null,
  "provider": "mock"
}
```

---

### 3. Model Status (`GET /api/v1/model/status`)
Inspects active model details, schema version, and feature count without exposing secrets.
```bash
curl http://localhost:8000/api/v1/model/status
```
**Response (200 OK):**
```json
{
  "loaded": true,
  "provider": "mock",
  "is_mock": true,
  "model_name": "development_mock",
  "model_version": "0.1.0-dev",
  "schema_version": "78d-v1",
  "feature_count": 78,
  "metadata": {
    "provider": "mock",
    "is_mock": true,
    "feature_count": 78,
    "classes": ["BENIGN", "DDOS", "RECON", "SLOW_HTTP", "DNS_TUNNEL", "C2_BEACON"]
  }
}
```

---

### 4. Single Sample Prediction (`POST /api/v1/predict`)
Accepts an ordered list of **exactly 78 numerical values**.
```bash
curl -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{
    "features": [0.0, 1.2, 0.0, 5.4, 100.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
  }'
```
**Response (200 OK):**
```json
{
  "prediction": {
    "class_id": 1,
    "class_name": "DDOS",
    "subtypes": ["TCP SYN Flood", "UDP Flood"]
  },
  "confidence": 0.90,
  "probabilities": {
    "BENIGN": 0.02,
    "DDOS": 0.90,
    "RECON": 0.02,
    "SLOW_HTTP": 0.02,
    "DNS_TUNNEL": 0.02,
    "C2_BEACON": 0.02
  },
  "model": {
    "provider": "mock",
    "model_version": "0.1.0-dev",
    "schema_version": "78d-v1",
    "feature_count": 78,
    "is_mock": true
  },
  "latency_ms": 0.52,
  "mode": "mock"
}
```

---

### 5. Batch Sample Prediction (`POST /api/v1/predict/batch`)
```bash
curl -X POST http://localhost:8000/api/v1/predict/batch \
  -H "Content-Type: application/json" \
  -d '{
    "samples": [
      {"features": [0.0, 0.0, ... 78 values ...]},
      {"features": [1.5, 2.3, ... 78 values ...]}
    ]
  }'
```

---

## 78-Dimensional Feature Validation Rules

1. **Exact Dimension Count**: Feature arrays must have length **exactly 78**. Arrays of length 77, 79, etc. return `422 Unprocessable Entity`.
2. **No NaN / Infinity**: Any presence of `NaN`, `+Infinity`, `-Infinity`, or `null` is rejected with `422`.
3. **No Non-Numeric Data**: Strings or invalid types are rejected with `422`.
4. **Named Dictionary Support**: A dictionary matching canonical feature names (`f_00_dst_port` .. `f_77_flow_anomaly_score` or `feature_0` .. `feature_77`) is supported.

---

## Plugging in Person 2's Trained Model

When Person 2 finishes model training:
1. Save the model file to `models/unidetect_model.joblib`.
2. Set in `.env`:
   ```env
   MODEL_PROVIDER=local
   MODEL_PATH=models/unidetect_model.joblib
   MODEL_VERSION=1.0.0
   ```
3. Restart the backend:
   ```bash
   uvicorn backend.main:app --reload
   ```
See [MODEL_INTEGRATION.md](MODEL_INTEGRATION.md) for full integration guidelines.

---

## External Model Provider Support

To route inference to a remote microservice:
```env
MODEL_PROVIDER=external
MODEL_API_URL=https://ml-inference.internal/predict
MODEL_API_KEY=your-secure-api-token-here
```
API keys are loaded via Pydantic `SecretStr` and are never logged or exposed in responses.

---

## Running Tests

Run the test suite:
```bash
# Pytest test suite (61 tests)
.venv/bin/pytest tests/ -v

# Unittest runner
.venv/bin/python -m unittest discover -s tests
```

---

## Security Best Practices
- **No hardcoded secrets**: All API keys and environment variables are loaded securely via `.env`.
- **Safe error messages**: Python tracebacks and internal credentials are not leaked to API clients.
- **Request ID tracking**: Every request generates a unique `X-Request-ID` header.
- **Configurable CORS**: Allowed origins are restricted and configurable via `CORS_ORIGINS`.
