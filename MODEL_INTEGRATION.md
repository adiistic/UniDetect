# UniDetect Model Integration Contract

This document specifies the exact contract required by the UniDetect Backend (Person 3) from the ML/Dataset Engineering Team (Person 2).

---

## 1. Required Artifact Details

| Item | Specification | Description |
| :--- | :--- | :--- |
| **Target Location** | `models/unidetect_model.joblib` (or `.pkl`) | Drop your final model file into the `models/` directory. |
| **Input Dimensions** | **Exactly 78 float values** | The vector schema is frozen at 78 dimensions (`78d-v1`). |
| **Feature Ordering** | Canonical indices `0` through `77` | Follows the frozen 78D feature contract. |
| **Model Interface** | `predict(X)` and `predict_proba(X)` | Must accept 2D array of shape `(N, 78)` with `dtype=float64`. |

---

## 2. Canonical Class Mapping

The backend strictly maps numeric prediction output to the following 6 canonical classes:

| Class ID | Class Name | Subtypes / Notes | Candidate Corpus Distribution |
| :---: | :--- | :--- | :---: |
| `0` | **BENIGN** | Normal network traffic | 52 vectors |
| `1` | **DDOS** | TCP SYN Flood, UDP Flood | 301 vectors |
| `2` | **RECON** | Port scans, host discovery | 59 vectors |
| `3` | **SLOW_HTTP** | Slowloris, Slow POST | 50 vectors |
| `4` | **DNS_TUNNEL** | Exfiltration / C2 over DNS | 52 vectors |
| `5` | **C2_BEACON** | Command & Control beaconing | 50 vectors |
| **Total** | | | **564 candidate vectors** |

---

## 3. Recommended Artifact Packaging

You can save either a raw trained scikit-learn estimator/pipeline or a metadata-wrapped dictionary:

### Option A: Metadata-Wrapped Dictionary (Recommended)
```python
import joblib

model_bundle = {
    "model": trained_pipeline_or_classifier,
    "version": "1.0.0",
    "schema_version": "78d-v1",
    "classes": [0, 1, 2, 3, 4, 5],
    "metadata": {
        "model_type": "RandomForestClassifier",
        "training_dataset": "unidetect_candidate_corpus_v1",
        "train_samples": 564,
        "features": 78,
    }
}

joblib.dump(model_bundle, "models/unidetect_model.joblib")
```

### Option B: Direct Scikit-Learn Model / Pipeline
```python
import joblib

joblib.dump(trained_model, "models/unidetect_model.joblib")
```

---

## 4. Activating Your Model in the Backend

Once your model file is saved in `models/unidetect_model.joblib`:

1. Update your `.env` file:
   ```env
   MODEL_PROVIDER=local
   MODEL_PATH=models/unidetect_model.joblib
   MODEL_VERSION=1.0.0
   ```
2. Start or restart the backend:
   ```bash
   uvicorn backend.main:app --reload
   ```
3. Check model readiness:
   ```bash
   curl http://localhost:8000/api/v1/readiness
   curl http://localhost:8000/api/v1/model/status
   ```

**The backend will immediately start serving real predictions without modifying any API or frontend code.**
