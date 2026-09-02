"""
UniDetect Final Model Serialization & Inference Preparation (Phase 6E)

Trains and serializes the authoritative final model candidate:
- Sigmoid-Calibrated HistGradientBoostingClassifier (CV=3)
- Frozen 78-dimensional Feature Contract
- Decoupled Decision Policy with Selective Abstention (theta=0.40) & RECON tuning (theta=0.35)
- Full Metadata Manifest & Serialization Verification
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    balanced_accuracy_score,
    classification_report,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES, NUM_FEATURES, THREAT_CLASSES
from src.inference.contract import FeatureContract, SCHEMA_VERSION
from src.inference.detector import ThreatDetector
from src.inference.policy import DecisionPolicy, DEFAULT_ABSTAIN_THRESHOLD, DEFAULT_RECON_THRESHOLD

MODEL_VERSION = "unidetect-hgb-calibrated-v1.0.0"
ACTIVE_CLASSES = ["BENIGN", "DDOS", "RECON", "DNS_TUNNEL", "C2_BEACON", "SLOW_HTTP"]
ACTIVE_LABEL_IDS = [THREAT_CLASSES.index(c) for c in ACTIVE_CLASSES]


def construct_canonical_split(df: pd.DataFrame):
    """Constructs the canonical Phase 6B/6C/6D train/test split."""
    train_indices = []
    test_indices = []
    split_info = {}

    for exp_id, grp in df.groupby("experiment_id", sort=False):
        grp_sorted = grp.sort_values(by=["timestamp", "master_row_id"])
        cls_name = grp["label"].iloc[0]

        if exp_id in [
            "exp_benign_iperf_002",
            "exp_benign_multi_003",
            "exp_benign_dns_004",
            "exp_benign_tls_005",
            "exp_benign_mixed_006",
        ]:
            idxs = grp_sorted.index.tolist()
            train_indices.extend(idxs)
            split_info[exp_id] = {"class": cls_name, "split": "train", "count": len(idxs)}
        elif exp_id == "exp_benign_periodic_007":
            idxs = grp_sorted.index.tolist()
            test_indices.extend(idxs)
            split_info[exp_id] = {"class": cls_name, "split": "test", "count": len(idxs)}
        elif exp_id == "exp_ddos_syn_001":
            idxs = grp_sorted.index.tolist()
            train_indices.extend(idxs)
            split_info[exp_id] = {"class": cls_name, "split": "train", "count": len(idxs)}
        elif exp_id == "exp_ddos_udp_002":
            idxs = grp_sorted.index.tolist()
            test_indices.extend(idxs)
            split_info[exp_id] = {"class": cls_name, "split": "test", "count": len(idxs)}
        else:
            n = len(grp_sorted)
            n_tr = int(round(n * 0.70))
            tr_part = grp_sorted.index[:n_tr].tolist()
            te_part = grp_sorted.index[n_tr:].tolist()
            train_indices.extend(tr_part)
            test_indices.extend(te_part)
            split_info[exp_id] = {
                "class": cls_name,
                "split": "chronological_70_30",
                "train_count": len(tr_part),
                "test_count": len(te_part),
            }

    return np.array(train_indices), np.array(test_indices), split_info


def serialize_phase6e_artifacts() -> Dict[str, Any]:
    """Trains, evaluates, serializes, and verifies the final model artifacts."""
    print("=" * 80)
    print("UniDetect Phase 6E: Final Model Training & Serialization")
    print("=" * 80)

    models_dir = REPO_ROOT / "models" / "phase6e"
    model_sub_dir = models_dir / "model"
    meta_sub_dir = models_dir / "metadata"
    contract_sub_dir = models_dir / "feature_contract"
    thresh_sub_dir = models_dir / "thresholds"

    for d in [model_sub_dir, meta_sub_dir, contract_sub_dir, thresh_sub_dir]:
        d.mkdir(parents=True, exist_ok=True)

    csv_path = REPO_ROOT / "data" / "master" / "master_dataset.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Master dataset CSV missing: {csv_path}")

    df = pd.read_csv(csv_path)
    train_idx, test_idx, split_info = construct_canonical_split(df)

    print(f"Loaded Master Dataset: {len(df)} rows | Train: {len(train_idx)} rows | Test: {len(test_idx)} rows")

    X_train = df.loc[train_idx, FEATURE_COLUMNS].values
    y_train = df.loc[train_idx, "label_id"].values
    X_test = df.loc[test_idx, FEATURE_COLUMNS].values
    y_test = df.loc[test_idx, "label_id"].values

    # 1. Train Final Model: CalibratedClassifierCV with Base HistGradientBoosting
    print("Training final production candidate: Sigmoid-Calibrated HistGradientBoosting (CV=3)...")
    base_estimator = HistGradientBoostingClassifier(
        class_weight="balanced",
        random_state=42,
        learning_rate=0.1,
        max_leaf_nodes=31,
        min_samples_leaf=20,
        l2_regularization=0.0,
    )
    final_model = CalibratedClassifierCV(
        estimator=base_estimator,
        method="sigmoid",
        cv=3,
    )
    final_model.fit(X_train, y_train)

    # 2. Evaluate on Holdout Test Partition
    test_preds = final_model.predict(X_test)
    test_probs = final_model.predict_proba(X_test)

    macro_p = precision_score(y_test, test_preds, average="macro", zero_division=0)
    macro_r = recall_score(y_test, test_preds, average="macro", zero_division=0)
    macro_f1 = f1_score(y_test, test_preds, average="macro", zero_division=0)
    bal_acc = balanced_accuracy_score(y_test, test_preds)
    loss = log_loss(y_test, test_probs, labels=final_model.classes_)

    per_class_f1 = f1_score(y_test, test_preds, average=None, labels=ACTIVE_LABEL_IDS, zero_division=0)
    per_class_rec = recall_score(y_test, test_preds, average=None, labels=ACTIVE_LABEL_IDS, zero_division=0)
    per_class_prec = precision_score(y_test, test_preds, average=None, labels=ACTIVE_LABEL_IDS, zero_division=0)

    print(f"\nFinal Test Partition Evaluation Metrics:")
    print(f"  Macro Precision: {macro_p:.4f}")
    print(f"  Macro Recall:    {macro_r:.4f}")
    print(f"  Macro F1:        {macro_f1:.4f}")
    print(f"  Balanced Acc:    {bal_acc:.4f}")
    print(f"  Log Loss:        {loss:.4f}")

    per_class_metrics = {
        cls_name: {
            "precision": round(per_class_prec[i], 4),
            "recall": round(per_class_rec[i], 4),
            "f1_score": round(per_class_f1[i], 4),
            "support": int(np.sum(y_test == ACTIVE_LABEL_IDS[i])),
        }
        for i, cls_name in enumerate(ACTIVE_CLASSES)
    }

    # 3. Serialize Model to model/model.joblib
    model_file_path = model_sub_dir / "model.joblib"
    print(f"Serializing trained model to: {model_file_path}...")
    joblib.dump(final_model, model_file_path, compress=3)

    # 4. Serialize Feature Contract to feature_contract/feature_contract.json
    contract = FeatureContract()
    contract_dict = contract.export_contract_dict()
    contract_file_path = contract_sub_dir / "feature_contract.json"
    print(f"Serializing feature contract to: {contract_file_path}...")
    with open(contract_file_path, "w", encoding="utf-8") as f:
        json.dump(contract_dict, f, indent=2)

    # 5. Serialize Decision Policy to thresholds/decision_policy.json
    policy = DecisionPolicy(
        abstain_threshold=DEFAULT_ABSTAIN_THRESHOLD,
        recon_threshold=DEFAULT_RECON_THRESHOLD,
        classes=ACTIVE_CLASSES,
        active_label_ids=ACTIVE_LABEL_IDS,
    )
    policy_dict = policy.export_policy_dict()
    policy_file_path = thresh_sub_dir / "decision_policy.json"
    print(f"Serializing decision policy to: {policy_file_path}...")
    with open(policy_file_path, "w", encoding="utf-8") as f:
        json.dump(policy_dict, f, indent=2)

    # 6. Serialize Metadata Manifest to metadata/model_metadata.json
    meta_dict = {
        "model_name": "UniDetect Passive Threat Classifier",
        "model_version": MODEL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "creation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "architecture": {
            "base_estimator": "HistGradientBoostingClassifier",
            "calibration_wrapper": "CalibratedClassifierCV(method='sigmoid', cv=3)",
            "hyperparameters": {
                "learning_rate": 0.1,
                "max_leaf_nodes": 31,
                "min_samples_leaf": 20,
                "l2_regularization": 0.0,
                "class_weight": "balanced",
                "random_state": 42,
            },
        },
        "feature_specification": {
            "num_features": NUM_FEATURES,
            "feature_columns": list(FEATURE_COLUMNS),
            "data_type": "float64",
        },
        "target_specification": {
            "classes": ACTIVE_CLASSES,
            "label_ids": ACTIVE_LABEL_IDS,
            "threat_classes_enum": list(THREAT_CLASSES),
        },
        "training_provenance": {
            "source_dataset": "data/master/master_dataset.csv",
            "total_corpus_rows": len(df),
            "training_rows_count": len(train_idx),
            "test_rows_count": len(test_idx),
            "split_specification": split_info,
        },
        "evaluation_metrics": {
            "macro_precision": round(macro_p, 4),
            "macro_recall": round(macro_r, 4),
            "macro_f1": round(macro_f1, 4),
            "balanced_accuracy": round(bal_acc, 4),
            "log_loss": round(loss, 4),
            "per_class_metrics": per_class_metrics,
        },
        "software_dependencies": {
            "python": sys.version.split()[0],
            "scikit_learn": joblib.__name__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
        },
        "operational_thresholds": {
            "abstain_confidence_threshold": DEFAULT_ABSTAIN_THRESHOLD,
            "recon_threshold": DEFAULT_RECON_THRESHOLD,
        },
    }
    meta_file_path = meta_sub_dir / "model_metadata.json"
    print(f"Serializing model metadata manifest to: {meta_file_path}...")
    with open(meta_file_path, "w", encoding="utf-8") as f:
        json.dump(meta_dict, f, indent=2)

    # 7. Serialization Round-Trip Verification via ThreatDetector
    print("\nVerifying serialization round-trip with ThreatDetector...")
    detector = ThreatDetector.from_artifact_dir(models_dir)

    # Test on first 5 rows of test partition
    sample_rows = df.loc[test_idx[:5], FEATURE_COLUMNS].to_dict(orient="records")
    for idx, row_dict in enumerate(sample_rows):
        verdict = detector.predict_single(row_dict)
        raw_prob = final_model.predict_proba(df.loc[test_idx[idx], FEATURE_COLUMNS].values.reshape(1, -1))[0]
        max_raw_prob = np.max(raw_prob)
        # Verify consistency within numerical precision
        diff = abs(verdict["confidence"] - max_raw_prob)
        if diff > 1e-3:
            raise ValueError(f"Round-trip prediction mismatch on row {idx}: diff {diff}")

    print("ThreatDetector successfully validated on serialized artifacts!")
    print(f"All Phase 6E artifacts saved to: {models_dir}")

    return {
        "models_dir": str(models_dir),
        "model_version": MODEL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "metrics": {
            "macro_precision": round(macro_p, 4),
            "macro_recall": round(macro_r, 4),
            "macro_f1": round(macro_f1, 4),
            "balanced_accuracy": round(bal_acc, 4),
            "log_loss": round(loss, 4),
        },
        "per_class_metrics": per_class_metrics,
    }


def main() -> None:
    serialize_phase6e_artifacts()


if __name__ == "__main__":
    main()
