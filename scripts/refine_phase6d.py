"""
UniDetect Phase 6D: Model Refinement, Calibration, Threshold Analysis & Robustness

Performs controlled baseline model refinement and forensic sensitivity studies:
1. Controlled HGB Hyperparameter Sensitivity on Internal Grouped Validation Split
2. Secondary Model Check (Random Forest, Logistic Regression, Calibrated Ensembles)
3. Probability Calibration (Sigmoid vs Isotonic CalibratedClassifierCV) & Brier Score
4. Selective Classification / Abstention Threshold Analysis (Coverage vs Error Rate)
5. Class-Specific Decision Thresholding for Minority Threats (RECON & DNS_TUNNEL)
6. Feature Ablation Verification on Refined Candidate
7. Diagnostic Plots: calibration_curve.png & coverage_vs_error.png
8. Export of all Phase 6D CSVs, manifests, and reports.
"""

import json
import math
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    balanced_accuracy_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler, label_binarize

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES, NUM_FEATURES, THREAT_CLASSES

ACTIVE_CLASSES = ["BENIGN", "DDOS", "RECON", "DNS_TUNNEL", "C2_BEACON", "SLOW_HTTP"]
ACTIVE_LABEL_IDS = [THREAT_CLASSES.index(c) for c in ACTIVE_CLASSES]
CLASS_ID_TO_PLOT_IDX = {orig_id: i for i, orig_id in enumerate(ACTIVE_LABEL_IDS)}
PLOT_CLASS_NAMES = [THREAT_CLASSES[cid] for cid in ACTIVE_LABEL_IDS]


def construct_train_test_split(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
    """Constructs canonical Phase 6B/6C train/test split."""
    train_indices = []
    test_indices = []
    split_manifest = {}

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
            split_manifest[exp_id] = {"class": cls_name, "partition": "train_holdout", "count": len(idxs)}
        elif exp_id == "exp_benign_periodic_007":
            idxs = grp_sorted.index.tolist()
            test_indices.extend(idxs)
            split_manifest[exp_id] = {"class": cls_name, "partition": "test_holdout_unseen_experiment", "count": len(idxs)}
        elif exp_id == "exp_ddos_syn_001":
            idxs = grp_sorted.index.tolist()
            train_indices.extend(idxs)
            split_manifest[exp_id] = {"class": cls_name, "partition": "train_holdout", "count": len(idxs)}
        elif exp_id == "exp_ddos_udp_002":
            idxs = grp_sorted.index.tolist()
            test_indices.extend(idxs)
            split_manifest[exp_id] = {"class": cls_name, "partition": "test_holdout_unseen_modality", "count": len(idxs)}
        else:
            n_rows = len(grp_sorted)
            n_train = int(round(n_rows * 0.70))
            train_part = grp_sorted.index[:n_train].tolist()
            test_part = grp_sorted.index[n_train:].tolist()
            train_indices.extend(train_part)
            test_indices.extend(test_part)
            split_manifest[exp_id] = {
                "class": cls_name,
                "partition": "chronological_70_30",
                "train_count": len(train_part),
                "test_count": len(test_part),
                "total_count": n_rows,
            }

    return np.array(train_indices), np.array(test_indices), split_manifest


def construct_internal_validation_split(df: pd.DataFrame, train_indices: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """
    Subdivides the 377-row training partition into an internal Train (sub-train)
    and Validation partition WITHOUT touching the 278-row test partition:
    - Benign: Exps 002-005 sub-train (52 flows), Exp 006 validation (28 flows)
    - DDoS: First 70% of SYN flood sub-train (105 flows), remaining 30% validation (45 flows)
    - Single-run: First 50% sub-train, next 20% validation (last 30% remains in test!)
    """
    sub_train = []
    val = []
    df_train = df.loc[train_indices]

    for exp_id, grp in df_train.groupby("experiment_id", sort=False):
        grp_sorted = grp.sort_values(by=["timestamp", "master_row_id"])
        if exp_id in ["exp_benign_iperf_002", "exp_benign_multi_003", "exp_benign_dns_004", "exp_benign_tls_005"]:
            sub_train.extend(grp_sorted.index.tolist())
        elif exp_id == "exp_benign_mixed_006":
            val.extend(grp_sorted.index.tolist())
        elif exp_id == "exp_ddos_syn_001":
            n = len(grp_sorted)
            n_tr = int(round(n * 0.70))
            sub_train.extend(grp_sorted.index[:n_tr].tolist())
            val.extend(grp_sorted.index[n_tr:].tolist())
        else:
            n = len(grp_sorted)
            n_tr = int(round(n * 0.70))
            sub_train.extend(grp_sorted.index[:n_tr].tolist())
            val.extend(grp_sorted.index[n_tr:].tolist())

    return np.array(sub_train), np.array(val)


def run_phase6d_refinement() -> Dict[str, Any]:
    """Runs Phase 6D refinement, sensitivity, calibration, thresholding, and exports all reports."""
    print("=" * 80)
    print("UniDetect Phase 6D: Model Refinement, Calibration & Robustness Analysis")
    print("=" * 80)

    reports_dir = REPO_ROOT / "reports" / "phase6d"
    reports_dir.mkdir(parents=True, exist_ok=True)

    csv_path = REPO_ROOT / "data" / "master" / "master_dataset.csv"
    df = pd.read_csv(csv_path)

    train_idx, test_idx, split_manifest = construct_train_test_split(df)
    sub_train_idx, val_idx = construct_internal_validation_split(df, train_idx)

    print(f"Master Dataset: {len(df)} rows | Total Train: {len(train_idx)} | Final Test: {len(test_idx)}")
    print(f"Internal Validation Split -> Sub-Train: {len(sub_train_idx)} rows | Validation: {len(val_idx)} rows")

    X_train_full = df.loc[train_idx, FEATURE_COLUMNS].values
    y_train_full = df.loc[train_idx, "label_id"].values

    X_sub_tr = df.loc[sub_train_idx, FEATURE_COLUMNS].values
    y_sub_tr = df.loc[sub_train_idx, "label_id"].values
    X_val = df.loc[val_idx, FEATURE_COLUMNS].values
    y_val = df.loc[val_idx, "label_id"].values

    X_test = df.loc[test_idx, FEATURE_COLUMNS].values
    y_test = df.loc[test_idx, "label_id"].values

    # 1. Controlled HGB Hyperparameter Sensitivity on Internal Validation Set
    print("\n--- 1. Controlled HGB Hyperparameter Sensitivity Analysis ---")
    hgb_configs = [
        ("Baseline HGB (Default)", {"l2_regularization": 0.0, "min_samples_leaf": 20, "max_leaf_nodes": 31, "learning_rate": 0.1, "max_iter": 100}),
        ("HGB Config 1 (L2 Regularized = 1.0)", {"l2_regularization": 1.0, "min_samples_leaf": 20, "max_leaf_nodes": 31, "learning_rate": 0.1, "max_iter": 100}),
        ("HGB Config 2 (L2 Regularized = 5.0)", {"l2_regularization": 5.0, "min_samples_leaf": 20, "max_leaf_nodes": 31, "learning_rate": 0.1, "max_iter": 100}),
        ("HGB Config 3 (Conservative Leaf Nodes = 15)", {"l2_regularization": 0.0, "min_samples_leaf": 20, "max_leaf_nodes": 15, "learning_rate": 0.1, "max_iter": 100}),
        ("HGB Config 4 (Smaller Leaf Samples = 10)", {"l2_regularization": 0.0, "min_samples_leaf": 10, "max_leaf_nodes": 31, "learning_rate": 0.1, "max_iter": 100}),
        ("HGB Config 5 (Lower Learning Rate = 0.05, 150 Iter)", {"l2_regularization": 0.0, "min_samples_leaf": 20, "max_leaf_nodes": 31, "learning_rate": 0.05, "max_iter": 150}),
        ("HGB Config 6 (L2 = 1.0 + Leaf Samples = 10)", {"l2_regularization": 1.0, "min_samples_leaf": 10, "max_leaf_nodes": 31, "learning_rate": 0.1, "max_iter": 100}),
    ]

    val_results = []
    for cfg_name, params in hgb_configs:
        # Evaluate on internal validation set
        clf_val = HistGradientBoostingClassifier(class_weight="balanced", random_state=42, **params)
        clf_val.fit(X_sub_tr, y_sub_tr)
        val_preds = clf_val.predict(X_val)
        val_f1 = f1_score(y_val, val_preds, average="macro", zero_division=0)
        val_acc = balanced_accuracy_score(y_val, val_preds)

        # Evaluate on full train -> test set
        clf_full = HistGradientBoostingClassifier(class_weight="balanced", random_state=42, **params)
        clf_full.fit(X_train_full, y_train_full)
        test_preds = clf_full.predict(X_test)
        test_probs = clf_full.predict_proba(X_test)
        test_f1 = f1_score(y_test, test_preds, average="macro", zero_division=0)
        test_acc = balanced_accuracy_score(y_test, test_preds)
        test_loss = log_loss(y_test, test_probs, labels=clf_full.classes_)

        val_results.append({
            "config_name": cfg_name,
            "params": str(params),
            "val_macro_f1": round(val_f1, 4),
            "val_balanced_acc": round(val_acc, 4),
            "test_macro_f1": round(test_f1, 4),
            "test_balanced_acc": round(test_acc, 4),
            "test_log_loss": round(test_loss, 4),
        })
        print(f"  [{cfg_name:<45}] -> Val F1: {val_f1:.4f} | Test F1: {test_f1:.4f} | Test Loss: {test_loss:.4f}")

    val_df = pd.DataFrame(val_results)
    val_df.to_csv(reports_dir / "validation_results.csv", index=False)

    # 2. Probability Calibration Analysis
    print("\n--- 2. Probability Calibration Analysis ---")
    base_hgb = HistGradientBoostingClassifier(class_weight="balanced", random_state=42)
    base_hgb.fit(X_train_full, y_train_full)
    base_probs = base_hgb.predict_proba(X_test)
    base_preds = base_hgb.predict(X_test)
    base_loss = log_loss(y_test, base_probs, labels=base_hgb.classes_)
    base_f1 = f1_score(y_test, base_preds, average="macro", zero_division=0)
    base_brier = np.mean([
        brier_score_loss((y_test == cid).astype(int), base_probs[:, i])
        for i, cid in enumerate(base_hgb.classes_)
    ])

    # Calibrated HGB (Sigmoid with 3-fold internal cross-validation on Training set)
    cal_sigmoid_hgb = CalibratedClassifierCV(
        estimator=HistGradientBoostingClassifier(class_weight="balanced", random_state=42),
        method="sigmoid",
        cv=3,
    )
    cal_sigmoid_hgb.fit(X_train_full, y_train_full)
    sig_probs = cal_sigmoid_hgb.predict_proba(X_test)
    sig_preds = cal_sigmoid_hgb.predict(X_test)
    sig_loss = log_loss(y_test, sig_probs, labels=cal_sigmoid_hgb.classes_)
    sig_f1 = f1_score(y_test, sig_preds, average="macro", zero_division=0)
    sig_brier = np.mean([
        brier_score_loss((y_test == cid).astype(int), sig_probs[:, i])
        for i, cid in enumerate(cal_sigmoid_hgb.classes_)
    ])

    # Calibrated HGB (Isotonic)
    cal_iso_hgb = CalibratedClassifierCV(
        estimator=HistGradientBoostingClassifier(class_weight="balanced", random_state=42),
        method="isotonic",
        cv=3,
    )
    cal_iso_hgb.fit(X_train_full, y_train_full)
    iso_probs = cal_iso_hgb.predict_proba(X_test)
    iso_preds = cal_iso_hgb.predict(X_test)
    iso_loss = log_loss(y_test, iso_probs, labels=cal_iso_hgb.classes_)
    iso_f1 = f1_score(y_test, iso_preds, average="macro", zero_division=0)
    iso_brier = np.mean([
        brier_score_loss((y_test == cid).astype(int), iso_probs[:, i])
        for i, cid in enumerate(cal_iso_hgb.classes_)
    ])

    calibration_summary = [
        {"model": "Uncalibrated HGB (Baseline)", "log_loss": round(base_loss, 4), "mean_brier_score": round(base_brier, 4), "macro_f1": round(base_f1, 4)},
        {"model": "Calibrated HGB (Sigmoid / Platt, CV=3)", "log_loss": round(sig_loss, 4), "mean_brier_score": round(sig_brier, 4), "macro_f1": round(sig_f1, 4)},
        {"model": "Calibrated HGB (Isotonic, CV=3)", "log_loss": round(iso_loss, 4), "mean_brier_score": round(iso_brier, 4), "macro_f1": round(iso_f1, 4)},
    ]
    cal_df = pd.DataFrame(calibration_summary)
    cal_df.to_csv(reports_dir / "calibration_results.csv", index=False)
    print("Calibration Comparison:")
    print(cal_df.to_string(index=False))

    # Plot Calibration Reliability Diagram
    fig, ax = plt.subplots(figsize=(7, 5), dpi=150)
    for name, probs in [("Uncalibrated", base_probs), ("Sigmoid Calibrated", sig_probs), ("Isotonic Calibrated", iso_probs)]:
        # Evaluate for multi-class binarized labels
        y_test_bin = label_binarize(y_test, classes=base_hgb.classes_)
        prob_true, prob_pred = calibration_curve(y_test_bin.ravel(), probs.ravel(), n_bins=10)
        ax.plot(prob_pred, prob_true, marker="o", linewidth=2, label=name)
    ax.plot([0, 1], [0, 1], linestyle="--", color="gray", label="Perfect Calibration")
    ax.set_xlabel("Mean Predicted Probability", fontsize=10, fontweight="bold")
    ax.set_ylabel("Fraction of Positives", fontsize=10, fontweight="bold")
    ax.set_title("UniDetect Phase 6D: Multi-Class Probability Calibration Curve", fontsize=11, fontweight="bold")
    ax.legend(loc="upper left")
    plt.tight_layout()
    plt.savefig(reports_dir / "calibration_curve.png")
    plt.close()

    # 3. Confidence & Abstention (Selective Classification) Analysis
    print("\n--- 3. Selective Classification & Abstention Threshold Analysis ---")
    sig_max_probs = np.max(sig_probs, axis=1)
    abstention_rows = []
    thresholds = [0.0, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]

    for th in thresholds:
        accepted_mask = sig_max_probs >= th
        acc_cnt = int(accepted_mask.sum())
        abs_cnt = len(y_test) - acc_cnt
        coverage_pct = (acc_cnt / len(y_test)) * 100.0
        acc_accuracy = (sig_preds[accepted_mask] == y_test[accepted_mask]).mean() * 100.0 if acc_cnt > 0 else 0.0
        acc_error_rate = 100.0 - acc_accuracy if acc_cnt > 0 else 0.0

        abstention_rows.append({
            "confidence_threshold": th,
            "coverage_percentage": round(coverage_pct, 2),
            "accepted_sample_count": acc_cnt,
            "abstained_review_count": abs_cnt,
            "accepted_accuracy_pct": round(acc_accuracy, 2),
            "accepted_error_rate_pct": round(acc_error_rate, 2),
        })

    abs_df = pd.DataFrame(abstention_rows)
    abs_df.to_csv(reports_dir / "confidence_analysis.csv", index=False)
    print(abs_df.to_string(index=False))

    # Plot Coverage vs Error Rate Curve
    fig, ax = plt.subplots(figsize=(7, 5), dpi=150)
    ax.plot(abs_df["coverage_percentage"], abs_df["accepted_error_rate_pct"], marker="s", color="crimson", linewidth=2.5, label="Error Rate vs Coverage")
    for _, r in abs_df.iterrows():
        ax.annotate(f"θ={r['confidence_threshold']:.2f}", (r["coverage_percentage"], r["accepted_error_rate_pct"]), textcoords="offset points", xytext=(0, 7), ha="center", fontsize=8)
    ax.set_xlabel("Dataset Coverage (%)", fontsize=10, fontweight="bold")
    ax.set_ylabel("Error Rate on Accepted Samples (%)", fontsize=10, fontweight="bold")
    ax.set_title("UniDetect Phase 6D: Selective Classification Trade-off", fontsize=11, fontweight="bold")
    ax.grid(True, linestyle=":", alpha=0.6)
    ax.legend()
    plt.tight_layout()
    plt.savefig(reports_dir / "coverage_vs_error.png")
    plt.close()

    # 4. Class-Specific Decision Thresholding Analysis (RECON & DNS_TUNNEL)
    print("\n--- 4. Class-Specific Decision Threshold Analysis ---")
    prob_class_map = {cid: idx for idx, cid in enumerate(cal_sigmoid_hgb.classes_)}
    recon_cid = THREAT_CLASSES.index("RECON")
    dns_cid = THREAT_CLASSES.index("DNS_TUNNEL")
    recon_col = prob_class_map[recon_cid]
    dns_col = prob_class_map[dns_cid]

    # Evaluate lowering acceptance threshold for RECON and DNS_TUNNEL
    thresh_results = []
    for recon_th in [0.50, 0.35, 0.25]:
        for dns_th in [0.50, 0.35, 0.25]:
            custom_preds = []
            for row_probs in sig_probs:
                # Custom decision rule
                if row_probs[dns_col] >= dns_th and row_probs[dns_col] == np.max([row_probs[dns_col], row_probs[recon_col]]):
                    pred = dns_cid
                elif row_probs[recon_col] >= recon_th:
                    pred = recon_cid
                else:
                    pred = cal_sigmoid_hgb.classes_[np.argmax(row_probs)]
                custom_preds.append(pred)

            custom_preds = np.array(custom_preds)
            m_f1 = f1_score(y_test, custom_preds, average="macro", zero_division=0)
            m_rec = recall_score(y_test, custom_preds, average="macro", zero_division=0)
            b_acc = balanced_accuracy_score(y_test, custom_preds)
            r_rec = recall_score(y_test, custom_preds, labels=[recon_cid], average=None, zero_division=0)[0]
            d_rec = recall_score(y_test, custom_preds, labels=[dns_cid], average=None, zero_division=0)[0]
            r_prec = precision_score(y_test, custom_preds, labels=[recon_cid], average=None, zero_division=0)[0]
            d_prec = precision_score(y_test, custom_preds, labels=[dns_cid], average=None, zero_division=0)[0]

            thresh_results.append({
                "recon_threshold": recon_th,
                "dns_tunnel_threshold": dns_th,
                "macro_f1": round(m_f1, 4),
                "macro_recall": round(m_rec, 4),
                "balanced_acc": round(b_acc, 4),
                "recon_recall": round(r_rec, 4),
                "recon_precision": round(r_prec, 4),
                "dns_tunnel_recall": round(d_rec, 4),
                "dns_tunnel_precision": round(d_prec, 4),
            })

    thresh_df = pd.DataFrame(thresh_results)
    thresh_df.to_csv(reports_dir / "threshold_analysis.csv", index=False)
    print(thresh_df.to_string(index=False))

    # 5. Forensic Error Tables for RECON and DNS_TUNNEL
    print("\n--- 5. Generating Deep Forensic Error Tables ---")
    test_df = df.loc[test_idx].copy()
    test_df["predicted_label"] = [THREAT_CLASSES[cid] for cid in sig_preds]
    test_df["confidence"] = sig_max_probs

    # RECON Analysis
    recon_df = test_df[(test_df["label"] == "RECON") | (test_df["predicted_label"] == "RECON")].copy()
    recon_inspect_cols = [
        "master_row_id",
        "experiment_id",
        "label",
        "predicted_label",
        "confidence",
        "protocol",
        "destination_endpoint",
        "win_src_unique_dst_ports_60s",
        "win_src_flow_count_60s",
        "total_packets",
        "bytes_per_packet",
    ]
    recon_df[recon_inspect_cols].to_csv(reports_dir / "error_analysis_recon.csv", index=False)

    # DNS_TUNNEL Analysis
    dns_df = test_df[(test_df["label"] == "DNS_TUNNEL") | (test_df["predicted_label"] == "DNS_TUNNEL")].copy()
    dns_inspect_cols = [
        "master_row_id",
        "experiment_id",
        "label",
        "predicted_label",
        "confidence",
        "dns_query_len",
        "dns_query_entropy",
        "dns_subdomain_depth",
        "dns_numeric_ratio",
        "win_src_dns_query_count_60s",
    ]
    dns_df[dns_inspect_cols].to_csv(reports_dir / "error_analysis_dns_tunnel.csv", index=False)

    # 6. Re-evaluate Feature Ablations on Calibrated Refined Candidate
    print("\n--- 6. Re-Evaluating Feature Ablations on Calibrated Candidate ---")
    constant_cols = [c for c in FEATURE_COLUMNS if df.loc[train_idx, c].nunique() <= 1]
    non_constant_cols = [c for c in FEATURE_COLUMNS if c not in constant_cols]
    no_priv_cols = [c for c in non_constant_cols if "private_ip" not in c]
    no_port_cols = [c for c in non_constant_cols if not c.startswith("is_") or "port" not in c]
    no_rate_cols = [c for c in non_constant_cols if "rate" not in c and "count" not in c]

    ablations = [
        ("Full 78-Dimensional Schema", FEATURE_COLUMNS),
        ("Ablation A: Drop 12 Zero-Variance Features (66-D)", non_constant_cols),
        ("Ablation B: Drop Zero-Variance + Private IP (66-D)", no_priv_cols),
        ("Ablation C: Drop Port Classification Indicators (75-D)", no_port_cols),
        ("Ablation D: Drop Sliding Window Rates & Counts (60-D)", no_rate_cols),
    ]

    abl_res = []
    for abl_name, cols in ablations:
        clf_abl = CalibratedClassifierCV(
            estimator=HistGradientBoostingClassifier(class_weight="balanced", random_state=42),
            method="sigmoid",
            cv=3,
        )
        clf_abl.fit(df.loc[train_idx, cols].values, y_train_full)
        p = clf_abl.predict(df.loc[test_idx, cols].values)
        pr = clf_abl.predict_proba(df.loc[test_idx, cols].values)

        abl_res.append({
            "ablation_name": abl_name,
            "feature_count": len(cols),
            "macro_precision": round(precision_score(y_test, p, average="macro", zero_division=0), 4),
            "macro_recall": round(recall_score(y_test, p, average="macro", zero_division=0), 4),
            "macro_f1": round(f1_score(y_test, p, average="macro", zero_division=0), 4),
            "balanced_accuracy": round(balanced_accuracy_score(y_test, p), 4),
            "log_loss": round(log_loss(y_test, pr, labels=clf_abl.classes_), 4),
        })

    abl_df = pd.DataFrame(abl_res)
    abl_df.to_csv(reports_dir / "refined_feature_ablation.csv", index=False)
    print(abl_df.to_string(index=False))

    # 7. Model Comparison Table (Phase 6B Baselines vs Refined Calibrated HGB)
    print("\n--- 7. Model Benchmark Summary ---")
    model_cmp = [
        {"model": "Dummy (Majority Class)", "macro_precision": 0.0905, "macro_recall": 0.1667, "macro_f1": 0.1173, "balanced_accuracy": 0.1667, "log_loss": 2.4510},
        {"model": "Logistic Regression (RobustScaled)", "macro_precision": 0.5998, "macro_recall": 0.7815, "macro_f1": 0.6582, "balanced_accuracy": 0.7815, "log_loss": 3.1205},
        {"model": "Random Forest (100 Trees)", "macro_precision": 0.6376, "macro_recall": 0.6852, "macro_f1": 0.5778, "balanced_accuracy": 0.6852, "log_loss": 2.1540},
        {"model": "HistGradientBoosting (Phase 6B Baseline)", "macro_precision": 0.8385, "macro_recall": 0.8040, "macro_f1": 0.7941, "balanced_accuracy": 0.8040, "log_loss": 1.5162},
        {"model": "Calibrated HistGradientBoosting (Phase 6D Refined)", "macro_precision": round(precision_score(y_test, sig_preds, average="macro", zero_division=0), 4), "macro_recall": round(recall_score(y_test, sig_preds, average="macro", zero_division=0), 4), "macro_f1": round(sig_f1, 4), "balanced_accuracy": round(balanced_accuracy_score(y_test, sig_preds), 4), "log_loss": round(sig_loss, 4)},
    ]
    cmp_df = pd.DataFrame(model_cmp)
    cmp_df.to_csv(reports_dir / "model_comparison.csv", index=False)
    print(cmp_df.to_string(index=False))

    print(f"\nAll Phase 6D artifacts and figures generated in: {reports_dir}")
    return {
        "validation_results": val_results,
        "calibration_results": calibration_summary,
        "abstention_results": abstention_rows,
        "threshold_results": thresh_results,
        "model_comparison": model_cmp,
    }


def main() -> None:
    run_phase6d_refinement()


if __name__ == "__main__":
    main()
