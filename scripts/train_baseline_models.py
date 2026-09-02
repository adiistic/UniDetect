"""
UniDetect Baseline Machine Learning Model Training & Evaluation (Phase 6B)

Evaluates baseline multiclass threat detection models on the 78-dimensional master
dataset using strict leakage-controlled train/test partitioning, ablation studies,
feature importance extraction, and confusion matrix visualizations.
"""

import json
import math
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler, StandardScaler
from sklearn.tree import DecisionTreeClassifier

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.features.schema import FEATURE_COLUMNS, FEATURE_INDICES, NUM_FEATURES, THREAT_CLASSES

# Target active classes in current corpus
ACTIVE_CLASSES = ["BENIGN", "DDOS", "RECON", "DNS_TUNNEL", "C2_BEACON", "SLOW_HTTP"]
ACTIVE_LABEL_IDS = [THREAT_CLASSES.index(c) for c in ACTIVE_CLASSES]
# Mapping for zero-indexed confusion matrix plotting (0..5)
CLASS_ID_TO_PLOT_IDX = {orig_id: i for i, orig_id in enumerate(ACTIVE_LABEL_IDS)}
PLOT_CLASS_NAMES = [THREAT_CLASSES[cid] for cid in ACTIVE_LABEL_IDS]


def construct_train_test_split(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
    """
    Constructs the leakage-controlled train/test index partition:
    - BENIGN: multi-run split (Exps 002-006 train, Exp 007 periodic hard negative test)
    - DDOS: multi-run split (Exp 001 SYN flood train, Exp 002 UDP flood test)
    - Single-run classes: strict chronological 70% train / 30% test holdout block
    """
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
            # Single-run classes: 70% chronological train, 30% chronological test
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

    train_idx_arr = np.array(train_indices)
    test_idx_arr = np.array(test_indices)

    return train_idx_arr, test_idx_arr, split_manifest


def plot_confusion_matrix(
    cm: np.ndarray,
    class_names: List[str],
    model_name: str,
    output_path: Path,
) -> None:
    """Renders and saves a clean, legible confusion matrix plot."""
    fig, ax = plt.subplots(figsize=(7, 6), dpi=150)
    cax = ax.matshow(cm, cmap=plt.cm.Blues, alpha=0.85)

    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            val = cm[i, j]
            color = "white" if val > cm.max() / 2 else "black"
            ax.text(j, i, str(val), va="center", ha="center", color=color, fontsize=11, fontweight="bold")

    fig.colorbar(cax, fraction=0.046, pad=0.04)
    ax.set_xticks(range(len(class_names)))
    ax.set_yticks(range(len(class_names)))
    ax.set_xticklabels(class_names, rotation=45, ha="left", fontsize=9)
    ax.set_yticklabels(class_names, fontsize=9)
    ax.set_xlabel("Predicted Label", fontsize=10, fontweight="bold", labelpad=10)
    ax.set_ylabel("True Label", fontsize=10, fontweight="bold", labelpad=10)
    ax.set_title(f"Confusion Matrix: {model_name}", fontsize=11, fontweight="bold", pad=20)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def train_and_evaluate_baselines() -> Dict[str, Any]:
    """Runs baseline model training, evaluations, ablations, and generates reports."""
    print("=" * 80)
    print("UniDetect Phase 6B: Baseline ML Training & Evaluation")
    print("=" * 80)

    reports_dir = REPO_ROOT / "reports" / "phase6b"
    reports_dir.mkdir(parents=True, exist_ok=True)

    csv_path = REPO_ROOT / "data" / "master" / "master_dataset.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Master dataset CSV missing: {csv_path}")

    df = pd.read_csv(csv_path)
    print(f"Loaded Master Dataset: {df.shape[0]} rows, {len(FEATURE_COLUMNS)} feature columns")

    train_idx, test_idx, split_manifest = construct_train_test_split(df)
    print(f"Train Partition: {len(train_idx)} rows | Test Partition: {len(test_idx)} rows")

    X_train_df = df.loc[train_idx, FEATURE_COLUMNS]
    y_train = df.loc[train_idx, "label_id"].values
    X_test_df = df.loc[test_idx, FEATURE_COLUMNS]
    y_test = df.loc[test_idx, "label_id"].values

    # Programmatically identify constant / zero-variance columns on Training Set
    constant_features = [c for c in FEATURE_COLUMNS if X_train_df[c].nunique() <= 1]
    non_constant_features = [c for c in FEATURE_COLUMNS if c not in constant_features]
    no_priv_features = [c for c in non_constant_features if "private_ip" not in c]
    no_port_features = [c for c in non_constant_features if not c.startswith("is_") or "port" not in c]

    print(f"\nProgrammatic Feature Mask Diagnostics:")
    print(f"  - Full 78-D Features: {len(FEATURE_COLUMNS)}")
    print(f"  - Training Zero-Variance Features ({len(constant_features)}): {constant_features}")
    print(f"  - Non-Constant Active Features: {len(non_constant_features)}")

    models = {
        "Dummy (Majority Class)": DummyClassifier(strategy="most_frequent"),
        "Logistic Regression (Balanced, RobustScaled)": Pipeline(
            [
                ("scaler", RobustScaler()),
                ("clf", LogisticRegression(class_weight="balanced", max_iter=2000, random_state=42)),
            ]
        ),
        "Decision Tree (Balanced)": DecisionTreeClassifier(class_weight="balanced", random_state=42),
        "Random Forest (Balanced, 100 Trees)": RandomForestClassifier(
            n_estimators=100, class_weight="balanced", random_state=42
        ),
        "HistGradientBoosting (Balanced)": HistGradientBoostingClassifier(
            class_weight="balanced", random_state=42
        ),
    }

    results = []
    confusion_matrices = {}

    for model_name, model in models.items():
        print(f"\nTraining Model: {model_name}...")
        # Fit on training data
        model.fit(X_train_df.values, y_train)

        # Predict
        y_train_pred = model.predict(X_train_df.values)
        y_test_pred = model.predict(X_test_df.values)

        # Compute Metrics on Test Set
        macro_p = precision_score(y_test, y_test_pred, average="macro", zero_division=0)
        macro_r = recall_score(y_test, y_test_pred, average="macro", zero_division=0)
        macro_f1 = f1_score(y_test, y_test_pred, average="macro", zero_division=0)
        weighted_f1 = f1_score(y_test, y_test_pred, average="weighted", zero_division=0)
        bal_acc = balanced_accuracy_score(y_test, y_test_pred)

        # Train metrics for overfitting gap
        train_macro_f1 = f1_score(y_train, y_train_pred, average="macro", zero_division=0)
        train_bal_acc = balanced_accuracy_score(y_train, y_train_pred)

        # Per-class metrics
        per_class_f1 = f1_score(y_test, y_test_pred, average=None, labels=ACTIVE_LABEL_IDS, zero_division=0)
        per_class_rec = recall_score(y_test, y_test_pred, average=None, labels=ACTIVE_LABEL_IDS, zero_division=0)
        per_class_prec = precision_score(y_test, y_test_pred, average=None, labels=ACTIVE_LABEL_IDS, zero_division=0)
        test_support = [np.sum(y_test == cid) for cid in ACTIVE_LABEL_IDS]

        # Remap confusion matrix to 0..5 index for active classes
        y_test_mapped = [CLASS_ID_TO_PLOT_IDX[val] for val in y_test]
        y_pred_mapped = [CLASS_ID_TO_PLOT_IDX.get(val, 0) for val in y_test_pred]
        cm = confusion_matrix(y_test_mapped, y_pred_mapped, labels=range(len(ACTIVE_LABEL_IDS)))
        confusion_matrices[model_name] = cm.tolist()

        # Plot confusion matrix
        safe_name = model_name.split("(")[0].strip().lower().replace(" ", "_")
        fig_path = reports_dir / f"confusion_matrix_{safe_name}.png"
        plot_confusion_matrix(cm, PLOT_CLASS_NAMES, model_name, fig_path)

        res_entry = {
            "model_name": model_name,
            "train_macro_f1": round(train_macro_f1, 4),
            "train_balanced_acc": round(train_bal_acc, 4),
            "test_macro_precision": round(macro_p, 4),
            "test_macro_recall": round(macro_r, 4),
            "test_macro_f1": round(macro_f1, 4),
            "test_weighted_f1": round(weighted_f1, 4),
            "test_balanced_acc": round(bal_acc, 4),
            "per_class": {
                cls_name: {
                    "precision": round(per_class_prec[i], 4),
                    "recall": round(per_class_rec[i], 4),
                    "f1": round(per_class_f1[i], 4),
                    "support": int(test_support[i]),
                }
                for i, cls_name in enumerate(ACTIVE_CLASSES)
            },
        }
        results.append(res_entry)

        print(f"  -> Test Macro F1: {macro_f1:.4f} | Balanced Acc: {bal_acc:.4f} | Weighted F1: {weighted_f1:.4f}")
        for cls_name in ACTIVE_CLASSES:
            sub = res_entry["per_class"][cls_name]
            print(f"     [{cls_name:<10}] F1: {sub['f1']:.4f} (Rec: {sub['recall']:.4f}, Prec: {sub['precision']:.4f}, N={sub['support']})")

    # 4. Feature Importance Extraction for Random Forest and HistGradientBoosting
    print("\nExtracting Feature Importances...")
    rf_model: RandomForestClassifier = models["Random Forest (Balanced, 100 Trees)"]
    rf_importances = rf_model.feature_importances_
    rf_feat_imp = pd.DataFrame({
        "feature_index": range(NUM_FEATURES),
        "feature_name": FEATURE_COLUMNS,
        "importance": rf_importances,
    }).sort_values(by="importance", ascending=False)
    rf_feat_imp.to_csv(reports_dir / "feature_importance_random_forest.csv", index=False)

    # Permutation importance for HistGradientBoosting
    hgb_model: HistGradientBoostingClassifier = models["HistGradientBoosting (Balanced)"]
    perm_imp = permutation_importance(hgb_model, X_test_df.values, y_test, n_repeats=10, random_state=42)
    hgb_feat_imp = pd.DataFrame({
        "feature_index": range(NUM_FEATURES),
        "feature_name": FEATURE_COLUMNS,
        "permutation_importance_mean": perm_imp.importances_mean,
        "permutation_importance_std": perm_imp.importances_std,
    }).sort_values(by="permutation_importance_mean", ascending=False)
    hgb_feat_imp.to_csv(reports_dir / "feature_importance_hist_gradient_boosting.csv", index=False)

    # 5. Ablation Studies (Evaluating Constant Removal, Private IP Removal, and Port Reliance)
    print("\nRunning Ablation Studies...")
    ablation_results = []
    ablation_configs = [
        ("Full 78-D Features", FEATURE_COLUMNS),
        ("Ablation A: Drop 12 Zero-Variance Constant Features (66-D)", non_constant_features),
        ("Ablation B: Drop Zero-Variance + Private IP Indicators (66-D)", no_priv_features),
        ("Ablation C: Drop Port Classification Indicators (75-D)", no_port_features),
    ]

    for abl_name, cols in ablation_configs:
        X_tr = X_train_df[cols].values
        X_te = X_test_df[cols].values

        rf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
        rf.fit(X_tr, y_train)
        rf_pred = rf.predict(X_te)

        hgb = HistGradientBoostingClassifier(class_weight="balanced", random_state=42)
        hgb.fit(X_tr, y_train)
        hgb_pred = hgb.predict(X_te)

        lr_pipe = Pipeline([
            ("scaler", RobustScaler()),
            ("clf", LogisticRegression(class_weight="balanced", max_iter=2000, random_state=42)),
        ])
        lr_pipe.fit(X_tr, y_train)
        lr_pred = lr_pipe.predict(X_te)

        abl_entry = {
            "ablation": abl_name,
            "feature_count": len(cols),
            "rf_macro_f1": round(f1_score(y_test, rf_pred, average="macro", zero_division=0), 4),
            "rf_bal_acc": round(balanced_accuracy_score(y_test, rf_pred), 4),
            "hgb_macro_f1": round(f1_score(y_test, hgb_pred, average="macro", zero_division=0), 4),
            "hgb_bal_acc": round(balanced_accuracy_score(y_test, hgb_pred), 4),
            "lr_macro_f1": round(f1_score(y_test, lr_pred, average="macro", zero_division=0), 4),
            "lr_bal_acc": round(balanced_accuracy_score(y_test, lr_pred), 4),
        }
        ablation_results.append(abl_entry)
        print(f"  [{abl_name:<55}] -> RF F1: {abl_entry['rf_macro_f1']:.4f} | HGB F1: {abl_entry['hgb_macro_f1']:.4f} | LR F1: {abl_entry['lr_macro_f1']:.4f}")

    # 6. Save Machine-Readable Results (JSON & CSV)
    baseline_payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_corpus_rows": len(df),
        "train_rows": len(train_idx),
        "test_rows": len(test_idx),
        "classes": ACTIVE_CLASSES,
        "split_manifest": split_manifest,
        "baseline_models": results,
        "ablation_studies": ablation_results,
        "top_10_rf_features": rf_feat_imp.head(10).to_dict(orient="records"),
        "top_10_hgb_features": hgb_feat_imp.head(10).to_dict(orient="records"),
        "confusion_matrices": confusion_matrices,
    }

    with open(reports_dir / "baseline_results.json", "w", encoding="utf-8") as f:
        json.dump(baseline_payload, f, indent=2)

    results_df = pd.DataFrame(results)
    results_df.drop(columns=["per_class"]).to_csv(reports_dir / "baseline_results.csv", index=False)

    print(f"\nAll baseline results and artifacts successfully saved to: {reports_dir}")
    return baseline_payload


def main() -> None:
    train_and_evaluate_baselines()


if __name__ == "__main__":
    main()
