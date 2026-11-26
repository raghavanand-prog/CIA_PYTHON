"""Evaluation metrics and leakage checks used by the training script."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from core import config

CLASS_NAMES = [config.CLASS_BENIGN, config.CLASS_MALICIOUS]


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray | None = None) -> dict:
    """Binary classification metrics with 'Malicious' as the positive class."""
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in cm.ravel())
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else 0.0,
        "confusion_matrix": cm.tolist(),
        "confusion_labels": CLASS_NAMES,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp,
        "support": int(len(y_true)),
        "classification_report": classification_report(
            y_true, y_pred, labels=[0, 1], target_names=CLASS_NAMES, output_dict=True, zero_division=0
        ),
    }
    if y_proba is not None and len(np.unique(y_true)) == 2:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_proba))
    return metrics


def row_fingerprints(X: pd.DataFrame) -> np.ndarray:
    """One 64-bit hash per row, so identical feature vectors share a hash."""
    return pd.util.hash_pandas_object(X, index=False).to_numpy()


def split_overlap(train_X: pd.DataFrame, test_X: pd.DataFrame) -> dict:
    """How many test rows have an identical feature vector in the training set.

    These rows are effectively 'seen' by the model, so a high count inflates
    the test score. A sound split should report zero.
    """
    train_fp = row_fingerprints(train_X)
    test_fp = row_fingerprints(test_X)
    overlap_mask = np.isin(test_fp, train_fp)
    count = int(overlap_mask.sum())
    return {
        "test_rows": int(len(test_fp)),
        "test_rows_seen_in_train": count,
        "test_rows_seen_in_train_pct": float(count / len(test_fp) * 100) if len(test_fp) else 0.0,
    }


def class_balance(y: np.ndarray) -> dict:
    """Counts and shares of benign (0) and malicious (1) rows."""
    y = np.asarray(y).astype(int)
    total = len(y)
    malicious = int(y.sum())
    benign = total - malicious
    return {
        "total": total,
        "benign": benign,
        "malicious": malicious,
        "benign_pct": benign / total * 100 if total else 0.0,
        "malicious_pct": malicious / total * 100 if total else 0.0,
        "majority_baseline_accuracy": max(benign, malicious) / total if total else 0.0,
    }
