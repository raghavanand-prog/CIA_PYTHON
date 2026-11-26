"""Running the trained Random Forest on network flows."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from core import config
from core.preprocessing import build_feature_matrix
from models.evaluation import compute_metrics
from models.model_utils import ModelBundle

SAMPLE_HELD_OUT = "Held-out test flows only"
SAMPLE_ALL = "Any flows in the dataset"


@dataclass
class DetectionResult:
    """Predictions for a set of flows plus summary counts."""

    table: pd.DataFrame
    total: int
    predicted_benign: int
    predicted_malicious: int
    sample_mode: str
    sample_metrics: dict | None  # only when true labels are available

    @property
    def malicious_pct(self) -> float:
        return self.predicted_malicious / self.total * 100 if self.total else 0.0


def held_out_available(bundle: ModelBundle, total_records: int, source_files: list[str]) -> bool:
    """Held-out row ids are only meaningful for the exact dataset used in training."""
    trained_on = bundle.metrics.get("dataset", {})
    return (
        bundle.test_row_ids is not None
        and trained_on.get("total_records") == total_records
        and trained_on.get("files") == source_files
    )


def select_flows(
    df: pd.DataFrame,
    n_records: int,
    mode: str,
    bundle: ModelBundle,
    seed: int = config.RANDOM_STATE,
) -> pd.DataFrame:
    """Pick the flows to analyse (reproducible random sample)."""
    if mode == SAMPLE_HELD_OUT:
        if bundle.test_row_ids is None:
            raise ValueError("Held-out row ids are not available for this model.")
        pool = df[df[config.ROW_ID_COLUMN].isin(bundle.test_row_ids)]
    else:
        pool = df
    if pool.empty:
        raise ValueError("No flows are available to analyse.")
    n = min(int(n_records), len(pool))
    return pool.sample(n=n, random_state=seed) if n < len(pool) else pool


def predict_flows(bundle: ModelBundle, flows: pd.DataFrame) -> tuple[np.ndarray, np.ndarray | None]:
    """Return predicted classes (1 = malicious) and malicious probabilities."""
    X = build_feature_matrix(flows, bundle.schema)  # validates the schema
    model = bundle.pipeline
    if hasattr(model, "predict_proba"):
        classes = list(model.classes_)
        proba = model.predict_proba(X)[:, classes.index(1)] if 1 in classes else np.zeros(len(X))
        threshold = bundle.metrics.get("model", {}).get("decision_threshold", 0.5)
        return (proba >= threshold).astype(int), proba
    return model.predict(X).astype(int), None


def run_detection(bundle: ModelBundle, flows: pd.DataFrame, sample_mode: str) -> DetectionResult:
    """Predict a set of flows and build the results table."""
    pred, proba = predict_flows(bundle, flows)

    table = pd.DataFrame({"Row ID": flows[config.ROW_ID_COLUMN].to_numpy()})
    for col in config.PREDICTION_TABLE_COLUMNS:
        if col in flows.columns:
            table[col] = flows[col].to_numpy()
    table["Predicted Class"] = np.where(pred == 1, config.CLASS_MALICIOUS, config.CLASS_BENIGN)
    if proba is not None:
        table["Malicious Confidence"] = np.round(proba, 4)

    sample_metrics = None
    if config.LABEL_COLUMN in flows.columns:
        actual = (flows[config.LABEL_COLUMN].astype("string").str.upper() != config.BENIGN_LABEL).to_numpy().astype(int)
        table["Actual Label"] = flows[config.LABEL_COLUMN].astype("string").to_numpy()
        table["Actual Class"] = np.where(actual == 1, config.CLASS_MALICIOUS, config.CLASS_BENIGN)
        table["Correct"] = pred == actual
        sample_metrics = compute_metrics(actual, pred, proba)

    malicious = int(pred.sum())
    return DetectionResult(
        table=table.reset_index(drop=True),
        total=int(len(pred)),
        predicted_benign=int(len(pred) - malicious),
        predicted_malicious=malicious,
        sample_mode=sample_mode,
        sample_metrics=sample_metrics,
    )
