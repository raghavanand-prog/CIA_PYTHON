"""Saving and loading the trained model and its metadata."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.pipeline import Pipeline

from core import config
from core.preprocessing import FeatureSchema


class ModelNotAvailableError(Exception):
    """Raised when the trained model or its metadata cannot be loaded."""


@dataclass
class ModelBundle:
    """Everything needed to run and describe the trained model."""

    pipeline: Pipeline
    schema: FeatureSchema
    metrics: dict
    test_row_ids: np.ndarray | None

    @property
    def algorithm(self) -> str:
        return type(self.pipeline.named_steps["model"]).__name__

    @property
    def n_features(self) -> int:
        return len(self.schema.features)


def _paths(artifacts_dir: Path) -> dict[str, Path]:
    return {
        "model": artifacts_dir / config.MODEL_FILE.name,
        "schema": artifacts_dir / config.SCHEMA_FILE.name,
        "metrics": artifacts_dir / config.METRICS_FILE.name,
        "test_ids": artifacts_dir / config.TEST_IDS_FILE.name,
    }


def backup_existing(artifacts_dir: Path = config.ARTIFACTS_DIR) -> Path | None:
    """Copy current artifacts into a timestamped backup folder before replacing them."""
    present = [p for p in _paths(artifacts_dir).values() if p.exists()]
    if not present:
        return None
    backup_dir = artifacts_dir / "backups" / datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir.mkdir(parents=True, exist_ok=True)
    for path in present:
        shutil.copy2(path, backup_dir / path.name)
    return backup_dir


def save_artifacts(
    pipeline: Pipeline,
    schema: FeatureSchema,
    metrics: dict,
    test_row_ids: np.ndarray,
    artifacts_dir: Path = config.ARTIFACTS_DIR,
) -> dict[str, Path]:
    """Write model, schema, metrics and held-out row ids.

    Files are written to temporary names first and then moved into place, so a
    failed run never leaves a half-written model behind.
    """
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    paths = _paths(artifacts_dir)
    tmp = {k: p.with_name(p.name + ".tmp") for k, p in paths.items()}

    joblib.dump(pipeline, tmp["model"], compress=3)
    tmp["schema"].write_text(json.dumps(schema.to_dict(), indent=2))
    tmp["metrics"].write_text(json.dumps(metrics, indent=2))
    with open(tmp["test_ids"], "wb") as fh:
        np.save(fh, np.asarray(test_row_ids, dtype=np.int64))

    for key, path in paths.items():
        tmp[key].replace(path)
    return paths


def load_model_bundle(artifacts_dir: Path = config.ARTIFACTS_DIR) -> ModelBundle:
    """Load the model with its schema and evaluation metadata."""
    paths = _paths(artifacts_dir)
    missing = [p.name for k, p in paths.items() if k != "test_ids" and not p.exists()]
    if missing:
        raise ModelNotAvailableError(
            "Trained model files not found (" + ", ".join(missing) + "). "
            "Run `python -m models.train_model` to train the model."
        )
    try:
        pipeline = joblib.load(paths["model"])
        schema = FeatureSchema.from_dict(json.loads(paths["schema"].read_text()))
        metrics = json.loads(paths["metrics"].read_text())
    except Exception as exc:  # corrupted file or incompatible library version
        raise ModelNotAvailableError(f"Model files exist but could not be loaded: {exc}") from exc
    test_ids = np.load(paths["test_ids"]) if paths["test_ids"].exists() else None
    return ModelBundle(pipeline=pipeline, schema=schema, metrics=metrics, test_row_ids=test_ids)
