"""Shared pytest fixtures built from small synthetic CIC-shaped data."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.data_loader import clean_dataset  # noqa: E402
from models.train_model import train_and_evaluate  # noqa: E402
from tests.synthetic_cic import make_cic_frame  # noqa: E402


@pytest.fixture
def raw_frame():
    return make_cic_frame(n=1500, seed=3)


@pytest.fixture
def csv_path(tmp_path, raw_frame):
    path = tmp_path / "sample.csv"
    raw_frame.to_csv(path, index=False)
    return path


@pytest.fixture
def clean(raw_frame):
    return clean_dataset(raw_frame.copy(), ["sample.csv"])


@pytest.fixture(scope="session")
def trained(tmp_path_factory):
    """A small model trained once and saved to a temporary artifacts folder."""
    artifacts = tmp_path_factory.mktemp("artifacts")
    df, report = clean_dataset(make_cic_frame(n=2500, seed=7), ["train.csv"])
    metrics = train_and_evaluate(df, report, params={"n_estimators": 25}, cv_folds=0, artifacts_dir=artifacts)
    return {"df": df, "report": report, "metrics": metrics, "artifacts": artifacts}
