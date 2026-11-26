"""Feature selection and the model preprocessing pipeline.

The same :class:`FeatureSchema` is produced once during training, saved next
to the model, and re-used at inference time. That guarantees the model always
receives exactly the columns, in exactly the order, that it was trained on.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from core import config
from core.data_loader import feature_columns


class FeatureMismatchError(Exception):
    """Raised when input data does not match the trained feature schema."""


@dataclass
class FeatureSchema:
    """Which columns the model uses and why the others were excluded."""

    features: list[str]
    dropped_identifier: list[str] = field(default_factory=list)
    dropped_non_numeric: list[str] = field(default_factory=list)
    dropped_constant: list[str] = field(default_factory=list)
    dropped_duplicate: dict[str, str] = field(default_factory=dict)
    label_column: str = config.LABEL_COLUMN
    benign_label: str = config.BENIGN_LABEL
    positive_class: str = config.CLASS_MALICIOUS

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "FeatureSchema":
        return cls(**data)


def make_target(df: pd.DataFrame) -> np.ndarray:
    """1 = malicious, 0 = benign. Derived only from the label column."""
    if config.LABEL_COLUMN not in df.columns:
        raise FeatureMismatchError(f"Column '{config.LABEL_COLUMN}' is required to build the target.")
    labels = df[config.LABEL_COLUMN].astype("string").str.strip().str.upper()
    return (labels != config.BENIGN_LABEL).to_numpy(dtype=np.int8)


def select_features(train_df: pd.DataFrame) -> FeatureSchema:
    """Choose model inputs using the TRAINING rows only.

    Excluded columns:
      * identifiers (IPs, ports of the source, timestamps, flow IDs),
      * non-numeric columns,
      * columns that are constant in the training data (carry no information),
      * columns whose values are an exact copy of an earlier column.
    The label and all derived columns are never candidates.
    """
    candidates = feature_columns(train_df)
    identifiers = [c for c in candidates if c in config.IDENTIFIER_COLUMNS]
    candidates = [c for c in candidates if c not in config.IDENTIFIER_COLUMNS]

    non_numeric = [c for c in candidates if not pd.api.types.is_numeric_dtype(train_df[c])]
    numeric = [c for c in candidates if c not in non_numeric]

    nunique = train_df[numeric].nunique(dropna=False)
    constant = [c for c in numeric if nunique[c] <= 1]
    numeric = [c for c in numeric if c not in constant]

    duplicates: dict[str, str] = {}
    seen: dict[int, str] = {}
    for col in numeric:
        signature = int(pd.util.hash_pandas_object(train_df[col], index=False).sum())
        original = seen.get(signature)
        if original is not None and train_df[col].equals(train_df[original]):
            duplicates[col] = original
        else:
            seen[signature] = col
    features = [c for c in numeric if c not in duplicates]

    if not features:
        raise FeatureMismatchError("No usable numeric features were found.")
    return FeatureSchema(
        features=features,
        dropped_identifier=identifiers,
        dropped_non_numeric=non_numeric,
        dropped_constant=constant,
        dropped_duplicate=duplicates,
    )


def validate_schema(df: pd.DataFrame, schema: FeatureSchema) -> None:
    """Raise a clear error if any trained feature is absent from ``df``."""
    missing = [c for c in schema.features if c not in df.columns]
    if missing:
        preview = ", ".join(missing[:8]) + (" …" if len(missing) > 8 else "")
        raise FeatureMismatchError(
            f"{len(missing)} feature(s) used by the model are missing from the data: {preview}"
        )
    non_numeric = [c for c in schema.features if not pd.api.types.is_numeric_dtype(df[c])]
    if non_numeric:
        raise FeatureMismatchError(f"These model features are not numeric: {', '.join(non_numeric)}")


def build_feature_matrix(df: pd.DataFrame, schema: FeatureSchema) -> pd.DataFrame:
    """Return model inputs in training order, with +/-inf turned into NaN.

    Missing values are deliberately left as NaN: the imputer inside the
    pipeline fills them with medians learned from the training split only.
    """
    validate_schema(df, schema)
    X = df[schema.features].astype("float64")
    return X.replace([np.inf, -np.inf], np.nan)


def build_pipeline(params: dict | None = None) -> Pipeline:
    """Median imputation + Random Forest, fitted together on training data."""
    rf_params = dict(config.RF_PARAMS)
    if params:
        rf_params.update(params)
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(**rf_params)),
        ]
    )
