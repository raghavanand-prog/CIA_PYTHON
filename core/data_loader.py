"""Loading and cleaning CIC-IDS2017 flow CSV files.

The loader never invents data. It only:
  * strips the stray whitespace CIC-IDS2017 puts in column names and labels,
  * converts text such as "Infinity" to numbers,
  * replaces +/-infinity with NaN (the value is undefined, not huge),
  * removes rows that are completely empty,
  * adds a stable ``row_id`` and a derived Benign/Malicious class.

Every change is counted in a :class:`QualityReport` so the dashboard can show
exactly what was done to the original file.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Iterable

import numpy as np
import pandas as pd

from core import config


class DatasetError(Exception):
    """Raised when a dataset is missing or cannot be used."""


@dataclass
class QualityReport:
    """Counts describing the raw file and the cleaning applied to it."""

    source_files: list[str]
    total_records: int
    raw_columns: int
    feature_count: int
    missing_values: int
    infinite_values: int
    duplicate_rows: int
    empty_rows_removed: int
    constant_columns: list[str] = field(default_factory=list)
    missing_by_column: dict[str, int] = field(default_factory=dict)
    infinite_by_column: dict[str, int] = field(default_factory=dict)
    loaded_at: str = ""

    def as_rows(self) -> list[tuple[str, str]]:
        """Key/value pairs used by tables and reports."""
        return [
            ("Total records", f"{self.total_records:,}"),
            ("Original columns", f"{self.raw_columns:,}"),
            ("Input features", f"{self.feature_count:,}"),
            ("Missing values (blank cells)", f"{self.missing_values:,}"),
            ("Infinite values (set to missing)", f"{self.infinite_values:,}"),
            ("Duplicate records", f"{self.duplicate_rows:,}"),
            ("Constant (zero-variance) columns", f"{len(self.constant_columns):,}"),
            ("Empty rows removed", f"{self.empty_rows_removed:,}"),
        ]


# ---------------------------------------------------------------- discovery
def discover_dataset_files(data_dir: Path = config.DATA_DIR) -> list[Path]:
    """Return all CSV files in the data folder, sorted by name."""
    if not data_dir.exists():
        return []
    return sorted(p for p in data_dir.glob("*.csv") if p.is_file())


# ---------------------------------------------------------------- reading
def read_csv(source: Path | str | bytes | BinaryIO) -> pd.DataFrame:
    """Read one CSV from a path, raw bytes or a file-like object."""
    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.exists():
            raise DatasetError(f"Dataset file not found: {path}")
        return pd.read_csv(path, low_memory=False, skipinitialspace=True)
    if isinstance(source, bytes):
        source = io.BytesIO(source)
    return pd.read_csv(source, low_memory=False, skipinitialspace=True)


def normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names (CIC-IDS2017 has ' Label' etc.)."""
    df.columns = [str(c).strip() for c in df.columns]
    return df


def feature_columns(df: pd.DataFrame) -> list[str]:
    """All original flow columns except the label and our derived columns."""
    derived = {config.LABEL_COLUMN, config.ROW_ID_COLUMN, config.CLASS_COLUMN, "Source File"}
    return [c for c in df.columns if c not in derived]


def _coerce_numeric(df: pd.DataFrame) -> pd.DataFrame:
    """Convert text columns that are really numbers (e.g. 'Infinity')."""
    skip = {config.LABEL_COLUMN} | config.IDENTIFIER_COLUMNS
    for col in df.columns:
        if col in skip or pd.api.types.is_numeric_dtype(df[col]):
            continue
        converted = pd.to_numeric(df[col], errors="coerce")
        # Only convert when the column is overwhelmingly numeric.
        if converted.notna().mean() >= 0.95 or df[col].isna().all():
            df[col] = converted
    return df


def clean_dataset(raw: pd.DataFrame, source_files: Iterable[str] = ()) -> tuple[pd.DataFrame, QualityReport]:
    """Clean a raw CIC-IDS2017 frame and describe what was changed."""
    if raw is None or raw.empty:
        raise DatasetError("The dataset is empty.")

    df = normalise_columns(raw)
    if config.LABEL_COLUMN not in df.columns:
        raise DatasetError(
            f"Required column '{config.LABEL_COLUMN}' not found. "
            "This does not look like a labelled CIC-IDS2017 flow file."
        )

    raw_columns = int(df.shape[1])
    if "Source File" in df.columns:
        raw_columns -= 1

    before = len(df)
    df = df.dropna(how="all")
    empty_removed = before - len(df)

    df[config.LABEL_COLUMN] = df[config.LABEL_COLUMN].astype("string").str.strip()
    df = df[df[config.LABEL_COLUMN].notna() & (df[config.LABEL_COLUMN] != "")]
    if df.empty:
        raise DatasetError("No labelled records remain after removing empty rows.")

    df = _coerce_numeric(df)
    numeric_cols = df.select_dtypes(include=[np.number]).columns

    missing_by_col = df.isna().sum()
    missing_by_col = {k: int(v) for k, v in missing_by_col.items() if v > 0}

    numeric_values = df[numeric_cols].to_numpy(dtype="float64", copy=False)
    inf_mask = np.isinf(numeric_values)
    inf_by_col = {col: int(n) for col, n in zip(numeric_cols, inf_mask.sum(axis=0)) if n > 0}
    if inf_by_col:
        df[list(inf_by_col)] = df[list(inf_by_col)].replace([np.inf, -np.inf], np.nan)

    feats = feature_columns(df)
    duplicate_rows = int(df.duplicated(subset=feats + [config.LABEL_COLUMN]).sum())
    nunique = df[feats].nunique(dropna=False)
    constant_cols = sorted(nunique[nunique <= 1].index.tolist())

    df = df.reset_index(drop=True)
    df[config.ROW_ID_COLUMN] = np.arange(len(df), dtype=np.int64)
    df[config.LABEL_COLUMN] = df[config.LABEL_COLUMN].astype("category")
    is_benign = df[config.LABEL_COLUMN].astype("string").str.upper() == config.BENIGN_LABEL
    df[config.CLASS_COLUMN] = pd.Categorical(
        np.where(is_benign, config.CLASS_BENIGN, config.CLASS_MALICIOUS),
        categories=[config.CLASS_BENIGN, config.CLASS_MALICIOUS],
    )

    report = QualityReport(
        source_files=list(source_files),
        total_records=int(len(df)),
        raw_columns=raw_columns,
        feature_count=len(feats),
        missing_values=int(sum(missing_by_col.values())),
        infinite_values=int(sum(inf_by_col.values())),
        duplicate_rows=duplicate_rows,
        empty_rows_removed=int(empty_removed),
        constant_columns=constant_cols,
        missing_by_column=missing_by_col,
        infinite_by_column=inf_by_col,
        loaded_at=datetime.now().strftime("%d %b %Y, %H:%M:%S"),
    )
    return df, report


def load_dataset(paths: list[Path] | None = None) -> tuple[pd.DataFrame, QualityReport]:
    """Load, combine and clean one or more CSV files from disk."""
    paths = paths if paths is not None else discover_dataset_files()
    if not paths:
        raise DatasetError(
            f"No CSV files found in {config.DATA_DIR.relative_to(config.PROJECT_ROOT)}. "
            "Add a CIC-IDS2017 CSV file to that folder or upload one in the sidebar."
        )
    frames = []
    for path in paths:
        frame = normalise_columns(read_csv(path))
        if len(paths) > 1:
            frame["Source File"] = path.name
        frames.append(frame)
    raw = frames[0] if len(frames) == 1 else pd.concat(frames, ignore_index=True)
    df, report = clean_dataset(raw, [p.name for p in paths])
    if "Source File" in df.columns:
        df["Source File"] = df["Source File"].astype("category")
    return df, report


def load_uploaded(data: bytes, filename: str) -> tuple[pd.DataFrame, QualityReport]:
    """Load and clean a CSV uploaded through the browser."""
    return clean_dataset(read_csv(data), [filename])
