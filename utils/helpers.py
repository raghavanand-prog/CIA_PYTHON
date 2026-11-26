"""Cached data/model access and number formatting shared by all pages.

The dataset (~225k rows) and the model are cached with ``st.cache_resource``
so they are loaded once per server process and shared without copying.
Pages must treat the returned DataFrame as read-only.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pandas as pd
import streamlit as st

from core import analytics, config
from core.data_loader import DatasetError, QualityReport, discover_dataset_files, load_dataset, load_uploaded
from models.model_utils import ModelBundle, ModelNotAvailableError, load_model_bundle

UPLOAD_KEY = "uploaded_dataset"


@dataclass
class DatasetHandle:
    df: pd.DataFrame
    report: QualityReport
    signature: str   # changes whenever the underlying data changes; used as a cache key
    source: str      # "local" or "upload"


# ---------------------------------------------------------------- formatting
def fmt_int(value: float | int) -> str:
    return f"{int(value):,}"


def fmt_pct(value: float, digits: int = 1) -> str:
    return f"{value:.{digits}f}%"


# ---------------------------------------------------------------- dataset
@st.cache_resource(show_spinner="Loading network flow dataset…", max_entries=2)
def _load_local(signature: str) -> tuple[pd.DataFrame, QualityReport]:
    return load_dataset(discover_dataset_files())


@st.cache_resource(show_spinner="Reading uploaded dataset…", max_entries=1)
def _load_upload(signature: str, _data: bytes, filename: str) -> tuple[pd.DataFrame, QualityReport]:
    return load_uploaded(_data, filename)


def local_signature() -> str | None:
    files = discover_dataset_files()
    if not files:
        return None
    parts = [f"{p.name}:{p.stat().st_size}:{int(p.stat().st_mtime)}" for p in files]
    return "local|" + "|".join(parts)


def get_dataset() -> DatasetHandle | None:
    """Return the active dataset: an uploaded file if present, otherwise local CSVs."""
    upload = st.session_state.get(UPLOAD_KEY)
    if upload:
        name, data = upload
        sig = "upload|" + name + "|" + hashlib.sha1(data).hexdigest()[:16]
        df, report = _load_upload(sig, data, name)
        return DatasetHandle(df, report, sig, "upload")
    sig = local_signature()
    if sig is None:
        return None
    df, report = _load_local(sig)
    return DatasetHandle(df, report, sig, "local")


def dataset_uploader(key: str = "uploader") -> None:
    """File uploader used when no local dataset is present (e.g. on Streamlit Cloud)."""
    file = st.file_uploader("Upload a CIC-IDS2017 flow CSV", type=["csv"], key=key,
                            help="For example Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    if file is not None:
        st.session_state[UPLOAD_KEY] = (file.name, file.getvalue())
        st.rerun()


def require_dataset() -> DatasetHandle:
    """Return the dataset or render a helpful empty state and stop the page."""
    from utils.styling import callout, empty_state

    try:
        handle = get_dataset()
    except DatasetError as exc:
        callout(str(exc), tone="malicious", bold_prefix="Dataset could not be used.")
        st.session_state.pop(UPLOAD_KEY, None)
        dataset_uploader("uploader_error")
        st.stop()
    except Exception as exc:  # unreadable CSV, encoding issues, etc.
        callout(f"{type(exc).__name__}: {exc}", tone="malicious", bold_prefix="Failed to read the dataset.")
        st.session_state.pop(UPLOAD_KEY, None)
        dataset_uploader("uploader_exception")
        st.stop()
    if handle is None:
        empty_state(
            "No dataset found. Place a CIC-IDS2017 CSV in data/sample_data/ "
            "or upload one below to start the analysis."
        )
        dataset_uploader("uploader_missing")
        st.stop()
    return handle


# ---------------------------------------------------------------- model
def _model_signature() -> str | None:
    if not config.MODEL_FILE.exists():
        return None
    files = [config.MODEL_FILE, config.SCHEMA_FILE, config.METRICS_FILE]
    return "|".join(f"{p.stat().st_mtime_ns}" for p in files if p.exists())


@st.cache_resource(show_spinner="Loading Random Forest model…", max_entries=1)
def _load_model(signature: str) -> ModelBundle:
    return load_model_bundle()


def get_model() -> tuple[ModelBundle | None, str | None]:
    """(bundle, None) when available, otherwise (None, reason)."""
    sig = _model_signature()
    if sig is None:
        return None, ("Trained model not found in models/artifacts/. "
                      "Run `python -m models.train_model` from the project folder to train it.")
    try:
        return _load_model(sig), None
    except ModelNotAvailableError as exc:
        return None, str(exc)


# ---------------------------------------------------------------- cached aggregates
@st.cache_data(show_spinner=False, max_entries=8)
def cached_label_counts(signature: str, _df: pd.DataFrame) -> pd.DataFrame:
    return analytics.label_counts(_df)


@st.cache_data(show_spinner=False, max_entries=8)
def cached_class_counts(signature: str, _df: pd.DataFrame) -> pd.DataFrame:
    return analytics.class_counts(_df)


@st.cache_data(show_spinner=False, max_entries=8)
def cached_attack_distribution(signature: str, _df: pd.DataFrame) -> pd.DataFrame:
    return analytics.attack_distribution(_df)


@st.cache_data(show_spinner=False, max_entries=8)
def cached_insights(signature: str, _df: pd.DataFrame, _report: QualityReport) -> list[str]:
    return analytics.generate_insights(_df, _report)


@st.cache_data(show_spinner=False, max_entries=16)
def cached_top_ports(signature: str, _df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    return analytics.top_ports(_df, n)


@st.cache_data(show_spinner=False, max_entries=8)
def cached_port_options(signature: str, _df: pd.DataFrame, n: int = 60) -> list[int]:
    if config.COL_DST_PORT not in _df.columns:
        return []
    return [int(p) for p in _df[config.COL_DST_PORT].value_counts().head(n).index]


@st.cache_data(show_spinner=False, max_entries=8)
def cached_ranges(signature: str, _df: pd.DataFrame) -> dict:
    """Min/max used to initialise the range filters."""
    out = {}
    if config.COL_DURATION in _df.columns:
        secs = _df[config.COL_DURATION].dropna() / 1e6
        out["duration"] = (float(max(secs.min(), 0)), float(secs.max()))
    if {config.COL_FWD_PACKETS, config.COL_BWD_PACKETS} & set(_df.columns):
        pk = analytics.total_packets(_df)
        out["packets"] = (int(pk.min()), int(pk.max()))
    return out
