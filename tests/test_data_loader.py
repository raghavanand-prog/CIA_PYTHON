import numpy as np
import pandas as pd
import pytest

from core import config
from core.data_loader import DatasetError, clean_dataset, load_dataset


def test_load_dataset_from_csv(csv_path):
    df, report = load_dataset([csv_path])
    assert len(df) == report.total_records > 0
    assert config.LABEL_COLUMN in df.columns
    assert all(c == c.strip() for c in df.columns), "column names must be stripped"
    assert set(df[config.LABEL_COLUMN].astype(str)) == {"BENIGN", "DDoS"}
    assert report.feature_count == 78


def test_missing_file_raises(tmp_path):
    with pytest.raises(DatasetError):
        load_dataset([tmp_path / "does_not_exist.csv"])


def test_no_files_raises():
    with pytest.raises(DatasetError):
        load_dataset([])


def test_missing_label_column(raw_frame):
    frame = raw_frame.drop(columns=[c for c in raw_frame.columns if c.strip() == "Label"])
    with pytest.raises(DatasetError, match="Label"):
        clean_dataset(frame)


def test_infinity_replaced_and_counted(clean, raw_frame):
    df, report = clean
    assert report.infinite_values == 5
    assert not np.isinf(df.select_dtypes("number").to_numpy()).any()
    assert report.infinite_by_column == {"Flow Bytes/s": 5}


def test_infinity_strings_converted():
    frame = pd.DataFrame({"Flow Bytes/s": ["1.5", "Infinity", "2"], "Label": ["BENIGN", "DDoS", "BENIGN"]})
    df, report = clean_dataset(frame)
    assert pd.api.types.is_numeric_dtype(df["Flow Bytes/s"])
    assert report.infinite_values == 1


def test_empty_data_raises():
    with pytest.raises(DatasetError):
        clean_dataset(pd.DataFrame())


def test_empty_rows_removed(raw_frame):
    blank = pd.DataFrame([[np.nan] * raw_frame.shape[1]] * 3, columns=raw_frame.columns)
    df, report = clean_dataset(pd.concat([raw_frame, blank], ignore_index=True))
    assert report.empty_rows_removed == 3
    assert len(df) == len(raw_frame)


def test_quality_counts(clean):
    df, report = clean
    assert report.duplicate_rows == 20
    assert report.missing_values == 4
    assert "Bwd PSH Flags" in report.constant_columns
    assert df[config.ROW_ID_COLUMN].is_unique
    assert set(df[config.CLASS_COLUMN].astype(str)) == {config.CLASS_BENIGN, config.CLASS_MALICIOUS}
