import numpy as np
import pytest

from core import config
from core.preprocessing import (
    FeatureMismatchError,
    FeatureSchema,
    build_feature_matrix,
    make_target,
    select_features,
)


def test_target_from_label_only(clean):
    df, _ = clean
    y = make_target(df)
    assert set(np.unique(y)) == {0, 1}
    assert y.sum() == (df[config.LABEL_COLUMN].astype(str) != "BENIGN").sum()


def test_feature_selection_excludes_label_constant_and_duplicates(clean):
    df, _ = clean
    schema = select_features(df)
    assert config.LABEL_COLUMN not in schema.features
    assert config.ROW_ID_COLUMN not in schema.features
    assert config.CLASS_COLUMN not in schema.features
    assert "Bwd PSH Flags" in schema.dropped_constant
    assert schema.dropped_duplicate == {"Fwd Header Length.1": "Fwd Header Length"}
    assert all(f not in schema.features for f in schema.dropped_constant)


def test_identifier_columns_excluded(clean):
    df, _ = clean
    df = df.assign(**{"Source Port": np.arange(len(df))})
    schema = select_features(df)
    assert "Source Port" not in schema.features
    assert "Source Port" in schema.dropped_identifier


def test_feature_matrix_handles_inf_and_missing(clean):
    df, _ = clean
    schema = select_features(df)
    X = build_feature_matrix(df.assign(**{"Flow Bytes/s": np.inf}), schema)
    assert list(X.columns) == schema.features
    assert not np.isinf(X.to_numpy()).any()
    assert X["Flow Bytes/s"].isna().all()


def test_schema_roundtrip_is_consistent(clean):
    df, _ = clean
    schema = select_features(df)
    restored = FeatureSchema.from_dict(schema.to_dict())
    assert build_feature_matrix(df, restored).columns.tolist() == build_feature_matrix(df, schema).columns.tolist()


def test_missing_feature_raises(clean):
    df, _ = clean
    schema = select_features(df)
    with pytest.raises(FeatureMismatchError, match="missing"):
        build_feature_matrix(df.drop(columns=[schema.features[0]]), schema)
