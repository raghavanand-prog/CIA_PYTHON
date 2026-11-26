import numpy as np
import pytest

from core import config
from core.detection_engine import SAMPLE_ALL, SAMPLE_HELD_OUT, held_out_available, run_detection, select_flows
from core.preprocessing import FeatureMismatchError
from models.model_utils import ModelNotAvailableError, load_model_bundle


def test_training_metrics_and_leakage_audit(trained):
    m = trained["metrics"]
    primary = m["evaluations"]["deduplicated_split"]
    assert primary["overlap"]["test_rows_seen_in_train"] == 0
    assert m["audit"]["exact_duplicate_rows_removed"] == 20
    assert m["audit"]["label_in_features"] is False
    assert 0.0 <= primary["accuracy"] <= 1.0
    assert sum(map(sum, primary["confusion_matrix"])) == primary["test_rows"]
    assert m["audit"]["label_permutation_check"]["passed"]
    assert len(m["feature_importance"]) == m["model"]["n_features"]


def test_model_loading(trained):
    bundle = load_model_bundle(trained["artifacts"])
    assert bundle.algorithm == "RandomForestClassifier"
    assert bundle.n_features == len(bundle.schema.features)
    assert bundle.test_row_ids is not None and len(bundle.test_row_ids) > 0


def test_missing_model_raises(tmp_path):
    with pytest.raises(ModelNotAvailableError):
        load_model_bundle(tmp_path)


def test_prediction_output_and_probabilities(trained):
    bundle = load_model_bundle(trained["artifacts"])
    df = trained["df"]
    flows = select_flows(df, 200, SAMPLE_ALL, bundle)
    result = run_detection(bundle, flows, SAMPLE_ALL)
    assert result.total == 200
    assert result.predicted_benign + result.predicted_malicious == 200
    conf = result.table["Malicious Confidence"]
    assert conf.between(0, 1).all()
    assert ((conf >= 0.5) == (result.table["Predicted Class"] == config.CLASS_MALICIOUS)).all()
    assert {"Row ID", "Actual Class", "Destination Port"} <= set(result.table.columns)
    assert result.sample_metrics is not None


def test_held_out_sampling_uses_only_test_rows(trained):
    bundle = load_model_bundle(trained["artifacts"])
    df, report = trained["df"], trained["report"]
    assert held_out_available(bundle, report.total_records, report.source_files)
    flows = select_flows(df, 100, SAMPLE_HELD_OUT, bundle)
    assert np.isin(flows[config.ROW_ID_COLUMN], bundle.test_row_ids).all()
    assert not held_out_available(bundle, report.total_records + 1, report.source_files)


def test_feature_mismatch(trained):
    bundle = load_model_bundle(trained["artifacts"])
    flows = trained["df"].head(10).drop(columns=bundle.schema.features[:2])
    with pytest.raises(FeatureMismatchError):
        run_detection(bundle, flows, SAMPLE_ALL)
