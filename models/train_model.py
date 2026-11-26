"""Train and audit the CyberPulse Random Forest.

Run from the project root:

    python -m models.train_model                 # full training + audit
    python -m models.train_model --cv-folds 0    # skip cross-validation (faster)
    python -m models.train_model --quick         # fewer trees, for a quick check

What this script does, in order:

1. Loads the CSV file(s) with the same loader the dashboard uses.
2. Audits the data for leakage risks: exact duplicate flows, flows with the
   same features but different labels, identifier columns, label-in-features.
3. Experiment A - "naive" stratified split on the raw rows (duplicates kept).
   This reproduces how the original ~100% accuracy figure was produced and
   measures how many test rows were already present in the training set.
4. Experiment B - deduplicated split (PRIMARY). Duplicate feature vectors are
   removed BEFORE splitting, so no test flow is identical to a training flow.
   Feature selection and median imputation are fitted on the training split only.
5. Optional stratified k-fold cross-validation on the deduplicated training set.
6. Label-permutation sanity check: with shuffled labels the model must fall to
   roughly the majority-class baseline. If it did not, information about the
   label would be leaking into the features.
7. Saves the primary model, feature schema, metrics and held-out row ids.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from core import config
from core.data_loader import DatasetError, QualityReport, feature_columns, load_dataset
from core.preprocessing import build_feature_matrix, build_pipeline, make_target, select_features
from models.evaluation import class_balance, compute_metrics, split_overlap
from models.model_utils import backup_existing, save_artifacts


def _candidate_columns(df: pd.DataFrame) -> list[str]:
    """Numeric, non-identifier columns used to decide whether two flows are identical."""
    return [
        c for c in feature_columns(df)
        if c not in config.IDENTIFIER_COLUMNS and pd.api.types.is_numeric_dtype(df[c])
    ]


def audit_duplicates(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Remove repeated feature vectors and report what was removed.

    * exact duplicates (same features, same label) keep one copy;
    * conflicting duplicates (same features, different labels) are removed
      entirely, because their correct label is ambiguous.
    """
    cols = _candidate_columns(df)
    exact_dupes = int(df.duplicated(subset=cols + [config.LABEL_COLUMN]).sum())
    deduped = df.drop_duplicates(subset=cols + [config.LABEL_COLUMN], keep="first")

    conflict_mask = deduped.duplicated(subset=cols, keep=False)
    conflicting_rows = int(conflict_mask.sum())
    conflicting_groups = int(deduped.loc[conflict_mask, cols].drop_duplicates().shape[0]) if conflicting_rows else 0
    deduped = deduped.loc[~conflict_mask]

    audit = {
        "rows_before": int(len(df)),
        "exact_duplicate_rows_removed": exact_dupes,
        "conflicting_label_rows_removed": conflicting_rows,
        "conflicting_label_groups": conflicting_groups,
        "rows_after_deduplication": int(len(deduped)),
        "rows_removed_pct": float((len(df) - len(deduped)) / len(df) * 100),
        "duplicate_columns_considered": len(cols),
    }
    return deduped, audit


def run_split_experiment(df: pd.DataFrame, params: dict | None, name: str) -> dict:
    """Stratified 80/20 split -> train -> evaluate. Returns metrics and fitted objects."""
    y = make_target(df)
    train_df, test_df, y_train, y_test = train_test_split(
        df, y, test_size=config.TEST_SIZE, stratify=y, random_state=config.RANDOM_STATE
    )
    schema = select_features(train_df)  # fitted on training rows only
    assert config.LABEL_COLUMN not in schema.features, "Label leaked into features"
    X_train = build_feature_matrix(train_df, schema)
    X_test = build_feature_matrix(test_df, schema)

    pipeline = build_pipeline(params)
    started = time.perf_counter()
    pipeline.fit(X_train, y_train)
    train_seconds = time.perf_counter() - started

    proba = pipeline.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    metrics = compute_metrics(y_test, pred, proba)
    metrics.update(
        {
            "name": name,
            "train_rows": int(len(train_df)),
            "test_rows": int(len(test_df)),
            "train_class_balance": class_balance(y_train),
            "test_class_balance": class_balance(y_test),
            "overlap": split_overlap(X_train, X_test),
            "training_seconds": round(train_seconds, 2),
        }
    )
    print(f"  [{name}] accuracy={metrics['accuracy']:.5f} f1={metrics['f1']:.5f} "
          f"test rows seen in train={metrics['overlap']['test_rows_seen_in_train']:,} "
          f"({metrics['overlap']['test_rows_seen_in_train_pct']:.2f}%)")
    return {
        "metrics": metrics,
        "pipeline": pipeline,
        "schema": schema,
        "X_train": X_train,
        "y_train": y_train,
        "test_row_ids": test_df[config.ROW_ID_COLUMN].to_numpy(),
    }


def permutation_sanity_check(X: pd.DataFrame, y: np.ndarray, max_rows: int = 40_000) -> dict:
    """Train on shuffled labels; accuracy should collapse to the majority baseline."""
    rng = np.random.default_rng(config.RANDOM_STATE)
    if len(X) > max_rows:
        idx = rng.choice(len(X), size=max_rows, replace=False)
        X, y = X.iloc[idx], y[idx]
    y_shuffled = rng.permutation(y)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y_shuffled, test_size=0.25, stratify=y_shuffled, random_state=config.RANDOM_STATE
    )
    model = build_pipeline({"n_estimators": 60})
    model.fit(X_tr, y_tr)
    acc = float((model.predict(X_te) == y_te).mean())
    baseline = class_balance(y_te)["majority_baseline_accuracy"]
    passed = acc <= baseline + 0.03
    print(f"  [label permutation] accuracy={acc:.4f} vs baseline={baseline:.4f} -> {'PASS' if passed else 'CHECK'}")
    return {"rows_used": int(len(X)), "shuffled_label_accuracy": acc,
            "majority_baseline": float(baseline), "passed": bool(passed)}


def cross_validate(X: pd.DataFrame, y: np.ndarray, folds: int, params: dict | None) -> dict:
    """Stratified k-fold F1 on the deduplicated training set (60 trees per fold to keep it quick)."""
    cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=config.RANDOM_STATE)
    cv_params = {**(params or {}), "n_estimators": min(60, (params or {}).get("n_estimators", 60))}
    scores = cross_val_score(build_pipeline(cv_params), X, y, cv=cv, scoring="f1", n_jobs=1)
    print(f"  [{folds}-fold CV] F1 mean={scores.mean():.5f} std={scores.std():.5f}")
    return {"folds": folds, "metric": "f1", "trees_per_fold": cv_params["n_estimators"], "scores": [float(s) for s in scores],
            "mean": float(scores.mean()), "std": float(scores.std())}


def train_and_evaluate(
    df: pd.DataFrame,
    report: QualityReport,
    params: dict | None = None,
    cv_folds: int = 3,
    artifacts_dir: Path = config.ARTIFACTS_DIR,
    save: bool = True,
) -> dict:
    """Full audit + training run. Returns the metrics dictionary that is saved."""
    started = time.perf_counter()
    y_all = make_target(df)
    label_counts = df[config.LABEL_COLUMN].astype("string").value_counts()
    print(f"Loaded {len(df):,} flows from {', '.join(report.source_files)}")
    print("Labels: " + ", ".join(f"{k}={v:,}" for k, v in label_counts.items()))

    identifier_present = [c for c in df.columns if c in config.IDENTIFIER_COLUMNS]

    print("\nExperiment A - naive stratified split (duplicates kept)")
    naive = run_split_experiment(df, params, "naive_random_split")

    print("\nExperiment B - deduplicated stratified split (primary)")
    deduped_df, dup_audit = audit_duplicates(df)
    print(f"  removed {dup_audit['exact_duplicate_rows_removed']:,} exact duplicates and "
          f"{dup_audit['conflicting_label_rows_removed']:,} conflicting-label rows")
    primary = run_split_experiment(deduped_df, params, "deduplicated_split")

    print("\nSanity checks")
    permutation = permutation_sanity_check(primary["X_train"], primary["y_train"])
    cv = cross_validate(primary["X_train"], primary["y_train"], cv_folds, params) if cv_folds >= 2 else None

    pipeline = primary["pipeline"]
    schema = primary["schema"]
    importances = pipeline.named_steps["model"].feature_importances_
    feature_importance = sorted(
        ({"feature": f, "importance": float(v)} for f, v in zip(schema.features, importances)),
        key=lambda d: d["importance"], reverse=True,
    )

    rf_params = pipeline.named_steps["model"].get_params()
    metrics = {
        "model": {
            "algorithm": "RandomForestClassifier",
            "pipeline": ["SimpleImputer(strategy='median')", "RandomForestClassifier"],
            "parameters": {k: rf_params[k] for k in
                           ("n_estimators", "max_depth", "min_samples_leaf", "class_weight", "random_state")},
            "n_features": len(schema.features),
            "decision_threshold": 0.5,
            "scikit_learn_version": sklearn.__version__,
            "trained_at": datetime.now().isoformat(timespec="seconds"),
            "total_run_seconds": None,
        },
        "dataset": {
            "name": config.DATASET_NAME,
            "files": report.source_files,
            "total_records": int(len(df)),
            "label_counts": {str(k): int(v) for k, v in label_counts.items()},
            "class_balance": class_balance(y_all),
        },
        "audit": {
            **dup_audit,
            "label_in_features": config.LABEL_COLUMN in schema.features,
            "identifier_columns_present": identifier_present,
            "identifier_columns_used": [c for c in identifier_present if c in schema.features],
            "preprocessing_fitted_on": "training split only (feature selection + median imputation)",
            "split": f"stratified {int((1 - config.TEST_SIZE) * 100)}/{int(config.TEST_SIZE * 100)}, "
                     f"random_state={config.RANDOM_STATE}",
            "label_permutation_check": permutation,
        },
        "primary_evaluation": "deduplicated_split",
        "evaluations": {
            "deduplicated_split": primary["metrics"],
            "naive_random_split": naive["metrics"],
        },
        "cross_validation": cv,
        "feature_importance": feature_importance,
        "schema_summary": {
            "features_used": len(schema.features),
            "dropped_constant": schema.dropped_constant,
            "dropped_duplicate": schema.dropped_duplicate,
            "dropped_identifier": schema.dropped_identifier,
            "dropped_non_numeric": schema.dropped_non_numeric,
        },
    }
    metrics["model"]["total_run_seconds"] = round(time.perf_counter() - started, 1)

    if save:
        backup = backup_existing(artifacts_dir)
        if backup:
            print(f"\nPrevious model backed up to {backup}")
        paths = save_artifacts(pipeline, schema, metrics, primary["test_row_ids"], artifacts_dir)
        print("Saved: " + ", ".join(p.name for p in paths.values()))
    return metrics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the CyberPulse Random Forest.")
    parser.add_argument("--data", nargs="*", type=Path, help="CSV file(s); default: all CSVs in data/sample_data")
    parser.add_argument("--cv-folds", type=int, default=3, help="Cross-validation folds (0 to skip)")
    parser.add_argument("--quick", action="store_true", help="Use 40 trees for a fast check run")
    args = parser.parse_args(argv)

    try:
        df, report = load_dataset(args.data or None)
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    params = {"n_estimators": 40} if args.quick else None
    metrics = train_and_evaluate(df, report, params=params, cv_folds=args.cv_folds)

    primary = metrics["evaluations"]["deduplicated_split"]
    naive = metrics["evaluations"]["naive_random_split"]
    print("\n================ SUMMARY ================")
    print(f"Naive split       accuracy {naive['accuracy']:.5f}  F1 {naive['f1']:.5f}  "
          f"(test rows already in train: {naive['overlap']['test_rows_seen_in_train']:,})")
    print(f"Deduplicated      accuracy {primary['accuracy']:.5f}  F1 {primary['f1']:.5f}  "
          f"(test rows already in train: {primary['overlap']['test_rows_seen_in_train']:,})")
    print(f"False positives {primary['false_positives']:,} | false negatives {primary['false_negatives']:,} "
          f"out of {primary['support']:,} held-out flows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
