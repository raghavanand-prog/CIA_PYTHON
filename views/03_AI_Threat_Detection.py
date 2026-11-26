"""Module 3 — AI Threat Detection: Random Forest inference, evaluation and explainability."""

import pandas as pd
import streamlit as st

from core import config
from core.detection_engine import SAMPLE_ALL, SAMPLE_HELD_OUT, held_out_available, run_detection, select_flows
from core.preprocessing import FeatureMismatchError
from utils import charts, helpers
from utils.report_generator import dataframe_to_csv
from utils.styling import callout, empty_state, key_value_card, kpi_row, page_header, section

RESULT_KEY = "detection_result"

page_header(
    "AI Threat Detection",
    "Detection that *shows its work.*",
    "A supervised Random Forest classifies each recorded flow as benign or malicious. "
    "Run it on a set of flows, inspect its confidence, and review how it was validated.",
)

handle = helpers.require_dataset()
df, report = handle.df, handle.report
bundle, model_error = helpers.get_model()

if bundle is None:
    callout(model_error or "Model unavailable.", tone="warning", bold_prefix="Model not available.")
    st.code("python -m models.train_model", language="bash")
    st.caption("Training reads the CSV in data/sample_data/, audits it for leakage, and saves the model, "
               "feature schema and evaluation metrics to models/artifacts/.")
    st.stop()

meta = bundle.metrics
model_info = meta.get("model", {})
primary_name = meta.get("primary_evaluation", "deduplicated_split")
primary = meta.get("evaluations", {}).get(primary_name, {})
naive = meta.get("evaluations", {}).get("naive_random_split")
trained_labels = list(meta.get("dataset", {}).get("label_counts", {}).keys())

# ---------------------------------------------------------------- model information
left, right = st.columns([1, 1], gap="medium")
with left:
    params = model_info.get("parameters", {})
    key_value_card("Model information", [
        ("Algorithm", "Random Forest classifier (scikit-learn)"),
        ("Pipeline", "Median imputation → Random Forest"),
        ("Input features", f"{bundle.n_features}"),
        ("Trees / max depth", f"{params.get('n_estimators', '—')} / {params.get('max_depth', '—')}"),
        ("Trained at", str(model_info.get("trained_at", "—")).replace("T", "  ")),
        ("Status", "Loaded and ready"),
    ])
with right:
    key_value_card("Training data", [
        ("Dataset", config.DATASET_NAME),
        ("File(s)", ", ".join(meta.get("dataset", {}).get("files", [])) or "—"),
        ("Labels learned", ", ".join(trained_labels) or "—"),
        ("Records used", f"{meta.get('audit', {}).get('rows_after_deduplication', 0):,} unique flows"),
        ("Evaluation split", f"{primary.get('train_rows', 0):,} train · {primary.get('test_rows', 0):,} test"),
        ("scikit-learn", model_info.get("scikit_learn_version", "—")),
    ])

tab_detect, tab_perf, tab_explain, tab_audit, tab_limits = st.tabs(
    ["Run detection", "Model performance", "Feature importance", "Validation audit", "Limitations"]
)

# ---------------------------------------------------------------- detection
with tab_detect:
    can_hold_out = held_out_available(bundle, report.total_records, report.source_files)
    modes = [SAMPLE_HELD_OUT, SAMPLE_ALL] if can_hold_out else [SAMPLE_ALL]
    c1, c2, c3 = st.columns([1.3, 1.2, 0.6], gap="medium")
    mode = c1.radio("Flows to analyse", modes, horizontal=False,
                    help="Held-out flows were never seen during training, so agreement with the true "
                         "labels is a fair check. 'Any flows' may include training flows.")
    pool_size = len(bundle.test_row_ids) if mode == SAMPLE_HELD_OUT else len(df)
    max_n = int(min(50_000, pool_size))
    default_n = int(min(5_000, max_n))
    n_records = c2.slider("Number of flows", min_value=min(100, max_n), max_value=max_n, value=default_n,
                          step=100 if max_n >= 1_000 else 1)
    seed = c3.number_input("Sample seed", min_value=0, max_value=9_999, value=config.RANDOM_STATE, step=1,
                           help="Same seed → same flows. Change it to draw a different random sample.")
    if not can_hold_out:
        st.caption("Held-out sampling is available only when the loaded dataset is the exact file the model was trained on.")

    if st.button("Run Threat Detection", type="primary"):
        try:
            with st.spinner("Classifying flows…"):
                flows = select_flows(df, n_records, mode, bundle, seed=int(seed))
                result = run_detection(bundle, flows, mode)
            st.session_state[RESULT_KEY] = (handle.signature, result)
        except FeatureMismatchError as exc:
            callout(str(exc), tone="malicious", bold_prefix="Feature schema mismatch.")
        except ValueError as exc:
            callout(str(exc), tone="malicious", bold_prefix="Detection could not run.")

    stored = st.session_state.get(RESULT_KEY)
    if not stored or stored[0] != handle.signature:
        st.write("")
        empty_state("Choose how many flows to analyse and press Run Threat Detection.")
    else:
        result = stored[1]
        st.write("")
        kpi_row([
            {"label": "Flows analysed", "value": helpers.fmt_int(result.total), "caption": result.sample_mode, "tone": "primary"},
            {"label": "Predicted benign", "value": helpers.fmt_int(result.predicted_benign), "tone": "benign"},
            {"label": "Predicted malicious", "value": helpers.fmt_int(result.predicted_malicious), "tone": "malicious"},
            {"label": "Malicious predictions", "value": helpers.fmt_pct(result.malicious_pct), "tone": "warning",
             "share": result.malicious_pct},
        ])
        st.write("")
        left, right = st.columns([1, 1.2], gap="medium")
        with left:
            st.plotly_chart(charts.donut([config.CLASS_BENIGN, config.CLASS_MALICIOUS],
                                         [result.predicted_benign, result.predicted_malicious],
                                         "Prediction distribution", center_label="flows analysed"),
                            width="stretch", config=charts.PLOTLY_CONFIG)
        with right:
            if result.sample_metrics:
                sm = result.sample_metrics
                st.plotly_chart(charts.confusion_heatmap(sm["confusion_matrix"], sm["confusion_labels"],
                                                         "Predictions vs dataset labels (this sample)"),
                                width="stretch", config=charts.PLOTLY_CONFIG)
        if result.sample_metrics:
            sm = result.sample_metrics
            note = ("These flows were held out from training." if result.sample_mode == SAMPLE_HELD_OUT
                    else "This sample may include flows used in training, so agreement can be optimistic.")
            callout(f"The model agreed with the dataset label on {sm['accuracy'] * 100:.2f}% of these "
                    f"{result.total:,} flows ({sm['false_positives']:,} false alarms, "
                    f"{sm['false_negatives']:,} missed attacks). {note}",
                    tone="primary", bold_prefix="Sample agreement.")

        section("Flow predictions", "Every verdict, with its confidence.")
        view = st.segmented_control("Show", ["All flows", "Predicted malicious", "Disagrees with label"],
                                    default="All flows")
        table = result.table
        if view == "Predicted malicious":
            table = table[table["Predicted Class"] == config.CLASS_MALICIOUS]
        elif view == "Disagrees with label" and "Correct" in table:
            table = table[~table["Correct"]]
        column_config = {}
        if "Malicious Confidence" in table:
            column_config["Malicious Confidence"] = st.column_config.ProgressColumn(
                "Malicious Confidence", min_value=0.0, max_value=1.0, format="%.3f")
        st.dataframe(table.head(2_000), hide_index=True, width="stretch", height=380, column_config=column_config)
        st.caption(f"{len(table):,} rows in this view (first 2,000 displayed). Download includes all rows of the view.")
        st.download_button("Download predictions (CSV)", dataframe_to_csv(table),
                           file_name="cyberpulse_detection_results.csv", mime="text/csv")

# ---------------------------------------------------------------- performance
with tab_perf:
    callout("These figures come from the held-out test split created during training "
            "(deduplicated, never seen by the model). They are not computed from the sample above.",
            tone="neutral", bold_prefix="Held-out evaluation.")
    if primary:
        kpi_row(columns=5, cards=[
            {"label": "Accuracy", "value": f"{primary['accuracy'] * 100:.3f}%", "tone": "primary", "share": primary["accuracy"] * 100},
            {"label": "Precision", "value": f"{primary['precision'] * 100:.3f}%", "caption": "Alerts that were real attacks", "tone": "neutral", "share": primary["precision"] * 100},
            {"label": "Recall", "value": f"{primary['recall'] * 100:.3f}%", "caption": "Attacks that were caught", "tone": "neutral", "share": primary["recall"] * 100},
            {"label": "F1-score", "value": f"{primary['f1'] * 100:.3f}%", "caption": "Balance of precision and recall", "tone": "neutral", "share": primary["f1"] * 100},
            {"label": "ROC AUC", "value": f"{primary.get('roc_auc', float('nan')):.4f}", "caption": "Ranking quality (1 = perfect)", "tone": "neutral"},
        ])
        st.write("")
        left, right = st.columns([1, 1.1], gap="medium")
        with left:
            st.plotly_chart(charts.confusion_heatmap(primary["confusion_matrix"], primary["confusion_labels"],
                                                     f"Confusion matrix · {primary['support']:,} test flows"),
                            width="stretch", config=charts.PLOTLY_CONFIG)
        with right:
            rep = pd.DataFrame(primary["classification_report"]).T.drop(index="accuracy", errors="ignore")
            rep = rep.rename(columns={"precision": "Precision", "recall": "Recall", "f1-score": "F1-score",
                                      "support": "Support"}).loc[:, ["Precision", "Recall", "F1-score", "Support"]]
            rep = rep.rename(index={"macro avg": "Macro average", "weighted avg": "Weighted average"})
            rep[["Precision", "Recall", "F1-score"]] = rep[["Precision", "Recall", "F1-score"]].astype(float).round(5)
            rep["Support"] = rep["Support"].astype(float).astype(int)
            st.markdown("**Classification report**")
            st.dataframe(rep, width="stretch")
            fp, fn = primary["false_positives"], primary["false_negatives"]
            st.caption(f"False positive rate {primary['false_positive_rate'] * 100:.3f}% ({fp:,} benign flows flagged) · "
                       f"False negative rate {primary['false_negative_rate'] * 100:.3f}% ({fn:,} attacks missed).")
        cv = meta.get("cross_validation")
        if cv:
            st.caption(f"{cv['folds']}-fold stratified cross-validation on the training set: "
                       f"F1 = {cv['mean'] * 100:.3f}% ± {cv['std'] * 100:.3f}%.")
    else:
        empty_state("No evaluation metrics were saved with this model. Retrain it to generate them.")

# ---------------------------------------------------------------- explainability
with tab_explain:
    st.plotly_chart(charts.feature_importance(meta.get("feature_importance", []), 15),
                    width="stretch", config=charts.PLOTLY_CONFIG)
    callout("Importance is the average reduction in Gini impurity a feature provides across all trees. "
            "It shows which features the model relies on, not that a feature causes an attack. "
            "Correlated features share importance, so their individual values can be understated.",
            tone="neutral", bold_prefix="How to read this.")

# ---------------------------------------------------------------- audit
with tab_audit:
    audit = meta.get("audit", {})
    perm = audit.get("label_permutation_check", {})
    st.markdown("The original model reported close to 100% accuracy. Before trusting that figure the training "
                "pipeline was audited for the usual causes of over-optimistic results.")
    rows = [
        ("Exact duplicate flows removed before splitting", f"{audit.get('exact_duplicate_rows_removed', 0):,}"),
        ("Same features with conflicting labels (removed)", f"{audit.get('conflicting_label_rows_removed', 0):,}"),
        ("Unique flows used for evaluation", f"{audit.get('rows_after_deduplication', 0):,}"),
        ("Label column among model inputs", "No" if not audit.get("label_in_features") else "YES — investigate"),
        ("Identifier columns used (IP, timestamp, flow ID)",
         ", ".join(audit.get("identifier_columns_used", [])) or "None"),
        ("Preprocessing fitted on", audit.get("preprocessing_fitted_on", "—")),
        ("Split strategy", audit.get("split", "—")),
    ]
    if perm:
        rows.append(("Shuffled-label accuracy vs majority baseline",
                     f"{perm['shuffled_label_accuracy'] * 100:.2f}% vs {perm['majority_baseline'] * 100:.2f}% "
                     f"({'pass' if perm['passed'] else 'check'})"))
    left, right = st.columns([1.15, 1], gap="medium")
    with left:
        key_value_card("Leakage checks", rows)
    with right:
        if naive and primary:
            st.plotly_chart(charts.metric_comparison(
                [{**naive, "name": "Random split (duplicates kept)"}, {**primary, "name": "Deduplicated split"}],
                "Effect of duplicate removal on test scores"), width="stretch", config=charts.PLOTLY_CONFIG)
    if naive and primary:
        overlap = naive["overlap"]
        delta = (naive["accuracy"] - primary["accuracy"]) * 100
        callout(
            f"In a plain random split, {overlap['test_rows_seen_in_train']:,} test flows "
            f"({overlap['test_rows_seen_in_train_pct']:.2f}%) had an identical copy in the training data. "
            f"Removing duplicates before splitting brings that to "
            f"{primary['overlap']['test_rows_seen_in_train']:,} and changes accuracy by {-delta:+.3f} percentage points "
            f"({naive['accuracy'] * 100:.3f}% → {primary['accuracy'] * 100:.3f}%). "
            "The deduplicated figure is the one reported.",
            tone="primary", bold_prefix="Finding.",
        )
    balance = meta.get("dataset", {}).get("class_balance", {})
    if balance:
        st.caption(f"Class balance: {balance['benign_pct']:.1f}% benign / {balance['malicious_pct']:.1f}% malicious. "
                   f"A model that always predicted the majority class would score "
                   f"{balance['majority_baseline_accuracy'] * 100:.1f}% accuracy — the baseline any real model must beat.")
    st.caption("Remaining caveat: flows from the same attack session are often near-identical rather than exact copies, "
               "so even a deduplicated random split can be optimistic compared with traffic from a different network or day.")

# ---------------------------------------------------------------- limitations
with tab_limits:
    attack_names = [l for l in trained_labels if l.upper() != config.BENIGN_LABEL]
    for item in [
        "Predictions are model-based estimates, not verified security events.",
        f"The model is trained on {config.DATASET_NAME} ({', '.join(meta.get('dataset', {}).get('files', [])) or 'recorded data'}).",
        f"The training data contains only these labels: {', '.join(trained_labels)}. "
        f"It can only recognise patterns similar to {', '.join(attack_names) or 'the attacks it saw'}; "
        "other attack types may be classified as benign.",
        "CIC-IDS2017 was captured in a lab network in 2017. Results may not generalise to other networks, "
        "newer traffic or encrypted-traffic patterns.",
        "This is an analytics and decision-support tool. It does not block, prevent or respond to attacks.",
    ]:
        st.markdown(f"- {item}")
