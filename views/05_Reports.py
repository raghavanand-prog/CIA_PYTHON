"""Module 5 — Security Reports: CSV exports and the PDF report."""

import streamlit as st

from core import analytics, config
from core.analytics import FilterSpec
from utils import helpers
from utils.report_generator import ReportInputs, build_pdf_report, dataframe_to_csv, dataset_summary_frame
from utils.styling import callout, page_header, panel_title, section, tile

handle = helpers.require_dataset()
df, report, sig = handle.df, handle.report, handle.signature
bundle, _ = helpers.get_model()

page_header(
    "Security Reports",
    "Findings, *ready to share.*",
    "Download the analysis as CSV tables or a formatted PDF security report. "
    "All figures are generated from the loaded dataset and the saved model evaluation.",
)

kpi = analytics.overview_kpis(df, report)
labels = helpers.cached_label_counts(sig, df)
attacks = helpers.cached_attack_distribution(sig, df)
stored_detection = st.session_state.get("detection_result")
detection = stored_detection[1] if stored_detection and stored_detection[0] == sig else None
spec: FilterSpec = st.session_state.get("network_filters", FilterSpec())


def export_card(title: str, description: str) -> None:
    panel_title(title, description)


# ---------------------------------------------------------------- PDF
section("PDF security report", index=1, caption="One document. Everything that matters.")
with tile():
    left, right = st.columns([1.6, 1], gap="medium")
    with left:
        contents = ["Executive summary and insights", "Dataset information and quality",
                    "Traffic classification and attack breakdown"]
        contents.append("Model performance, confusion matrix, leakage audit and feature importance"
                        if bundle else "Model section omitted — no trained model found")
        if detection:
            contents.append(f"Latest detection run ({detection.total:,} flows)")
        contents.append("Methodology, limitations and offline-analysis disclaimer")
        st.markdown("\n".join(f"- {c}" for c in contents))
    with right:
        if st.button("Generate PDF report", type="primary", width="stretch"):
            detection_summary = None
            if detection:
                detection_summary = {
                    "total": detection.total, "mode": detection.sample_mode,
                    "benign": detection.predicted_benign, "malicious": detection.predicted_malicious,
                    "malicious_pct": detection.malicious_pct,
                    "agreement": detection.sample_metrics["accuracy"] if detection.sample_metrics else None,
                }
            with st.spinner("Building PDF…"):
                pdf = build_pdf_report(ReportInputs(
                    report=report, kpi=kpi, label_counts=labels, attack_distribution=attacks,
                    insights=helpers.cached_insights(sig, df, report),
                    model_metrics=bundle.metrics if bundle else None,
                    detection_summary=detection_summary,
                ))
            st.session_state["pdf_report"] = (sig, pdf)
        stored_pdf = st.session_state.get("pdf_report")
        if stored_pdf and stored_pdf[0] == sig:
            st.download_button("Download PDF report", stored_pdf[1], file_name="CHRIST_CyberPulse_Security_Report.pdf",
                               mime="application/pdf", width="stretch")
            st.caption(f"{len(stored_pdf[1]) / 1024:,.0f} KB · ready")

# ---------------------------------------------------------------- CSV
section("CSV exports", index=2, caption="Clean tables for any spreadsheet.")
c1, c2, c3 = st.columns(3, gap="medium")
with c1, tile():
    export_card("Dataset summary", "Totals, class counts and data-quality metrics.")
    st.download_button("Download CSV", dataframe_to_csv(dataset_summary_frame(report, kpi)),
                       file_name="cyberpulse_dataset_summary.csv", mime="text/csv", key="dl_summary", width="stretch")
with c2, tile():
    export_card("Traffic classification", "Every dataset label with flow count and share.")
    st.download_button("Download CSV", dataframe_to_csv(labels), file_name="cyberpulse_traffic_classification.csv",
                       mime="text/csv", key="dl_labels", width="stretch")
with c3, tile():
    export_card("AI detection results", f"{detection.total:,} predictions from the latest run." if detection
                else "Run detection in the AI Threat Detection module first.")
    st.download_button("Download CSV", dataframe_to_csv(detection.table) if detection else b"",
                       file_name="cyberpulse_detection_results.csv", mime="text/csv", key="dl_detect",
                       disabled=detection is None, width="stretch")

c4, c5, _ = st.columns(3, gap="medium")
active = any([spec.classes, spec.labels, spec.ports, spec.duration_range_s, spec.packet_range])
with c4, tile():
    filtered_n = len(analytics.apply_filters(df, spec)) if active else len(df)
    export_card("Filtered network records",
                f"{filtered_n:,} flows matching the Network Analytics filters." if active
                else "No filters are active in Network Analytics, so this equals the complete dataset.")
    if st.button("Prepare filtered CSV", key="prep_filtered", width="stretch"):
        st.session_state["reports_filtered_csv"] = (f"{sig}|{spec!r}", dataframe_to_csv(analytics.apply_filters(df, spec)))
    prepared = st.session_state.get("reports_filtered_csv")
    if prepared and prepared[0] == f"{sig}|{spec!r}":
        st.download_button("Download CSV", prepared[1], file_name="cyberpulse_filtered_flows.csv",
                           mime="text/csv", key="dl_filtered", type="primary", width="stretch")
with c5, tile():
    export_card("Complete dataset", f"All {len(df):,} cleaned flows ({df.shape[1]} columns). Large file.")
    if st.button("Prepare complete CSV", key="prep_full", width="stretch"):
        with st.spinner("Writing CSV…"):
            st.session_state["reports_full_csv"] = (sig, dataframe_to_csv(df))
    prepared_full = st.session_state.get("reports_full_csv")
    if prepared_full and prepared_full[0] == sig:
        st.download_button(f"Download CSV ({len(prepared_full[1]) / 1e6:,.0f} MB)", prepared_full[1],
                           file_name="cyberpulse_complete_dataset.csv", mime="text/csv", key="dl_full",
                           type="primary", width="stretch")

callout("Exports contain recorded CIC-IDS2017 traffic and model predictions only. "
        f"They are not a record of live activity on the {config.INSTITUTION.split(',')[0]} network.",
        tone="neutral", bold_prefix="Note.")
