"""Module 1 — Security Overview: what is happening in the analysed traffic?"""

import streamlit as st

from core import analytics, config
from utils import charts, helpers
from utils.styling import callout, insight_list, key_value_card, kpi_row, page_header, posture_hero, section

handle = helpers.require_dataset()
df, report, sig = handle.df, handle.report, handle.signature

page_header(
    "Security Overview",
    "Network security. *At a glance.*",
    "An executive summary of the recorded network flows: how much traffic was analysed, "
    "how much of it is malicious and how trustworthy the underlying data is.",
    badges=[("Dataset", config.DATASET_NAME), ("Records", f"{report.total_records:,}"),
            ("Files", str(len(report.source_files)))],
)

kpi = analytics.overview_kpis(df, report)
labels = helpers.cached_label_counts(sig, df)
attacks = helpers.cached_attack_distribution(sig, df)

# ---- hero: composition by label + three data-derived highlights
label_colours = charts.label_colors(labels["Label"].tolist())
segments = [(row.Label, int(row.Flows), colour) for row, colour in zip(labels.itertuples(), label_colours)]
side = []
if not attacks.empty:
    top = attacks.iloc[0]
    side.append(("Dominant attack", str(top["Attack Category"]),
                 f"{int(top['Flows']):,} flows · {top['Share of Malicious (%)']:.1f}% of malicious"))
    prof = analytics.category_profile(df, str(top["Attack Category"]))
    if "top_port" in prof:
        side.append(("Most targeted port", f"{prof['top_port']}", f"{prof['top_port_share']:.1f}% of {top['Attack Category']} flows"))
else:
    side.append(("Dominant attack", "None", "No malicious labels in the data"))
side.append(("Data quality", f"{report.duplicate_rows:,} duplicates",
             f"{report.missing_values + report.infinite_values:,} missing / infinite values"))
posture_hero(kpi["total"], kpi["benign"], kpi["malicious"], side[:3], segments)

kpi_row(columns=3, cards=[
    {"label": "Total flows", "value": helpers.fmt_int(kpi["total"]), "caption": "Recorded flows", "tone": "primary"},
    {"label": "Benign flows", "value": helpers.fmt_int(kpi["benign"]),
     "caption": f"{analytics.pct(kpi['benign'], kpi['total']):.1f}% of traffic", "tone": "benign",
     "share": analytics.pct(kpi["benign"], kpi["total"])},
    {"label": "Malicious flows", "value": helpers.fmt_int(kpi["malicious"]),
     "caption": f"{kpi['malicious_pct']:.1f}% of traffic", "tone": "malicious", "share": kpi["malicious_pct"]},
    {"label": "Malicious share", "value": helpers.fmt_pct(kpi["malicious_pct"]), "caption": "Labelled attack traffic",
     "tone": "warning", "share": kpi["malicious_pct"]},
    {"label": "Attack categories", "value": str(kpi["attack_categories"]), "caption": "From dataset labels", "tone": "neutral"},
    {"label": "Flow features", "value": str(kpi["features"]), "caption": "Columns per flow", "tone": "neutral"},
])
callout(
    "This dashboard analyses a recorded CIC-IDS2017 capture. It does not capture packets or monitor "
    "the CHRIST University network in real time.",
    tone="warning", bold_prefix="Offline analysis.",
)

section("Traffic classification", index=1, caption="Every flow, labelled.")
classes = helpers.cached_class_counts(sig, df)
left, right = st.columns([1, 1.25], gap="medium")
with left:
    st.plotly_chart(
        charts.donut(classes["Traffic Class"].tolist(), classes["Flows"].tolist(), "Benign vs malicious"),
        width="stretch", config=charts.PLOTLY_CONFIG,
    )
with right:
    st.plotly_chart(
        charts.horizontal_bar(labels, "Flows", "Label", "Flows by dataset label", color_col="Label",
                              share_col="Share (%)", height=340),
        width="stretch", config=charts.PLOTLY_CONFIG,
    )

section("Security insights", index=2, caption="Computed from the data. Nothing invented.")
left, right = st.columns([1.35, 1], gap="medium")
with left:
    insight_list("Key observations", helpers.cached_insights(sig, df, report))
with right:
    key_value_card("Dataset quality", [
        ("Total records", f"{report.total_records:,}"),
        ("Feature columns", f"{report.feature_count:,}"),
        ("Missing values", f"{report.missing_values:,}"),
        ("Infinite values", f"{report.infinite_values:,}"),
        ("Duplicate records", f"{report.duplicate_rows:,} ({analytics.pct(report.duplicate_rows, report.total_records):.2f}%)"),
        ("Constant columns", f"{len(report.constant_columns):,}"),
    ])

section("Dataset information", index=3, caption="Where every number comes from.")
left, right = st.columns([1.35, 1], gap="medium")
with left:
    key_value_card("Source", [
        ("Dataset", f"{config.DATASET_NAME} (Canadian Institute for Cybersecurity)"),
        ("File(s)", ", ".join(report.source_files)),
        ("Analysis mode", config.ANALYSIS_MODE),
        ("Records analysed", f"{report.total_records:,}"),
        ("Loaded at", report.loaded_at),
    ])
with right:
    with st.expander("Column-level data quality", expanded=False):
        if report.missing_by_column or report.infinite_by_column:
            cols = sorted(set(report.missing_by_column) | set(report.infinite_by_column))
            st.dataframe(
                {"Column": cols,
                 "Missing": [report.missing_by_column.get(c, 0) for c in cols],
                 "Infinite": [report.infinite_by_column.get(c, 0) for c in cols]},
                hide_index=True, width="stretch",
            )
        else:
            st.caption("No missing or infinite values were found.")
        if report.constant_columns:
            st.caption("Constant columns (single value in every row): " + ", ".join(report.constant_columns))
