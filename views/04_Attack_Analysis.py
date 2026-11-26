"""Module 4 — Attack Analysis: what does malicious traffic look like?"""

import streamlit as st

from core import analytics, config
from utils import charts, helpers
from utils.styling import callout, empty_state, key_value_card, kpi_row, page_header, section

handle = helpers.require_dataset()
df, report, sig = handle.df, handle.report, handle.signature

page_header(
    "Attack Analysis",
    "The anatomy of *an attack.*",
    "Attack categories are discovered from the dataset labels. Select one to compare its flow "
    "characteristics with benign traffic.",
)

attacks = helpers.cached_attack_distribution(sig, df)
labels = helpers.cached_label_counts(sig, df)
kpi = analytics.overview_kpis(df, report)

callout(
    f"The loaded data ({', '.join(report.source_files)}) contains {len(labels)} label(s): "
    f"{', '.join(labels['Label'])}. Only these categories are analysed. Adding more CIC-IDS2017 CSV files to "
    "data/sample_data/ makes their attack categories appear here automatically.",
    tone="neutral", bold_prefix="Analysis scope.",
)

kpi_row([
    {"label": "Malicious flows", "value": helpers.fmt_int(kpi["malicious"]), "tone": "malicious"},
    {"label": "Attack categories", "value": str(len(attacks)), "caption": "Found in labels", "tone": "warning"},
    {"label": "Share of all traffic", "value": helpers.fmt_pct(kpi["malicious_pct"]), "caption": "Malicious flows",
     "tone": "warning", "share": kpi["malicious_pct"]},
    {"label": "Benign flows", "value": helpers.fmt_int(kpi["benign"]),
     "caption": f"{analytics.pct(kpi['benign'], kpi['total']):.1f}% of traffic", "tone": "benign",
     "share": analytics.pct(kpi["benign"], kpi["total"])},
])

if attacks.empty:
    st.write("")
    empty_state("No malicious flows are present in the loaded dataset.")
    st.stop()

section("Attack distribution", index=1, caption="Discovered from the labels.")
left, right = st.columns([1, 1.25], gap="medium")
with left:
    classes = helpers.cached_class_counts(sig, df)
    st.plotly_chart(charts.donut(classes["Traffic Class"].tolist(), classes["Flows"].tolist(),
                                 "Benign vs malicious"), width="stretch", config=charts.PLOTLY_CONFIG)
with right:
    st.plotly_chart(charts.horizontal_bar(attacks, "Flows", "Attack Category", "Flows per attack category",
                                          color_col="Attack Category", share_col="Share of All Traffic (%)",
                                          height=340),
                    width="stretch", config=charts.PLOTLY_CONFIG)

section("Category details", index=2, caption="One attack, up close.")
category = st.selectbox("Attack category", attacks["Attack Category"].tolist())
profile = analytics.category_profile(df, category)
benign = analytics.category_profile(df, labels.loc[labels["Traffic Class"] == config.CLASS_BENIGN, "Label"].iloc[0]) \
    if (labels["Traffic Class"] == config.CLASS_BENIGN).any() else None

left, right = st.columns([1, 1], gap="medium")
with left:
    rows = [("Category", category), ("Flows", f"{profile['flows']:,}"),
            ("Share of total traffic", f"{profile['share_pct']:.2f}%")]
    if "top_port" in profile:
        rows += [("Most targeted port", f"{profile['top_port']} ({profile['top_port_share']:.1f}% of its flows)"),
                 ("Distinct destination ports", f"{profile['distinct_ports']:,}")]
    if "median_duration_s" in profile:
        rows.append(("Median flow duration", f"{profile['median_duration_s']:.3f} s"))
    if "mean_fwd_packets" in profile:
        rows.append(("Mean packets (fwd / bwd)", f"{profile['mean_fwd_packets']:.2f} / {profile['mean_bwd_packets']:.2f}"))
    key_value_card(f"{category} profile", rows)
with right:
    compare_cols = [config.COL_DURATION, config.COL_FWD_PACKETS, config.COL_BWD_PACKETS, config.COL_BYTES_PER_S,
                    config.COL_PACKETS_PER_S, "Packet Length Mean", "Average Packet Size"]
    subset = df[df[config.LABEL_COLUMN].astype("string").isin([category, config.BENIGN_LABEL])]
    table = analytics.feature_profile(subset, compare_cols, group_col=config.LABEL_COLUMN)
    if not table.empty:
        st.markdown(f"**Median flow characteristics — {category} vs BENIGN**")
        st.dataframe(table, width="stretch")
        st.caption("Medians are used because these features are heavily skewed by a few extreme flows.")

section("Attack patterns", index=3, caption=f"How {category} differs from normal traffic.")
left, right = st.columns(2, gap="medium")
with left:
    st.plotly_chart(charts.stacked_ports(analytics.top_ports(df[df[config.LABEL_COLUMN].astype("string") == category], 8),
                                         f"Destination ports targeted by {category}"),
                    width="stretch", config=charts.PLOTLY_CONFIG)
with right:
    st.plotly_chart(charts.log_distribution(
        analytics.log_histogram(subset, config.COL_DURATION, scale=1e6, group_col=config.LABEL_COLUMN),
        "Flow duration", "Seconds (log scale)", "s"), width="stretch", config=charts.PLOTLY_CONFIG)

metric = st.segmented_control(
    "Flow characteristic",
    [c for c in (config.COL_FWD_PACKETS, config.COL_BWD_PACKETS, config.COL_BYTES_PER_S, config.COL_PACKETS_PER_S)
     if c in df.columns],
    default=config.COL_BYTES_PER_S if config.COL_BYTES_PER_S in df.columns else None,
)
if metric:
    st.plotly_chart(charts.box_from_stats(analytics.box_stats(subset, metric, group_col=config.LABEL_COLUMN),
                                          f"{metric}: {category} vs BENIGN", f"{metric} (log scale)"),
                    width="stretch", config=charts.PLOTLY_CONFIG)

section("Classification table", index=4, caption="Original labels and their counts.")
st.dataframe(labels, hide_index=True, width="stretch",
             column_config={"Share (%)": st.column_config.NumberColumn(format="%.2f%%"),
                            "Flows": st.column_config.NumberColumn(format="localized")})
