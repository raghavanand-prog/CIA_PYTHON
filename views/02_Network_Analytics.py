"""Module 2 — Network Analytics: interactive exploration of flow behaviour."""

import streamlit as st

from core import analytics, config
from core.analytics import FilterSpec
from utils import charts, helpers
from utils.report_generator import dataframe_to_csv
from utils.styling import callout, empty_state, kpi_row, page_header, panel_title, section, tile

FILTER_KEY = "network_filters"
TABLE_LIMIT = 1_000

handle = helpers.require_dataset()
df, sig = handle.df, handle.signature

page_header(
    "Network Analytics",
    "Traffic, *decoded.*",
    "Filter the recorded flows by class, attack label, port, duration and packet volume. "
    "Every chart is computed from all matching flows — nothing is sampled.",
)

# ---------------------------------------------------------------- filters
ranges = helpers.cached_ranges(sig, df)
label_options = helpers.cached_label_counts(sig, df)["Label"].tolist()
port_options = helpers.cached_port_options(sig, df)

with tile():
    panel_title("Refine the view", "Filters apply to every chart and table on this page.")
    c1, c2, c3 = st.columns(3, gap="medium")
    classes = c1.multiselect("Traffic classification", [config.CLASS_BENIGN, config.CLASS_MALICIOUS],
                             placeholder="All classes")
    labels = c2.multiselect("Attack category / label", label_options, placeholder="All labels")
    ports = c3.multiselect("Destination port", port_options, placeholder="All ports",
                           help="The 60 most frequent destination ports in the dataset.")
    c4, c5 = st.columns(2, gap="medium")
    duration_range = None
    if "duration" in ranges:
        lo, hi = ranges["duration"]
        duration_range = c4.slider("Flow duration (seconds)", min_value=0.0, max_value=float(round(hi + 0.5)),
                                   value=(0.0, float(round(hi + 0.5))), step=0.5)
    packet_range = None
    if "packets" in ranges:
        plo, phi = ranges["packets"]
        with c5:
            p1, p2 = st.columns(2)
            pmin = p1.number_input("Min total packets", min_value=plo, max_value=phi, value=plo, step=1)
            pmax = p2.number_input("Max total packets", min_value=plo, max_value=phi, value=phi, step=1)
            packet_range = (int(min(pmin, pmax)), int(max(pmin, pmax)))

full_duration = duration_range is None or (duration_range[0] <= 0 and duration_range[1] >= ranges["duration"][1])
full_packets = packet_range is None or packet_range == ranges.get("packets")
spec = FilterSpec(
    classes=classes, labels=labels, ports=[int(p) for p in ports],
    duration_range_s=None if full_duration else duration_range,
    packet_range=None if full_packets else packet_range,
)
st.session_state[FILTER_KEY] = spec
filtered = analytics.apply_filters(df, spec)

n = len(filtered)
mal = int((filtered[config.CLASS_COLUMN] == config.CLASS_MALICIOUS).sum()) if n else 0
avg_packets = float(analytics.total_packets(filtered).mean()) if n else 0.0
kpi_row([
    {"label": "Matching flows", "value": helpers.fmt_int(n),
     "caption": f"{analytics.pct(n, len(df)):.1f}% of all flows", "tone": "primary",
     "share": analytics.pct(n, len(df))},
    {"label": "Malicious in selection", "value": helpers.fmt_int(mal),
     "caption": f"{analytics.pct(mal, n):.1f}% of selection", "tone": "malicious",
     "share": analytics.pct(mal, n)},
    {"label": "Distinct destination ports",
     "value": helpers.fmt_int(filtered[config.COL_DST_PORT].nunique()) if n and config.COL_DST_PORT in filtered else "—",
     "tone": "neutral"},
    {"label": "Average packets per flow", "value": f"{avg_packets:,.1f}", "caption": "Forward + backward", "tone": "neutral"},
])

if n == 0:
    st.write("")
    empty_state("No flows match these filters. Widen the ranges or clear a filter.")
    st.stop()

# ---------------------------------------------------------------- charts
section("Destination ports", index=1, caption="Where the traffic is headed.")
st.plotly_chart(charts.stacked_ports(analytics.top_ports(filtered, 10), "Top 10 destination ports"),
                width="stretch", config=charts.PLOTLY_CONFIG)

section("Flow duration", index=2, caption="From microseconds to minutes, on a log scale.")
st.plotly_chart(
    charts.log_distribution(analytics.log_histogram(filtered, config.COL_DURATION, scale=1e6),
                            "Distribution of flow durations", "Flow duration (seconds, log scale)", "s"),
    width="stretch", config=charts.PLOTLY_CONFIG,
)

section("Packet analysis", index=3, caption="Forward is client to server. Backward is the reply.")
left, right = st.columns(2, gap="medium")
with left:
    summary = analytics.packet_summary(filtered)
    st.plotly_chart(
        charts.grouped_bar(summary, "Traffic Class", [c for c in (config.COL_FWD_PACKETS, config.COL_BWD_PACKETS)
                                                     if c in summary.columns],
                           "Average packets per flow", "Packets", colors=[config.COLORS["primary"], config.COLORS["neutral"]]),
        width="stretch", config=charts.PLOTLY_CONFIG,
    )
with right:
    st.plotly_chart(
        charts.box_from_stats(analytics.box_stats(filtered, config.COL_FWD_PACKETS),
                              "Forward packets per flow", "Packets (log scale)"),
        width="stretch", config=charts.PLOTLY_CONFIG,
    )

section("Flow behaviour", index=4, caption="Throughput, measured across every matching flow.")
left, right = st.columns(2, gap="medium")
with left:
    st.plotly_chart(charts.box_from_stats(analytics.box_stats(filtered, config.COL_BYTES_PER_S),
                                          "Flow bytes per second", "Bytes/s (log scale)"),
                    width="stretch", config=charts.PLOTLY_CONFIG)
with right:
    st.plotly_chart(charts.box_from_stats(analytics.box_stats(filtered, config.COL_PACKETS_PER_S),
                                          "Flow packets per second", "Packets/s (log scale)"),
                    width="stretch", config=charts.PLOTLY_CONFIG)

length_cols = [c for c in config.PACKET_LENGTH_COLUMNS if c in filtered.columns]
if length_cols:
    profile = analytics.feature_profile(filtered, length_cols)
    st.markdown("**Packet length statistics — median per class (bytes)**")
    st.dataframe(profile, width="stretch")

if analytics.has_column(filtered, config.COL_PROTOCOL):
    section("Protocol distribution")
    proto = filtered[config.COL_PROTOCOL].value_counts().rename_axis("Protocol").reset_index(name="Flows")
    proto["Protocol"] = proto["Protocol"].astype(str)
    st.plotly_chart(charts.horizontal_bar(proto, "Flows", "Protocol", "Flows by protocol number"),
                    width="stretch", config=charts.PLOTLY_CONFIG)
else:
    callout("This CIC-IDS2017 file has no protocol column, so protocol-level analysis is not shown.",
            tone="neutral", bold_prefix="Protocol data unavailable.")

# ---------------------------------------------------------------- records
section("Filtered records", index=5, caption=f"First {TABLE_LIMIT:,} of {n:,} matching flows.")
key_cols = [config.ROW_ID_COLUMN, config.LABEL_COLUMN, config.CLASS_COLUMN, config.COL_DST_PORT, config.COL_DURATION,
            config.COL_FWD_PACKETS, config.COL_BWD_PACKETS, config.COL_BYTES_PER_S, config.COL_PACKETS_PER_S]
key_cols = [c for c in key_cols if c in filtered.columns]
show_all = st.toggle("Show all columns", value=False)
view_cols = list(filtered.columns) if show_all else key_cols
st.dataframe(filtered[view_cols].head(TABLE_LIMIT), hide_index=True, width="stretch", height=380)

export_key = f"{sig}|{spec!r}|{show_all}"
with st.container(horizontal=True):
    if st.button("Prepare CSV of filtered records"):
        st.session_state["network_csv"] = (export_key, dataframe_to_csv(filtered[view_cols]))
    prepared = st.session_state.get("network_csv")
    if prepared and prepared[0] == export_key:
        st.download_button(f"Download {n:,} records (CSV)", prepared[1],
                           file_name="cyberpulse_filtered_flows.csv", mime="text/csv", type="primary")
