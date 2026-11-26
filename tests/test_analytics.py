import pandas as pd

from core import analytics, config
from core.analytics import FilterSpec


def test_class_counts_sum_to_total(clean):
    df, _ = clean
    counts = analytics.class_counts(df)
    assert counts["Flows"].sum() == len(df)
    assert abs(counts["Share (%)"].sum() - 100) < 0.05


def test_attack_distribution_is_discovered(clean):
    df, _ = clean
    attacks = analytics.attack_distribution(df)
    assert attacks["Attack Category"].tolist() == ["DDoS"]
    assert attacks["Share of Malicious (%)"].iloc[0] == 100.0
    assert analytics.attack_labels(df) == ["DDoS"]


def test_new_attack_labels_appear_automatically(clean):
    df, _ = clean
    df = df.copy()
    df[config.LABEL_COLUMN] = df[config.LABEL_COLUMN].astype(str)
    df.loc[df.index[:10], config.LABEL_COLUMN] = "PortScan"
    df.loc[df.index[:10], config.CLASS_COLUMN] = config.CLASS_MALICIOUS
    assert set(analytics.attack_labels(df)) == {"DDoS", "PortScan"}


def test_percentages_safe():
    assert analytics.pct(1, 0) == 0.0
    assert analytics.pct(1, 4) == 25.0


def test_filters_and_empty_selection(clean):
    df, _ = clean
    only_mal = analytics.apply_filters(df, FilterSpec(classes=[config.CLASS_MALICIOUS]))
    assert (only_mal[config.CLASS_COLUMN] == config.CLASS_MALICIOUS).all()
    port80 = analytics.apply_filters(df, FilterSpec(ports=[80]))
    assert (port80[config.COL_DST_PORT] == 80).all()
    empty = analytics.apply_filters(df, FilterSpec(ports=[1]))
    assert empty.empty
    # every aggregate must cope with an empty selection
    assert analytics.top_ports(empty).empty
    assert analytics.log_histogram(empty, config.COL_DURATION).empty
    assert analytics.box_stats(empty, config.COL_BYTES_PER_S).empty
    assert analytics.packet_summary(empty).empty


def test_duration_filter_in_seconds(clean):
    df, _ = clean
    out = analytics.apply_filters(df, FilterSpec(duration_range_s=(0, 1)))
    assert (out[config.COL_DURATION] <= 1e6).all()


def test_log_histogram_keeps_every_flow(clean):
    df, _ = clean
    hist = analytics.log_histogram(df, config.COL_DURATION, scale=1e6)
    assert hist["count"].sum() == df[config.COL_DURATION].notna().sum()


def test_box_stats_ignore_nan(clean):
    df, _ = clean
    stats = analytics.box_stats(df, config.COL_BYTES_PER_S)
    assert stats["n"].sum() == df[config.COL_BYTES_PER_S].notna().sum()
    assert (stats["q1"] <= stats["median"]).all() and (stats["median"] <= stats["q3"]).all()


def test_insights_are_data_driven(clean):
    df, report = clean
    insights = analytics.generate_insights(df, report)
    kpi = analytics.overview_kpis(df, report)
    assert f"{kpi['total']:,}" in insights[0]
    assert any("DDoS" in i for i in insights)


def test_unexpected_label_is_treated_as_malicious():
    from core.data_loader import clean_dataset
    df, _ = clean_dataset(pd.DataFrame({"x": [1, 2, 3], "Label": ["BENIGN", "Weird-Thing", "benign "]}))
    assert df[config.CLASS_COLUMN].astype(str).tolist() == ["Benign", "Malicious", "Benign"]
