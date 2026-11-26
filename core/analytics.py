"""Shared metric definitions used by every page and by the reports.

All functions work on the full cleaned dataset (no sampling) and return small
summary tables, so the browser only ever receives aggregated numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from core import config
from core.data_loader import QualityReport

CLASS_ORDER = [config.CLASS_BENIGN, config.CLASS_MALICIOUS]


def pct(part: float, whole: float) -> float:
    """Percentage that never divides by zero."""
    return float(part) / float(whole) * 100 if whole else 0.0


def has_column(df: pd.DataFrame, column: str) -> bool:
    return column in df.columns and df[column].notna().any()


# ---------------------------------------------------------------- counts
def class_counts(df: pd.DataFrame) -> pd.DataFrame:
    """Benign vs malicious flow counts and shares."""
    counts = df[config.CLASS_COLUMN].value_counts().reindex(CLASS_ORDER, fill_value=0)
    total = int(counts.sum())
    return pd.DataFrame(
        {
            "Traffic Class": counts.index.astype(str),
            "Flows": counts.to_numpy(dtype=int),
            "Share (%)": [round(pct(v, total), 2) for v in counts.to_numpy()],
        }
    )


def label_counts(df: pd.DataFrame) -> pd.DataFrame:
    """Original dataset labels with counts, shares and class."""
    counts = df[config.LABEL_COLUMN].astype("string").value_counts()
    total = int(counts.sum())
    out = pd.DataFrame({"Label": counts.index.astype(str), "Flows": counts.to_numpy(dtype=int)})
    out["Traffic Class"] = np.where(
        out["Label"].str.upper() == config.BENIGN_LABEL, config.CLASS_BENIGN, config.CLASS_MALICIOUS
    )
    out["Share (%)"] = (out["Flows"] / total * 100).round(2) if total else 0.0
    return out[["Label", "Traffic Class", "Flows", "Share (%)"]].reset_index(drop=True)


def attack_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Only the malicious labels, with share of all traffic and of malicious traffic."""
    labels = label_counts(df)
    attacks = labels[labels["Traffic Class"] == config.CLASS_MALICIOUS].copy()
    malicious_total = int(attacks["Flows"].sum())
    attacks["Share of Malicious (%)"] = (
        (attacks["Flows"] / malicious_total * 100).round(2) if malicious_total else 0.0
    )
    return attacks.rename(columns={"Label": "Attack Category", "Share (%)": "Share of All Traffic (%)"}).drop(
        columns="Traffic Class"
    ).reset_index(drop=True)


def attack_labels(df: pd.DataFrame) -> list[str]:
    """Attack categories discovered in the data (never hard-coded)."""
    return attack_distribution(df)["Attack Category"].tolist()


def overview_kpis(df: pd.DataFrame, report: QualityReport) -> dict:
    classes = class_counts(df).set_index("Traffic Class")["Flows"]
    total = int(classes.sum())
    malicious = int(classes.get(config.CLASS_MALICIOUS, 0))
    return {
        "total": total,
        "benign": int(classes.get(config.CLASS_BENIGN, 0)),
        "malicious": malicious,
        "malicious_pct": pct(malicious, total),
        "attack_categories": len(attack_labels(df)),
        "features": report.feature_count,
    }


def generate_insights(df: pd.DataFrame, report: QualityReport) -> list[str]:
    """Plain-language observations computed from the data. Deterministic."""
    insights: list[str] = []
    kpi = overview_kpis(df, report)
    if kpi["total"] == 0:
        return ["No flows are available for analysis."]

    insights.append(
        f"{kpi['malicious_pct']:.1f}% of the {kpi['total']:,} recorded flows are labelled malicious "
        f"({kpi['malicious']:,} flows)."
    )
    labels = label_counts(df)
    top = labels.iloc[0]
    insights.append(f"The largest traffic category is {top['Label']} with {top['Flows']:,} flows ({top['Share (%)']:.1f}%).")

    attacks = attack_distribution(df)
    if not attacks.empty:
        a = attacks.iloc[0]
        if len(attacks) == 1:
            insights.append(f"{a['Attack Category']} is the only attack category present in the loaded data.")
        else:
            insights.append(
                f"{a['Attack Category']} is the most common attack, accounting for "
                f"{a['Share of Malicious (%)']:.1f}% of malicious flows."
            )

    if has_column(df, config.COL_DST_PORT) and kpi["malicious"]:
        mal = df.loc[df[config.CLASS_COLUMN] == config.CLASS_MALICIOUS, config.COL_DST_PORT]
        port_counts = mal.value_counts()
        if not port_counts.empty:
            port, n = port_counts.index[0], int(port_counts.iloc[0])
            insights.append(
                f"Destination port {int(port)} receives {pct(n, len(mal)):.1f}% of malicious flows."
            )

    if has_column(df, config.COL_DURATION):
        med = df.groupby(config.CLASS_COLUMN, observed=False)[config.COL_DURATION].median() / 1e6
        if med.notna().all() and len(med) == 2:
            insights.append(
                f"Median flow duration is {med[config.CLASS_BENIGN]:.2f} s for benign traffic and "
                f"{med[config.CLASS_MALICIOUS]:.2f} s for malicious traffic."
            )

    issues = report.missing_values + report.infinite_values
    insights.append(
        f"Data quality: {report.duplicate_rows:,} duplicate records "
        f"({pct(report.duplicate_rows, report.total_records):.2f}%) and {issues:,} missing or infinite values "
        f"(handled by median imputation inside the model pipeline)."
    )
    return insights


# ---------------------------------------------------------------- filtering
@dataclass
class FilterSpec:
    classes: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    duration_range_s: tuple[float, float] | None = None
    packet_range: tuple[int, int] | None = None


def total_packets(df: pd.DataFrame) -> pd.Series:
    fwd = df[config.COL_FWD_PACKETS] if config.COL_FWD_PACKETS in df.columns else 0
    bwd = df[config.COL_BWD_PACKETS] if config.COL_BWD_PACKETS in df.columns else 0
    return pd.Series(fwd, index=df.index).add(pd.Series(bwd, index=df.index), fill_value=0)


def apply_filters(df: pd.DataFrame, spec: FilterSpec) -> pd.DataFrame:
    """Return the rows matching every active filter (empty lists = no filter)."""
    mask = pd.Series(True, index=df.index)
    if spec.classes:
        mask &= df[config.CLASS_COLUMN].isin(spec.classes)
    if spec.labels:
        mask &= df[config.LABEL_COLUMN].astype("string").isin(spec.labels)
    if spec.ports and config.COL_DST_PORT in df.columns:
        mask &= df[config.COL_DST_PORT].isin(spec.ports)
    if spec.duration_range_s and config.COL_DURATION in df.columns:
        lo, hi = spec.duration_range_s
        seconds = df[config.COL_DURATION] / 1e6
        mask &= seconds.between(lo, hi)
    if spec.packet_range and {config.COL_FWD_PACKETS, config.COL_BWD_PACKETS} & set(df.columns):
        lo, hi = spec.packet_range
        mask &= total_packets(df).between(lo, hi)
    return df.loc[mask]


# ---------------------------------------------------------------- aggregates for charts
def top_ports(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Top destination ports with a benign/malicious breakdown."""
    if not has_column(df, config.COL_DST_PORT) or df.empty:
        return pd.DataFrame(columns=["Port", *CLASS_ORDER, "Total"])
    table = pd.crosstab(df[config.COL_DST_PORT], df[config.CLASS_COLUMN]).reindex(columns=CLASS_ORDER, fill_value=0)
    table["Total"] = table.sum(axis=1)
    table = table.sort_values("Total", ascending=False).head(n).reset_index()
    table = table.rename(columns={config.COL_DST_PORT: "Port"})
    table.columns.name = None
    table["Port"] = table["Port"].astype("int64")
    return table


def log_histogram(df: pd.DataFrame, column: str, scale: float = 1.0, bins: int = 40,
                  group_col: str = config.CLASS_COLUMN) -> pd.DataFrame:
    """Counts per log10-spaced bin, split by group.

    Network flow features are extremely skewed, so equal-width bins would put
    almost everything in one bar. Log-spaced bins keep every flow (nothing is
    clipped or sampled); zero values get their own '0' bin and negative values
    (recording artefacts in some CIC-IDS2017 files) are counted in a '-1' marker bin.
    """
    if df.empty or column not in df.columns:
        return pd.DataFrame(columns=["bin_left", "bin_right", "group", "count"])
    values = (df[column].astype("float64") / scale).to_numpy()
    groups = df[group_col].astype("string").to_numpy()
    finite = np.isfinite(values)
    values, groups = values[finite], groups[finite]
    positive = values[values > 0]
    if positive.size:
        lo, hi = np.log10(positive.min()), np.log10(positive.max())
        if hi - lo < 1e-9:
            hi = lo + 1
        edges = np.logspace(lo, hi, bins + 1)
        edges[0], edges[-1] = positive.min(), max(positive.max(), edges[-1])  # exact ends: no flow lost to rounding
    else:
        edges = np.array([0.0, 1.0])
    rows = []
    for g in pd.unique(groups):
        gv = values[groups == g]
        negatives = int((gv < 0).sum())
        if negatives:  # CIC-IDS2017 contains a few negative durations (recording artefacts)
            rows.append({"bin_left": -1.0, "bin_right": -1.0, "group": g, "count": negatives})
        zeros = int((gv == 0).sum())
        if zeros:
            rows.append({"bin_left": 0.0, "bin_right": 0.0, "group": g, "count": zeros})
        counts, _ = np.histogram(gv[gv > 0], bins=edges)
        rows.extend({"bin_left": float(edges[i]), "bin_right": float(edges[i + 1]), "group": g, "count": int(c)}
                    for i, c in enumerate(counts))
    return pd.DataFrame(rows)


def box_stats(df: pd.DataFrame, column: str, group_col: str = config.CLASS_COLUMN) -> pd.DataFrame:
    """Five-number summaries per group, computed on all rows (Tukey 1.5×IQR whiskers)."""
    if df.empty or column not in df.columns:
        return pd.DataFrame()
    rows = []
    for group, values in df.groupby(group_col, observed=True)[column]:
        v = values.replace([np.inf, -np.inf], np.nan).dropna().astype("float64")
        if v.empty:
            continue
        q1, med, q3 = v.quantile([0.25, 0.5, 0.75]).to_numpy()
        iqr = q3 - q1
        lower = v[v >= q1 - 1.5 * iqr].min()
        upper = v[v <= q3 + 1.5 * iqr].max()
        rows.append({
            "group": str(group), "n": int(v.size), "min": float(v.min()), "q1": float(q1), "median": float(med),
            "q3": float(q3), "lower_fence": float(lower), "upper_fence": float(upper),
            "max": float(v.max()), "mean": float(v.mean()),
            "outliers": int(((v < lower) | (v > upper)).sum()),
        })
    return pd.DataFrame(rows)


def packet_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Average forward/backward packets per flow for each class."""
    cols = [c for c in (config.COL_FWD_PACKETS, config.COL_BWD_PACKETS) if c in df.columns]
    if df.empty or not cols:
        return pd.DataFrame()
    out = df.groupby(config.CLASS_COLUMN, observed=True)[cols].mean().round(2)
    out["Flows"] = df.groupby(config.CLASS_COLUMN, observed=True).size()
    return out.reset_index().rename(columns={config.CLASS_COLUMN: "Traffic Class"})


def feature_profile(df: pd.DataFrame, columns: list[str], group_col: str = config.CLASS_COLUMN,
                    stat: str = "median") -> pd.DataFrame:
    """Median (or mean) of selected features per group, ready for a table."""
    cols = [c for c in columns if c in df.columns]
    if df.empty or not cols:
        return pd.DataFrame()
    grouped = df.groupby(group_col, observed=True)[cols]
    table = grouped.median() if stat == "median" else grouped.mean()
    return table.T.round(2)


def category_profile(df: pd.DataFrame, category: str) -> dict:
    """Key figures for one attack (or benign) label."""
    subset = df[df[config.LABEL_COLUMN].astype("string") == category]
    n = len(subset)
    info = {"category": category, "flows": n, "share_pct": pct(n, len(df))}
    if n and has_column(subset, config.COL_DST_PORT):
        ports = subset[config.COL_DST_PORT].value_counts()
        info["top_port"] = int(ports.index[0])
        info["top_port_share"] = pct(int(ports.iloc[0]), n)
        info["distinct_ports"] = int(ports.size)
    if n and has_column(subset, config.COL_DURATION):
        info["median_duration_s"] = float(subset[config.COL_DURATION].median() / 1e6)
    if n and {config.COL_FWD_PACKETS, config.COL_BWD_PACKETS} <= set(subset.columns):
        info["mean_fwd_packets"] = float(subset[config.COL_FWD_PACKETS].mean())
        info["mean_bwd_packets"] = float(subset[config.COL_BWD_PACKETS].mean())
    return info
