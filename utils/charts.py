"""Plotly chart builders with one consistent visual style.

Every function returns a ``go.Figure`` and accepts already-aggregated data
from :mod:`core.analytics`, so charts never sample or alter the data.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import plotly.graph_objects as go

from core import config

C = config.COLORS
FONT = "-apple-system, BlinkMacSystemFont, SF Pro Text, Inter, Helvetica Neue, sans-serif"
HEAD_FONT = "-apple-system, BlinkMacSystemFont, SF Pro Display, Inter, Helvetica Neue, sans-serif"
MONO_FONT = FONT  # tabular figures come from the system font
CLASS_COLORS = {config.CLASS_BENIGN: C["benign"], config.CLASS_MALICIOUS: C["malicious"]}
PLOTLY_CONFIG = {"displaylogo": False, "modeBarButtonsToRemove": ["lasso2d", "select2d", "autoScale2d"]}


def label_colors(labels: list[str]) -> list[str]:
    """Stable colours: BENIGN is green, attacks take the palette in the order given
    (pages pass labels sorted by flow count, so the largest attack is always red)."""
    out, i = [], 0
    for label in labels:
        if str(label) in CLASS_COLORS or str(label).upper() == config.BENIGN_LABEL:
            out.append(color_for(str(label)))
        else:
            out.append(config.CATEGORY_PALETTE[i % len(config.CATEGORY_PALETTE)])
            i += 1
    return out


def color_for(group: str, index: int = 0) -> str:
    if group in CLASS_COLORS:
        return CLASS_COLORS[group]
    if str(group).upper() == config.BENIGN_LABEL:
        return C["benign"]
    return config.CATEGORY_PALETTE[index % len(config.CATEGORY_PALETTE)]


def style(fig: go.Figure, title: str = "", height: int = 360, legend: bool = True,
          x_title: str | None = None, y_title: str | None = None) -> go.Figure:
    """Apply the shared CyberPulse look to a figure."""
    fig.update_layout(
        title=dict(text=title, x=0.02, y=0.97, xanchor="left",
                   font=dict(size=18, color=C["text"], family=HEAD_FONT, weight=650)),
        height=height,
        margin=dict(l=18, r=18, t=64 if title else 22, b=18),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT, size=12, color=C["text_secondary"]),
        showlegend=legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.0, xanchor="right", x=1,
                    bgcolor="rgba(0,0,0,0)", font=dict(size=11, color=C["text_secondary"])),
        hoverlabel=dict(bgcolor=C["elevated"], bordercolor=C["primary_soft"], font=dict(family=FONT, color=C["text"], size=12)),
        bargap=0.32,
        barcornerradius=6,
    )
    axis = dict(gridcolor=C["border_soft"], zerolinecolor=C["border"], linecolor=C["border"], 
                tickfont=dict(size=11, color=C["text_muted"], family=MONO_FONT), title_font=dict(size=12, color=C["text_secondary"]))
    fig.update_xaxes(**axis)
    fig.update_yaxes(**axis)
    if x_title is not None:
        fig.update_xaxes(title_text=x_title)
    if y_title is not None:
        fig.update_yaxes(title_text=y_title)
    return fig


def empty_figure(message: str = "No records match the current selection.", height: int = 300) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=message, showarrow=False, font=dict(size=13, color=C["text_muted"]),
                       xref="paper", yref="paper", x=0.5, y=0.5)
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return style(fig, height=height, legend=False)


def donut(labels: list[str], values: list[int], title: str = "", center_label: str = "flows",
          colors: list[str] | None = None, height: int = 340) -> go.Figure:
    total = int(sum(values))
    if total == 0:
        return empty_figure(height=height)
    colors = colors or [color_for(lbl, i) for i, lbl in enumerate(labels)]
    fig = go.Figure(go.Pie(
        labels=labels, values=values, hole=0.72, sort=False, direction="clockwise",
        marker=dict(colors=colors, line=dict(color=C["surface"], width=5)),
        textinfo="percent", textfont=dict(size=12, color=C["text"]),
        hovertemplate="<b>%{label}</b><br>%{value:,} flows<br>%{percent:.2%}<extra></extra>",
    ))
    fig.add_annotation(text=f"<span style='font-size:24px;color:{C['text']}'>{total:,}</span><br>"
                            f"<span style='font-size:11px;color:{C['text_muted']}'>{center_label.upper()}</span>",
                       showarrow=False, x=0.5, y=0.5, font=dict(family=MONO_FONT, color=C["text_secondary"]))
    fig = style(fig, title, height)
    fig.update_layout(legend=dict(orientation="h", y=-0.05, x=0.5, xanchor="center", yanchor="top"))
    return fig


def horizontal_bar(df: pd.DataFrame, value_col: str, label_col: str, title: str = "",
                   color_col: str | None = None, value_title: str = "Flows", height: int | None = None,
                   share_col: str | None = None) -> go.Figure:
    if df.empty:
        return empty_figure()
    ranked = df.sort_values(value_col, ascending=False)
    color_map = dict(zip(ranked[color_col].astype(str), label_colors(ranked[color_col].astype(str).tolist()))) \
        if color_col else {}
    data = df.sort_values(value_col, ascending=True)
    colors = [color_map[str(v)] for v in data[color_col]] if color_col else [C["primary"]] * len(data)
    custom = data[share_col].to_numpy() if share_col else np.zeros(len(data))
    hover = "<b>%{y}</b><br>%{x:,} " + value_title.lower()
    if share_col:
        hover += "<br>%{customdata:.2f}% of total"
    fig = go.Figure(go.Bar(
        x=data[value_col], y=data[label_col].astype(str), orientation="h",
        marker=dict(color=colors, line=dict(width=0)), customdata=custom,
        text=[f"{v:,.0f}" for v in data[value_col]], textposition="outside", cliponaxis=False,
        textfont=dict(size=11, color=C["text_secondary"]),
        hovertemplate=hover + "<extra></extra>",
    ))
    height = height or max(220, 60 + 42 * len(data))
    fig = style(fig, title, height, legend=False, x_title=value_title)
    fig.update_xaxes(range=[0, float(data[value_col].max()) * 1.14])
    fig.update_yaxes(gridcolor="rgba(0,0,0,0)", automargin=True)
    return fig


def stacked_ports(table: pd.DataFrame, title: str = "Top destination ports") -> go.Figure:
    """Horizontal stacked bars: benign vs malicious flows per port."""
    if table.empty:
        return empty_figure()
    data = table.sort_values("Total", ascending=True)
    labels = [f"Port {p}" for p in data["Port"]]
    fig = go.Figure()
    for cls in (config.CLASS_BENIGN, config.CLASS_MALICIOUS):
        if cls in data.columns:
            share = np.where(data["Total"] > 0, data[cls] / data["Total"] * 100, 0)
            fig.add_bar(y=labels, x=data[cls], name=cls, orientation="h", marker_color=CLASS_COLORS[cls],
                        customdata=share,
                        hovertemplate=f"<b>%{{y}}</b><br>{cls}: %{{x:,}} flows (%{{customdata:.1f}}% of port)<extra></extra>")
    fig = style(fig, title, max(260, 70 + 36 * len(data)), x_title="Flows")
    fig.update_layout(barmode="stack")
    fig.update_yaxes(gridcolor="rgba(0,0,0,0)", automargin=True)
    return fig


def log_distribution(hist: pd.DataFrame, title: str, x_title: str, unit: str = "") -> go.Figure:
    """Step-area histogram on a log x-axis (from analytics.log_histogram)."""
    if hist.empty or hist["count"].sum() == 0:
        return empty_figure()
    fig = go.Figure()
    zero_notes = []
    groups = list(dict.fromkeys(hist["group"].astype(str)))
    palette = dict(zip(groups, label_colors(groups)))
    for group, part in hist.groupby("group", sort=False):
        zeros = int(part.loc[part["bin_right"] == 0, "count"].sum())
        negatives = int(part.loc[part["bin_right"] < 0, "count"].sum())
        part = part[part["bin_right"] > 0].sort_values("bin_left")
        if zeros:
            zero_notes.append(f"{group}: {zeros:,} at zero")
        if negatives:
            zero_notes.append(f"{group}: {negatives:,} negative")
        if part.empty:
            continue
        color = palette[str(group)]
        x = np.append(part["bin_left"].to_numpy(), part["bin_right"].to_numpy()[-1])
        y = np.append(part["count"].to_numpy(), part["count"].to_numpy()[-1])
        custom = np.column_stack([np.append(part["bin_left"], part["bin_left"].iloc[-1]),
                                  np.append(part["bin_right"], part["bin_right"].iloc[-1])])
        fig.add_scatter(
            x=x, y=y, name=str(group), mode="lines", line=dict(color=color, width=1.6, shape="hv"),
            fill="tozeroy", fillcolor=_rgba(color, 0.18), customdata=custom,
            hovertemplate=f"<b>{group}</b><br>%{{customdata[0]:,.4g}} – %{{customdata[1]:,.4g}} {unit}"
                          "<br>%{y:,} flows<extra></extra>",
        )
    fig = style(fig, title, 340, x_title=x_title, y_title="Flows")
    fig.update_xaxes(type="log", dtick=1)
    if zero_notes:
        fig.add_annotation(text=" · ".join(zero_notes) + " (not shown on log axis)", showarrow=False,
                           xref="paper", yref="paper", x=0, y=-0.31, xanchor="left",
                           font=dict(size=10, color=C["text_muted"]))
        fig.update_layout(margin=dict(b=58))
    return fig


def box_from_stats(stats: pd.DataFrame, title: str, y_title: str, log: bool = True) -> go.Figure:
    """Box plot drawn from pre-computed quartiles (all rows, no sampling)."""
    if stats.empty:
        return empty_figure()
    fig = go.Figure()
    palette = dict(zip(stats["group"], label_colors(stats["group"].tolist())))
    for _, row in stats.reset_index(drop=True).iterrows():
        color = palette[row["group"]]
        floor = 1e-3 if log else None
        def clip(v):  # log axes cannot show zero
            return max(v, floor) if floor else v
        fig.add_trace(go.Box(
            name=row["group"], x=[row["group"]],
            q1=[clip(row["q1"])], median=[clip(row["median"])], q3=[clip(row["q3"])],
            lowerfence=[clip(row["lower_fence"])], upperfence=[clip(row["upper_fence"])], mean=[clip(row["mean"])],
            marker_color=color, fillcolor=_rgba(color, 0.22), line=dict(color=color, width=1.5),
            boxpoints=False,
            hovertemplate=(f"<b>{row['group']}</b><br>median {row['median']:,.4g}<br>"
                           f"Q1 {row['q1']:,.4g} · Q3 {row['q3']:,.4g}<br>mean {row['mean']:,.4g}<br>"
                           f"max {row['max']:,.4g}<br>{row['outliers']:,} outliers beyond whiskers"
                           f"<br>n = {row['n']:,}<extra></extra>"),
        ))
    fig = style(fig, title, 340, legend=False, y_title=y_title)
    if log:
        fig.update_yaxes(type="log", dtick=1)
    return fig


def grouped_bar(df: pd.DataFrame, category_col: str, value_cols: list[str], title: str,
                y_title: str, colors: list[str] | None = None) -> go.Figure:
    if df.empty:
        return empty_figure()
    colors = colors or [C["primary"], C["neutral"], C["warning"]]
    fig = go.Figure()
    for col, color in zip(value_cols, colors):
        fig.add_bar(x=df[category_col].astype(str), y=df[col], name=col, marker_color=color,
                    hovertemplate=f"<b>%{{x}}</b><br>{col}: %{{y:,.2f}}<extra></extra>")
    fig = style(fig, title, 340, y_title=y_title)
    fig.update_layout(barmode="group")
    return fig


def confusion_heatmap(cm: list[list[int]], labels: list[str], title: str = "Confusion matrix") -> go.Figure:
    z = np.asarray(cm)
    row_totals = z.sum(axis=1, keepdims=True)
    share = np.divide(z, row_totals, out=np.zeros_like(z, dtype=float), where=row_totals > 0) * 100
    text = [[f"<b>{z[i, j]:,}</b><br>{share[i, j]:.2f}%" for j in range(z.shape[1])] for i in range(z.shape[0])]
    fig = go.Figure(go.Heatmap(
        z=share, x=[f"Predicted {l}" for l in labels], y=[f"Actual {l}" for l in labels],
        text=text, texttemplate="%{text}", textfont=dict(size=13, color=C["text"], family=MONO_FONT),
        colorscale=[[0, "#1D1D1F"], [0.4, "#3B3122"], [1, "#9E7C45"]],
        showscale=False, xgap=3, ygap=3, customdata=z,
        hovertemplate="%{y} → %{x}<br>%{customdata:,} flows (%{z:.2f}% of actual class)<extra></extra>",
    ))
    fig = style(fig, title, 330, legend=False)
    fig.update_yaxes(autorange="reversed", gridcolor="rgba(0,0,0,0)")
    fig.update_xaxes(side="top", gridcolor="rgba(0,0,0,0)")
    return fig


def feature_importance(fi: list[dict], top_n: int = 15) -> go.Figure:
    if not fi:
        return empty_figure("Feature importance is not available.")
    df = pd.DataFrame(fi[:top_n])
    df["pct"] = df["importance"] * 100
    df = df.sort_values("pct")
    fig = go.Figure(go.Bar(
        x=df["pct"], y=df["feature"], orientation="h",
        marker=dict(color=df["pct"], colorscale=[[0, "#4A3E2A"], [1, C["primary"]]], line=dict(width=0), cornerradius=6),
        text=[f"{v:.1f}%" for v in df["pct"]], textposition="outside", cliponaxis=False,
        textfont=dict(size=11, color=C["text_secondary"]),
        hovertemplate="<b>%{y}</b><br>Mean decrease in impurity: %{x:.2f}%<extra></extra>",
    ))
    fig = style(fig, f"Top {len(df)} features by Random Forest importance", 60 + 30 * len(df),
                legend=False, x_title="Relative importance (%)")
    fig.update_xaxes(range=[0, float(df["pct"].max()) * 1.15])
    fig.update_yaxes(gridcolor="rgba(0,0,0,0)", automargin=True)
    return fig


def metric_comparison(rows: list[dict], title: str) -> go.Figure:
    """Grouped bars comparing evaluation strategies. rows: name + metric values (0-1)."""
    if not rows:
        return empty_figure()
    metrics = ["accuracy", "precision", "recall", "f1"]
    colors = ["#48484A", C["primary"]]
    fig = go.Figure()
    for row, color in zip(rows, colors):
        fig.add_bar(x=[m.upper() if m == "f1" else m.title() for m in metrics],
                    y=[row[m] * 100 for m in metrics], name=row["name"], marker_color=color,
                    text=[f"{row[m] * 100:.2f}" for m in metrics], textposition="outside",
                    textfont=dict(size=10, color=C["text_secondary"]), cliponaxis=False,
                    hovertemplate=f"<b>{row['name']}</b><br>%{{x}}: %{{y:.4f}}%<extra></extra>")
    lows = [row[m] * 100 for row in rows for m in metrics]
    fig = style(fig, title, 330, y_title="Score (%)")
    fig.update_layout(barmode="group")
    fig.update_yaxes(range=[max(0, min(lows) - 2), 100.6])
    return fig


def _rgba(hex_color: str, alpha: float) -> str:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{alpha})"
