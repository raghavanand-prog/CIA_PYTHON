"""Design system: global CSS and small HTML components shared by all pages.

Inspired by Apple's dark "Pro" product pages:
  * a true-black canvas and soft graphite tiles with large radii, no hard borders,
  * very large, tightly tracked headlines with a champagne-gold gradient,
  * the system font (SF Pro on macOS, Inter elsewhere),
  * pill-shaped buttons and segmented tabs, generous whitespace, quiet motion.
"""

from __future__ import annotations

import html

import streamlit as st

from core import config

C = config.COLORS
GOLD_GRADIENT = "linear-gradient(100deg, #F6E7C8 0%, #E0BF83 38%, #B8925A 72%, #8C7356 100%)"

_CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:opsz,wght@14..32,400;14..32,500;14..32,600;14..32,700&display=swap');

:root {{
  --bg: {C['background']}; --tile: {C['surface']}; --tile-2: {C['elevated']};
  --line: {C['border']}; --line-soft: {C['border_soft']};
  --gold: {C['primary']}; --gold-soft: {C['primary_soft']};
  --text: {C['text']}; --text-2: {C['text_secondary']}; --text-3: {C['text_muted']};
  --benign: {C['benign']}; --malicious: {C['malicious']}; --warning: {C['warning']};
  --gold-grad: {GOLD_GRADIENT};
  --font: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Inter', 'Helvetica Neue', sans-serif;
  --ease: cubic-bezier(.28,.11,.32,1);
  --radius: 28px;
}}

html, body, .stApp, .stMarkdown, button, input, textarea, select, label, h1, h2, h3, h4, p, li {{
  font-family: var(--font) !important; -webkit-font-smoothing: antialiased; font-feature-settings: "cv11", "ss01";
}}
.stApp {{ background: var(--bg); }}
[data-testid="stHeader"] {{ background: rgba(0,0,0,0); }}
[data-testid="stMainBlockContainer"], .block-container {{ padding: 2.2rem 3rem 5rem; max-width: 1240px; }}
p, li {{ color: var(--text-2); }}
::selection {{ background: rgba(217,178,111,.35); }}
hr {{ border-color: var(--line-soft) !important; }}

@keyframes cpRise {{ from {{ opacity: 0; transform: translateY(18px); }} to {{ opacity: 1; transform: none; }} }}
.cp-anim {{ animation: cpRise .9s var(--ease) both; animation-delay: var(--d, 0ms); }}
@media (prefers-reduced-motion: reduce) {{ .cp-anim, [data-testid="stPlotlyChart"] {{ animation: none !important; }} }}

/* ---------------------------------------------------------------- sidebar */
[data-testid="stSidebar"] {{ background: rgba(22,22,23,.92); backdrop-filter: saturate(180%) blur(20px); border-right: 1px solid var(--line-soft); }}
[data-testid="stSidebarHeader"] {{ padding-bottom: .6rem; }}
[data-testid="stNavSectionHeader"], [data-testid="stSidebarNav"] header {{
  font-size: .68rem !important; font-weight: 600 !important; letter-spacing: .08em; text-transform: uppercase; color: var(--text-3) !important;
}}
[data-testid="stSidebarNavSeparator"] {{ border-color: var(--line-soft); }}
[data-testid="stSidebar"] [data-testid="stSidebarNavLink"] {{ border-radius: 10px; padding: .42rem .7rem; margin: 1px 0; transition: background .25s var(--ease); }}
[data-testid="stSidebar"] [data-testid="stSidebarNavLink"] span {{ color: var(--text-2); font-size: .92rem; letter-spacing: -.01em; }}
[data-testid="stSidebar"] [data-testid="stSidebarNavLink"]:hover {{ background: rgba(255,255,255,.05); }}
[data-testid="stSidebar"] [data-testid="stSidebarNavLink"][aria-current="page"] {{ background: rgba(255,255,255,.09); }}
[data-testid="stSidebar"] [data-testid="stSidebarNavLink"][aria-current="page"] span {{ color: var(--text); font-weight: 600; }}
[data-testid="stSidebarNavLink"] [data-testid="stIconMaterial"] {{ color: var(--text-3); }}
[data-testid="stSidebarNavLink"][aria-current="page"] [data-testid="stIconMaterial"] {{ color: var(--gold); }}

/* ---------------------------------------------------------------- controls */
.stButton > button, .stDownloadButton > button {{
  border-radius: 980px; border: 1px solid rgba(255,255,255,.16); background: transparent; color: var(--text);
  font-weight: 500; font-size: .95rem; padding: .55rem 1.35rem; letter-spacing: -.01em; transition: all .3s var(--ease);
}}
.stButton > button:hover, .stDownloadButton > button:hover {{ border-color: rgba(255,255,255,.4); background: rgba(255,255,255,.06); color: var(--text); }}
button[data-testid="stBaseButton-primary"] {{
  background: var(--text) !important; border: 1px solid var(--text) !important; border-radius: 980px !important;
}}
button[data-testid="stBaseButton-primary"] p {{ color: #000 !important; font-weight: 600; }}
button[data-testid="stBaseButton-primary"]:hover {{ background: #fff !important; transform: scale(1.02); }}
[data-baseweb="select"] > div, [data-baseweb="input"] > div, [data-testid="stNumberInputContainer"] {{
  border-radius: 12px !important; border-color: transparent !important; background: var(--tile-2) !important;
}}
[data-baseweb="select"] > div:hover, [data-baseweb="input"] > div:hover {{ border-color: var(--line) !important; }}
[data-baseweb="tag"] {{ background: rgba(217,178,111,.16) !important; border-radius: 980px !important; }}
[data-baseweb="tag"] span {{ color: var(--text) !important; }}
[data-testid="stWidgetLabel"] p {{ font-size: .82rem !important; color: var(--text-2) !important; font-weight: 500; letter-spacing: -.005em; }}
[data-testid="stExpander"], [data-testid="stExpander"] details {{ border: none !important; border-radius: 18px; background: var(--tile); }}
[data-testid="stExpander"] summary {{ border-radius: 18px; }}
[data-testid="stDataFrame"] {{ border-radius: 18px; overflow: hidden; border: 1px solid var(--line-soft); }}
[data-testid="stVerticalBlockBorderWrapper"] {{ border-radius: 24px !important; }}
div[data-testid="stVerticalBlock"]:has(> [data-testid="stElementContainer"] .cp-tile-marker) {{
  background: var(--tile); border-color: transparent !important; border-radius: var(--radius) !important; padding: 1.5rem 1.6rem !important;
}}
[data-testid="stElementContainer"]:has(.cp-tile-marker) {{ display: none; }}
[data-testid="stCaptionContainer"] p {{ color: var(--text-3); font-size: .8rem; }}

/* segmented tabs (Apple style) */
[data-testid="stTabs"] {{ margin-top: 2.2rem; }}
[data-testid="stTabs"] [role="tablist"] {{
  gap: 2px; background: var(--tile-2); border-radius: 980px; padding: 4px; width: fit-content; max-width: 100%;
  border: none !important; box-shadow: none !important; overflow-x: auto;
}}
[data-testid="stTabs"] [role="tablist"]::after, [data-testid="stTabs"] [role="tablist"] > div:not([role="tab"]) {{ display: none !important; }}
[data-testid="stTab"] {{
  border-radius: 980px !important; padding: .48rem 1.1rem !important; height: auto !important; margin: 0 !important;
  border: none !important; background: transparent; transition: background .35s var(--ease); white-space: nowrap;
}}
[data-testid="stTab"] p {{ color: var(--text-2) !important; font-weight: 500 !important; font-size: .9rem !important; }}
[data-testid="stTab"][aria-selected="true"] {{ background: #3A3A3C !important; box-shadow: 0 1px 6px rgba(0,0,0,.35); }}
[data-testid="stTab"][aria-selected="true"] p {{ color: var(--text) !important; }}
[data-testid="stTabs"] [role="tabpanel"] {{ padding-top: 1.8rem; }}
[data-testid="stSegmentedControl"] button, [data-testid="stButtonGroup"] button {{ border-radius: 980px !important; }}

/* charts as tiles */
[data-testid="stPlotlyChart"] {{
  background: var(--tile); border-radius: var(--radius); padding: .9rem .7rem .4rem;
  animation: cpRise .9s var(--ease) both;
}}

/* ---------------------------------------------------------------- page header */
.cp-header {{ text-align: center; padding: 2.6rem 1rem 2.4rem; margin-bottom: .6rem; }}
.cp-eyebrow {{ font-size: 1.05rem; font-weight: 600; color: var(--gold); letter-spacing: -.01em; margin-bottom: .55rem; }}
.cp-title {{
  font-size: clamp(2.5rem, 4.6vw, 4rem) !important; font-weight: 700 !important; line-height: 1.04 !important;
  letter-spacing: -.045em !important; margin: 0 auto .9rem !important; padding: 0 !important; max-width: 1080px;
  background: linear-gradient(180deg, #FFFFFF 30%, #B9B9BE 100%); -webkit-background-clip: text; background-clip: text; color: transparent !important;
}}
.cp-title em {{ font-style: normal; background: var(--gold-grad); -webkit-background-clip: text; background-clip: text; color: transparent; }}
.cp-subtitle {{ font-size: 1.22rem; line-height: 1.45; color: var(--text-2) !important; max-width: 720px; margin: 0 auto !important; letter-spacing: -.012em; font-weight: 400; }}
.cp-badges {{ display: flex; gap: .5rem; flex-wrap: wrap; justify-content: center; margin-top: 1.5rem; }}
.cp-badge {{ font-size: .78rem; color: var(--text-2); border-radius: 980px; padding: .32rem .85rem; background: var(--tile-2); letter-spacing: -.005em; }}
.cp-badge b {{ color: var(--text); font-weight: 600; }}
.cp-dot {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: .45rem; vertical-align: middle; }}

/* ---------------------------------------------------------------- bento tiles */
.cp-grid {{ display: grid; gap: 14px; grid-template-columns: repeat(var(--cols, 4), minmax(0, 1fr)); margin: .4rem 0 .6rem; }}
@media (max-width: 1100px) {{ .cp-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} }}
.cp-tile {{
  position: relative; background: var(--tile); border-radius: var(--radius); padding: 1.6rem 1.6rem 1.5rem; overflow: hidden;
  transition: transform .5s var(--ease), background .5s var(--ease);
}}
.cp-tile:hover {{ transform: scale(1.012); background: #1A1A1B; }}
.cp-kpi-label {{ font-size: .86rem; font-weight: 600; color: var(--text-2); letter-spacing: -.01em; display: flex; align-items: center; gap: .5rem; }}
.cp-kpi-value {{ font-size: 2.5rem; font-weight: 700; color: var(--text); letter-spacing: -.045em; line-height: 1.05; margin-top: .6rem; font-variant-numeric: tabular-nums; }}
.cp-kpi-value.gold {{ background: var(--gold-grad); -webkit-background-clip: text; background-clip: text; color: transparent; }}
.cp-kpi-caption {{ font-size: .84rem; color: var(--text-3); margin-top: .4rem; letter-spacing: -.01em; }}
.cp-kpi-bar {{ height: 4px; border-radius: 4px; background: rgba(255,255,255,.08); margin-top: 1rem; overflow: hidden; }}
.cp-kpi-bar span {{ display: block; height: 100%; border-radius: 4px; background: var(--tone); }}

/* hero tile */
.cp-hero {{ display: grid; grid-template-columns: 1.5fr 1fr; gap: 14px; margin: .4rem 0 14px; }}
@media (max-width: 1100px) {{ .cp-hero {{ grid-template-columns: 1fr; }} }}
.cp-hero-main {{
  background: radial-gradient(120% 140% at 100% 0%, rgba(217,178,111,.16) 0%, rgba(217,178,111,0) 55%), var(--tile);
  border-radius: var(--radius); padding: 2.4rem 2.4rem 2.1rem; display: flex; flex-direction: column; justify-content: center;
}}
.cp-hero-label {{ font-size: .95rem; font-weight: 600; color: var(--text-2); letter-spacing: -.01em; }}
.cp-hero-value {{
  font-size: clamp(4.5rem, 9vw, 7.4rem); font-weight: 700; letter-spacing: -.06em; line-height: .95; margin: .7rem 0 .8rem;
  background: var(--gold-grad); -webkit-background-clip: text; background-clip: text; color: transparent;
}}
.cp-hero-text {{ font-size: 1.08rem; color: var(--text-2); line-height: 1.5; max-width: 560px; letter-spacing: -.01em; }}
.cp-hero-text b {{ color: var(--text); font-weight: 600; }}
.cp-comp {{ display: flex; height: 10px; border-radius: 10px; overflow: hidden; margin: 1.8rem 0 .9rem; gap: 4px; }}
.cp-comp span {{ display: block; height: 100%; border-radius: 10px; }}
.cp-legend {{ display: flex; gap: 1.4rem; flex-wrap: wrap; font-size: .86rem; color: var(--text-2); }}
.cp-legend b {{ color: var(--text); font-weight: 600; margin-left: .3rem; }}
.cp-hero-side {{ display: grid; grid-template-rows: repeat(3, 1fr); gap: 14px; }}
.cp-hero-stat {{ background: var(--tile); border-radius: var(--radius); padding: 1.3rem 1.6rem; display: flex; flex-direction: column; justify-content: center; }}
.cp-hero-stat .k {{ font-size: .8rem; font-weight: 600; color: var(--text-3); letter-spacing: -.005em; }}
.cp-hero-stat .v {{ font-size: 1.65rem; color: var(--text); font-weight: 700; letter-spacing: -.035em; margin-top: .2rem; }}
.cp-hero-stat .c {{ font-size: .82rem; color: var(--text-2); margin-top: .1rem; }}

/* ---------------------------------------------------------------- sections */
.cp-section {{ margin: 4.2rem 0 1.4rem; max-width: 900px; }}
.cp-section-title {{
  font-size: clamp(1.9rem, 3.2vw, 2.6rem) !important; font-weight: 700 !important; letter-spacing: -.04em !important;
  line-height: 1.1 !important; color: var(--text) !important; margin: 0 !important; padding: 0 !important;
}}
.cp-section-title .muted {{ color: var(--text-3); }}
.cp-section-eyebrow {{ font-size: .9rem; font-weight: 600; color: var(--gold); margin-bottom: .5rem; letter-spacing: -.01em; }}
.cp-section-caption {{ font-size: 1.02rem; color: var(--text-2); margin: .7rem 0 0; line-height: 1.5; letter-spacing: -.01em; }}
.cp-panel-title {{ font-size: 1.15rem; font-weight: 650; color: var(--text); margin: 0 0 .2rem; letter-spacing: -.025em; }}
.cp-panel-caption {{ font-size: .85rem; color: var(--text-3); margin: 0 0 .8rem; }}

/* cards & lists */
.cp-card {{ background: var(--tile); border-radius: var(--radius); padding: 1.7rem 1.8rem; height: 100%; }}
.cp-card-title {{ font-size: 1.15rem; font-weight: 650; letter-spacing: -.025em; color: var(--text); margin-bottom: .8rem; }}
.cp-kv {{ display: flex; justify-content: space-between; gap: 1.2rem; padding: .75rem 0; border-bottom: 1px solid var(--line-soft); font-size: .94rem; letter-spacing: -.01em; }}
.cp-kv:last-child {{ border-bottom: none; padding-bottom: 0; }}
.cp-kv span:first-child {{ color: var(--text-2); }}
.cp-kv span:last-child {{ color: var(--text); font-weight: 500; text-align: right; font-variant-numeric: tabular-nums; }}
.cp-insight {{ display: flex; gap: 1rem; padding: .85rem 0; border-bottom: 1px solid var(--line-soft); font-size: .98rem; color: var(--text); line-height: 1.5; letter-spacing: -.012em; }}
.cp-insight:last-child {{ border-bottom: none; padding-bottom: 0; }}
.cp-insight-num {{ font-size: .8rem; font-weight: 700; color: var(--gold); padding-top: .18rem; min-width: 1.6rem; font-variant-numeric: tabular-nums; }}
.cp-callout {{ display: flex; gap: .9rem; align-items: flex-start; background: var(--tile); border-radius: 18px; padding: 1rem 1.25rem; font-size: .92rem; color: var(--text-2); line-height: 1.55; margin: .8rem 0 1rem; letter-spacing: -.01em; }}
.cp-callout::before {{ content: ""; flex: 0 0 8px; height: 8px; margin-top: .45rem; border-radius: 50%; background: var(--tone); box-shadow: 0 0 0 5px color-mix(in srgb, var(--tone) 18%, transparent); }}
.cp-callout b {{ color: var(--text); font-weight: 600; }}
.cp-empty {{ text-align: center; padding: 3.2rem 1rem; color: var(--text-2); font-size: 1rem; background: var(--tile); border-radius: var(--radius); letter-spacing: -.01em; }}

/* sidebar blocks */
.cp-brand {{ padding: .2rem 0 .9rem; }}
.cp-brand-name {{ font-weight: 650; color: var(--text); font-size: .92rem; letter-spacing: -.015em; }}
.cp-brand-sub {{ font-size: .72rem; color: var(--text-3); margin-top: .15rem; line-height: 1.45; }}
.cp-status {{ background: rgba(255,255,255,.04); border-radius: 16px; padding: .85rem 1rem; margin-top: .3rem; }}
.cp-status-row {{ display: flex; justify-content: space-between; font-size: .8rem; padding: .28rem 0; letter-spacing: -.01em; }}
.cp-status-row span:first-child {{ color: var(--text-3); }}
.cp-status-row span:last-child {{ color: var(--text); font-weight: 500; text-align: right; }}
.cp-footer {{ font-size: .72rem; color: var(--text-3); margin-top: 1.1rem; line-height: 1.6; }}
.cp-footer b {{ color: var(--text-2); font-weight: 600; }}
</style>
"""

TONES = {
    "primary": C["primary"],
    "benign": C["benign"],
    "malicious": C["malicious"],
    "warning": C["warning"],
    "neutral": C["neutral"],
}


def esc(text: object) -> str:
    return html.escape(str(text))


def apply_theme() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)


def page_header(eyebrow: str, title: str, subtitle: str, badges: list[tuple[str, str]] | None = None) -> None:
    """Centred Apple-style hero header.

    In ``title`` the text between ``*asterisks*`` is rendered with the gold gradient.
    """
    safe_title = esc(title)
    parts = safe_title.split("*")
    title_html = "".join(f"<em>{p}</em>" if i % 2 else p for i, p in enumerate(parts))
    pills = [("", "Offline analysis · recorded traffic")] + list(badges or [])
    badge_html = "".join(
        f'<span class="cp-badge">{esc(k)} <b>{esc(v)}</b></span>' if k else f'<span class="cp-badge">{esc(v)}</span>'
        for k, v in pills
    )
    st.markdown(
        f'<div class="cp-header cp-anim"><div class="cp-eyebrow">{esc(eyebrow)}</div>'
        f'<h1 class="cp-title">{title_html}</h1><p class="cp-subtitle">{esc(subtitle)}</p>'
        f'<div class="cp-badges">{badge_html}</div></div>',
        unsafe_allow_html=True,
    )


def kpi_card(label: str, value: str, caption: str = "", tone: str = "neutral",
             share: float | None = None, delay: int = 0, gold: bool = False) -> str:
    """One bento tile. ``share`` (0-100) draws a thin proportion bar; ``gold`` uses the gradient figure."""
    color = TONES.get(tone, C["neutral"])
    dot = f'<span class="cp-dot" style="background:{color};margin:0"></span>'
    cap = f'<div class="cp-kpi-caption">{esc(caption)}</div>' if caption else ""
    bar = (f'<div class="cp-kpi-bar"><span style="width:{max(0.0, min(100.0, share)):.2f}%"></span></div>'
           if share is not None else "")
    value_cls = "cp-kpi-value gold" if gold else "cp-kpi-value"
    return (f'<div class="cp-tile cp-anim" style="--tone:{color};--d:{delay}ms">'
            f'<div class="cp-kpi-label">{dot}{esc(label)}</div>'
            f'<div class="{value_cls}">{esc(value)}</div>{cap}{bar}</div>')


def kpi_row(cards: list[dict], columns: int | None = None) -> None:
    """Bento grid of KPI tiles. Each dict: label, value, caption?, tone?, share?, gold?"""
    cols = columns or min(len(cards), 4)
    tiles = "".join(kpi_card(**card, delay=i * 70) for i, card in enumerate(cards))
    st.markdown(f'<div class="cp-grid" style="--cols:{cols}">{tiles}</div>', unsafe_allow_html=True)


def posture_hero(total: int, benign: int, malicious: int, side_stats: list[tuple[str, str, str]],
                 segments: list[tuple[str, int, str]] | None = None) -> None:
    """Large hero tile with the malicious share, a composition bar and three side tiles."""
    share = malicious / total * 100 if total else 0.0
    segments = segments or [("Benign", benign, C["benign"]), ("Malicious", malicious, C["malicious"])]
    bar = "".join(f'<span title="{esc(n)}: {c:,}" style="flex:{max(c, 0)};background:{col}"></span>'
                  for n, c, col in segments if c > 0)
    legend = "".join(f'<span><span class="cp-dot" style="background:{col}"></span>{esc(n)}'
                     f'<b>{c / total * 100 if total else 0:.1f}%</b></span>' for n, c, col in segments)
    side = "".join(f'<div class="cp-hero-stat cp-anim" style="--d:{120 + i * 90}ms"><span class="k">{esc(k)}</span>'
                   f'<span class="v">{esc(v)}</span><span class="c">{esc(c)}</span></div>'
                   for i, (k, v, c) in enumerate(side_stats))
    st.markdown(
        f'<div class="cp-hero"><div class="cp-hero-main cp-anim">'
        f'<div class="cp-hero-label">Malicious share of recorded traffic</div>'
        f'<div class="cp-hero-value">{share:.1f}%</div>'
        f'<div class="cp-hero-text"><b>{malicious:,}</b> of {total:,} network flows in the analysed capture carry an '
        f'attack label. <b>{benign:,}</b> are benign.</div>'
        f'<div class="cp-comp">{bar}</div><div class="cp-legend">{legend}</div></div>'
        f'<div class="cp-hero-side">{side}</div></div>',
        unsafe_allow_html=True,
    )


def section(title: str, caption: str = "", index: int | None = None) -> None:
    """Apple-style section headline: white statement, optional grey follow-on.

    Short captions continue the headline in grey; longer ones become a paragraph.
    """
    eyebrow = f'<div class="cp-section-eyebrow">{index:02d}</div>' if index is not None else ""
    if caption and len(caption) <= 64:
        heading = f'{esc(title)}. <span class="muted">{esc(caption)}</span>'
        para = ""
    else:
        heading = esc(title) + "."
        para = f'<p class="cp-section-caption">{esc(caption)}</p>' if caption else ""
    st.markdown(f'<div class="cp-section cp-anim">{eyebrow}<h2 class="cp-section-title">{heading}</h2>{para}</div>',
                unsafe_allow_html=True)


def panel_title(title: str, caption: str = "") -> None:
    cap = f'<p class="cp-panel-caption">{esc(caption)}</p>' if caption else ""
    st.markdown(f'<p class="cp-panel-title">{esc(title)}</p>{cap}', unsafe_allow_html=True)


def key_value_card(title: str, rows: list[tuple[str, str]]) -> None:
    body = "".join(f'<div class="cp-kv"><span>{esc(k)}</span><span>{esc(v)}</span></div>' for k, v in rows)
    st.markdown(f'<div class="cp-card cp-anim"><div class="cp-card-title">{esc(title)}</div>{body}</div>',
                unsafe_allow_html=True)


def insight_list(title: str, items: list[str]) -> None:
    body = "".join(
        f'<div class="cp-insight"><span class="cp-insight-num">{i:02d}</span><span>{esc(t)}</span></div>'
        for i, t in enumerate(items, 1)
    )
    st.markdown(f'<div class="cp-card cp-anim"><div class="cp-card-title">{esc(title)}</div>{body}</div>',
                unsafe_allow_html=True)


def callout(text: str, tone: str = "primary", bold_prefix: str = "") -> None:
    color = TONES.get(tone, C["primary"])
    prefix = f"<b>{esc(bold_prefix)}</b> " if bold_prefix else ""
    st.markdown(f'<div class="cp-callout" style="--tone:{color}"><div>{prefix}{esc(text)}</div></div>',
                unsafe_allow_html=True)


def tile():
    """A bordered Streamlit container restyled as a borderless rounded tile.

    Usage:  with tile(): st.button(...)
    """
    box = st.container(border=True)
    box.markdown('<span class="cp-tile-marker"></span>', unsafe_allow_html=True)
    return box


def empty_state(message: str) -> None:
    st.markdown(f'<div class="cp-empty">{esc(message)}</div>', unsafe_allow_html=True)


def sidebar_brand() -> None:
    """University block shown under the navigation (emblem used when the asset exists)."""
    text = ('<div class="cp-brand-name">CHRIST University</div>'
            '<div class="cp-brand-sub">Deemed to be University<br>Bengaluru, India</div>')
    if config.EMBLEM_PATH.exists():
        left, right = st.sidebar.columns([1, 3.2], vertical_alignment="center")
        left.image(str(config.EMBLEM_PATH), width=44)
        right.markdown(text, unsafe_allow_html=True)
    else:
        st.sidebar.markdown(f'<div class="cp-brand">{text}</div>', unsafe_allow_html=True)


def sidebar_status(rows: list[tuple[str, str, str | None]]) -> None:
    """Status rows: (label, value, dot colour or None)."""
    body = ""
    for label, value, dot in rows:
        dot_html = f'<span class="cp-dot" style="background:{dot}"></span>' if dot else ""
        body += f'<div class="cp-status-row"><span>{esc(label)}</span><span>{dot_html}{esc(value)}</span></div>'
    st.sidebar.markdown(f'<div class="cp-status">{body}</div>', unsafe_allow_html=True)


def sidebar_footer() -> None:
    st.sidebar.markdown(
        f'<div class="cp-footer"><b>{esc(config.APP_NAME)}</b> · v{esc(config.APP_VERSION)}<br>'
        f'MCA · Python CIA-3<br>Developed by <b>{esc(config.DEVELOPER)}</b><br>'
        f'{esc(config.ANALYSIS_MODE)}. Not live monitoring.</div>',
        unsafe_allow_html=True,
    )
