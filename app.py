"""CHRIST CyberPulse — application entry point.

Run with:  streamlit run app.py

This file only sets up the page, theme, sidebar and navigation. Each module
lives in its own file under views/ and shares data through utils.helpers.
"""

from __future__ import annotations

import streamlit as st

from core import config
from utils import helpers
from utils.styling import apply_theme, sidebar_brand, sidebar_footer, sidebar_status

st.set_page_config(
    page_title=config.APP_NAME,
    page_icon=str(config.ICON_PATH) if config.ICON_PATH.exists() else ":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)
apply_theme()

if config.LOGO_PATH.exists():
    st.logo(str(config.LOGO_PATH), size="large", icon_image=str(config.ICON_PATH))

pages = {
    "Analytics": [
        st.Page("views/01_Security_Overview.py", title="Security Overview", icon=":material/space_dashboard:", default=True),
        st.Page("views/02_Network_Analytics.py", title="Network Analytics", icon=":material/lan:"),
        st.Page("views/04_Attack_Analysis.py", title="Attack Analysis", icon=":material/policy:"),
    ],
    "Intelligence": [
        st.Page("views/03_AI_Threat_Detection.py", title="AI Threat Detection", icon=":material/neurology:"),
    ],
    "Output": [
        st.Page("views/05_Reports.py", title="Security Reports", icon=":material/description:"),
    ],
}
navigation = st.navigation(pages)

# ---------------------------------------------------------------- sidebar
sidebar_brand()
C = config.COLORS
try:
    handle = helpers.get_dataset()
except Exception:
    handle = None
model, _ = helpers.get_model()

if handle is not None:
    files = handle.report.source_files
    status_rows = [
        ("Dataset", config.DATASET_NAME, C["primary"]),
        ("Source", "Uploaded" if handle.source == "upload" else "Local", None),
        ("Flows", f"{handle.report.total_records:,}", None),
    ]
else:
    status_rows = [("Dataset", "Not loaded", C["warning"])]
status_rows.append(("Model", "Random Forest ready" if model else "Not trained",
                    C["primary"] if model else C["warning"]))
status_rows.append(("Mode", "Offline analysis", None))
sidebar_status(status_rows)
if st.session_state.get(helpers.UPLOAD_KEY):
    if st.sidebar.button("Use local dataset instead", width="stretch"):
        st.session_state.pop(helpers.UPLOAD_KEY, None)
        st.rerun()

sidebar_footer()

navigation.run()
