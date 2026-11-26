"""Central configuration: paths, dataset constants and design tokens.

Everything that more than one module needs to agree on lives here, so the
pages, the training script and the tests all share one definition.
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------- paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("CYBERPULSE_DATA_DIR", PROJECT_ROOT / "data" / "sample_data"))
ASSETS_DIR = PROJECT_ROOT / "assets"
EMBLEM_PATH = ASSETS_DIR / "christ-emblem.png"
LOGO_PATH = ASSETS_DIR / "cyberpulse-logo.png"
ICON_PATH = ASSETS_DIR / "cyberpulse-icon.png"
ARTIFACTS_DIR = Path(os.environ.get("CYBERPULSE_ARTIFACTS_DIR", PROJECT_ROOT / "models" / "artifacts"))

MODEL_FILE = ARTIFACTS_DIR / "cyberpulse_random_forest.joblib"
SCHEMA_FILE = ARTIFACTS_DIR / "feature_schema.json"
METRICS_FILE = ARTIFACTS_DIR / "evaluation_metrics.json"
TEST_IDS_FILE = ARTIFACTS_DIR / "test_row_ids.npy"

# ---------------------------------------------------------------- app info
APP_NAME = "CHRIST CyberPulse"
APP_TITLE = "Smart Network Traffic Analysis & AI-Powered Cyber Threat Detection Dashboard"
APP_VERSION = "2.0.0"
INSTITUTION = "CHRIST (Deemed to be University), Bengaluru"
COURSE = "Master of Computer Applications (MCA) · Python CIA-3"
DEVELOPER = "Raghav Anand"
DATASET_NAME = "CIC-IDS2017"
ANALYSIS_MODE = "Offline analysis of recorded network flows"

# ---------------------------------------------------------------- dataset
LABEL_COLUMN = "Label"
BENIGN_LABEL = "BENIGN"
ROW_ID_COLUMN = "row_id"
CLASS_COLUMN = "Traffic Class"  # derived: "Benign" / "Malicious"
CLASS_BENIGN = "Benign"
CLASS_MALICIOUS = "Malicious"

# Columns that identify a specific flow/host/time. If a CIC-IDS2017 variant
# contains them they are never used as model inputs: they would let the model
# memorise the capture instead of learning traffic behaviour.
IDENTIFIER_COLUMNS = {
    "Flow ID",
    "Source IP",
    "Src IP",
    "Destination IP",
    "Dst IP",
    "Source Port",
    "Src Port",
    "Timestamp",
}

# Friendly names for the flow columns the dashboard talks about most.
COL_DST_PORT = "Destination Port"
COL_DURATION = "Flow Duration"            # microseconds in CIC-IDS2017
COL_FWD_PACKETS = "Total Fwd Packets"
COL_BWD_PACKETS = "Total Backward Packets"
COL_BYTES_PER_S = "Flow Bytes/s"
COL_PACKETS_PER_S = "Flow Packets/s"
COL_PROTOCOL = "Protocol"
PACKET_LENGTH_COLUMNS = [
    "Packet Length Mean",
    "Packet Length Std",
    "Max Packet Length",
    "Min Packet Length",
    "Average Packet Size",
]
PREDICTION_TABLE_COLUMNS = [COL_DST_PORT, COL_DURATION, COL_FWD_PACKETS, COL_BWD_PACKETS]

# ---------------------------------------------------------------- model
RANDOM_STATE = 42
TEST_SIZE = 0.20
RF_PARAMS = {
    "n_estimators": 150,
    "max_depth": 24,
    "min_samples_leaf": 2,
    "class_weight": "balanced",
    "n_jobs": -1,
    "random_state": RANDOM_STATE,
}

# ---------------------------------------------------------------- design tokens
# Apple-inspired "Pro" dark theme: true-black canvas, soft graphite tiles,
# champagne-gold accent, muted semantic colours. No blue anywhere.
COLORS = {
    "background": "#000000",
    "surface": "#161617",
    "elevated": "#1D1D1F",
    "border": "#2C2C2E",
    "border_soft": "#232325",
    "primary": "#D9B26F",
    "primary_soft": "#8F7444",
    "primary_glow": "rgba(217,178,111,0.12)",
    "text": "#F5F5F7",
    "text_secondary": "#A1A1A6",
    "text_muted": "#6E6E73",
    "benign": "#8CCBA4",
    "malicious": "#F07463",
    "warning": "#F2A85C",
    "neutral": "#8E8E93",
}

# Attack categories, largest first (coral, gold, mauve, sand, copper, ...).
CATEGORY_PALETTE = [
    "#F07463", "#D9B26F", "#C49BC0", "#CFC09A", "#D99266",
    "#A9B97A", "#E3A3B1", "#A8A29A", "#CFA67E", "#9CC3B4",
]
