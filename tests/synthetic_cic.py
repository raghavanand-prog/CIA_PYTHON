"""Small synthetic CIC-IDS2017-shaped frames for automated tests ONLY.

The values are random and carry no meaning; they exist so the tests can run
without the real 70 MB dataset. The dashboard never displays this data.
The column names (including stray leading spaces and the duplicated
'Fwd Header Length' column) mirror the real CIC-IDS2017 CSV layout.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

CIC_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
    "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean",
    "Idle Std", "Idle Max", "Idle Min",
]


def make_cic_frame(n: int = 2000, seed: int = 0, attack_label: str = "DDoS",
                   attack_share: float = 0.55, duplicates: int = 20) -> pd.DataFrame:
    """Return a raw (uncleaned) frame laid out like a CIC-IDS2017 CSV."""
    rng = np.random.default_rng(seed)
    malicious = rng.random(n) < attack_share
    data = {c: rng.gamma(1.5, 50, n) for c in CIC_COLUMNS}

    data["Destination Port"] = np.where(
        malicious, rng.choice([80, 80, 80, 443], n), rng.choice([53, 443, 80, 8080, 22, 123], n)
    ).astype(int)
    data["Flow Duration"] = np.where(malicious, rng.lognormal(13, 2, n), rng.lognormal(11, 3, n)).astype(np.int64)
    data["Total Fwd Packets"] = np.where(malicious, rng.poisson(4, n), rng.poisson(8, n)) + 1
    data["Total Backward Packets"] = np.where(malicious, rng.poisson(3, n), rng.poisson(7, n))
    data["Fwd Header Length.1"] = data["Fwd Header Length"]
    for c in ("Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
              "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Bwd PSH Flags"):
        data[c] = np.zeros(n)
    data["Packet Length Mean"] = np.where(malicious, rng.normal(900, 300, n), rng.normal(300, 200, n)).clip(0)
    data["Flow Bytes/s"] = rng.lognormal(8, 3, n)
    data["Flow Packets/s"] = rng.lognormal(4, 2, n)

    df = pd.DataFrame(data)
    df["Label"] = np.where(malicious, attack_label, "BENIGN")
    # Real-file quirks: infinities, blanks, duplicate rows, padded names/labels.
    df.loc[df.sample(5, random_state=seed).index, "Flow Bytes/s"] = np.inf
    df.loc[df.sample(4, random_state=seed + 1).index, "Flow Bytes/s"] = np.nan
    if duplicates:
        df = pd.concat([df, df.sample(duplicates, random_state=seed + 2)], ignore_index=True)
    df.columns = [f" {c}" if i % 3 == 0 else c for i, c in enumerate(df.columns)]
    df[df.columns[-1]] = " " + df[df.columns[-1]].astype(str)
    return df
