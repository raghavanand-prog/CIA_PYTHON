"""CSV exports and the ReportLab PDF security report.

The PDF only includes model figures when evaluation metrics have actually
been produced by the training script; nothing is filled in by hand.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from datetime import datetime

import pandas as pd
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from core import config
from core.data_loader import QualityReport

# ---------------------------------------------------------------- CSV


def dataframe_to_csv(df: pd.DataFrame) -> bytes:
    """UTF-8 CSV bytes for st.download_button."""
    return df.to_csv(index=False).encode("utf-8")


def dataset_summary_frame(report: QualityReport, kpi: dict) -> pd.DataFrame:
    rows = [
        ("Dataset", config.DATASET_NAME),
        ("Source file(s)", "; ".join(report.source_files)),
        ("Analysis mode", config.ANALYSIS_MODE),
        ("Total flows", kpi["total"]),
        ("Benign flows", kpi["benign"]),
        ("Malicious flows", kpi["malicious"]),
        ("Malicious share (%)", round(kpi["malicious_pct"], 4)),
        ("Attack categories", kpi["attack_categories"]),
        ("Feature columns", report.feature_count),
        ("Missing values", report.missing_values),
        ("Infinite values", report.infinite_values),
        ("Duplicate records", report.duplicate_rows),
        ("Constant columns", len(report.constant_columns)),
        ("Loaded at", report.loaded_at),
        ("Generated at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ]
    return pd.DataFrame(rows, columns=["Metric", "Value"]).astype({"Value": "string"})


# ---------------------------------------------------------------- PDF
INK = colors.HexColor("#1B1A17")
MUTED = colors.HexColor("#6B655B")
GREEN = colors.HexColor("#8C6B35")  # dark gold accent
GREEN_LIGHT = colors.HexColor("#F6EFE2")
RED = colors.HexColor("#B4474B")
RULE = colors.HexColor("#E2DCD1")
ZEBRA = colors.HexColor("#FAF7F1")

STYLES = {
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=INK, spaceAfter=4),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=10, leading=14, textColor=MUTED),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=GREEN,
                         spaceBefore=14, spaceAfter=6),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK, alignment=TA_LEFT),
    "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8, leading=11, textColor=MUTED),
    "bullet": ParagraphStyle("bullet", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK,
                             leftIndent=10, bulletIndent=0, spaceAfter=2),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=8.8, leading=11.5, textColor=INK),
    "kpi_value": ParagraphStyle("kv", fontName="Helvetica-Bold", fontSize=15, leading=18, textColor=INK),
    "kpi_label": ParagraphStyle("kl", fontName="Helvetica", fontSize=7.8, leading=10, textColor=MUTED),
}


@dataclass
class ReportInputs:
    report: QualityReport
    kpi: dict
    label_counts: pd.DataFrame
    attack_distribution: pd.DataFrame
    insights: list[str]
    model_metrics: dict | None = None
    detection_summary: dict | None = None


def _p(text: object, style: str = "body") -> Paragraph:
    return Paragraph(str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), STYLES[style])


def _table(rows: list[list], col_widths: list[float], header: bool = True) -> Table:
    data = [[_p(c, "cell") if isinstance(c, str) else c for c in row] for row in rows]
    t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), GREEN_LIGHT), ("LINEBELOW", (0, 0), (-1, 0), 0.8, GREEN)]
        for r in range(2, len(rows), 2):
            style.append(("BACKGROUND", (0, r), (-1, r), ZEBRA))
    t.setStyle(TableStyle(style))
    return t


def _kv_table(rows: list[tuple[str, str]], width: float) -> Table:
    return _table([[k, v] for k, v in rows], [width * 0.45, width * 0.55], header=False)


def _kpi_grid(cards: list[tuple[str, str]], width: float) -> Table:
    cells = [[_p(v, "kpi_value"), _p(k, "kpi_label")] for k, v in cards]
    per_row = 3
    grid = []
    for i in range(0, len(cells), per_row):
        chunk = cells[i:i + per_row]
        chunk += [["", ""]] * (per_row - len(chunk))
        grid.append([Table([[c[0]], [c[1]]], colWidths=[width / per_row - 8]) for c in chunk])
    t = Table(grid, colWidths=[width / per_row] * per_row)
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, RULE), ("INNERGRID", (0, 0), (-1, -1), 0.6, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
    ]))
    return t


def _bar_drawing(items: list[tuple[str, float]], width: float, bar_color=colors.HexColor("#C99A49"), value_fmt="{:.1f}%") -> Drawing:
    """Simple horizontal bar chart drawn with ReportLab shapes."""
    row_h = 15
    label_w = width * 0.42
    bar_w = width - label_w - 40
    d = Drawing(width, row_h * len(items) + 4)
    max_v = max((v for _, v in items), default=1) or 1
    for i, (label, value) in enumerate(items):
        y = (len(items) - 1 - i) * row_h + 3
        d.add(String(0, y + 2, label[:42], fontName="Helvetica", fontSize=7.8, fillColor=INK))
        d.add(Rect(label_w, y, bar_w, 9, fillColor=ZEBRA, strokeColor=None))
        d.add(Rect(label_w, y, bar_w * value / max_v, 9, fillColor=bar_color, strokeColor=None))
        d.add(String(label_w + bar_w + 4, y + 2, value_fmt.format(value), fontName="Helvetica", fontSize=7.6,
                     fillColor=MUTED))
    return d


def _header_footer(canvas, doc) -> None:
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(INK)
    canvas.rect(0, h - 6 * mm, w, 6 * mm, stroke=0, fill=1)
    canvas.setFillColor(colors.HexColor("#D6A858"))
    canvas.rect(0, h - 6.8 * mm, w, 0.8 * mm, stroke=0, fill=1)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, f"{config.APP_NAME} · {config.INSTITUTION} · Offline analysis of recorded traffic")
    canvas.drawRightString(w - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(RULE)
    canvas.line(18 * mm, 13.5 * mm, w - 18 * mm, 13.5 * mm)
    canvas.restoreState()


def build_pdf_report(data: ReportInputs) -> bytes:
    """Create the full security report and return it as PDF bytes."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=20 * mm,
                            title=f"{config.APP_NAME} Security Report", author=config.DEVELOPER)
    width = A4[0] - 36 * mm
    story: list = []
    generated = datetime.now().strftime("%d %B %Y, %H:%M")

    # ---- cover block
    brand_cells = []
    logo = config.EMBLEM_PATH if config.EMBLEM_PATH.exists() else config.ICON_PATH
    if logo.exists():
        brand_cells.append(Image(str(logo), width=16 * mm, height=16 * mm, kind="proportional"))
    brand_text = [
        _p(config.APP_NAME.upper(), "small"),
        Paragraph("Network Security Analysis Report", STYLES["title"]),
        _p(f"{config.APP_TITLE}", "subtitle"),
        _p(f"{config.INSTITUTION} · {config.COURSE}", "subtitle"),
        _p(f"Generated {generated} · Prepared by {config.DEVELOPER}", "subtitle"),
    ]
    if brand_cells:
        head = Table([[brand_cells[0], brand_text]], colWidths=[22 * mm, width - 22 * mm])
        head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        story.append(head)
    else:
        story.extend(brand_text)
    story.append(Spacer(1, 8))
    disclaimer = Table([[_p(
        "Offline analysis disclaimer: this report describes a recorded CIC-IDS2017 network capture. "
        "It does not reflect live monitoring of the CHRIST University network or any production network.", "small")]],
        colWidths=[width])
    disclaimer.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FBF4E6")),
                                    ("LINEBEFORE", (0, 0), (0, -1), 2.5, colors.HexColor("#D9A14A")),
                                    ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(disclaimer)

    # ---- 1. executive summary
    k, r = data.kpi, data.report
    story.append(Paragraph("1. Executive summary", STYLES["h2"]))
    story.append(_kpi_grid([
        ("Total network flows", f"{k['total']:,}"),
        ("Benign flows", f"{k['benign']:,}"),
        ("Malicious flows", f"{k['malicious']:,}"),
        ("Malicious traffic share", f"{k['malicious_pct']:.2f}%"),
        ("Attack categories", str(k["attack_categories"])),
        ("Feature columns", str(r.feature_count)),
    ], width))
    story.append(Spacer(1, 8))
    for item in data.insights:
        story.append(Paragraph(_p(item).text, STYLES["bullet"], bulletText="•"))

    # ---- 2. dataset
    story.append(Paragraph("2. Dataset information", STYLES["h2"]))
    story.append(_kv_table([
        ("Dataset", f"{config.DATASET_NAME} (Canadian Institute for Cybersecurity)"),
        ("Source file(s)", ", ".join(r.source_files)),
        ("Analysis mode", config.ANALYSIS_MODE),
        ("Records analysed", f"{r.total_records:,}"),
        ("Loaded at", r.loaded_at),
    ], width))

    # ---- 3. traffic classification
    lc = data.label_counts
    story.append(KeepTogether([
        Paragraph("3. Traffic classification", STYLES["h2"]),
        _table([["Label", "Traffic class", "Flows", "Share"]] +
               [[row[0], row[1], f"{row[2]:,}", f"{row[3]:.2f}%"] for row in lc.itertuples(index=False)],
               [width * 0.4, width * 0.25, width * 0.18, width * 0.17]),
    ]))

    # ---- 4. data quality
    story.append(KeepTogether([
        Paragraph("4. Dataset quality", STYLES["h2"]),
        _kv_table(r.as_rows(), width),
        Spacer(1, 4),
        _p("Infinite values (for example Flow Bytes/s when a flow lasts 0 microseconds) are treated as missing and, "
           "like blank cells, are filled with the training-set median inside the model pipeline.", "small"),
    ]))

    # ---- 5. attacks
    ad = data.attack_distribution
    block = [Paragraph("5. Attack category breakdown", STYLES["h2"])]
    if ad.empty:
        block.append(_p("No malicious flows are present in the analysed data."))
    else:
        block.append(_table([["Attack category", "Flows", "Share of all traffic", "Share of malicious"]] +
                            [[row[0], f"{row[1]:,}", f"{row[2]:.2f}%", f"{row[3]:.2f}%"]
                             for row in ad.itertuples(index=False)],
                            [width * 0.4, width * 0.18, width * 0.21, width * 0.21]))
    story.append(KeepTogether(block))

    # ---- 6. model
    story.append(Paragraph("6. AI threat detection model", STYLES["h2"]))
    m = data.model_metrics
    primary = (m or {}).get("evaluations", {}).get((m or {}).get("primary_evaluation", ""), None)
    if not m or not primary:
        story.append(_p("No validated model evaluation is available, so model results are not included. "
                        "Train the model with `python -m models.train_model` to add them."))
    else:
        info, audit = m["model"], m.get("audit", {})
        params = info.get("parameters", {})
        story.append(_kv_table([
            ("Algorithm", "Random Forest classifier (scikit-learn)"),
            ("Pipeline", "Median imputation → Random Forest"),
            ("Input features", str(info.get("n_features"))),
            ("Trees / max depth", f"{params.get('n_estimators')} / {params.get('max_depth')}"),
            ("Trained at", str(info.get("trained_at", "")).replace("T", " ")),
            ("Evaluation split", f"{audit.get('split', '')}; {primary['train_rows']:,} train / {primary['test_rows']:,} test"),
        ], width))
        story.append(Spacer(1, 6))
        story.append(_p("Performance on the held-out, deduplicated test set (flows never seen during training):"))
        story.append(Spacer(1, 4))
        story.append(_table(
            [["Accuracy", "Precision", "Recall", "F1-score", "ROC AUC"],
             [f"{primary['accuracy'] * 100:.3f}%", f"{primary['precision'] * 100:.3f}%",
              f"{primary['recall'] * 100:.3f}%", f"{primary['f1'] * 100:.3f}%",
              f"{primary.get('roc_auc', float('nan')):.4f}"]],
            [width / 5] * 5))
        cm = primary["confusion_matrix"]
        story.append(KeepTogether([
            Spacer(1, 8), _p("Confusion matrix (rows = actual class, columns = predicted class)"), Spacer(1, 4),
            _table([["", "Predicted Benign", "Predicted Malicious"],
                    ["Actual Benign", f"{cm[0][0]:,}", f"{cm[0][1]:,}"],
                    ["Actual Malicious", f"{cm[1][0]:,}", f"{cm[1][1]:,}"]],
                   [width * 0.34, width * 0.33, width * 0.33]),
        ]))
        naive = m.get("evaluations", {}).get("naive_random_split")
        audit_rows = [
            ("Exact duplicates removed before split", f"{audit.get('exact_duplicate_rows_removed', 0):,}"),
            ("Conflicting-label rows removed", f"{audit.get('conflicting_label_rows_removed', 0):,}"),
            ("Label used as an input", "Yes" if audit.get("label_in_features") else "No"),
            ("Preprocessing fitted on", audit.get("preprocessing_fitted_on", "")),
        ]
        if naive:
            audit_rows.append(("Random split with duplicates (for comparison)",
                               f"accuracy {naive['accuracy'] * 100:.3f}%, "
                               f"{naive['overlap']['test_rows_seen_in_train']:,} test rows also in training"))
        perm = audit.get("label_permutation_check")
        if perm:
            audit_rows.append(("Shuffled-label sanity check",
                               f"{perm['shuffled_label_accuracy'] * 100:.2f}% vs baseline {perm['majority_baseline'] * 100:.2f}%"))
        story.append(KeepTogether([Spacer(1, 8), _p("Validation and leakage audit"), Spacer(1, 4),
                                   _kv_table(audit_rows, width)]))
        fi = m.get("feature_importance", [])[:12]
        if fi:
            story.append(KeepTogether([
                Spacer(1, 8), _p("Top features by Random Forest importance (mean decrease in impurity)"), Spacer(1, 4),
                _bar_drawing([(f["feature"], f["importance"] * 100) for f in fi], width),
                _p("Importance reflects how much the model relies on a feature, not causation.", "small"),
            ]))

    if data.detection_summary:
        d = data.detection_summary
        rows = [("Flows analysed", f"{d['total']:,}"), ("Sampling", d["mode"]),
                ("Predicted benign", f"{d['benign']:,}"), ("Predicted malicious", f"{d['malicious']:,} ({d['malicious_pct']:.2f}%)")]
        if d.get("agreement") is not None:
            rows.append(("Agreement with dataset labels", f"{d['agreement'] * 100:.2f}%"))
        story.append(KeepTogether([Paragraph("7. Latest detection run", STYLES["h2"]), _kv_table(rows, width)]))

    # ---- methodology + limitations
    n = 8 if data.detection_summary else 7
    story.append(Paragraph(f"{n}. Analysis methodology", STYLES["h2"]))
    for line in [
        "Flow records are loaded from CIC-IDS2017 CSV files; column names and labels are trimmed, text values such "
        "as 'Infinity' are converted, infinite values are treated as missing and empty rows are removed.",
        "Traffic statistics are computed on all records. Distributions use log-scaled bins and quartile summaries "
        "instead of sampling, because flow features are extremely skewed.",
        "For the model, duplicate flows are removed before a stratified 80/20 train/test split (random_state 42). "
        "Feature selection (dropping identifier, constant and duplicated columns) and median imputation are fitted "
        "on the training split only and saved as a schema that is re-applied at prediction time.",
        "A Random Forest classifier is evaluated on the held-out split with accuracy, precision, recall, F1-score, "
        "ROC AUC and a confusion matrix, and compared with a naive split to quantify duplicate leakage.",
    ]:
        story.append(Paragraph(_p(line).text, STYLES["bullet"], bulletText="•"))
    labels = ", ".join(data.label_counts["Label"].tolist())
    limitation_block = [Paragraph(f"{n + 1}. Limitations", STYLES["h2"])]
    for line in [
        f"The analysed data contains only the following labels: {labels}. Other attack types are not represented.",
        "CIC-IDS2017 was generated in a laboratory network in 2017; results may not generalise to other environments.",
        "Model outputs are statistical predictions, not confirmed incidents. The system does not block or respond to attacks.",
        "This report covers recorded traffic only and is not evidence of the state of any live network.",
    ]:
        limitation_block.append(Paragraph(_p(line).text, STYLES["bullet"], bulletText="•"))
    story.append(KeepTogether(limitation_block))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buffer.getvalue()
