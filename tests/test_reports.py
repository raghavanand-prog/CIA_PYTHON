import io

import pandas as pd

from core import analytics
from models.model_utils import load_model_bundle
from utils.report_generator import ReportInputs, build_pdf_report, dataframe_to_csv, dataset_summary_frame


def _inputs(df, report, metrics=None):
    return ReportInputs(
        report=report,
        kpi=analytics.overview_kpis(df, report),
        label_counts=analytics.label_counts(df),
        attack_distribution=analytics.attack_distribution(df),
        insights=analytics.generate_insights(df, report),
        model_metrics=metrics,
    )


def test_csv_roundtrip(clean):
    df, report = clean
    data = dataframe_to_csv(analytics.label_counts(df))
    back = pd.read_csv(io.BytesIO(data))
    assert back["Flows"].sum() == len(df)
    summary = dataset_summary_frame(report, analytics.overview_kpis(df, report))
    assert "Total flows" in summary["Metric"].tolist()


def test_pdf_without_model(clean):
    df, report = clean
    pdf = build_pdf_report(_inputs(df, report))
    assert pdf.startswith(b"%PDF") and len(pdf) > 3_000


def test_pdf_with_model(trained):
    bundle = load_model_bundle(trained["artifacts"])
    pdf = build_pdf_report(_inputs(trained["df"], trained["report"], bundle.metrics))
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > len(build_pdf_report(_inputs(trained["df"], trained["report"])))
