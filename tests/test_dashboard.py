from __future__ import annotations
from pathlib import Path
import pytest


def test_synthetic_dashboard_run_renders_results() -> None:
    pytest.importorskip("streamlit")
    app_test_module = pytest.importorskip("streamlit.testing.v1")
    script = Path(__file__).resolve().parents[1] / "app.py"
    app = app_test_module.AppTest.from_file(str(script), default_timeout=90).run()
    app.button[0].click().run()
    assert not app.exception
    assert not app.error
    assert {metric.label for metric in app.metric} >= {"Accuracy", "Precision", "Recall", "F1", "False-positive rate"}
    assert len(app.dataframe) >= 1


def test_csv_mode_warns_before_file_selection() -> None:
    pytest.importorskip("streamlit")
    app_test_module = pytest.importorskip("streamlit.testing.v1")
    script = Path(__file__).resolve().parents[1] / "app.py"
    app = app_test_module.AppTest.from_file(str(script), default_timeout=90).run()
    app.radio[0].set_value("Upload CSV log").run()
    assert not app.exception
    assert any("Public hosted demo" in item.value for item in app.warning)
