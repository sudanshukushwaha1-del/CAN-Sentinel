"""CAN-Sentinel dashboard: reproducible offline simulation and authorized CSV inspection."""
from __future__ import annotations
from dataclasses import asdict
import io
import json
import tempfile
from datetime import date
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
from sklearn.metrics import RocCurveDisplay
from can_sentinel.detector_ml import MLDetector
from can_sentinel.engine import IDSEngine
from can_sentinel.evaluator import evaluate
from can_sentinel.preprocessor import FeatureExtractor, normalize_frame_table
from can_sentinel.seasonal_theme import seasonal_background_css, season_for_month
from can_sentinel.simulator import TrafficSimulator

st.set_page_config(page_title="CAN-Sentinel IDS", page_icon="🛡️", layout="wide")
current_season = season_for_month(date.today().month)
st.markdown(seasonal_background_css(current_season), unsafe_allow_html=True)
st.title("CAN-Sentinel | CAN Bus IDS Demo")
st.caption("Inspect a reproducible synthetic scenario or an authorized offline CSV capture.")
st.caption(f"Seasonal background: {current_season.title()} · selected automatically from the calendar.")
st.warning("Educational prototype only. Scores are trained on synthetic traffic, not calibrated vehicle performance. This app never connects to or transmits on a physical CAN bus.")

@st.cache_resource(show_spinner="Training the reproducible synthetic demo model…")
def get_model(seed_value: int) -> MLDetector:
    return MLDetector(seed=seed_value).fit()

source = st.sidebar.radio("Traffic source", ["Synthetic scenario", "Upload CSV log"])
seed = int(st.sidebar.number_input("Model / simulation seed", min_value=0, max_value=100000, value=7, step=1))
attack_names = {"DoS flood (dominant ID 0x000)": "dos", "Fuzzy (random standard IDs/payloads)": "fuzzy", "RPM spoof (ID 0x316)": "spoof"}
if source == "Synthetic scenario":
    attack_label = st.sidebar.selectbox("Attack type", list(attack_names))
    normal_count = st.sidebar.slider("Benign frames", 100, 1000, 400, 100)
    attack_count = st.sidebar.slider("Injected attack frames", 50, 500, 120, 10)
    uploaded_file = None
else:
    st.sidebar.warning("Public hosted demo: CSV contents are sent to this website for analysis. Never upload confidential, personal, or unauthorized vehicle captures; use sanitized authorized data only.")
    st.sidebar.caption("CSV headers: Timestamp, Arbitration_ID, DLC, Data_Bytes; optional Label (0/1).")
    uploaded_file = st.sidebar.file_uploader("Choose an authorized CSV capture", type=["csv"])
    attack_label = "CSV inspection"

if st.button("Analyze traffic", type="primary", disabled=(source == "Upload CSV log" and uploaded_file is None)):
    try:
        if source == "Synthetic scenario":
            frames = TrafficSimulator(seed=seed).scenario(normal_count, attack_count, attack_names[attack_label])
            table = pd.DataFrame([frame.as_record() for frame in frames])
        else:
            raw_table = pd.read_csv(io.BytesIO(uploaded_file.getvalue()))
            table = normalize_frame_table(raw_table)
            frames = table.to_dict(orient="records")
        model = get_model(seed)
        with tempfile.TemporaryDirectory() as tmp:
            engine = IDSEngine(model, Path(tmp) / "alerts.jsonl")
            has_labels = all((hasattr(frame, "label") or (isinstance(frame, dict) and "Label" in frame)) for frame in frames)
            if has_labels:
                metrics = evaluate(frames, engine)
            else:
                metrics = None
                for frame in frames:
                    engine.process(frame)
            alert_rows = [asdict(alert) for alert in engine.alerts]
            alert_jsonl = "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in alert_rows)
            # ROC displays the model's ranking score only; rule decisions are included in headline classification metrics.
            if has_labels:
                features = FeatureExtractor().transform(frames)
                scores = [model.score(row) for row in features.to_dict(orient="records")]
                labels = [int(frame.label if hasattr(frame, "label") else frame["Label"]) for frame in frames]
            else:
                scores, labels = [], []
        st.session_state["analysis"] = {
            "source": source, "scenario": attack_label, "table": table, "metrics": metrics,
            "alerts": pd.DataFrame(alert_rows), "alert_jsonl": alert_jsonl,
            "labels": labels, "scores": scores, "frame_count": len(frames), "error": None}
    except Exception as exc:
        st.session_state["analysis"] = {"error": str(exc)}

analysis = st.session_state.get("analysis")
if analysis:
    if analysis.get("error"):
        st.error(f"Could not analyze input: {analysis['error']}")
        st.info("Check the CSV headers, valid timestamps/IDs, DLC (0–8), payload byte count, and optional 0/1 labels.")
    else:
        metrics = analysis["metrics"]
        st.subheader(f"Results · {analysis['scenario']}")
        if metrics is None:
            st.info(f"Inspected {analysis['frame_count']} frames. No ground-truth `Label` column was supplied, so classification metrics and ROC-AUC are intentionally omitted.")
            st.metric("Frames with one or more alerts", int(analysis["alerts"]["frame_index"].nunique()) if not analysis["alerts"].empty else 0)
        else:
            st.caption("Frame-level classification uses fused decisions (any rule alert OR ML threshold). ROC-AUC ranks the ML score only.")
            cols = st.columns(5)
            for col, (label, key) in zip(cols, [("Accuracy", "accuracy"), ("Precision", "precision"), ("Recall", "recall"), ("F1", "f1"), ("False-positive rate", "false_positive_rate")]):
                col.metric(label, f"{metrics[key]:.3f}")
            st.caption(f"{metrics['frames']} frames · rules alerted on {metrics['rule_alert_frames']} frame(s) · ML alerted on {metrics['ml_alert_frames']} frame(s) · mean detector latency {metrics['mean_latency_ms']:.3f} ms · p95 {metrics['p95_latency_ms']:.3f} ms · ML ROC-AUC {metrics['roc_auc'] if metrics['roc_auc'] is not None else 'n/a'}")
        left, right = st.columns(2)
        with left:
            st.subheader("Traffic timeline")
            chart = analysis["table"].copy()
            if "Attack" not in chart.columns:
                chart["Attack"] = chart["Label"].map({0: "Benign", 1: "Attack"}) if "Label" in chart else "Unlabeled"
            st.scatter_chart(chart[["Timestamp", "Arbitration_ID", "Attack"]],
                             x="Timestamp", y="Arbitration_ID", color="Attack")
            st.subheader("Packet inspector")
            display = chart.tail(50).copy()
            if "Data_Bytes" in display.columns:
                display["Data_Bytes"] = display["Data_Bytes"].map(lambda value: value.hex(" ") if isinstance(value, bytes) else value)
            st.dataframe(display, width="stretch", hide_index=True)
        with right:
            st.subheader("ML ROC curve")
            if analysis["labels"] and len(set(analysis["labels"])) == 2:
                fig, ax = plt.subplots()
                RocCurveDisplay.from_predictions(analysis["labels"], analysis["scores"], ax=ax)
                st.pyplot(fig); plt.close(fig)
            else:
                st.info("A labeled capture with both benign and attack examples is required for ROC-AUC.")
            st.subheader("Alert feed")
            alerts = analysis["alerts"]
            if alerts.empty:
                st.success("No rule or ML alerts fired for this input.")
            else:
                st.caption("`source` distinguishes deterministic `rule` alerts from `ml` score-threshold alerts.")
                st.dataframe(alerts.sort_values("frame_timestamp", ascending=False).head(200), width="stretch", hide_index=True)
                st.download_button("Download forensic alerts (JSONL)", analysis["alert_jsonl"],
                                   file_name="can_sentinel_alerts.jsonl", mime="application/x-ndjson")

with st.expander("How to read this dashboard"):
    st.markdown("""- **Accuracy / precision / recall / F1 / false-positive rate:** frame-level outcomes from the fused rule + ML decision, only when labels exist.
- **ROC-AUC:** ranking performance of the synthetic-trained ML score only; it is not a probability or evidence of vehicle readiness.
- **Latency:** detector decision time per frame before JSONL disk I/O; it is host-dependent and not a real-time guarantee.
- **CSV input:** chronological ordering is normalized; use only captures you are authorized to analyze. Add a `Label` column containing 0 (benign) or 1 (attack) for evaluation.
- Dashboard alert logs can be downloaded as JSON Lines; they are not retained by the app after the session.""")
