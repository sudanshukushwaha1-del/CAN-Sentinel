"""Interactive simulation dashboard. Run: streamlit run app.py"""
from __future__ import annotations
import tempfile
from dataclasses import asdict
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
from sklearn.metrics import RocCurveDisplay
from can_sentinel.detector_ml import MLDetector
from can_sentinel.engine import IDSEngine
from can_sentinel.evaluator import evaluate
from can_sentinel.simulator import TrafficSimulator

st.set_page_config(page_title="CAN-Sentinel", layout="wide")
st.title("CAN-Sentinel | ECU Intrusion Detection")
st.caption("Offline simulation and IDS demonstration. This dashboard does not connect to or transmit on a physical vehicle bus.")
attack = st.sidebar.selectbox("Scenario", ["dos", "fuzzy", "spoof"])
normal_count = st.sidebar.slider("Normal frames", 100, 1000, 400, 100)
attack_count = st.sidebar.slider("Attack frames", 50, 500, 120, 10)
seed = st.sidebar.number_input("Reproducible seed", 0, 100000, 7)
if st.button("Run simulation", type="primary"):
    with st.spinner("Training demonstration model and analyzing scenario…"):
        sim = TrafficSimulator(seed=int(seed))
        frames = sim.scenario(normal_count, attack_count, attack)
        model = MLDetector(seed=int(seed)).fit()
        with tempfile.TemporaryDirectory() as tmp:
            engine = IDSEngine(model, Path(tmp) / "alerts.jsonl")
            metrics = evaluate(frames, engine)
            st.session_state["metrics"] = metrics
            st.session_state["frames"] = pd.DataFrame([f.as_record() for f in frames])
            st.session_state["alerts"] = pd.DataFrame([asdict(a) for a in engine.alerts])
            st.session_state["scores"] = [engine.last_ml_score]
            # ROC curve uses a separate clean causal feature pass over the complete labeled scenario.
            from can_sentinel.preprocessor import FeatureExtractor
            feat = FeatureExtractor().transform(frames)
            st.session_state["y"] = [f.label for f in frames]
            st.session_state["scores"] = [model.predict_proba(row) for row in feat.to_dict(orient="records")]

if "metrics" in st.session_state:
    m = st.session_state["metrics"]
    cols = st.columns(5)
    for col, (label, key) in zip(cols, [("Accuracy", "accuracy"), ("Precision", "precision"), ("Recall", "recall"), ("F1", "f1"), ("FPR", "false_positive_rate")]):
        col.metric(label, f"{m[key]:.3f}")
    st.caption(f"{m['frames']} frames · mean measured inference {m['mean_latency_ms']:.4f} ms · p95 {m['p95_latency_ms']:.4f} ms · ROC-AUC {m['roc_auc'] if m['roc_auc'] is not None else 'n/a'}")
    left, right = st.columns(2)
    with left:
        st.subheader("Traffic timeline")
        packets = st.session_state["frames"]
        st.scatter_chart(packets, x="Timestamp", y="Arbitration_ID", color="Attack")
        st.subheader("Packet inspector")
        st.dataframe(packets.tail(30), use_container_width=True)
    with right:
        st.subheader("ROC curve")
        if len(set(st.session_state["y"])) == 2:
            fig, ax = plt.subplots()
            RocCurveDisplay.from_predictions(st.session_state["y"], st.session_state["scores"], ax=ax)
            st.pyplot(fig); plt.close(fig)
        else:
            st.info("ROC requires both benign and attack frames.")
        st.subheader("Alert feed")
        alerts = st.session_state["alerts"]
        if alerts.empty:
            st.success("No deterministic rule alerts in this run.")
        else:
            st.dataframe(alerts.sort_values("frame_timestamp", ascending=False).head(100), use_container_width=True)
