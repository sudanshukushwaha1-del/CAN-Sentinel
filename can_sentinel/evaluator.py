"""Frame-level fused IDS metrics and ML-only ranking metrics for labeled traces."""
from __future__ import annotations
from typing import Any, Iterable
import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from .engine import IDSEngine

def evaluate(frames: Iterable[Any], engine: IDSEngine) -> dict[str, Any]:
    """Evaluate a fresh engine over an ordered, fully labeled trace.

    Classification metrics use the actual fused decision (any rule alert OR ML score over
    the engine threshold). ROC-AUC ranks the ML score alone, so it is None without a model.
    """
    if engine.processed_frames:
        raise ValueError("evaluate() requires a fresh IDSEngine; create a new engine for each trace")
    y_true: list[int] = []
    fused_prediction: list[int] = []
    ml_scores: list[float] = []
    latencies: list[float] = []
    rule_hits = ml_hits = 0
    for frame in frames:
        if hasattr(frame, "label"):
            truth = int(frame.label)
        elif isinstance(frame, dict) and "Label" in frame:
            truth = int(frame["Label"])
        else:
            raise ValueError("evaluation requires a Label (0 benign / 1 attack) on every frame")
        if truth not in (0, 1):
            raise ValueError("labels must be 0 (benign) or 1 (attack)")
        alerts, elapsed = engine.process(frame)
        y_true.append(truth)
        fused_prediction.append(int(engine.last_detected))
        ml_scores.append(engine.last_ml_score)
        latencies.append(elapsed)
        rule_hits += int(bool(engine.last_rule_alerts))
        ml_hits += int(any(alert.source == "ml" for alert in alerts))
    if not y_true:
        raise ValueError("cannot evaluate an empty frame sequence")
    tn, fp, fn, tp = confusion_matrix(y_true, fused_prediction, labels=[0, 1]).ravel()
    auc = float(roc_auc_score(y_true, ml_scores)) if engine.ml is not None and len(set(y_true)) == 2 else None
    return {"accuracy": float(accuracy_score(y_true, fused_prediction)),
            "precision": float(precision_score(y_true, fused_prediction, zero_division=0)),
            "recall": float(recall_score(y_true, fused_prediction, zero_division=0)),
            "f1": float(f1_score(y_true, fused_prediction, zero_division=0)),
            "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
            "roc_auc": auc, "roc_auc_scope": "ML score only" if engine.ml is not None else "unavailable without ML model",
            "mean_latency_ms": float(np.mean(latencies)),
            "p95_latency_ms": float(np.percentile(latencies, 95)),
            "frames": len(y_true), "rule_alert_frames": rule_hits, "ml_alert_frames": ml_hits,
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}
