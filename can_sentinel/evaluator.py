"""IDS evaluation helpers for labeled, offline frame sequences."""
from __future__ import annotations
from typing import Any, Iterable
import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from .engine import IDSEngine

def evaluate(frames: Iterable[Any], engine: IDSEngine) -> dict[str, Any]:
    y_true: list[int] = []; y_score: list[float] = []; latencies: list[float] = []
    for frame in frames:
        truth = int(frame.label if hasattr(frame, "label") else frame.get("Label", 0))
        _, elapsed = engine.process(frame)
        y_true.append(truth); y_score.append(engine.last_ml_score); latencies.append(elapsed)
    if not y_true:
        raise ValueError("cannot evaluate an empty frame sequence")
    predicted = np.asarray(y_score) >= (engine.ml_threshold if engine.ml is not None else 0.5)
    tn, fp, fn, tp = confusion_matrix(y_true, predicted.astype(int), labels=[0, 1]).ravel()
    auc = float(roc_auc_score(y_true, y_score)) if len(set(y_true)) == 2 else None
    return {"accuracy": float(accuracy_score(y_true, predicted)),
            "precision": float(precision_score(y_true, predicted, zero_division=0)),
            "recall": float(recall_score(y_true, predicted, zero_division=0)),
            "f1": float(f1_score(y_true, predicted, zero_division=0)),
            "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
            "roc_auc": auc, "mean_latency_ms": float(np.mean(latencies)),
            "p95_latency_ms": float(np.percentile(latencies, 95)), "frames": len(y_true),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}
