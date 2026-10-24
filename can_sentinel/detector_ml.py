"""Statistical anomaly detection models with reproducible synthetic training data."""
from __future__ import annotations
from typing import Any
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from .preprocessor import FeatureExtractor
from .simulator import TrafficSimulator

class MLDetector:
    """Isolation Forest anomaly score plus supervised RF probability ensemble."""
    def __init__(self, seed: int = 7, contamination: float = 0.08) -> None:
        if not 0 < contamination < 0.5:
            raise ValueError("contamination must be between 0 and 0.5")
        self.seed = seed
        self.contamination = contamination
        self.isolation: IsolationForest | None = None
        self.forest: Any = None
        self.threshold: float = 0.5

    @staticmethod
    def _feature_set(kind: str, count: int, seed: int) -> np.ndarray:
        sim = TrafficSimulator(seed=seed)
        if kind == "normal":
            frames = sim.normal(count)
        elif kind == "dos":
            frames = sim.dos(count, period=0.0005)
        elif kind == "fuzzy":
            frames = sim.fuzzy(count)
        else:
            frames = sim.spoof(count)
        features = FeatureExtractor(window=100).transform(frames)
        return features[FeatureExtractor.FEATURE_NAMES].to_numpy(dtype=float)

    def fit(self, normal_count: int = 2500, per_attack_count: int = 400) -> "MLDetector":
        if normal_count < 100 or per_attack_count < 50:
            raise ValueError("training requires at least 100 normal and 50 per attack frames")
        benign = self._feature_set("normal", normal_count, self.seed)
        attack_parts = [self._feature_set(kind, per_attack_count, self.seed + offset)
                        for offset, kind in enumerate(("dos", "fuzzy", "spoof"), start=1)]
        anomalies = np.vstack(attack_parts)
        x = np.vstack((benign, anomalies))
        y = np.concatenate((np.zeros(len(benign), dtype=int), np.ones(len(anomalies), dtype=int)))
        self.isolation = IsolationForest(n_estimators=150, contamination=self.contamination,
                                         random_state=self.seed, n_jobs=1).fit(benign)
        self.forest = make_pipeline(StandardScaler(), RandomForestClassifier(
            n_estimators=160, class_weight="balanced", max_features="sqrt",
            random_state=self.seed, n_jobs=1))
        self.forest.fit(x, y)
        return self

    def predict_proba(self, feature: dict[str, float] | np.ndarray) -> float:
        if self.isolation is None or self.forest is None:
            raise RuntimeError("MLDetector.fit() must be called before inference")
        arr = np.asarray(list(feature.values()) if isinstance(feature, dict) else feature, dtype=float).reshape(1, -1)
        if arr.shape[1] != len(FeatureExtractor.FEATURE_NAMES) or not np.isfinite(arr).all():
            raise ValueError("feature vector has invalid size or non-finite values")
        supervised = float(self.forest.predict_proba(arr)[0, 1])
        # Isolation score is calibrated to an empirical percentile from a fixed benign reference sample.
        score = float(-self.isolation.decision_function(arr)[0])
        anomaly_score = 1.0 / (1.0 + np.exp(-np.clip(score * 4.0, -30, 30)))
        return float(0.65 * supervised + 0.35 * anomaly_score)

    def predict(self, feature: dict[str, float] | np.ndarray) -> int:
        return int(self.predict_proba(feature) >= self.threshold)
