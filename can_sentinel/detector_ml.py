"""Demonstration anomaly scoring with Isolation Forest and Random Forest."""
from __future__ import annotations
import warnings
from typing import Any
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from .preprocessor import FeatureExtractor
from .simulator import TrafficSimulator

class MLDetector:
    """Synthetic-trained model; outputs a bounded risk score, not a calibrated probability."""
    def __init__(self, seed: int = 7, contamination: float = 0.08, threshold: float = 0.75) -> None:
        if not 0 < contamination < 0.5:
            raise ValueError("contamination must be between 0 and 0.5")
        if not 0 <= threshold <= 1:
            raise ValueError("threshold must be between 0 and 1")
        self.seed = seed
        self.contamination = contamination
        self.threshold = threshold
        self.isolation: IsolationForest | None = None
        self.forest: Any = None

    @staticmethod
    def _training_data(normal_count: int, per_attack_count: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
        """Generate one chronological mixed run so feature state crosses class boundaries."""
        sim = TrafficSimulator(seed=seed)
        normal = sim.normal(normal_count)
        attack_start = max(0, (normal_count // 2) * sim.normal_period)
        injected = []
        for offset, kind in enumerate(("dos", "fuzzy", "spoof"), start=1):
            attack_sim = TrafficSimulator(seed=seed + offset)
            if kind == "dos":
                injected.extend(attack_sim.dos(per_attack_count, attack_start, sim.normal_period / 10))
            elif kind == "fuzzy":
                injected.extend(attack_sim.fuzzy(per_attack_count, attack_start, sim.normal_period))
            else:
                injected.extend(attack_sim.spoof(per_attack_count, attack_start, sim.normal_period))
        sequence = sorted(normal + injected, key=lambda item: item.timestamp)
        extractor = FeatureExtractor(window=100)
        all_features = extractor.transform(sequence).to_numpy(dtype=float)
        labels = np.asarray([frame.label for frame in sequence], dtype=int)
        if not np.any(labels == 0) or not np.any(labels == 1):
            raise ValueError("training generator must produce benign and attack examples")
        return all_features, labels

    def fit(self, normal_count: int = 1200, per_attack_count: int = 150) -> "MLDetector":
        if normal_count < 100 or per_attack_count < 50:
            raise ValueError("training requires at least 100 normal and 50 per attack frames")
        x, y = self._training_data(normal_count, per_attack_count, self.seed)
        benign = x[y == 0]
        self.isolation = IsolationForest(n_estimators=80, contamination=self.contamination,
                                         random_state=self.seed, n_jobs=1).fit(benign)
        self.forest = make_pipeline(StandardScaler(), RandomForestClassifier(
            n_estimators=100, class_weight="balanced", max_features="sqrt",
            random_state=self.seed, n_jobs=1))
        self.forest.fit(x, y)
        return self

    def score(self, feature: dict[str, float] | np.ndarray) -> float:
        """Return a heuristic 0..1 ranking score; it is not a calibrated probability."""
        if self.isolation is None or self.forest is None:
            raise RuntimeError("MLDetector.fit() must be called before inference")
        if isinstance(feature, dict):
            missing = set(FeatureExtractor.FEATURE_NAMES) - set(feature)
            extra = set(feature) - set(FeatureExtractor.FEATURE_NAMES)
            if missing or extra:
                raise ValueError(f"feature keys mismatch (missing={sorted(missing)}, extra={sorted(extra)})")
            values = [feature[name] for name in FeatureExtractor.FEATURE_NAMES]
        else:
            values = feature
        arr = np.asarray(values, dtype=float).reshape(1, -1)
        if arr.shape[1] != len(FeatureExtractor.FEATURE_NAMES) or not np.isfinite(arr).all():
            raise ValueError("feature vector has invalid size or non-finite values")
        supervised = float(self.forest.predict_proba(arr)[0, 1])
        # Monotonic squashing keeps a ranking contribution; it is not probability calibration.
        isolation_score = float(-self.isolation.decision_function(arr)[0])
        isolation_risk = 1.0 / (1.0 + np.exp(-np.clip(isolation_score * 4.0, -30, 30)))
        return float(np.clip(0.65 * supervised + 0.35 * isolation_risk, 0.0, 1.0))

    def predict(self, feature: dict[str, float] | np.ndarray) -> int:
        return int(self.score(feature) >= self.threshold)

    def predict_proba(self, feature: dict[str, float] | np.ndarray) -> float:
        """Compatibility alias; the returned ensemble score is not calibrated probability."""
        warnings.warn("predict_proba returns an uncalibrated risk score; use score()", DeprecationWarning, stacklevel=2)
        return self.score(feature)
