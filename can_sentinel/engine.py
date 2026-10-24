"""Per-frame IDS pipeline with rule/ML fusion and JSONL forensic alerts."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import time
from typing import Any
from .detector_rules import RuleAlert, RuleDetector
from .preprocessor import FeatureExtractor, parse_data, parse_identifier
from .simulator import CANFrame

@dataclass(frozen=True)
class Alert:
    event_time: str
    frame_timestamp: float
    arbitration_id: int
    severity: str
    source: str
    rule: str
    detail: str
    ml_score: float
    detection_latency_ms: float

class IDSEngine:
    """Stateful detector; instantiate one engine per chronological trace/stream."""
    def __init__(self, ml_detector: Any | None = None, log_path: str | Path = "can_sentinel_alerts.jsonl",
                 ml_threshold: float | None = None) -> None:
        effective_threshold = ml_threshold if ml_threshold is not None else getattr(ml_detector, "threshold", 0.75)
        if not math.isfinite(effective_threshold) or not 0 <= effective_threshold <= 1:
            raise ValueError("ml_threshold must be between 0 and 1")
        self.ml = ml_detector
        self.rules = RuleDetector()
        self.features = FeatureExtractor()
        self.log_path = Path(log_path)
        self.ml_threshold = float(effective_threshold)
        if ml_detector is not None and hasattr(ml_detector, "threshold"):
            ml_detector.threshold = self.ml_threshold
        self.alerts: list[Alert] = []
        self.last_ml_score = 0.0
        self.last_rule_alerts: list[RuleAlert] = []
        self.last_detected = False
        self.processed_frames = 0

    @staticmethod
    def _normalize(frame: CANFrame | dict[str, Any]) -> CANFrame:
        if isinstance(frame, CANFrame):
            return frame
        try:
            timestamp = float(frame["Timestamp"])
            arb_id = parse_identifier(frame["Arbitration_ID"])
            raw_dlc = float(frame["DLC"])
            if not math.isfinite(raw_dlc) or not raw_dlc.is_integer():
                raise ValueError("DLC must be a whole number")
            dlc = int(raw_dlc)
            data = parse_data(frame["Data_Bytes"])
            raw_label = float(frame.get("Label", 0))
            if raw_label not in (0.0, 1.0):
                raise ValueError("Label must be 0 or 1")
            label = int(raw_label)
            attack = str(frame.get("Attack", "normal"))
            return CANFrame(timestamp, arb_id, dlc, data, label, attack)  # type: ignore[arg-type]
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"invalid CAN frame mapping: {exc}") from exc

    def process(self, frame: CANFrame | dict[str, Any]) -> tuple[list[Alert], float]:
        started = time.perf_counter_ns()
        normalized = self._normalize(frame)
        rule_alerts = self.rules.check(normalized)
        vector = self.features.transform_one(normalized)
        score = self.ml.score(vector) if self.ml is not None else 0.0
        detected_by_ml = self.ml is not None and score >= self.ml_threshold
        self.last_ml_score = score
        self.last_rule_alerts = rule_alerts
        self.last_detected = bool(rule_alerts) or detected_by_ml
        self.processed_frames += 1
        # This is detector processing time before alert construction and disk logging, not end-to-end I/O latency.
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        now = datetime.now(timezone.utc).isoformat()
        new_alerts = [Alert(now, normalized.timestamp, normalized.arbitration_id, item.severity,
                            "rule", item.rule, item.detail, score, elapsed_ms) for item in rule_alerts]
        if detected_by_ml:
            new_alerts.append(Alert(now, normalized.timestamp, normalized.arbitration_id,
                                    "medium", "ml", "ML_ANOMALY",
                                    f"ensemble anomaly score {score:.3f} meets threshold {self.ml_threshold:.3f}",
                                    score, elapsed_ms))
        if new_alerts:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as handle:
                for alert in new_alerts:
                    handle.write(json.dumps(asdict(alert), separators=(",", ":")) + "\n")
            self.alerts.extend(new_alerts)
        return new_alerts, elapsed_ms
