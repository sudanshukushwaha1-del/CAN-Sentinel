"""Real-time-compatible IDS pipeline; latency measurements are host-dependent."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any
from .detector_rules import RuleAlert, RuleDetector
from .preprocessor import FeatureExtractor
from .simulator import CANFrame

@dataclass(frozen=True)
class Alert:
    event_time: str
    frame_timestamp: float
    arbitration_id: int
    severity: str
    rule: str
    detail: str
    ml_score: float
    processing_latency_ms: float

class IDSEngine:
    def __init__(self, ml_detector: Any | None = None, log_path: str | Path = "can_sentinel_alerts.jsonl",
                 ml_threshold: float = 0.75) -> None:
        self.ml = ml_detector
        self.rules = RuleDetector()
        self.features = FeatureExtractor()
        self.log_path = Path(log_path)
        self.ml_threshold = ml_threshold
        self.alerts: list[Alert] = []
        self.last_ml_score = 0.0

    def process(self, frame: CANFrame | dict[str, Any]) -> tuple[list[Alert], float]:
        started = time.perf_counter_ns()
        if isinstance(frame, CANFrame):
            timestamp, arb_id, dlc, data = frame.timestamp, frame.arbitration_id, frame.dlc, frame.data
        else:
            timestamp = float(frame["Timestamp"]); arb_id = int(frame["Arbitration_ID"])
            dlc = int(frame["DLC"]); raw = frame["Data_Bytes"]
            data = raw if isinstance(raw, bytes) else bytes.fromhex(str(raw).replace(" ", ""))
        if not 0 <= dlc <= 8 or len(data) != dlc or not 0 <= arb_id <= 0x1FFFFFFF:
            raise ValueError("invalid CAN frame")
        normalized = CANFrame(timestamp, arb_id, dlc, data,
                              int(frame.label) if isinstance(frame, CANFrame) else int(frame.get("Label", 0)),
                              frame.attack if isinstance(frame, CANFrame) else "normal")
        rule_alerts = self.rules.check(normalized)
        vector = self.features.transform_one({"Timestamp": timestamp, "Arbitration_ID": arb_id,
                                              "DLC": dlc, "Data_Bytes": data})
        score = self.ml.predict_proba(vector) if self.ml is not None else 0.0
        self.last_ml_score = score
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        new_alerts: list[Alert] = []
        for detected in rule_alerts:
            new_alerts.append(Alert(datetime.now(timezone.utc).isoformat(), timestamp, arb_id,
                                    detected.severity, detected.rule, detected.detail, score, elapsed_ms))
        if self.ml is not None and score >= self.ml_threshold:
            new_alerts.append(Alert(datetime.now(timezone.utc).isoformat(), timestamp, arb_id,
                                    "medium", "ML_ANOMALY", f"ensemble anomaly probability {score:.3f}", score, elapsed_ms))
        if new_alerts:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as handle:
                for alert in new_alerts:
                    handle.write(json.dumps(asdict(alert), separators=(",", ":")) + "\n")
            self.alerts.extend(new_alerts)
        return new_alerts, elapsed_ms
