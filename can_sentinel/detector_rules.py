"""Interpretable rolling-rate and protocol-bound CAN checks."""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
import math
from typing import Any

@dataclass(frozen=True)
class RuleAlert:
    rule: str
    severity: str
    detail: str

class RuleDetector:
    """Stateful rule checks for one non-decreasing timestamp stream."""
    def __init__(self, window_seconds: float = 1.0, max_frames_per_second: int = 200,
                 per_id_rate: int = 80, reserved_ids: set[int] | None = None) -> None:
        if not math.isfinite(window_seconds) or window_seconds <= 0 or max_frames_per_second <= 0 or per_id_rate <= 0:
            raise ValueError("rate limits and finite window must be positive")
        self.window_seconds = window_seconds
        self.max_frames_per_second = max_frames_per_second
        self.per_id_rate = per_id_rate
        self.reserved_ids = set(reserved_ids) if reserved_ids is not None else {0x000}
        self.times: deque[float] = deque()
        self.id_times: dict[int, deque[float]] = {}
        self.last_timestamp: float | None = None

    def check(self, frame: Any) -> list[RuleAlert]:
        timestamp = float(frame.timestamp if hasattr(frame, "timestamp") else frame["Timestamp"])
        arb_id = int(frame.arbitration_id if hasattr(frame, "arbitration_id") else frame["Arbitration_ID"])
        dlc = int(frame.dlc if hasattr(frame, "dlc") else frame["DLC"])
        if not math.isfinite(timestamp) or timestamp < 0:
            raise ValueError("frame timestamp must be finite and non-negative")
        if self.last_timestamp is not None and timestamp < self.last_timestamp:
            raise ValueError("frames must be processed in non-decreasing timestamp order")
        if not 0 <= arb_id <= 0x1FFFFFFF:
            raise ValueError("arbitration identifier outside CAN range")
        alerts: list[RuleAlert] = []
        if not 0 <= dlc <= 8:
            alerts.append(RuleAlert("DLC_BOUNDS", "critical", f"DLC {dlc} outside CAN 2.0 range 0..8"))
        if arb_id in self.reserved_ids:
            alerts.append(RuleAlert("RESERVED_ID", "high", f"traffic observed on reserved identifier 0x{arb_id:X}"))
        cutoff = timestamp - self.window_seconds
        while self.times and self.times[0] < cutoff:
            self.times.popleft()
        self.times.append(timestamp)
        for old_id in list(self.id_times):
            queue = self.id_times[old_id]
            while queue and queue[0] < cutoff:
                queue.popleft()
            if not queue and old_id != arb_id:
                del self.id_times[old_id]
        id_queue = self.id_times.setdefault(arb_id, deque())
        id_queue.append(timestamp)
        self.last_timestamp = timestamp
        if len(self.times) > self.max_frames_per_second * self.window_seconds:
            alerts.append(RuleAlert("BUS_FLOOD", "high", f"{len(self.times)} frames in {self.window_seconds:.2f}s window"))
        if len(id_queue) > self.per_id_rate * self.window_seconds:
            alerts.append(RuleAlert("ID_RATE", "high", f"ID 0x{arb_id:X}: {len(id_queue)} frames in rate window"))
        return alerts
