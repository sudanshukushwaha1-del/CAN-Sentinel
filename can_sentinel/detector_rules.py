"""Deterministic safeguards for known CAN misuse patterns."""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class RuleAlert:
    rule: str
    severity: str
    detail: str

class RuleDetector:
    def __init__(self, window_seconds: float = 1.0, max_frames_per_second: int = 200,
                 per_id_rate: int = 80, reserved_ids: set[int] | None = None) -> None:
        if window_seconds <= 0 or max_frames_per_second <= 0 or per_id_rate <= 0:
            raise ValueError("rate limits and window must be positive")
        self.window_seconds = window_seconds
        self.max_frames_per_second = max_frames_per_second
        self.per_id_rate = per_id_rate
        self.reserved_ids = reserved_ids if reserved_ids is not None else {0x000}
        self.times: deque[float] = deque()
        self.id_times: dict[int, deque[float]] = {}

    def check(self, frame: Any) -> list[RuleAlert]:
        timestamp = float(frame.timestamp if hasattr(frame, "timestamp") else frame["Timestamp"])
        arb_id = int(frame.arbitration_id if hasattr(frame, "arbitration_id") else frame["Arbitration_ID"])
        dlc = int(frame.dlc if hasattr(frame, "dlc") else frame["DLC"])
        alerts: list[RuleAlert] = []
        if not 0 <= dlc <= 8:
            alerts.append(RuleAlert("DLC_BOUNDS", "critical", f"DLC {dlc} outside CAN 2.0 range 0..8"))
        if arb_id in self.reserved_ids:
            alerts.append(RuleAlert("RESERVED_ID", "high", f"traffic observed on reserved identifier 0x{arb_id:X}"))
        cutoff = timestamp - self.window_seconds
        while self.times and self.times[0] < cutoff:
            self.times.popleft()
        self.times.append(timestamp)
        id_queue = self.id_times.setdefault(arb_id, deque())
        while id_queue and id_queue[0] < cutoff:
            id_queue.popleft()
        id_queue.append(timestamp)
        if len(self.times) > self.max_frames_per_second * self.window_seconds:
            alerts.append(RuleAlert("BUS_FLOOD", "high", f"{len(self.times)} frames in {self.window_seconds:.2f}s window"))
        if len(id_queue) > self.per_id_rate * self.window_seconds:
            alerts.append(RuleAlert("ID_RATE", "high", f"ID 0x{arb_id:X}: {len(id_queue)} frames in rate window"))
        return alerts
