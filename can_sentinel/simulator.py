"""Deterministic synthetic CAN 2.0B traffic generator; never transmits to hardware."""
from __future__ import annotations
from dataclasses import dataclass
import math
import random
from typing import Iterator, Literal

Attack = Literal["normal", "dos", "fuzzy", "spoof"]

@dataclass(frozen=True, slots=True)
class CANFrame:
    timestamp: float
    arbitration_id: int
    dlc: int
    data: bytes
    label: int = 0
    attack: Attack = "normal"

    def __post_init__(self) -> None:
        if not math.isfinite(self.timestamp) or self.timestamp < 0:
            raise ValueError("timestamp must be finite and non-negative")
        if isinstance(self.arbitration_id, bool) or not isinstance(self.arbitration_id, int) or not 0 <= self.arbitration_id <= 0x1FFFFFFF:
            raise ValueError("arbitration_id must be an integer in the CAN identifier range")
        if isinstance(self.dlc, bool) or not isinstance(self.dlc, int) or not 0 <= self.dlc <= 8:
            raise ValueError("CAN 2.0 DLC must be an integer in 0..8")
        if not isinstance(self.data, bytes) or len(self.data) != self.dlc:
            raise ValueError("payload must be bytes whose length equals DLC")
        if self.label not in (0, 1):
            raise ValueError("label must be 0 (benign) or 1 (attack)")
        if self.attack not in {"normal", "dos", "fuzzy", "spoof"}:
            raise ValueError("unsupported attack label")

    def as_record(self) -> dict[str, object]:
        return {"Timestamp": self.timestamp, "Arbitration_ID": self.arbitration_id,
                "DLC": self.dlc, "Data_Bytes": self.data.hex(" "),
                "Label": self.label, "Attack": self.attack}

@dataclass
class TrafficSimulator:
    """Create in-memory sample frames with a reproducible random seed."""
    seed: int = 7
    normal_period: float = 0.01

    RPM_ID = 0x316

    def __post_init__(self) -> None:
        if not math.isfinite(self.normal_period) or self.normal_period <= 0:
            raise ValueError("normal_period must be finite and positive")
        self.rng = random.Random(self.seed)

    @staticmethod
    def _validate_generation(count: int, start: float, period: float) -> None:
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("count must be a non-negative integer")
        if not math.isfinite(start) or start < 0:
            raise ValueError("start must be finite and non-negative")
        if not math.isfinite(period) or period <= 0:
            raise ValueError("period must be finite and positive")

    def normal(self, count: int, start: float = 0.0) -> list[CANFrame]:
        self._validate_generation(count, start, self.normal_period)
        ids = (0x100, 0x120, 0x200, self.RPM_ID, 0x400)
        frames: list[CANFrame] = []
        for i in range(count):
            arb_id = ids[i % len(ids)]
            payload = bytearray(self.rng.randrange(256) for _ in range(8))
            if arb_id == self.RPM_ID:
                payload[0:2] = (800 + (i % 40) * 25).to_bytes(2, "little")
            frames.append(CANFrame(start + i * self.normal_period, arb_id, 8, bytes(payload)))
        return frames

    def dos(self, count: int, start: float = 0.0, period: float | None = None) -> list[CANFrame]:
        interval = self.normal_period / 10 if period is None else period
        self._validate_generation(count, start, interval)
        return [CANFrame(start + i * interval, 0x000,
                         8, bytes(self.rng.randrange(256) for _ in range(8)), 1, "dos")
                for i in range(count)]

    def fuzzy(self, count: int, start: float = 0.0, period: float | None = None) -> list[CANFrame]:
        interval = self.normal_period if period is None else period
        self._validate_generation(count, start, interval)
        return [CANFrame(start + i * interval, self.rng.randrange(0x800), 8,
                         bytes(self.rng.randrange(256) for _ in range(8)), 1, "fuzzy")
                for i in range(count)]

    def spoof(self, count: int, start: float = 0.0, period: float | None = None) -> list[CANFrame]:
        interval = self.normal_period if period is None else period
        self._validate_generation(count, start, interval)
        result: list[CANFrame] = []
        for i in range(count):
            data = bytearray(self.rng.randrange(256) for _ in range(8))
            data[0:2] = (7000 + self.rng.randrange(3000)).to_bytes(2, "little")
            result.append(CANFrame(start + i * interval, self.RPM_ID, 8, bytes(data), 1, "spoof"))
        return result

    def scenario(self, normal_count: int = 500, attack_count: int = 100,
                 attack: Attack = "dos") -> list[CANFrame]:
        if attack not in {"normal", "dos", "fuzzy", "spoof"}:
            raise ValueError(f"unsupported attack scenario: {attack}")
        if attack == "normal":
            return self.normal(normal_count)
        base = self.normal(normal_count)
        start = base[-1].timestamp + self.normal_period if base else 0.0
        injected = {"dos": self.dos, "fuzzy": self.fuzzy, "spoof": self.spoof}[attack](attack_count, start)
        return sorted(base + injected, key=lambda frame: frame.timestamp)

    @staticmethod
    def stream(frames: list[CANFrame]) -> Iterator[CANFrame]:
        yield from frames
