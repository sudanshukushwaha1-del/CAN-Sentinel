"""Deterministic synthetic CAN 2.0B traffic generator; no hardware transmission."""
from __future__ import annotations

from dataclasses import asdict, dataclass
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
        if not 0 <= self.arbitration_id <= 0x1FFFFFFF:
            raise ValueError("arbitration_id must fit an extended CAN identifier")
        if not 0 <= self.dlc <= 8 or len(self.data) != self.dlc:
            raise ValueError("CAN 2.0 data length must equal DLC and be in 0..8")
        if self.timestamp < 0:
            raise ValueError("timestamp must be non-negative")

    def as_record(self) -> dict[str, object]:
        return {"Timestamp": self.timestamp, "Arbitration_ID": self.arbitration_id,
                "DLC": self.dlc, "Data_Bytes": self.data.hex(" "), "Label": self.label,
                "Attack": self.attack}

class TrafficSimulator:
    """Generate deterministic traffic suitable for offline tests and demos."""
    RPM_ID = 0x316

    def __init__(self, seed: int = 7, normal_period: float = 0.01) -> None:
        if normal_period <= 0:
            raise ValueError("normal_period must be positive")
        self.rng = random.Random(seed)
        self.normal_period = normal_period

    def normal(self, count: int, start: float = 0.0) -> list[CANFrame]:
        if count < 0:
            raise ValueError("count cannot be negative")
        ids = (0x100, 0x120, 0x200, self.RPM_ID, 0x400)
        frames: list[CANFrame] = []
        for i in range(count):
            arb_id = ids[i % len(ids)]
            payload = bytearray(self.rng.randrange(256) for _ in range(8))
            if arb_id == self.RPM_ID:
                rpm = 800 + (i % 40) * 25
                payload[0:2] = rpm.to_bytes(2, "little")
            frames.append(CANFrame(start + i * self.normal_period, arb_id, 8, bytes(payload)))
        return frames

    def dos(self, count: int, start: float = 0.0, period: float | None = None) -> list[CANFrame]:
        """Inject dominant standard ID 0x000 at 10x baseline rate by default."""
        if count < 0:
            raise ValueError("count cannot be negative")
        interval = period or self.normal_period / 10
        return [CANFrame(start + i * interval, 0x000, 8,
                         bytes(self.rng.randrange(256) for _ in range(8)), 1, "dos") for i in range(count)]

    def fuzzy(self, count: int, start: float = 0.0, period: float | None = None) -> list[CANFrame]:
        if count < 0:
            raise ValueError("count cannot be negative")
        interval = period or self.normal_period
        return [CANFrame(start + i * interval, self.rng.randrange(0x800), 8,
                         bytes(self.rng.randrange(256) for _ in range(8)), 1, "fuzzy") for i in range(count)]

    def spoof(self, count: int, start: float = 0.0, period: float | None = None) -> list[CANFrame]:
        """Spoof engine-speed ID 0x316 with physically implausible RPM payloads."""
        if count < 0:
            raise ValueError("count cannot be negative")
        interval = period or self.normal_period
        result = []
        for i in range(count):
            data = bytearray(self.rng.randrange(256) for _ in range(8))
            data[0:2] = (7000 + self.rng.randrange(3000)).to_bytes(2, "little")
            result.append(CANFrame(start + i * interval, self.RPM_ID, 8, bytes(data), 1, "spoof"))
        return result

    def scenario(self, normal_count: int = 500, attack_count: int = 100,
                 attack: Attack = "dos") -> list[CANFrame]:
        if attack == "normal":
            return self.normal(normal_count)
        base = self.normal(normal_count)
        start = (base[-1].timestamp + self.normal_period) if base else 0.0
        injected = {"dos": self.dos, "fuzzy": self.fuzzy, "spoof": self.spoof}[attack](attack_count, start)
        return sorted(base + injected, key=lambda frame: frame.timestamp)

    @staticmethod
    def stream(frames: list[CANFrame]) -> Iterator[CANFrame]:
        yield from frames
