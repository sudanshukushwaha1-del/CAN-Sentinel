"""CAN log parsing and causal feature extraction."""
from __future__ import annotations

from collections import Counter, deque
import math
from pathlib import Path
import re
from typing import Iterable
import pandas as pd

REQUIRED = {"Timestamp", "Arbitration_ID", "DLC", "Data_Bytes"}

def parse_identifier(value: object) -> int:
    text = str(value).strip()
    try:
        return int(text, 0) if text.lower().startswith("0x") else int(text, 10)
    except ValueError as exc:
        raise ValueError(f"invalid Arbitration_ID: {value!r}") from exc

def parse_data(value: object) -> bytes:
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none"}:
        return b""
    text = re.sub(r"[\s,:_-]", "", text)
    if text.lower().startswith("0x"):
        text = text[2:]
    if len(text) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", text):
        raise ValueError(f"invalid Data_Bytes hex string: {value!r}")
    return bytes.fromhex(text)

def read_can_csv(path: str | Path) -> pd.DataFrame:
    try:
        frame = pd.read_csv(path)
    except (OSError, pd.errors.ParserError, UnicodeError) as exc:
        raise ValueError(f"could not read CAN log {path}: {exc}") from exc
    missing = REQUIRED - set(frame.columns)
    if missing:
        raise ValueError(f"missing required columns: {', '.join(sorted(missing))}")
    return normalize_frame_table(frame)

def normalize_frame_table(frame: pd.DataFrame) -> pd.DataFrame:
    missing = REQUIRED - set(frame.columns)
    if missing:
        raise ValueError(f"missing required columns: {', '.join(sorted(missing))}")
    out = frame.copy()
    try:
        out["Timestamp"] = pd.to_numeric(out["Timestamp"], errors="raise").astype(float)
        out["Arbitration_ID"] = out["Arbitration_ID"].map(parse_identifier).astype("int64")
        out["DLC"] = pd.to_numeric(out["DLC"], errors="raise").astype(int)
        out["Data_Bytes"] = out["Data_Bytes"].map(parse_data)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError(f"invalid CAN frame row: {exc}") from exc
    if (out["Timestamp"] < 0).any() or (out["Arbitration_ID"] < 0).any() or (out["Arbitration_ID"] > 0x1FFFFFFF).any():
        raise ValueError("timestamp or CAN identifier outside valid range")
    if ((out["DLC"] < 0) | (out["DLC"] > 8)).any():
        raise ValueError("CAN 2.0 DLC must be in 0..8")
    if any(len(data) != dlc for data, dlc in zip(out["Data_Bytes"], out["DLC"])):
        raise ValueError("DLC does not match Data_Bytes length")
    if not out["Timestamp"].is_monotonic_increasing:
        out = out.sort_values("Timestamp", kind="stable").reset_index(drop=True)
    return out

class FeatureExtractor:
    """Stateful, causal extractor; no future-frame information is used."""
    FEATURE_NAMES = ["iat", "id_frequency", "payload_entropy", "dlc", "identifier", "id_novelty", "rpm_raw"]
    def __init__(self, window: int = 100) -> None:
        if window < 2:
            raise ValueError("window must be at least 2")
        self.window = window
        self.timestamps: deque[float] = deque(maxlen=window)
        self.ids: deque[int] = deque(maxlen=window)
        self.seen: set[int] = set()
        self.last_timestamp: float | None = None

    @staticmethod
    def entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        return -sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values())

    def transform_one(self, row: object) -> dict[str, float]:
        if isinstance(row, dict):
            get = row.get
            timestamp = float(get("Timestamp"))
            arb_id = parse_identifier(get("Arbitration_ID"))
            dlc = int(get("DLC"))
            data_val = get("Data_Bytes")
        else:
            timestamp = float(getattr(row, "timestamp"))
            arb_id = parse_identifier(getattr(row, "arbitration_id"))
            dlc = int(getattr(row, "dlc"))
            data_val = getattr(row, "data")
        data = data_val if isinstance(data_val, bytes) else parse_data(data_val)
        if not 0 <= dlc <= 8 or len(data) != dlc or arb_id > 0x1FFFFFFF:
            raise ValueError("invalid CAN frame supplied to feature extractor")
        iat = 0.0 if self.last_timestamp is None else max(0.0, timestamp - self.last_timestamp)
        self.timestamps.append(timestamp)
        self.ids.append(arb_id)
        frequency = Counter(self.ids)[arb_id]
        novelty = 0.0 if arb_id in self.seen else 1.0
        self.seen.add(arb_id)
        self.last_timestamp = timestamp
        rpm = float(int.from_bytes(data[:2], "little")) if arb_id == 0x316 and dlc >= 2 else 0.0
        return {"iat": iat, "id_frequency": float(frequency), "payload_entropy": self.entropy(data),
                "dlc": float(dlc), "identifier": float(arb_id), "id_novelty": novelty, "rpm_raw": rpm}

    def transform(self, frames: Iterable[object]) -> pd.DataFrame:
        return pd.DataFrame([self.transform_one(row) for row in frames], columns=self.FEATURE_NAMES)
