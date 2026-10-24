"""CAN log parsing, validation, and causal feature extraction."""
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
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid Arbitration_ID: {value!r}") from exc

def parse_data(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if value is None:
        return b""
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
    return normalize_frame_table(frame)

def normalize_frame_table(frame: pd.DataFrame) -> pd.DataFrame:
    """Validate a CSV-like table and sort it chronologically, stably."""
    missing = REQUIRED - set(frame.columns)
    if missing:
        raise ValueError(f"missing required columns: {', '.join(sorted(missing))}")
    if frame.empty:
        raise ValueError("CAN log contains no frames")
    out = frame.copy()
    try:
        out["Timestamp"] = pd.to_numeric(out["Timestamp"], errors="raise").astype(float)
        out["Arbitration_ID"] = out["Arbitration_ID"].map(parse_identifier).astype("int64")
        numeric_dlc = pd.to_numeric(out["DLC"], errors="raise")
        if not ((numeric_dlc % 1) == 0).all():
            raise ValueError("DLC values must be whole numbers")
        out["DLC"] = numeric_dlc.astype(int)
        out["Data_Bytes"] = out["Data_Bytes"].map(parse_data)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError(f"invalid CAN frame row: {exc}") from exc
    if not out["Timestamp"].map(math.isfinite).all():
        raise ValueError("timestamps must be finite")
    if (out["Timestamp"] < 0).any() or (out["Arbitration_ID"] < 0).any() or (out["Arbitration_ID"] > 0x1FFFFFFF).any():
        raise ValueError("timestamp or CAN identifier outside valid range")
    if ((out["DLC"] < 0) | (out["DLC"] > 8)).any():
        raise ValueError("CAN 2.0 DLC must be in 0..8")
    if any(len(data) != dlc for data, dlc in zip(out["Data_Bytes"], out["DLC"])):
        raise ValueError("DLC does not match Data_Bytes length")
    if "Label" in out.columns:
        labels = pd.to_numeric(out["Label"], errors="raise")
        if not labels.isin([0, 1]).all():
            raise ValueError("Label values must be 0 (benign) or 1 (attack)")
        out["Label"] = labels.astype(int)
    return out.sort_values("Timestamp", kind="stable").reset_index(drop=True)

class FeatureExtractor:
    """Stateful causal features for one chronological stream; create anew per trace."""
    FEATURE_NAMES = ["iat", "id_frequency", "payload_entropy", "dlc", "identifier", "id_novelty", "rpm_raw"]

    def __init__(self, window: int = 100) -> None:
        if window < 2:
            raise ValueError("window must be at least 2")
        self.window = window
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
            timestamp = float(row["Timestamp"])
            arb_id = parse_identifier(row["Arbitration_ID"])
            raw_dlc = float(row["DLC"])
            if not math.isfinite(raw_dlc) or not raw_dlc.is_integer():
                raise ValueError("DLC must be a whole number")
            dlc = int(raw_dlc)
            data_val = row["Data_Bytes"]
        else:
            timestamp = float(getattr(row, "timestamp"))
            arb_id = parse_identifier(getattr(row, "arbitration_id"))
            dlc = int(getattr(row, "dlc"))
            data_val = getattr(row, "data")
        data = parse_data(data_val)
        if not math.isfinite(timestamp) or timestamp < 0:
            raise ValueError("frame timestamp must be finite and non-negative")
        if self.last_timestamp is not None and timestamp < self.last_timestamp:
            raise ValueError("frames must be processed in non-decreasing timestamp order")
        if not 0 <= dlc <= 8 or len(data) != dlc or not 0 <= arb_id <= 0x1FFFFFFF:
            raise ValueError("invalid CAN frame supplied to feature extractor")
        iat = 0.0 if self.last_timestamp is None else timestamp - self.last_timestamp
        prior_window = list(self.ids)
        if len(prior_window) == self.ids.maxlen:
            prior_window = prior_window[1:]
        frequency = sum(1 for observed_id in prior_window if observed_id == arb_id) + 1
        novelty = 0.0 if arb_id in self.seen else 1.0
        self.ids.append(arb_id)
        self.seen.add(arb_id)
        self.last_timestamp = timestamp
        rpm = float(int.from_bytes(data[:2], "little")) if arb_id == 0x316 and dlc >= 2 else 0.0
        return {"iat": iat, "id_frequency": float(frequency), "payload_entropy": self.entropy(data),
                "dlc": float(dlc), "identifier": float(arb_id), "id_novelty": novelty, "rpm_raw": rpm}

    def transform(self, frames: Iterable[object]) -> pd.DataFrame:
        return pd.DataFrame([self.transform_one(row) for row in frames], columns=self.FEATURE_NAMES)
