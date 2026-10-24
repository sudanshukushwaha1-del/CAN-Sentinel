from __future__ import annotations
import json
from pathlib import Path
import pytest
from can_sentinel.detector_rules import RuleDetector
from can_sentinel.engine import IDSEngine
from can_sentinel.evaluator import evaluate
from can_sentinel.preprocessor import normalize_frame_table
from can_sentinel.simulator import CANFrame, TrafficSimulator


def test_simulation_is_reproducible_and_attacks_are_labeled() -> None:
    first = TrafficSimulator(31).dos(4)
    second = TrafficSimulator(31).dos(4)
    assert first == second
    assert all(frame.arbitration_id == 0 and frame.label == 1 for frame in first)
    assert TrafficSimulator(31).fuzzy(2)[0].arbitration_id <= 0x7FF
    assert int.from_bytes(TrafficSimulator(31).spoof(1)[0].data[:2], "little") >= 7000


def test_frame_and_log_validation() -> None:
    with pytest.raises(ValueError):
        CANFrame(0.0, 1, 9, b"123456789")
    with pytest.raises(ValueError):
        normalize_frame_table(__import__("pandas").DataFrame([{
            "Timestamp": 0, "Arbitration_ID": "0x316", "DLC": 2, "Data_Bytes": "01"
        }]))


def test_reserved_identifier_alert_is_forensically_logged(tmp_path: Path) -> None:
    engine = IDSEngine(log_path=tmp_path / "alerts.jsonl")
    alerts, latency = engine.process(CANFrame(0.0, 0, 8, b"12345678", 1, "dos"))
    assert latency >= 0
    assert any(alert.rule == "RESERVED_ID" for alert in alerts)
    record = json.loads((tmp_path / "alerts.jsonl").read_text().splitlines()[0])
    assert record["rule"] == "RESERVED_ID"


def test_metrics_accepts_labeled_frames(tmp_path: Path) -> None:
    frames = TrafficSimulator(2).scenario(20, 10, "dos")
    result = evaluate(frames, IDSEngine(log_path=tmp_path / "events.jsonl"))
    assert result["frames"] == 30
    assert 0 <= result["false_positive_rate"] <= 1
    assert result["mean_latency_ms"] >= 0
