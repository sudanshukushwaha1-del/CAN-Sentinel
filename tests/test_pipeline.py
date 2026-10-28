from __future__ import annotations
from pathlib import Path
import json
import pandas as pd
import pytest
from can_sentinel.detector_ml import MLDetector
from can_sentinel.engine import IDSEngine
from can_sentinel.evaluator import evaluate
from can_sentinel.preprocessor import FeatureExtractor, normalize_frame_table, parse_data
from can_sentinel.simulator import CANFrame, TrafficSimulator


def test_simulation_is_reproducible_and_attack_cases_are_labeled() -> None:
    assert TrafficSimulator(31).dos(4) == TrafficSimulator(31).dos(4)
    assert all(f.arbitration_id == 0 and f.label == 1 for f in TrafficSimulator(31).dos(4))
    assert all(f.arbitration_id <= 0x7FF for f in TrafficSimulator(31).fuzzy(20))
    assert all(int.from_bytes(f.data[:2], "little") >= 7000 for f in TrafficSimulator(31).spoof(10))


def test_frame_and_csv_validation_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        CANFrame(float("nan"), 1, 1, b"x")
    with pytest.raises(ValueError):
        normalize_frame_table(pd.DataFrame([{"Timestamp": 0, "Arbitration_ID": "0x316", "DLC": 1.5, "Data_Bytes": "01"}]))
    with pytest.raises(ValueError):
        normalize_frame_table(pd.DataFrame([{"Timestamp": float("inf"), "Arbitration_ID": "0x316", "DLC": 1, "Data_Bytes": "01"}]))


def test_shared_payload_parser_accepts_documented_separators() -> None:
    assert parse_data("0x01:02_03-04") == bytes.fromhex("01020304")


def test_engine_mapping_uses_shared_id_and_payload_parser(tmp_path: Path) -> None:
    engine = IDSEngine(log_path=tmp_path / "alerts.jsonl")
    alerts, _ = engine.process({"Timestamp": 0, "Arbitration_ID": "0x316", "DLC": 2, "Data_Bytes": "01:02"})
    assert not alerts


def test_feature_extractor_preserves_state_and_rejects_disordered_stream() -> None:
    extractor = FeatureExtractor(window=3)
    first = extractor.transform_one(CANFrame(1.0, 0x100, 1, b"a"))
    second = extractor.transform_one(CANFrame(1.1, 0x100, 1, b"b"))
    assert first["id_novelty"] == 1 and second["id_novelty"] == 0
    assert second["id_frequency"] == 2 and second["iat"] == pytest.approx(0.1)
    with pytest.raises(ValueError, match="non-decreasing"):
        extractor.transform_one(CANFrame(1.05, 0x100, 1, b"c"))


def test_frequency_uses_current_bounded_window() -> None:
    extractor = FeatureExtractor(window=2)
    extractor.transform_one(CANFrame(0.0, 1, 1, b"a"))
    extractor.transform_one(CANFrame(0.1, 2, 1, b"b"))
    third = extractor.transform_one(CANFrame(0.2, 2, 1, b"c"))
    assert third["id_frequency"] == 2


def test_jsonl_rule_alert_is_recorded(tmp_path: Path) -> None:
    engine = IDSEngine(log_path=tmp_path / "alerts.jsonl")
    alerts, latency = engine.process(CANFrame(0.0, 0, 8, b"12345678", 1, "dos"))
    assert latency >= 0 and engine.last_detected
    assert any(alert.rule == "RESERVED_ID" and alert.source == "rule" for alert in alerts)
    records = [json.loads(line) for line in (tmp_path / "alerts.jsonl").read_text().splitlines()]
    assert records[0]["rule"] == "RESERVED_ID"


def test_alert_frame_indices_disambiguate_duplicate_timestamps(tmp_path: Path) -> None:
    log_path = tmp_path / "duplicate-timestamps.jsonl"
    engine = IDSEngine(log_path=log_path)
    frame = CANFrame(1.0, 0, 8, b"12345678", 1, "dos")
    first_alerts, _ = engine.process(frame)
    second_alerts, _ = engine.process(frame)
    assert first_alerts and second_alerts
    assert {alert.frame_index for alert in first_alerts} == {1}
    assert {alert.frame_index for alert in second_alerts} == {2}
    records = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert {record["frame_index"] for record in records} == {1, 2}


def test_metrics_measure_fused_rules_without_an_ml_model(tmp_path: Path) -> None:
    frames = TrafficSimulator(2).scenario(20, 10, "dos")
    result = evaluate(frames, IDSEngine(log_path=tmp_path / "events.jsonl"))
    assert result["confusion_matrix"] == {"tn": 20, "fp": 0, "fn": 0, "tp": 10}
    assert result["precision"] == result["recall"] == result["f1"] == 1.0
    assert result["roc_auc"] is None


def test_evaluator_requires_labels(tmp_path: Path) -> None:
    row = {"Timestamp": 0, "Arbitration_ID": 0x100, "DLC": 1, "Data_Bytes": b"x"}
    with pytest.raises(ValueError, match="requires a Label"):
        evaluate([row], IDSEngine(log_path=tmp_path / "events.jsonl"))


def test_evaluator_requires_fresh_engine(tmp_path: Path) -> None:
    engine = IDSEngine(log_path=tmp_path / "events.jsonl")
    engine.process(CANFrame(0, 0x100, 1, b"a"))
    with pytest.raises(ValueError, match="fresh IDSEngine"):
        evaluate([CANFrame(0, 0x100, 1, b"a")], engine)


def test_engine_inherits_detector_threshold_and_rejects_fractional_dlc(tmp_path: Path) -> None:
    class FixedScore:
        threshold = 0.75
        def score(self, feature: dict[str, float]) -> float:
            return 0.75

    detector = FixedScore()
    engine = IDSEngine(detector, tmp_path / "alerts.jsonl")
    assert engine.ml_threshold == detector.threshold
    alerts, _ = engine.process(CANFrame(0, 0x100, 1, b"a"))
    assert any(alert.source == "ml" for alert in alerts)
    fresh = IDSEngine(log_path=tmp_path / "invalid.jsonl")
    with pytest.raises(ValueError, match="whole number"):
        fresh.process({"Timestamp": 0, "Arbitration_ID": "0x100", "DLC": 1.5, "Data_Bytes": "01"})


def test_ml_score_is_order_independent_and_reproducible() -> None:
    model = MLDetector(seed=13).fit(normal_count=150, per_attack_count=50)
    values = {"iat": 0.01, "id_frequency": 2.0, "payload_entropy": 1.0, "dlc": 8.0,
              "identifier": 0x316, "id_novelty": 0.0, "rpm_raw": 1000.0}
    reordered = dict(reversed(list(values.items())))
    assert model.score(values) == pytest.approx(model.score(reordered))
    assert model.score(values) == pytest.approx(MLDetector(seed=13).fit(150, 50).score(values))
