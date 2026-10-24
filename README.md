# CAN-Sentinel

**An educational, offline CAN 2.0B intrusion-detection demo.** It creates synthetic vehicle-network frames or inspects an authorized CSV log, applies simple rules plus a synthetic-trained ML score, records alerts, and displays results in a Streamlit dashboard.

> **Safety and claims:** This project never connects to or transmits on a physical CAN bus. It is not production automotive security software, is not safety-certified, and has no hard-real-time guarantee. The model is trained on synthetic examples. Its scores are not calibrated vehicle performance or proof of zero-day detection.

## Quick start

Requirements: Python 3.10 or newer.

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

In the dashboard, choose **Synthetic scenario**, select an attack type and frame counts, set a seed, then click **Analyze traffic**. The same seed gives repeatable generated traffic. The first analysis trains a demonstration model; subsequent runs with the same seed reuse it in the dashboard session. The app shows traffic, packet bytes, frame-level alerts, and—when labels are available—classification metrics and an ML ROC curve. Alert events can be downloaded from the dashboard as JSONL.

## What the output means

- **Accuracy, precision, recall, F1, and false-positive rate** describe frame-level outcomes from the *fused IDS decision*: an alert from any deterministic rule OR the ML score crossing its configured threshold.
- **ROC-AUC** is the ranking performance of the ML score alone. The score is bounded between 0 and 1 but is **not a calibrated probability**. AUC is omitted when there is no ML model or both labels are not present.
- **Latency** is per-frame detector processing time before alert construction and disk logging. It varies by host and load; it is not a hard-real-time measurement.

Metrics from generated samples are demonstrations only. Synthetic attack patterns are known to the training procedure and are not independent evidence of generalization to real vehicles. Use independent, authorized data and a leakage-safe evaluation protocol for any research claim.

## CSV inspection

Choose **Upload CSV log** in the dashboard for offline inspection of an authorized capture. Required columns are:

```text
Timestamp,Arbitration_ID,DLC,Data_Bytes
```

An optional `Label` column must contain `0` for benign and `1` for attack. Timestamps must be finite/non-negative; IDs may be decimal or `0x`-prefixed; DLC must be an integer 0–8 and equal the byte count. Payloads accept hex with whitespace, colon, comma, underscore, or hyphen separators. Out-of-order rows are stably sorted by timestamp. Without labels, the dashboard can show alerts and inspect packets but will not calculate accuracy/precision/recall/F1 or ROC-AUC.

Library use:

```python
from can_sentinel.preprocessor import read_can_csv
from can_sentinel.detector_ml import MLDetector
from can_sentinel.engine import IDSEngine
from can_sentinel.evaluator import evaluate

rows = read_can_csv("authorized_capture.csv")
model = MLDetector(seed=7).fit()
engine = IDSEngine(model, log_path="output/alerts.jsonl")
if "Label" not in rows.columns:
    for row in rows.to_dict(orient="records"):
        alerts, detector_ms = engine.process(row)
        if alerts:
            print(alerts)
else:
    records = rows.to_dict(orient="records")
    print(evaluate(records, IDSEngine(model, log_path="output/evaluation-alerts.jsonl")))
```

Use a **fresh `IDSEngine` for each independent trace**; the rolling timing and frequency features carry state forward and require chronological frames. Evaluation requires a ground-truth label on every frame.

## What is implemented

- **DoS generator:** `0x000` frames at 10x the nominal generator rate.
- **Fuzzy generator:** randomized standard IDs (`0x000`–`0x7FF`) and randomized eight-byte payloads.
- **RPM spoof generator:** implausible engine-speed data on `0x316`.
- **Rules:** reserved-ID observations, aggregate bus rate, per-ID rate, and DLC bounds.
- **Causal features:** inter-arrival time, recent ID frequency, payload entropy, DLC, ID novelty, and raw RPM field.
- **ML:** Isolation Forest plus Random Forest ensemble, trained reproducibly on generated benign/attack runs. Output is a heuristic ranking score, not a calibrated probability.
- **Forensics:** UTC event time, frame time, ID, source (`rule`/`ml`), rule/severity/detail, score, and detector duration in JSONL.
- **Evaluation:** fused frame-level classification metrics and ML-only ROC-AUC when possible.

## Project layout

```text
can_sentinel/                 Core simulator, parser, rules, ML, engine, evaluator
app.py                        Streamlit simulation and CSV dashboard
generate_report.py            Project summary and vulnerability table generator
CAN-Sentinel-Project-Report.md Short project/vulnerability summary
CAN-Sentinel-Technical-Guide.md Detailed walkthrough
CAN-Sentinel-Technical-Guide.pdf PDF copy of the walkthrough
tests/                        Regression tests
requirements.txt              Runtime dependencies
requirements-dev.txt           Runtime + pytest
```

## Tests and reports

```bash
pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall -q can_sentinel app.py generate_report.py
python generate_report.py
```

The report generator writes `CAN-Sentinel-Project-Report.md` in the current folder by default. Optional PDF export uses the external `manus-md-to-pdf` converter (`python generate_report.py --pdf`). The checked-in technical guide is the fuller explanation; the generated project report is a concise risk summary.

## Important limitations

Classic CAN does not authenticate the sender merely from its arbitration ID. This demonstration does not implement a vehicle-specific signal database, cryptographic CAN security, gateway enforcement, safety response, secure log signing, or adapter connectivity. Thresholds and generated traffic are illustrative. Do not use the output to make safety decisions or to claim vehicle-level security efficacy.
