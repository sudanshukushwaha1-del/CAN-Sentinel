# CAN-Sentinel

**A simulation-only CAN 2.0B intrusion-detection demo.** The dashboard generates reproducible traffic, applies deterministic rules and a synthetic-trained anomaly model, and shows packets, alerts, and evaluation metrics.

[![Try the live app](https://img.shields.io/badge/Try%20the%20app-Live%20site-FF4B4B?logo=streamlit&logoColor=white)](https://cansentinel-knbjqxgy.manus.space)
[![Download the source ZIP](https://img.shields.io/badge/Download-source%20ZIP-2ea44f?logo=github&logoColor=white)](https://github.com/sudanshukushwaha1-del/CAN-Sentinel/archive/refs/heads/development.zip)
[Browse the project on GitHub](https://github.com/sudanshukushwaha1-del/CAN-Sentinel)

## Important safety and data note

This is an educational prototype—not a certified automotive IDS. It never connects to a vehicle, reads from a CAN adapter, or transmits CAN frames. Model scores are trained on synthetic traffic and are not calibrated vehicle performance or proof of zero-day detection. Do not use the results for safety decisions.

The public dashboard can inspect an offline CSV, but uploaded content is sent to the hosted app for analysis. **Never upload confidential, personal, or unauthorized vehicle captures.** Use synthetic examples or sanitized data you are permitted to share.

## Try the dashboard

Choose **Synthetic scenario**, select an attack and seed, then click **Analyze traffic**. Available attacks are DoS flooding led by arbitration ID `0x000`, fuzzy traffic with randomized standard IDs and payloads, and Engine Speed spoofing on ID `0x316`. Results show the traffic timeline, packet inspector, source-aware alert feed, and a downloadable JSONL alert log. Each alert includes a per-trace frame index so frames with identical timestamps remain distinguishable.

For an offline capture, choose **Upload CSV log**. Required columns are `Timestamp`, `Arbitration_ID`, `DLC`, and `Data_Bytes`; optional `Label` values are `0` for benign and `1` for attack. IDs can be decimal or `0x`-prefixed. DLC must be an integer from 0–8 and match the byte count. Chronological ordering is normalized. Without labels, the dashboard omits classification metrics and ROC-AUC.

The subtle background palette follows the calendar season. It changes only the appearance, not detector behavior.

## Run locally

Requirements: Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate              # Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

The local Streamlit run is the simplest way to explore the dashboard. To test the production-style Nginx proxy and required root route manifest, see [DEPLOYMENT.md](DEPLOYMENT.md).

## How detection and metrics work

The preprocessor validates the CAN log fields and extracts causal features such as inter-arrival time, recent ID frequency and payload entropy. The deterministic detector checks protocol and frequency rules. An Isolation Forest/Random Forest ensemble trained reproducibly on generated data produces a heuristic anomaly score. A fused frame is detected if a rule alerts or the ML score crosses its configured threshold.

Accuracy, precision, recall, F1, false-positive rate, and detector decision latency describe frame-level results when labels are available. ROC-AUC ranks the ML score only; it is not a probability. Detector latency is host-dependent and excludes JSONL disk I/O, so it is not a real-time guarantee. Synthetic results do not establish performance on actual vehicles.

## Project layout

```text
app.py                         Streamlit interface and analysis flow
can_sentinel/                  Simulator, parser, rules, ML, engine, evaluator, seasonal palette
Dockerfile                     Managed container image
start.sh                       Starts Streamlit and Nginx
nginx/nginx.conf.template      WebSocket proxy and route-manifest endpoint
public/manus-routes.json       Declares the website page route
requirements.txt               Runtime dependencies
requirements-dev.txt           Runtime dependencies plus pytest
tests/                         Pipeline, dashboard and theme regressions
DEPLOYMENT.md                  Managed hosting and local proxy details
CAN-Sentinel-Technical-Guide.md Detailed project walkthrough
CAN-Sentinel-Technical-Guide.pdf PDF copy of the walkthrough
```

## Tests and report

```bash
pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall -q can_sentinel app.py generate_report.py
python generate_report.py
```

The report generator produces the short Markdown vulnerability summary; optional PDF export uses `manus-md-to-pdf` (`python generate_report.py --pdf`). The technical guide explains the architecture and metric caveats in more depth.
