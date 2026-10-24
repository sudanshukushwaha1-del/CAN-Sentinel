"""Generate a project overview and prioritized vulnerability assessment (Markdown/PDF)."""
from __future__ import annotations
import argparse
from pathlib import Path

REPORT = '''# CAN-Sentinel: Automotive ECU Intrusion Detection System

## Executive summary
CAN-Sentinel is a research/demo pipeline for inspecting offline CAN 2.0B logs and reproducible synthetic traffic. It combines deterministic protocol/rate rules with Isolation Forest and Random Forest scores, emits JSON Lines forensic alerts, and calculates standard IDS metrics. The included scenarios are synthetic and are not a substitute for vehicle testing, a validated threat model, or safety certification.

## Architecture
`TrafficSimulator / CSV -> validation + causal feature extraction -> deterministic rules + ML ensemble -> JSONL alert feed -> evaluator / Streamlit dashboard`

## Implemented attack scenarios
- **DoS:** repeated dominant-priority arbitration ID `0x000`, generated at 10x the normal period.
- **Fuzzy:** randomized 11-bit IDs (`0x000`–`0x7FF`) and random eight-byte payloads.
- **Spoofing:** implausible high engine-speed payloads on `0x316`.

## Vulnerability assessment
| Finding | Severity | Potential impact | Mitigation / next step |
|---|---|---|---|
| Classical CAN lacks sender authentication | Critical | A compromised node may impersonate another ECU | Use secure gateway controls; evaluate CANsec where supported; protect keys and trust boundaries |
| Bus-level availability exposure | High | High-priority floods can starve lower-priority messages | Rate-limit at a gateway, monitor deadlines, isolate segments; validate fail-safe behavior |
| Static ID/rate assumptions | High | Vehicle-specific legitimate traffic may be falsely blocked or missed | Derive allowlists and timing envelopes from approved OEM specifications and representative traces |
| Synthetic training distribution | High | Benchmark scores may not generalize to production ECUs or novel attacks | Train/validate on consented vehicle captures; hold out vehicles, routes, and attack families |
| No cryptographic provenance in log input | Medium | Logs may be altered or misattributed | Protect collection chain, timestamp source, storage access, and signed export manifests |
| Host-side Python timing is non-deterministic | Medium | Sub-millisecond measurements are not hard real-time guarantees | Profile on target hardware; isolate process; use bounded queues and a safety-reviewed implementation |

## Metrics
The evaluator reports accuracy, precision, recall, F1, false-positive rate, ROC-AUC, mean latency, and p95 latency. Results depend on the generated seed, threshold, machine, Python/OS load, and scenario composition. Do not present demo values as validated vehicle metrics.

## Safe use
The simulator only creates in-memory records. No module opens a CAN interface or transmits frames. Use only authorized captures and controlled test benches; never inject traffic into a public road vehicle.
'''

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="CAN-Sentinel-Project-Report.md")
    parser.add_argument("--pdf", action="store_true", help="also convert report to PDF using manus-md-to-pdf")
    args = parser.parse_args()
    output = Path(args.output)
    output.write_text(REPORT, encoding="utf-8")
    print(f"Wrote {output.resolve()}")
    if args.pdf:
        import subprocess
        pdf = output.with_suffix(".pdf")
        subprocess.run(["manus-md-to-pdf", str(output), str(pdf)], check=True)
        print(f"Wrote {pdf.resolve()}")

if __name__ == "__main__":
    main()
